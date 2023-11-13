/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/thread.h"
#include "spdk/fsdev.h"
#include "spdk/fuse_dispatcher.h"
#include "spdk/env.h"
#include "spdk/event.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "linux/fuse_kernel.h"

#define TEST_FILENAME "hello_file"
#define DATA_SIZE 512
#define ROOT_NODEID 1

/**
 * FUSE command-specific parameters
 *
 * Opcode specific parameters structure, if required.
 */
union fuse_cmd_params {
	struct fuse_forget_in forget_in;
	struct fuse_getattr_in getattr_in;
	struct fuse_setattr_in setattr_in;
	struct fuse_mknod_in mknod_in;
	struct fuse_mkdir_in mkdir_in;
	struct fuse_rename_in rename_in;
	struct fuse_link_in link_in;
	struct fuse_open_in open_in;
	struct fuse_read_in read_in;
	struct fuse_write_in write_in;
	struct fuse_release_in release_in;
	struct fuse_fsync_in fsync_in;
	struct fuse_setxattr_in setxattr_in;
	struct fuse_getxattr_in getxattr_in;
	struct fuse_flush_in flush_in;
	struct fuse_init_in init_in;
	struct fuse_access_in access_in;
	struct fuse_create_in create_in;
	struct fuse_interrupt_in interrupt_in;
	struct fuse_bmap_in bmap_in;
	struct fuse_ioctl_in ioctl_in;
	struct fuse_poll_in poll_in;
	struct fuse_batch_forget_in batch_forget_in;
	struct fuse_fallocate_in fallocate_in;
	struct fuse_rename2_in rename2_in;
	struct fuse_lseek_in lseek_in;
	struct fuse_copy_file_range_in copy_file_range_in;
};

/**
 * FUSE command-specific completion data
 *
 * Opcode specific output structure will be filled in by the fuse_dispatcher module
 * on FUSE command completion.
 */
union fuse_cpl_data {
	struct fuse_entry_out entry_out;
	struct fuse_attr_out attr_out;
	struct fuse_open_out open_out;
	struct fuse_write_out write_out;
	struct fuse_statfs_out statfs_out;
	struct fuse_getxattr_out getxattr_out;
	struct fuse_init_out init_out;
	struct fuse_bmap_out bmap_out;
	struct fuse_ioctl_out ioctl_out;
	struct fuse_poll_out poll_out;
	struct fuse_lseek_out lseek_out;
};

#define MAX_FUSE_CMD_PARAMS_SIZE sizeof(union fuse_cmd_params)
#define MAX_FUSE_CPL_DATA_SIZE sizeof(union fuse_cpl_data)

static char *g_fsdev_name = "Fs0";
int g_result = 0;

struct fuse_cmd_cpl {
	struct {
		struct fuse_in_header hdr;
		union fuse_cmd_params params;
	} cmd;
	struct {
		struct fuse_out_header hdr;
		union fuse_cpl_data data;
	} cpl;

	struct iovec in_iov[2];
	struct iovec out_iov[2];
};

/*
 * We'll use this struct to gather housekeeping hello_context to pass between
 * our events and callbacks.
 */
struct hello_context_t {
	struct spdk_thread *app_thread;
	struct spdk_fsdev_desc *fsdev_desc;
	struct spdk_fuse_dispatcher *fuse_disp;
	struct spdk_io_channel *fsdev_io_channel;
	char *fsdev_name;
	int thread_count;
	struct fuse_cmd_cpl fcc;
};

struct hello_thread_t {
	struct hello_context_t *hello_context;
	struct spdk_thread *thread;
	struct spdk_io_channel *fsdev_io_channel;
	uint64_t unique;
	uint8_t *buf;
	char *file_name;
	uint64_t file_nodeid;
	uint64_t file_handle;
	struct fuse_cmd_cpl fcc;
};

/*
 * Usage function for printing parameters that are specific to this application
 */
static void
hello_fsdev_usage(void)
{
	printf(" -f <fs>                 name of the fsdev to use\n");
}

/*
 * This function is called to parse the parameters that are specific to this application
 */
static int
hello_fsdev_parse_arg(int ch, char *arg)
{
	switch (ch) {
	case 'f':
		g_fsdev_name = arg;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static void
fuse_cmd_cpl_init(struct fuse_cmd_cpl *fcc, const void *params, size_t cmd_params_len,
		  size_t cpl_data_len, uint32_t opcode, uint64_t unique, uint32_t nodeid)
{
	assert(cmd_params_len <= MAX_FUSE_CMD_PARAMS_SIZE);
	assert(cpl_data_len <= MAX_FUSE_CPL_DATA_SIZE);

	memset(fcc, 0, sizeof(*fcc));

	fcc->cmd.hdr.len = sizeof(fcc->cmd.hdr) + cmd_params_len;
	fcc->cmd.hdr.opcode = opcode;
	fcc->cmd.hdr.unique = unique;
	fcc->cmd.hdr.nodeid = nodeid;
	/* @todo: what should be set to uid, gid, pid? */
	fcc->cmd.hdr.uid = 0;
	fcc->cmd.hdr.gid = 0;
	fcc->cmd.hdr.pid = 0;

	if (cmd_params_len) {
		memcpy(&fcc->cmd.params, params, cmd_params_len);
	}

	fcc->in_iov[0].iov_base = &fcc->cmd;
	fcc->in_iov[0].iov_len = fcc->cmd.hdr.len;

	fcc->out_iov[0].iov_base = &fcc->cpl;
	fcc->out_iov[0].iov_len = sizeof(fcc->cpl.hdr) + cpl_data_len;
}

static void
fuse_cmd_cpl_add_cmd_buf(struct fuse_cmd_cpl *fcc, void *buf, size_t size)
{
	assert(!fcc->in_iov[1].iov_base && !fcc->in_iov[1].iov_len);

	fcc->cmd.hdr.len += size;

	fcc->in_iov[1].iov_base = buf;
	fcc->in_iov[1].iov_len = size;
}

static void
fuse_cmd_cpl_add_cpl_buf(struct fuse_cmd_cpl *fcc, void *buf, size_t size)
{
	assert(!fcc->out_iov[1].iov_base && !fcc->out_iov[1].iov_len);

	fcc->out_iov[1].iov_base = buf;
	fcc->out_iov[1].iov_len = size;
}

static void
print_fuse_cpl(const char *prefix, const struct fuse_cmd_cpl *fcc)
{
	SPDK_NOTICELOG("%s: len %u, error %d, unique %lu\n",
		       prefix,
		       fcc->cpl.hdr.len,
		       fcc->cpl.hdr.error,
		       fcc->cpl.hdr.unique);
}

static void
print_fuse_attr(const struct fuse_attr *attr)
{
	SPDK_NOTICELOG("fuse_attr: ino %lu, size %lu, blocks %lu, atime %lu, mtime %lu, ctime %lu, "
		       "atimensec %u, mtimensec %u, ctimensec %u, mode %u, nlink %u, uid %u, gid %u, "
		       "rdev %u\n",
		       attr->ino,
		       attr->size,
		       attr->blocks,
		       attr->atime,
		       attr->mtime,
		       attr->ctime,
		       attr->atimensec,
		       attr->mtimensec,
		       attr->ctimensec,
		       attr->mode,
		       attr->nlink,
		       attr->uid,
		       attr->gid,
		       attr->rdev);
}

static void
print_fuse_entry_out(const struct fuse_entry_out *entry_out)
{
	SPDK_NOTICELOG("fuse_entry_out: inode %lu, generation %lu, entry_valid %lu, attr_valid %lu, "
		       "entry_valid_nsec %u, attr_valid_nsec %u\n",
		       entry_out->nodeid,
		       entry_out->generation,
		       entry_out->entry_valid,
		       entry_out->attr_valid,
		       entry_out->entry_valid_nsec,
		       entry_out->attr_valid_nsec);
	print_fuse_attr(&entry_out->attr);
}

static void
hello_app_done(struct hello_context_t *hello_context, int rc)
{
	spdk_put_io_channel(hello_context->fsdev_io_channel);
	spdk_fuse_dispatcher_delete(hello_context->fuse_disp);
	spdk_fsdev_close(hello_context->fsdev_desc);
	SPDK_NOTICELOG("Stopping app: rc %d\n", rc);
	spdk_app_stop(rc);
}

static void
fuse_destroy_complete(void *cb_arg, uint32_t error)
{
	struct hello_context_t *hello_context = cb_arg;

	print_fuse_cpl("Fuse destroy complete", &hello_context->fcc);
	if (error) {
		SPDK_ERRLOG("Fuse destroy failed: error %" PRIu32 "\n", error);
		g_result = EINVAL;
	}

	hello_app_done(hello_context, g_result);
}

static void
hello_fuse_destroy(struct hello_context_t *hello_context)
{
	int err;

	SPDK_NOTICELOG("Fuse destroy\n");
	fuse_cmd_cpl_init(&hello_context->fcc, NULL, 0, 0, FUSE_DESTROY, 1, 0);

	err = spdk_fuse_dispatcher_submit_request(hello_context->fuse_disp,
			hello_context->fsdev_io_channel,
			hello_context->fcc.in_iov, 1, hello_context->fcc.out_iov, 1,
			fuse_destroy_complete, hello_context);
	if (err) {
		fuse_destroy_complete(hello_context, err);
	}
}

static void
hello_app_notify_thread_done(void *ctx)
{
	struct hello_context_t *hello_context = (struct hello_context_t *)ctx;

	assert(hello_context->thread_count > 0);
	hello_context->thread_count--;
	if (hello_context->thread_count == 0) {
		hello_fuse_destroy(hello_context);
	}
}

static void
hello_thread_done(struct hello_thread_t *hello_thread, int rc)
{
	struct hello_context_t *hello_context = hello_thread->hello_context;

	spdk_put_io_channel(hello_thread->fsdev_io_channel);
	free(hello_thread->buf);
	free(hello_thread->file_name);
	SPDK_NOTICELOG("Thread %s done: rc %d\n",
		       spdk_thread_get_name(hello_thread->thread), rc);
	spdk_thread_exit(hello_thread->thread);
	free(hello_thread);
	if (rc) {
		g_result = rc;
	}

	spdk_thread_send_msg(hello_context->app_thread, hello_app_notify_thread_done, hello_context);
}

static void
hello_submit(struct hello_thread_t *hello_thread,
	     struct iovec *in_iov, int in_iovcnt,
	     struct iovec *out_iov, int out_iovcnt,
	     spdk_fuse_dispatcher_submit_cpl_cb complete_cb)
{
	int err;

	err = spdk_fuse_dispatcher_submit_request(hello_thread->hello_context->fuse_disp,
			hello_thread->fsdev_io_channel,
			in_iov, in_iovcnt,
			out_iov, out_iovcnt,
			complete_cb, hello_thread);
	if (err) {
		complete_cb(hello_thread, err);
	}
}

static bool
hello_check_complete(struct hello_thread_t *hello_thread, int32_t expected_error)
{
	assert(hello_thread->fcc.cpl.hdr.unique == hello_thread->unique);
	hello_thread->unique++;
	if (hello_thread->fcc.cpl.hdr.error != expected_error) {
		SPDK_ERRLOG("Unexpected error code: %d != %d\n",
			    hello_thread->fcc.cpl.hdr.error, expected_error);
		hello_thread_done(hello_thread, EIO);
		return false;
	}

	return true;
}

static void
unlink_complete(void *cb_arg, uint32_t error)
{
	struct hello_thread_t *hello_thread = cb_arg;

	print_fuse_cpl("Unlink complete", &hello_thread->fcc);
	if (!hello_check_complete(hello_thread, 0)) {
		return;
	}

	hello_thread->file_nodeid = 0;
	hello_thread_done(hello_thread, 0);
}

static void
hello_unlink(struct hello_thread_t *hello_thread)
{
	SPDK_NOTICELOG("Unlink file %s\n", hello_thread->file_name);

	fuse_cmd_cpl_init(&hello_thread->fcc, NULL, 0, 0, FUSE_UNLINK, hello_thread->unique, ROOT_NODEID);
	fuse_cmd_cpl_add_cmd_buf(&hello_thread->fcc, hello_thread->file_name,
				 strlen(hello_thread->file_name) + 1);

	hello_submit(hello_thread, hello_thread->fcc.in_iov, 2, hello_thread->fcc.out_iov, 1,
		     unlink_complete);
}

static void
release_complete(void *cb_arg, uint32_t error)
{
	struct hello_thread_t *hello_thread = cb_arg;

	print_fuse_cpl("Release complete", &hello_thread->fcc);
	if (!hello_check_complete(hello_thread, 0)) {
		return;
	}

	hello_thread->file_handle = 0;
	hello_unlink(hello_thread);
}

static void
hello_release(struct hello_thread_t *hello_thread)
{
	struct fuse_release_in params = {0};

	params.fh = hello_thread->file_handle;

	SPDK_NOTICELOG("Release file handle %lu\n", hello_thread->file_handle);

	fuse_cmd_cpl_init(&hello_thread->fcc, &params, sizeof(params), 0, FUSE_RELEASE,
			  hello_thread->unique, hello_thread->file_nodeid);

	hello_submit(hello_thread, hello_thread->fcc.in_iov, 1, hello_thread->fcc.out_iov, 1,
		     release_complete);
}

static void
read_complete(void *cb_arg, uint32_t error)
{
	struct hello_thread_t *hello_thread = cb_arg;
	uint8_t data = spdk_env_get_current_core();
	int i;

	print_fuse_cpl("Read complete", &hello_thread->fcc);
	if (!hello_check_complete(hello_thread, 0)) {
		return;
	}

	for (i = 0; i < DATA_SIZE; ++i) {
		if (hello_thread->buf[i] != data) {
			SPDK_NOTICELOG("Bad read data at offset %d, 0x%02X != 0x%02X\n",
				       i, hello_thread->buf[i], data);
			break;
		}
	}

	hello_release(hello_thread);
}

static void
hello_read(struct hello_thread_t *hello_thread)
{
	struct fuse_read_in params = {0};

	SPDK_NOTICELOG("Read from file handle %lu\n", hello_thread->file_handle);

	memset(hello_thread->buf, 0xFF, DATA_SIZE);

	params.fh = hello_thread->file_handle;
	params.size = DATA_SIZE;

	fuse_cmd_cpl_init(&hello_thread->fcc, &params, sizeof(params), 0, FUSE_READ,
			  hello_thread->unique, hello_thread->file_nodeid);
	fuse_cmd_cpl_add_cpl_buf(&hello_thread->fcc, hello_thread->buf, DATA_SIZE);

	hello_submit(hello_thread, hello_thread->fcc.in_iov, 1, hello_thread->fcc.out_iov, 2,
		     read_complete);
}

static void
write_complete(void *cb_arg, uint32_t error)
{
	struct hello_thread_t *hello_thread = cb_arg;

	print_fuse_cpl("Write complete", &hello_thread->fcc);
	if (!hello_check_complete(hello_thread, 0)) {
		return;
	}

	SPDK_NOTICELOG("fuse_write_out: size %u\n", hello_thread->fcc.cpl.data.write_out.size);
	hello_read(hello_thread);
}

static void
hello_write(struct hello_thread_t *hello_thread)
{
	uint8_t data = spdk_env_get_current_core();
	struct fuse_write_in params = {0};

	SPDK_NOTICELOG("Write to file handle %lu\n", hello_thread->file_handle);

	memset(hello_thread->buf, data, DATA_SIZE);

	params.fh = hello_thread->file_handle;
	params.size = DATA_SIZE;

	fuse_cmd_cpl_init(&hello_thread->fcc, &params, sizeof(params), sizeof(struct fuse_write_out),
			  FUSE_WRITE, hello_thread->unique, hello_thread->file_nodeid);
	fuse_cmd_cpl_add_cmd_buf(&hello_thread->fcc, hello_thread->buf, DATA_SIZE);


	hello_submit(hello_thread, hello_thread->fcc.in_iov, 2, hello_thread->fcc.out_iov, 1,
		     write_complete);
}

static void
open_complete(void *cb_arg, uint32_t error)
{
	struct hello_thread_t *hello_thread = cb_arg;

	print_fuse_cpl("Open complete", &hello_thread->fcc);
	if (!hello_check_complete(hello_thread, 0)) {
		return;
	}

	SPDK_NOTICELOG("fuse_open_out: fh %lu, open flags 0x%08X\n",
		       hello_thread->fcc.cpl.data.open_out.fh,
		       hello_thread->fcc.cpl.data.open_out.open_flags);
	hello_thread->file_handle = hello_thread->fcc.cpl.data.open_out.fh;
	hello_write(hello_thread);
}

static void
hello_open(struct hello_thread_t *hello_thread)
{
	struct fuse_open_in params = {0};

	SPDK_NOTICELOG("Open nodeid %lu\n", hello_thread->file_nodeid);

	params.flags = O_RDWR;

	fuse_cmd_cpl_init(&hello_thread->fcc, &params, sizeof(params), sizeof(struct fuse_open_out),
			  FUSE_OPEN, hello_thread->unique, hello_thread->file_nodeid);

	hello_submit(hello_thread, hello_thread->fcc.in_iov, 1, hello_thread->fcc.out_iov, 1,
		     open_complete);
}

static void
lookup_complete(void *cb_arg, uint32_t error)
{
	struct hello_thread_t *hello_thread = cb_arg;

	print_fuse_cpl("Lookup complete", &hello_thread->fcc);
	if (!hello_check_complete(hello_thread, 0)) {
		return;
	}

	print_fuse_entry_out(&hello_thread->fcc.cpl.data.entry_out);
	assert(hello_thread->file_nodeid == hello_thread->fcc.cpl.data.entry_out.nodeid);
	hello_open(hello_thread);
}

static void
hello_lookup(struct hello_thread_t *hello_thread)
{
	SPDK_NOTICELOG("Lookup file %s\n", hello_thread->file_name);

	fuse_cmd_cpl_init(&hello_thread->fcc, NULL, 0, sizeof(struct fuse_entry_out),
			  FUSE_LOOKUP, hello_thread->unique, ROOT_NODEID);
	fuse_cmd_cpl_add_cmd_buf(&hello_thread->fcc, hello_thread->file_name,
				 strlen(hello_thread->file_name) + 1);

	hello_submit(hello_thread, hello_thread->fcc.in_iov, 2, hello_thread->fcc.out_iov, 1,
		     lookup_complete);
}

static void
mknod_complete(void *cb_arg, uint32_t error)
{
	struct hello_thread_t *hello_thread = cb_arg;

	print_fuse_cpl("Mknod complete", &hello_thread->fcc);
	if (!hello_check_complete(hello_thread, 0)) {
		return;
	}

	print_fuse_entry_out(&hello_thread->fcc.cpl.data.entry_out);
	hello_thread->file_nodeid = hello_thread->fcc.cpl.data.entry_out.nodeid;
	hello_lookup(hello_thread);
}

static void
hello_mknod(void *ctx)
{
	struct hello_thread_t *hello_thread = (struct hello_thread_t *)ctx;
	struct fuse_mknod_in params = {0};

	SPDK_NOTICELOG("Mknod file %s\n", hello_thread->file_name);

	params.mode = S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO;

	fuse_cmd_cpl_init(&hello_thread->fcc, &params, sizeof(params), sizeof(struct fuse_entry_out),
			  FUSE_MKNOD, hello_thread->unique, ROOT_NODEID);
	fuse_cmd_cpl_add_cmd_buf(&hello_thread->fcc, hello_thread->file_name,
				 strlen(hello_thread->file_name) + 1);

	hello_submit(hello_thread, hello_thread->fcc.in_iov, 2, hello_thread->fcc.out_iov, 1,
		     mknod_complete);
}

static void
hello_start_thread(void *ctx)
{
	struct hello_context_t *hello_context = (struct hello_context_t *)ctx;
	struct hello_thread_t *hello_thread;
	/* File name size assumes that core number will fit into 3 characters */
	const int filename_size = strlen(TEST_FILENAME) + 5;

	hello_thread = calloc(1, sizeof(struct hello_thread_t));
	if (!hello_thread) {
		SPDK_ERRLOG("Failed to allocate thread context\n");
		spdk_thread_send_msg(hello_context->app_thread, hello_app_notify_thread_done, hello_context);
		return;
	}

	hello_thread->hello_context = hello_context;
	hello_thread->thread = spdk_get_thread();
	hello_thread->unique = 1;
	hello_thread->buf = (char *)malloc(DATA_SIZE);
	if (!hello_thread->buf) {
		SPDK_ERRLOG("Could not allocate data buffer\n");
		hello_thread_done(hello_thread, ENOMEM);
		return;
	}

	hello_thread->file_name = (char *)malloc(filename_size);
	if (!hello_thread->file_name) {
		SPDK_ERRLOG("Could not allocate file name buffer\n");
		hello_thread_done(hello_thread, ENOMEM);
		return;
	}

	if (snprintf(hello_thread->file_name, filename_size, "%s_%u",
		     TEST_FILENAME, spdk_env_get_current_core()) >= filename_size) {
		SPDK_ERRLOG("File name size doesn't fit into buffer\n");
		hello_thread_done(hello_thread, ENOMEM);
		return;
	}

	hello_thread->fsdev_io_channel = spdk_fsdev_get_io_channel(hello_thread->hello_context->fsdev_desc);
	if (!hello_thread->fsdev_io_channel) {
		SPDK_ERRLOG("Could not create fsdev I/O channel!\n");
		hello_thread_done(hello_thread, ENOMEM);
		return;
	}

	SPDK_NOTICELOG("Started thread %s on core %u\n",
		       spdk_thread_get_name(hello_thread->thread),
		       spdk_env_get_current_core());
	spdk_thread_send_msg(hello_thread->thread, hello_mknod, hello_thread);
}

static void
hello_create_threads(struct hello_context_t *hello_context)
{
	uint32_t cpu;
	char thread_name[32];
	struct spdk_cpuset mask = {};
	struct spdk_thread *thread;

	SPDK_ENV_FOREACH_CORE(cpu) {
		snprintf(thread_name, sizeof(thread_name), "hello_fsdev_%u", cpu);
		spdk_cpuset_zero(&mask);
		spdk_cpuset_set_cpu(&mask, cpu, true);
		thread = spdk_thread_create(thread_name, &mask);
		assert(thread != NULL);
		hello_context->thread_count++;
		spdk_thread_send_msg(thread, hello_start_thread, hello_context);
	}
}

static void
fuse_init_complete(void *cb_arg, uint32_t error)
{
	struct hello_context_t *hello_context = cb_arg;
	struct fuse_init_out *init_out;

	print_fuse_cpl("Fuse init complete", &hello_context->fcc);
	if (hello_context->fcc.cpl.hdr.error) {
		SPDK_ERRLOG("Fuse init failed: error %d\n", hello_context->fcc.cpl.hdr.error);
		hello_app_done(hello_context, EINVAL);
		return;
	}

	init_out = &hello_context->fcc.cpl.data.init_out;
	SPDK_NOTICELOG("fuse_init_out: major %u, minor %u, max_readahead %u, flags 0x%08X, max_write %u\n",
		       init_out->major, init_out->minor,
		       init_out->max_readahead, init_out->flags, init_out->max_write);

	hello_create_threads(hello_context);
}

static void
hello_fuse_init(struct hello_context_t *hello_context)
{
	int err;
	struct fuse_init_in params = {0};

	SPDK_NOTICELOG("Fuse init\n");

	params.major = FUSE_KERNEL_VERSION;
	params.minor = FUSE_KERNEL_MINOR_VERSION;

	fuse_cmd_cpl_init(&hello_context->fcc, &params, sizeof(params), sizeof(struct fuse_init_out),
			  FUSE_INIT, 1, 0);

	err = spdk_fuse_dispatcher_submit_request(hello_context->fuse_disp,
			hello_context->fsdev_io_channel,
			hello_context->fcc.in_iov, 1, hello_context->fcc.out_iov, 1,
			fuse_init_complete, hello_context);
	if (err) {
		fuse_init_complete(hello_context, err);
	}
}

static void
hello_fsdev_event_cb(enum spdk_fsdev_event_type type, struct spdk_fsdev *fsdev, void *event_ctx)
{
	SPDK_NOTICELOG("Unsupported fsdev event: type %d\n", type);
}

/*
 * Our initial event that kicks off everything from main().
 */
static void
hello_start(void *arg1)
{
	struct hello_context_t *hello_context = arg1;
	int rc = 0;
	hello_context->fsdev_desc = NULL;

	SPDK_NOTICELOG("Successfully started the application\n");

	hello_context->app_thread = spdk_get_thread();

	/*
	 * There can be many bdevs configured, but this application will only use
	 * the one input by the user at runtime.
	 *
	 * Open the fs by calling spdk_fsdev_open() with its name.
	 * The function will return a descriptor
	 */
	SPDK_NOTICELOG("Opening the fsdev %s\n", hello_context->fsdev_name);
	rc = spdk_fsdev_open(hello_context->fsdev_name,
			     hello_fsdev_event_cb, NULL,
			     &hello_context->fsdev_desc);
	if (rc) {
		SPDK_ERRLOG("Could not open fsdev: %s\n", hello_context->fsdev_name);
		spdk_app_stop(-1);
		return;
	}

	SPDK_NOTICELOG("Creating FUSE dispatcher\n");
	hello_context->fuse_disp = spdk_fuse_dispatcher_create(hello_context->fsdev_desc);
	if (rc) {
		SPDK_ERRLOG("Could not create dispatcher for fsdev: %s\n", hello_context->fsdev_name);
		spdk_fsdev_close(hello_context->fsdev_desc);
		spdk_app_stop(-1);
		return;
	}

	SPDK_NOTICELOG("Opening io channel\n");
	/* Open I/O channel */
	hello_context->fsdev_io_channel = spdk_fsdev_get_io_channel(hello_context->fsdev_desc);
	if (!hello_context->fsdev_io_channel) {
		SPDK_ERRLOG("Could not create fsdev I/O channel!\n");
		spdk_fuse_dispatcher_delete(hello_context->fuse_disp);
		spdk_fsdev_close(hello_context->fsdev_desc);
		spdk_app_stop(-1);
		return;
	}

	hello_fuse_init(hello_context);
}

int
main(int argc, char **argv)
{
	struct spdk_app_opts opts = {};
	int rc = 0;
	struct hello_context_t hello_context = {};

	/* Set default values in opts structure. */
	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "hello_fsdev";

	/*
	 * Parse built-in SPDK command line parameters as well
	 * as our custom one(s).
	 */
	if ((rc = spdk_app_parse_args(argc, argv, &opts, "f:", NULL, hello_fsdev_parse_arg,
				      hello_fsdev_usage)) != SPDK_APP_PARSE_ARGS_SUCCESS) {
		exit(rc);
	}
	hello_context.fsdev_name = g_fsdev_name;

	/*
	 * spdk_app_start() will initialize the SPDK framework, call hello_start(),
	 * and then block until spdk_app_stop() is called (or if an initialization
	 * error occurs, spdk_app_start() will return with rc even without calling
	 * hello_start().
	 */
	rc = spdk_app_start(&opts, hello_start, &hello_context);
	if (rc) {
		SPDK_ERRLOG("ERROR starting application\n");
	}

	/* At this point either spdk_app_stop() was called, or spdk_app_start()
	 * failed because of internal error.
	 */

	/* Gracefully close out all of the SPDK subsystems. */
	spdk_app_fini();
	return rc;
}
