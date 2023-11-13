/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"

#include "spdk/fsdev.h"
#include "spdk/fuse_dispatcher.h"
#include "spdk/env.h"
#include "spdk/log.h"
#include "spdk/thread.h"
#include "spdk/event.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "spdk/string.h"
#include "linux/fuse_kernel.h"

#include "CUnit/Basic.h"

#define MAX_IOVS 16
#define MAX_IOV_LEN 256
#define TEST_FILE "file1"
#define TEST_DIR "dir1"

uint64_t g_test_file_nodeid;
mode_t g_umask;

pthread_mutex_t g_test_mutex;
pthread_cond_t g_test_cond;

static struct spdk_thread *g_thread_init;
static struct spdk_thread *g_thread_ut;
static struct spdk_thread *g_thread_io;
static bool g_wait_for_tests = false;
static int g_num_failures = 0;
static bool g_shutdown = false;

struct io_target {
	struct spdk_fsdev		*fsdev;
	struct spdk_fsdev_desc		*fsdev_desc;
	struct spdk_fuse_dispatcher	*fuse_disp;
	struct spdk_io_channel		*ch;
	struct io_target		*next;
};

struct fsdevio_request_bufs {
	uint8_t bufs[MAX_IOVS][MAX_IOV_LEN];
	struct iovec iovs[MAX_IOVS];
	int iovcnt;
};

struct fsdevio_request {
	struct io_target *target;
	struct fsdevio_request_bufs in;
	struct fsdevio_request_bufs out;
};

static struct fuse_in_header *
fsdevio_request_in_hdr(struct fsdevio_request *req)
{
	assert(req->in.iovcnt);
	return req->in.iovs[0].iov_base;
}

static struct fuse_out_header *
fsdevio_request_out_hdr(struct fsdevio_request *req)
{
	assert(req->out.iovcnt);
	return req->out.iovs[0].iov_base;
}

static void *
fsdevio_request_reserve(struct fsdevio_request *req, bool in, size_t size)
{
	struct iovec *iov;
	struct fsdevio_request_bufs *bufs = in ? &req->in : &req->out;
	assert(size < MAX_IOV_LEN);
	assert(bufs->iovcnt < MAX_IOVS);
	iov = &bufs->iovs[bufs->iovcnt];
	iov->iov_base = bufs->bufs[bufs->iovcnt];
	iov->iov_len = size;
	bufs->iovcnt++;
	if (in) {
		fsdevio_request_in_hdr(req)->len += size;
	}

	return iov->iov_base;
}

static void
fsdevio_request_add_iovs(struct fsdevio_request *req, bool in, struct iovec *iovs, int iovcnt)
{
	struct fsdevio_request_bufs *bufs = in ? &req->in : &req->out;
	struct iovec *iov;
	int i;
	assert(bufs->iovcnt + iovcnt < MAX_IOVS);
	for (i = 0; i < iovcnt; i++) {
		iov = &bufs->iovs[bufs->iovcnt];
		iov->iov_base = iovs[i].iov_base;
		iov->iov_len = iovs[i].iov_len;
		bufs->iovcnt++;
		if (in) {
			fsdevio_request_in_hdr(req)->len += iov->iov_len;
		}
	}
}

static void
fsdevio_request_init(struct fsdevio_request *req)
{
	assert(req->in.iovcnt == 0);
	assert(req->out.iovcnt == 0);
	fsdevio_request_reserve(req, true, sizeof(struct fuse_in_header));
	fsdevio_request_reserve(req, false, sizeof(struct fuse_out_header));
}

struct io_target *g_io_targets = NULL;
struct io_target *g_current_io_target = NULL;
static void rpc_perform_tests_cb(unsigned num_failures, struct spdk_jsonrpc_request *request);

static void
execute_spdk_function(spdk_msg_fn fn, void *arg)
{
	pthread_mutex_lock(&g_test_mutex);
	spdk_thread_send_msg(g_thread_io, fn, arg);
	pthread_cond_wait(&g_test_cond, &g_test_mutex);
	pthread_mutex_unlock(&g_test_mutex);
}

static void
wake_ut_thread(void)
{
	pthread_mutex_lock(&g_test_mutex);
	pthread_cond_signal(&g_test_cond);
	pthread_mutex_unlock(&g_test_mutex);
}

static void
__get_io_channel(void *arg)
{
	struct io_target *target = arg;

	target->ch = spdk_fsdev_get_io_channel(target->fsdev_desc);
	assert(target->ch);
	wake_ut_thread();
}

static void
fsdevio_event_cb(enum spdk_fsdev_event_type type,
		 struct spdk_fsdev *fsdev,
		 void *event_ctx)
{
}

static int
fsdevio_construct_target(struct spdk_fsdev *fsdev)
{
	struct io_target *target;
	int rc;

	target = malloc(sizeof(struct io_target));
	if (target == NULL) {
		return -ENOMEM;
	}

	rc = spdk_fsdev_open(spdk_fsdev_get_name(fsdev), fsdevio_event_cb, NULL,
			     &target->fsdev_desc);
	if (rc != 0) {
		free(target);
		SPDK_ERRLOG("Could not open fsdev %s, error=%d\n", spdk_fsdev_get_name(fsdev), rc);
		return rc;
	}

	printf("  %s: opened\n", spdk_fsdev_get_name(fsdev));

	target->fuse_disp = spdk_fuse_dispatcher_create(target->fsdev_desc);
	if (!target->fuse_disp) {
		spdk_fsdev_close(target->fsdev_desc);
		free(target);
		SPDK_ERRLOG("Could not create FUSE disp for fsdev %s\n", spdk_fsdev_get_name(fsdev));
		return rc;
	}

	target->fsdev = fsdev;
	target->next = g_io_targets;
	execute_spdk_function(__get_io_channel, target);
	g_io_targets = target;

	return 0;
}

static int
fsdevio_construct_targets(void)
{
	SPDK_ERRLOG("No fsdevs to perform tests on\n");
	return -1;
}

static void
__put_io_channel(void *arg)
{
	struct io_target *target = arg;

	spdk_put_io_channel(target->ch);
	wake_ut_thread();
}

static void
fsdevio_cleanup_targets(void)
{
	struct io_target *target;

	target = g_io_targets;
	while (target != NULL) {
		execute_spdk_function(__put_io_channel, target);
		spdk_fuse_dispatcher_delete(target->fuse_disp);
		spdk_fsdev_close(target->fsdev_desc);
		g_io_targets = target->next;
		free(target);
		target = g_io_targets;
	}
}

static bool g_completion_success;

static void
quick_test_complete(void *cb_arg, uint32_t error)
{
	struct fsdevio_request *req = cb_arg;
	struct fuse_out_header *hdr_out = fsdevio_request_out_hdr(req);

	g_completion_success = hdr_out->error == 0;
	wake_ut_thread();
}

static void
__fsdev_submit(void *arg)
{
	int err;
	struct fsdevio_request *req = arg;
	struct io_target *target = req->target;
	struct fuse_in_header *hdr_in = fsdevio_request_in_hdr(req);

	SPDK_NOTICELOG("fuse cmd: len %u, opcode %u, unique %lu, nodeid %lu, iovcnt %d\n",
		       hdr_in->len,
		       hdr_in->opcode,
		       hdr_in->unique,
		       hdr_in->nodeid,
		       req->in.iovcnt);
	err = spdk_fuse_dispatcher_submit_request(target->fuse_disp,
			target->ch,
			req->in.iovs, req->in.iovcnt,
			req->out.iovs, req->out.iovcnt,
			quick_test_complete, req);
	if (err) {
		quick_test_complete(req, err);
	}
}

#define FSDEVIO_REQ_PREPARE_BASIC(_opcode, _nodeid) \
	struct fsdevio_request req = {}; \
	struct fuse_in_header *hdr_in; \
	struct fuse_out_header *hdr_out; \
	req.target = target; \
	fsdevio_request_init(&req); \
	hdr_in = fsdevio_request_in_hdr(&req); \
	hdr_out = fsdevio_request_out_hdr(&req); \
	hdr_in->opcode = _opcode; \
	hdr_in->unique = 1; \
	hdr_in->nodeid = _nodeid;

#define FSDEVIO_REQ_PREPARE_IN(_opcode, _nodeid, type_in) \
	struct type_in *in; \
	FSDEVIO_REQ_PREPARE_BASIC(_opcode, _nodeid);\
	in = fsdevio_request_reserve(&req, true, sizeof(*in));

#define FSDEVIO_REQ_PREPARE_OUT(_opcode, _nodeid, type_out) \
	struct type_out *out; \
	FSDEVIO_REQ_PREPARE_BASIC(_opcode, _nodeid);\
	out = fsdevio_request_reserve(&req, false, sizeof(*out)); \

#define FSDEVIO_REQ_PREPARE_INOUT(_opcode, _nodeid, type_in, type_out) \
	struct type_out *out; \
	FSDEVIO_REQ_PREPARE_IN(_opcode, _nodeid, type_in); \
	out = fsdevio_request_reserve(&req, false, sizeof(*out));

#define FSDEVIO_REQ_ADD_IN_STR(str) \
	do { \
		size_t _len = strlen(str) + 1; \
		char *_buf  = fsdevio_request_reserve(&req, true, _len); \
		memcpy(_buf, str, _len);\
	} while (0)

static void
fsdev_fuse_init(struct io_target *target, uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_INOUT(FUSE_INIT, 0, fuse_init_in, fuse_init_out);

	in->major = FUSE_KERNEL_VERSION;
	in->minor = FUSE_KERNEL_MINOR_VERSION;
	in->max_readahead = 0;
	in->flags = 0;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("init fuse cpl: error %d, unique %lu, major %u, "
		       "minor %u, max_readahead %u, flags 0x%08X, max_write %u\n",
		       hdr_out->error, hdr_out->unique,
		       out->major, out->minor, out->max_readahead, out->flags, out->max_write);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);
}

static void
fsdev_fuse_destroy(struct io_target *target, uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_BASIC(FUSE_DESTROY, 0);

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("destroy fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);
}

static void
fsdev_lookup(struct io_target *target,
	     uint64_t parent_nodeid, const char *name,
	     struct fuse_entry_out *entry_out,
	     uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_OUT(FUSE_LOOKUP, parent_nodeid, fuse_entry_out);
	FSDEVIO_REQ_ADD_IN_STR(name);

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("lookup fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);

	if (entry_out) {
		*entry_out = *out;
	}
}

static void
fsdev_forget(struct io_target *target, uint64_t nodeid, uint64_t nlookup)
{
	FSDEVIO_REQ_PREPARE_IN(FUSE_FORGET, nodeid, fuse_forget_in);

	(void)hdr_out; 	/* Special case as FUSE_FORGET doesn't require reply */

	in->nlookup = nlookup;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("forget fuse cpl\n");
}

static void
fsdev_getattr(struct io_target *target,
	      uint64_t nodeid, uint32_t flags, uint64_t file_handle,
	      struct fuse_attr_out *attr_out,
	      uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_INOUT(FUSE_GETATTR, nodeid, fuse_getattr_in, fuse_attr_out);

	in->getattr_flags = flags;
	in->fh = file_handle;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("getattr fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);

	if (attr_out) {
		*attr_out = *out;
	}
}

static void
fsdev_setattr(struct io_target *target,
	      uint64_t nodeid, struct fuse_setattr_in *setattr_in,
	      struct fuse_attr_out *attr_out,
	      uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_INOUT(FUSE_SETATTR, nodeid, fuse_setattr_in, fuse_attr_out);

	*in = *setattr_in;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("setattr fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);

	if (attr_out) {
		*attr_out = *out;
	}
}

static void
fsdev_readlink(struct io_target *target,
	       uint64_t nodeid, char *link, int link_len,
	       uint32_t expected_error)
{
	struct iovec iov;

	FSDEVIO_REQ_PREPARE_BASIC(FUSE_READLINK, nodeid);

	iov.iov_base = link;
	iov.iov_len = link_len;
	fsdevio_request_add_iovs(&req, false, &iov, 1);

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("readlink fuse cpl: error %d, unique %lu res=%s\n",
		       hdr_out->error, hdr_out->unique, hdr_out->error ? "" : link);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);
}

static void
fsdev_symlink(struct io_target *target,
	      uint64_t nodeid, const char *link_target, const char *link_name,
	      struct fuse_entry_out *entry_out,
	      uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_OUT(FUSE_SYMLINK, nodeid, fuse_entry_out);
	FSDEVIO_REQ_ADD_IN_STR(link_name);
	FSDEVIO_REQ_ADD_IN_STR(link_target);

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("symlink fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);

	if (entry_out) {
		*entry_out = *out;
	}
}

static void
fsdev_mknod(struct io_target *target,
	    uint64_t parent_nodeid, const char *name, uint32_t mode,
	    uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_INOUT(FUSE_MKNOD, parent_nodeid, fuse_mknod_in, fuse_entry_out);
	FSDEVIO_REQ_ADD_IN_STR(name);

	in->mode = mode;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("mknod fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);
}

static void
fsdev_mkdir(struct io_target *target,
	    uint64_t parent_nodeid, const char *name, uint32_t mode,
	    uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_INOUT(FUSE_MKDIR, parent_nodeid, fuse_mkdir_in, fuse_entry_out);
	FSDEVIO_REQ_ADD_IN_STR(name);

	in->mode = mode;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("mkdir fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);
}

static void
fsdev_unlink(struct io_target *target, uint64_t parent_nodeid, const char *name,
	     uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_BASIC(FUSE_UNLINK, parent_nodeid);
	FSDEVIO_REQ_ADD_IN_STR(name);

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("unlink fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);
}

static void
fsdev_rmdir(struct io_target *target, uint64_t parent_nodeid, const char *name,
	    uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_BASIC(FUSE_RMDIR, parent_nodeid);
	FSDEVIO_REQ_ADD_IN_STR(name);

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("rmdir fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);
}

static void
fsdev_rename(struct io_target *target, uint64_t parent_nodeid, const char *name,
	     uint64_t new_parent_nodeid, const char *new_name, uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_IN(FUSE_RENAME, parent_nodeid, fuse_rename_in);
	FSDEVIO_REQ_ADD_IN_STR(name);
	FSDEVIO_REQ_ADD_IN_STR(new_name);

	in->newdir = new_parent_nodeid;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("rename fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);
}

static void
fsdev_link(struct io_target *target,
	   uint64_t parent_nodeid, uint64_t target_nodeid, const char *name,
	   struct fuse_entry_out *entry_out, uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_INOUT(FUSE_LINK, parent_nodeid, fuse_link_in, fuse_entry_out);
	FSDEVIO_REQ_ADD_IN_STR(name);

	in->oldnodeid = target_nodeid;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("link fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);

	if (entry_out) {
		*entry_out = *out;
	}
}

static void
fsdev_open(struct io_target *target, uint64_t nodeid, uint32_t flags,
	   struct fuse_open_out *open_out, uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_INOUT(FUSE_OPEN, nodeid, fuse_open_in, fuse_open_out);

	in->flags = flags;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("open fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);

	if (open_out) {
		*open_out = *out;
	}
}

static uint32_t
fsdev_read(struct io_target *target, uint64_t file_handle, uint64_t offset, uint32_t size,
	   struct iovec *iovs, int iovcnt, uint32_t read_flags, uint64_t lock_owner,
	   uint32_t flags, uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_IN(FUSE_READ, 0, fuse_read_in);

	fsdevio_request_add_iovs(&req, false, iovs, iovcnt);

	in->fh = file_handle;
	in->offset = offset;
	in->size = size;
	in->read_flags = read_flags;
	in->lock_owner = lock_owner;
	in->flags = flags;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("read fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);
	return hdr_out->len - sizeof(struct fuse_out_header);
}

static uint32_t
fsdev_write(struct io_target *target, uint64_t file_handle, uint64_t offset, uint32_t size,
	    struct iovec *iovs, int iovcnt, uint32_t write_flags, uint64_t lock_owner,
	    uint32_t flags, uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_INOUT(FUSE_WRITE, 0, fuse_write_in, fuse_write_out);

	fsdevio_request_add_iovs(&req, true, iovs, iovcnt);

	in->fh = file_handle;
	in->offset = offset;
	in->size = size;
	in->write_flags = write_flags;
	in->lock_owner = lock_owner;
	in->flags = flags;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("write fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);
	return out->size;
}

static void
fsdev_statfs(struct io_target *target, uint64_t nodeid, struct fuse_statfs_out *statfs_out,
	     uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_OUT(FUSE_STATFS, nodeid, fuse_statfs_out);

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("statfs fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);

	if (statfs_out) {
		*statfs_out = *out;
	}
}

static void
fsdev_release(struct io_target *target, uint64_t file_handle, uint32_t flags,
	      uint32_t release_flags, uint64_t lock_owner, uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_IN(FUSE_RELEASE, 0, fuse_release_in);

	in->fh = file_handle;
	in->flags = flags;
	in->release_flags = release_flags;
	in->lock_owner = lock_owner;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("release fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);
}

static void
fsdev_fsync(struct io_target *target, uint64_t file_handle, uint32_t flags, uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_IN(FUSE_FSYNC, 0, fuse_fsync_in);

	in->fh = file_handle;
	in->fsync_flags = flags;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("fsync fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);
}

static bool
fsdev_setxattr(struct io_target *target, uint64_t nodeid, const char *name,
	       const void *value, uint32_t size, uint32_t expected_error)
{
	char *v;
	FSDEVIO_REQ_PREPARE_IN(FUSE_SETXATTR, nodeid, fuse_setxattr_in);
	FSDEVIO_REQ_ADD_IN_STR(name);

	v  = fsdevio_request_reserve(&req, true, size);
	memcpy(v, value, size);

	in->size = size;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("setxattr fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);

	if (hdr_out->error == -EOPNOTSUPP) {
		SPDK_WARNLOG("Test skipped as Text Extended User Attributes are not supported\n");
		return false;
	}

	CU_ASSERT_EQUAL(hdr_out->error, expected_error);
	return true;
}

static bool
fsdev_getxattr(struct io_target *target, uint64_t nodeid, const char *name,
	       void *value, uint32_t size,
	       struct fuse_getxattr_out *getxattr_out, uint32_t expected_error)
{
	struct iovec iov;

	FSDEVIO_REQ_PREPARE_INOUT(FUSE_GETXATTR, nodeid, fuse_getxattr_in, fuse_getxattr_out);
	FSDEVIO_REQ_ADD_IN_STR(name);

	in->size = size;

	iov.iov_base = value;
	iov.iov_len = size;
	fsdevio_request_add_iovs(&req, false, &iov, 1);

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("getxattr fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);

	if (hdr_out->error == -ENOTSUP) {
		SPDK_WARNLOG("Test skipped as Text Extended User Attributes are not supported\n");
		return false;
	}

	CU_ASSERT_EQUAL(hdr_out->error, expected_error);

	if (getxattr_out) {
		*getxattr_out = *out;
	}

	return true;
}

static bool
fsdev_listxattr(struct io_target *target, uint64_t nodeid, char *list, uint32_t size,
		struct fuse_getxattr_out *getxattr_out, uint32_t expected_error, uint32_t *attr_size)
{
	FSDEVIO_REQ_PREPARE_INOUT(FUSE_LISTXATTR, nodeid, fuse_getxattr_in, fuse_getxattr_out);

	in->size = size;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("listxattr fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);

	if (hdr_out->error == -EOPNOTSUPP) {
		SPDK_WARNLOG("Test skipped as Text Extended User Attributes are not supported\n");
		return false;
	}

	CU_ASSERT_EQUAL(hdr_out->error, expected_error);

	if (getxattr_out) {
		*getxattr_out = *out;
	}

	*attr_size = hdr_out->len - sizeof(struct fuse_out_header);
	return true;
}

static bool
fsdev_removexattr(struct io_target *target, uint64_t nodeid, const char *name,
		  uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_BASIC(FUSE_REMOVEXATTR, nodeid);
	FSDEVIO_REQ_ADD_IN_STR(name);

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("removexattr fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);

	if (hdr_out->error == -EOPNOTSUPP) {
		SPDK_WARNLOG("Test skipped as Text Extended User Attributes are not supported\n");
		return false;
	}

	CU_ASSERT_EQUAL(hdr_out->error, expected_error);
	return true;
}

static void
fsdev_flush(struct io_target *target, uint64_t file_handle, uint64_t lock_owner,
	    uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_IN(FUSE_FLUSH, 0, fuse_flush_in);

	in->fh = file_handle;
	in->lock_owner = lock_owner;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("flush fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);
}

static void
fsdev_opendir(struct io_target *target, uint64_t nodeid, uint32_t flags,
	      struct fuse_open_out *open_out, uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_INOUT(FUSE_OPENDIR, nodeid, fuse_open_in, fuse_open_out);

	in->flags = flags;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("opendir fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);

	if (open_out) {
		*open_out = *out;
	}
}

static uint32_t
fsdev_readdir(struct io_target *target, uint64_t nodeid, uint64_t dir_handle,
	      uint64_t offset, uint32_t size, struct iovec *iovs, int iovcnt,
	      uint32_t read_flags, uint64_t lock_owner, uint32_t flags,
	      uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_IN(FUSE_READDIR, nodeid, fuse_read_in);

	in->fh = dir_handle;
	in->offset = offset;
	in->size = size;
	in->read_flags = read_flags;
	in->lock_owner = lock_owner;
	in->flags = flags;

	fsdevio_request_add_iovs(&req, false, iovs, iovcnt);

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("readdir fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);
	return hdr_out->len - sizeof(struct fuse_out_header);
}

static void
fsdev_releasedir(struct io_target *target, uint64_t dir_handle, uint32_t flags,
		 uint32_t release_flags, uint64_t lock_owner, uint32_t expected_error)
{
	FSDEVIO_REQ_PREPARE_IN(FUSE_RELEASEDIR, 0, fuse_release_in);

	in->fh = dir_handle;
	in->flags = flags;
	in->release_flags = release_flags;
	in->lock_owner = lock_owner;

	g_completion_success = false;
	execute_spdk_function(__fsdev_submit, &req);
	SPDK_NOTICELOG("releasedir fuse cpl: error %d, unique %lu\n",
		       hdr_out->error, hdr_out->unique);
	CU_ASSERT_EQUAL(hdr_out->error, expected_error);
}

static void
fsdev_init_test_fs(void)
{
	struct io_target *target = g_current_io_target;
	struct fuse_entry_out entry_out;

	g_umask = umask(0); /* make sure the file creation flags are preserved */
	fsdev_fuse_init(target, 0);
	fsdev_mknod(target, 1, TEST_FILE, S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO, 0);
	fsdev_lookup(target, 1, TEST_FILE, &entry_out, 0);
	g_test_file_nodeid = entry_out.nodeid;
	fsdev_forget(target, entry_out.nodeid, 1);
}

static void
fsdev_cleanup_test_fs(void)
{
	struct io_target *target = g_current_io_target;

	fsdev_unlink(target, 1, TEST_FILE, 0);
	fsdev_fuse_destroy(target, 0);

	umask(g_umask);
}

static void
test_fsdev_fuse_init_destroy(void)
{
	struct io_target *target = g_current_io_target;

	fsdev_fuse_init(target, 0);
	fsdev_fuse_destroy(target, 0);
}

static void
test_fsdev_files(void)
{
	struct io_target *target = g_current_io_target;
	const char *filename = "another_test_file";
	const char *new_filename = "renamed_test_file";
	struct fuse_entry_out entry_out;
	uint64_t file_nodeid;

	fsdev_init_test_fs();

	fsdev_lookup(target, 1, filename, NULL, -ENOENT);
	/* Create file */
	fsdev_mknod(target, 1, filename, S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO, 0);
	fsdev_lookup(target, 1, filename, &entry_out, 0);
	CU_ASSERT_EQUAL(entry_out.attr.size, 0);
	CU_ASSERT_EQUAL(entry_out.attr.mode, S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO);
	CU_ASSERT_EQUAL(entry_out.attr.uid, 0);
	CU_ASSERT_EQUAL(entry_out.attr.gid, 0);
	file_nodeid = entry_out.nodeid;
	fsdev_forget(target, entry_out.nodeid, 1);
	/* Rename file */
	fsdev_rename(target, 1, filename, 1, new_filename, 0);
	memset(&entry_out, 0, sizeof(entry_out));
	fsdev_lookup(target, 1, new_filename, &entry_out, 0);
	CU_ASSERT_EQUAL(entry_out.nodeid, file_nodeid);
	fsdev_forget(target, entry_out.nodeid, 1);
	fsdev_lookup(target, 1, filename, NULL, -ENOENT);
	/* Create hardlink to file */
	memset(&entry_out, 0, sizeof(entry_out));
	fsdev_link(target, 1, file_nodeid, filename, &entry_out, 0);
	CU_ASSERT_EQUAL(entry_out.nodeid, file_nodeid);
	CU_ASSERT_EQUAL(entry_out.attr.nlink, 2);
	/* Delete one hardlink to file */
	fsdev_unlink(target, 1, new_filename, 0);
	fsdev_lookup(target, 1, new_filename, NULL, -ENOENT);
	memset(&entry_out, 0, sizeof(entry_out));
	fsdev_lookup(target, 1, filename, &entry_out, 0);
	CU_ASSERT_EQUAL(entry_out.nodeid, file_nodeid);
	CU_ASSERT_EQUAL(entry_out.attr.nlink, 1);
	fsdev_forget(target, entry_out.nodeid, 1);
	/* Delete the last hardlink to file */
	fsdev_unlink(target, 1, filename, 0);
	fsdev_lookup(target, 1, filename, NULL, -ENOENT);

	fsdev_cleanup_test_fs();
}

static void
test_fsdev_file_attr(void)
{
	struct io_target *target = g_current_io_target;
	struct fuse_setattr_in setattr_in;
	struct fuse_attr_out attr_out;
	const char *xattr_name = "test_xattr";
	const char *xattr_value = "test_xattr_value";
	char xattr_value_buf[256];
	char xattr_list[256];
	struct fuse_getxattr_out getxattr_out;
	uint32_t size;

	fsdev_init_test_fs();
	/* Standard attributes */
	fsdev_getattr(target, g_test_file_nodeid, 0, 0, &attr_out, 0);
	CU_ASSERT_EQUAL(attr_out.attr.size, 0);
	CU_ASSERT_EQUAL(attr_out.attr.mode, S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO);
	CU_ASSERT_EQUAL(attr_out.attr.uid, 0);
	CU_ASSERT_EQUAL(attr_out.attr.gid, 0);
	setattr_in.valid = FATTR_MODE;
	setattr_in.mode = S_IFREG | S_IRWXU;
	fsdev_setattr(target, g_test_file_nodeid, &setattr_in, &attr_out, 0);
	CU_ASSERT_EQUAL(attr_out.attr.mode, S_IFREG | S_IRWXU);
	/* Extended attributes */
	/* @todo: looks like xattr cap is not set in virtiofs_bdev_open */
	if (!fsdev_setxattr(target, g_test_file_nodeid, xattr_name, xattr_value, strlen(xattr_value), 0)) {
		SPDK_WARNLOG("xattr related tests will be skipped as Text Extended User Attributes are not supported\n");
		goto do_cleanup;
	}
	fsdev_getxattr(target, g_test_file_nodeid, xattr_name, xattr_value_buf, sizeof(xattr_value_buf),
		       &getxattr_out, 0);
	CU_ASSERT_EQUAL(getxattr_out.size, strlen(xattr_value));
	CU_ASSERT_NSTRING_EQUAL(xattr_value_buf, xattr_value, strlen(xattr_value));
	fsdev_listxattr(target, g_test_file_nodeid, xattr_list, sizeof(xattr_list), NULL, 0, &size);
	CU_ASSERT_EQUAL(size, strlen(xattr_value) + 1);
	CU_ASSERT_STRING_EQUAL(xattr_list, xattr_name);
	fsdev_removexattr(target, g_test_file_nodeid, xattr_name, 0);

do_cleanup:
	fsdev_cleanup_test_fs();
}

static void
test_fsdev_symlinks(void)
{
	struct io_target *target = g_current_io_target;
	struct fuse_entry_out entry_out;
	const char *linkname = "link1";
	char buf[256];

	fsdev_init_test_fs();
	/* Test file is not a symlink */
	fsdev_readlink(target, g_test_file_nodeid, buf, sizeof(buf), -ENOENT);
	/* Create a symlink to test file in the root dir */
	strcpy(buf, linkname);
	fsdev_symlink(target, 1, TEST_FILE, buf, &entry_out, 0);
	CU_ASSERT(S_ISLNK(entry_out.attr.mode));
	/* Read created link */
	memset(buf, 0, sizeof(link));
	fsdev_readlink(target, entry_out.nodeid, buf, sizeof(buf), 0);
	CU_ASSERT_STRING_EQUAL(buf, TEST_FILE);
	/* Remove symlink */
	fsdev_unlink(target, 1, linkname, 0);
	fsdev_cleanup_test_fs();
}

static void
print_dir_entries(void *dir_entries, uint32_t size)
{
	struct fuse_dirent *dir_entry;

	for (dir_entry = dir_entries;
	     (void *)dir_entry < dir_entries + size;
	     dir_entry = (void *)dir_entry + FUSE_DIRENT_SIZE(dir_entry)) {
		fprintf(stderr, "Dirent: ino %lu, off %lu, namelen %u, type %u, name %s\n",
			dir_entry->ino, dir_entry->off, dir_entry->namelen,
			dir_entry->type, dir_entry->name);
	}
}

static void
test_fsdev_dirs(void)
{
	struct io_target *target = g_current_io_target;
	const char *dirname = "another_test_dir";
	struct fuse_entry_out entry_out;
	struct fuse_open_out open_out;
	uint64_t dir_nodeid;
	uint64_t dir_handle;
	char dir_entries[1024];
	struct fuse_dirent *dir_entry;
	struct iovec iov;
	uint32_t size;

	fsdev_init_test_fs();

	fsdev_lookup(target, 1, dirname, NULL, -ENOENT);
	/* Create directory */
	fsdev_mkdir(target, 1, dirname, S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO, 0);
	fsdev_lookup(target, 1, dirname, &entry_out, 0);
	CU_ASSERT_EQUAL(entry_out.attr.size, 4096);
	CU_ASSERT_EQUAL(entry_out.attr.mode, S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO);
	CU_ASSERT_EQUAL(entry_out.attr.uid, 0);
	CU_ASSERT_EQUAL(entry_out.attr.gid, 0);
	dir_nodeid = entry_out.nodeid;
	fsdev_forget(target, dir_nodeid, 1);
	/* Open and read directory */
	fsdev_opendir(target, dir_nodeid, 0, &open_out, 0);
	CU_ASSERT_EQUAL(open_out.open_flags, 0);
	dir_handle = open_out.fh;
	iov.iov_base = dir_entries;
	iov.iov_len = sizeof(dir_entries);
	size = fsdev_readdir(target, dir_nodeid, dir_handle, 0, sizeof(dir_entries),
			     &iov, 1, 0, 0, 0, 0);
	print_dir_entries(dir_entries, size);
	CU_ASSERT_EQUAL(size, 64);
	dir_entry = (void *)dir_entries;
	CU_ASSERT_EQUAL(dir_entry->type, 4);
	CU_ASSERT_EQUAL(dir_entry->namelen, 1);
	CU_ASSERT_NSTRING_EQUAL(dir_entry->name, ".", 1);
	dir_entry = (void *)((char *)dir_entry + FUSE_DIRENT_SIZE(dir_entry));
	CU_ASSERT_EQUAL(dir_entry->type, 4);
	CU_ASSERT_EQUAL(dir_entry->namelen, 2);
	CU_ASSERT_NSTRING_EQUAL(dir_entry->name, "..", 2);
	fsdev_releasedir(target, dir_handle, 0, 0, 0, 0);
	fsdev_opendir(target, 1, 0, &open_out, 0);
	dir_handle = open_out.fh;
	size = fsdev_readdir(target, 1, dir_handle, 0, sizeof(dir_entries),
			     &iov, 1, 0, 0, 0, 0);
	print_dir_entries(dir_entries, size);
	fsdev_releasedir(target, dir_handle, 0, 0, 0, 0);
	/* Can't unlink directory */
	fsdev_unlink(target, 1, dirname, -EISDIR);
	/* Remove directory */
	fsdev_rmdir(target, 1, dirname, 0);
	fsdev_lookup(target, 1, dirname, NULL, -ENOENT);
	/* Can't rmdir regular file */
	fsdev_rmdir(target, 1, TEST_FILE, -ENOTDIR);

	fsdev_cleanup_test_fs();
}

static bool
memall(const char *buf, char val, size_t len)
{
	for (; len > 0 && *buf == val; buf++, len--);
	return len == 0;
}

static void
test_fsdev_file_handle(void)
{
	struct io_target *target = g_current_io_target;
	struct fuse_open_out open_out;
	uint64_t file_handle;
	uint32_t size;
	char buf[4096];
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = sizeof(buf)
	};

	fsdev_init_test_fs();

	/* Open file */
	fsdev_open(target, g_test_file_nodeid, O_RDWR, &open_out, 0);
	CU_ASSERT_EQUAL(open_out.open_flags, FOPEN_DIRECT_IO);
	file_handle = open_out.fh;
	/* Read empty file */
	size = fsdev_read(target, file_handle, 0, 4096, &iov, 1, 0, 0, 0, 0);
	CU_ASSERT_EQUAL(size, 0);
	/* Write data to file */
	memset(buf, 0xA5, sizeof(buf));
	size = fsdev_write(target, file_handle, 0, 4096, &iov, 1, 0, 0, 0, 0);
	CU_ASSERT_EQUAL(size, 4096);
	/* Read and check data */
	memset(buf, 0, sizeof(buf));
	size = fsdev_read(target, file_handle, 0, 4096, &iov, 1, 0, 0, 0, 0);
	CU_ASSERT_EQUAL(size, 4096);
	CU_ASSERT_TRUE(memall(buf, 0xA5, sizeof(buf)));
	/* Fsync file */
	fsdev_fsync(target, file_handle, 0, 0);
	/* Flush file */
	fsdev_flush(target, file_handle, 0, 0);
	/* Close file */
	fsdev_release(target, file_handle, 0, 0, 0, 0);

	fsdev_cleanup_test_fs();
}

static void
test_fsdev_fs(void)
{
	struct io_target *target = g_current_io_target;
	struct fuse_statfs_out statfs_out;

	fsdev_init_test_fs();

	fsdev_statfs(target, 1, &statfs_out, 0);
	fprintf(stderr,
		"statfs: blocks %lu, bfree %lu, bavail %lu, files %lu, ffree %lu, bsize %u, namelen %u, frsize %u\n",
		statfs_out.st.blocks,
		statfs_out.st.bfree,
		statfs_out.st.bavail,
		statfs_out.st.files,
		statfs_out.st.ffree,
		statfs_out.st.bsize,
		statfs_out.st.namelen,
		statfs_out.st.frsize);

	fsdev_cleanup_test_fs();
}

static void
__stop_init_thread(void *arg)
{
	unsigned num_failures = g_num_failures;
	struct spdk_jsonrpc_request *request = arg;

	g_num_failures = 0;

	fsdevio_cleanup_targets();
	if (g_wait_for_tests && !g_shutdown) {
		/* Do not stop the app yet, wait for another RPC */
		rpc_perform_tests_cb(num_failures, request);
		return;
	}
	spdk_app_stop(num_failures);
}

static void
stop_init_thread(unsigned num_failures, struct spdk_jsonrpc_request *request)
{
	g_num_failures = num_failures;

	spdk_thread_send_msg(g_thread_init, __stop_init_thread, request);
}

static int
suite_init(void)
{
	if (g_current_io_target == NULL) {
		g_current_io_target = g_io_targets;
	}
	return 0;
}

static int
suite_fini(void)
{
	g_current_io_target = g_current_io_target->next;
	return 0;
}

#define SUITE_NAME_MAX 64

static int
__setup_ut_on_single_target(struct io_target *target)
{
	unsigned rc = 0;
	CU_pSuite suite = NULL;
	char name[SUITE_NAME_MAX];

	snprintf(name, sizeof(name), "fsdevio tests on: %s", spdk_fsdev_get_name(target->fsdev));
	suite = CU_add_suite(name, suite_init, suite_fini);
	if (suite == NULL) {
		CU_cleanup_registry();
		rc = CU_get_error();
		return -rc;
	}

	if (
		CU_add_test(suite, "fsdev fuse init destroy",
			    test_fsdev_fuse_init_destroy) == NULL
		|| CU_add_test(suite, "fsdev files",
			       test_fsdev_files) == NULL
		|| CU_add_test(suite, "fsdev file attributes",
			       test_fsdev_file_attr) == NULL
		|| CU_add_test(suite, "fsdev symbolic links",
			       test_fsdev_symlinks) == NULL
		|| CU_add_test(suite, "fsdev directories",
			       test_fsdev_dirs) == NULL
		|| CU_add_test(suite, "fsdev file handle",
			       test_fsdev_file_handle) == NULL
		|| CU_add_test(suite, "fsdev file system",
			       test_fsdev_fs) == NULL
	) {
		CU_cleanup_registry();
		rc = CU_get_error();
		return -rc;
	}
	return 0;
}

static void
__run_ut_thread(void *arg)
{
	struct spdk_jsonrpc_request *request = arg;
	int rc = 0;
	struct io_target *target;
	unsigned num_failures;

	if (CU_initialize_registry() != CUE_SUCCESS) {
		/* CUnit error, probably won't recover */
		rc = CU_get_error();
		stop_init_thread(-rc, request);
	}

	target = g_io_targets;
	while (target != NULL) {
		rc = __setup_ut_on_single_target(target);
		if (rc < 0) {
			/* CUnit error, probably won't recover */
			stop_init_thread(-rc, request);
		}
		target = target->next;
	}
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	num_failures = CU_get_number_of_failures();
	CU_cleanup_registry();

	stop_init_thread(num_failures, request);
}

static void
__construct_targets(void *arg)
{
	if (fsdevio_construct_targets() < 0) {
		spdk_app_stop(-1);
		return;
	}

	spdk_thread_send_msg(g_thread_ut, __run_ut_thread, NULL);
}

static void
test_main(void *arg1)
{
	struct spdk_cpuset tmpmask = {};
	uint32_t i;

	pthread_mutex_init(&g_test_mutex, NULL);
	pthread_cond_init(&g_test_cond, NULL);

	/* This test runs specifically on at least three cores.
	 * g_thread_init is the app_thread on main core from event framework.
	 * Next two are only for the tests and should always be on separate CPU cores. */
	if (spdk_env_get_core_count() < 3) {
		spdk_app_stop(-1);
		return;
	}

	SPDK_ENV_FOREACH_CORE(i) {
		if (i == spdk_env_get_current_core()) {
			g_thread_init = spdk_get_thread();
			continue;
		}
		spdk_cpuset_zero(&tmpmask);
		spdk_cpuset_set_cpu(&tmpmask, i, true);
		if (g_thread_ut == NULL) {
			g_thread_ut = spdk_thread_create("ut_thread", &tmpmask);
		} else if (g_thread_io == NULL) {
			g_thread_io = spdk_thread_create("io_thread", &tmpmask);
		}

	}

	if (g_wait_for_tests) {
		/* Do not perform any tests until RPC is received */
		return;
	}

	spdk_thread_send_msg(g_thread_init, __construct_targets, NULL);
}

static void
fsdevio_usage(void)
{
	printf(" -w                        start fsdevio app and wait for RPC to start the tests\n");
}

static int
fsdevio_parse_arg(int ch, char *arg)
{
	switch (ch) {
	case 'w':
		g_wait_for_tests =  true;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

struct rpc_perform_tests {
	char *name;
};

static void
free_rpc_perform_tests(struct rpc_perform_tests *r)
{
	free(r->name);
}

static const struct spdk_json_object_decoder rpc_perform_tests_decoders[] = {
	{"name", offsetof(struct rpc_perform_tests, name), spdk_json_decode_string, true},
};

static void
rpc_perform_tests_cb(unsigned num_failures, struct spdk_jsonrpc_request *request)
{
	struct spdk_json_write_ctx *w;

	if (num_failures == 0) {
		w = spdk_jsonrpc_begin_result(request);
		spdk_json_write_uint32(w, num_failures);
		spdk_jsonrpc_end_result(request, w);
	} else {
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						     "%d test cases failed", num_failures);
	}
}

static void
rpc_perform_tests(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct rpc_perform_tests req = {NULL};
	struct spdk_fsdev *fsdev;
	int rc;

	if (params && spdk_json_decode_object(params, rpc_perform_tests_decoders,
					      SPDK_COUNTOF(rpc_perform_tests_decoders),
					      &req)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid parameters");
		goto invalid;
	}

	if (req.name) {
		fsdev = spdk_fsdev_get_by_name(req.name);
		if (fsdev == NULL) {
			SPDK_ERRLOG("Fsdev '%s' does not exist\n", req.name);
			spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
							     "Fsdev '%s' does not exist: %s",
							     req.name, spdk_strerror(ENODEV));
			goto invalid;
		}
		rc = fsdevio_construct_target(fsdev);
		if (rc < 0) {
			SPDK_ERRLOG("Could not construct target for fsdev '%s'\n", spdk_fsdev_get_name(fsdev));
			spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
							     "Could not construct target for fsdev '%s': %s",
							     spdk_fsdev_get_name(fsdev), spdk_strerror(-rc));
			goto invalid;
		}
	} else {
		rc = fsdevio_construct_targets();
		if (rc < 0) {
			SPDK_ERRLOG("Could not construct targets for all fsdevs\n");
			spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
							     "Could not construct targets for all fsdevs: %s",
							     spdk_strerror(-rc));
			goto invalid;
		}
	}
	free_rpc_perform_tests(&req);

	spdk_thread_send_msg(g_thread_ut, __run_ut_thread, request);

	return;

invalid:
	free_rpc_perform_tests(&req);
}
SPDK_RPC_REGISTER("perform_tests", rpc_perform_tests, SPDK_RPC_RUNTIME)

static void
spdk_fsdevio_shutdown_cb(void)
{
	g_shutdown = true;
	spdk_thread_send_msg(g_thread_init, __stop_init_thread, NULL);
}

int
main(int argc, char **argv)
{
	int			rc;
	struct spdk_app_opts	opts = {};

	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "fsdevio";
	opts.reactor_mask = "0x7";
	opts.shutdown_cb = spdk_fsdevio_shutdown_cb;

	if ((rc = spdk_app_parse_args(argc, argv, &opts, "w", NULL,
				      fsdevio_parse_arg, fsdevio_usage)) !=
	    SPDK_APP_PARSE_ARGS_SUCCESS) {
		return rc;
	}

	rc = spdk_app_start(&opts, test_main, NULL);
	spdk_app_fini();

	return rc;
}
