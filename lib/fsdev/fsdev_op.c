/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/fsdev.h"
#include "spdk/fsdev_module.h"
#include "fsdev_internal.h"

#define CALL_USR_CLB(_fsdev_io, ch, type, ...) \
	do { \
		type *usr_cpl_clb = _fsdev_io->internal.usr_cpl_clb; \
		usr_cpl_clb(_fsdev_io->internal.usr_cpl_ctx, ch, _fsdev_io->internal.status, ## __VA_ARGS__); \
	} while (0)

static struct spdk_fsdev_io *
fsdev_io_get_and_fill(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		      void *usr_cpl_clb, void *usr_cpl_ctx, spdk_fsdev_io_completion_cb cb, void *cb_arg,
		      enum spdk_fsdev_op op)
{
	struct spdk_fsdev_io *fsdev_io;
	struct spdk_fsdev_channel *channel = __io_ch_to_fsdev_ch(ch);

	fsdev_io = fsdev_channel_get_io(channel);
	if (!fsdev_io) {
		return NULL;
	}

	fsdev_io->fsdev = spdk_fsdev_desc_get_fsdev(desc);
	fsdev_io->internal.ch = channel;
	fsdev_io->internal.desc = desc;
	fsdev_io->internal.op = op;
	fsdev_io->internal.unique = unique;
	fsdev_io->internal.usr_cpl_clb = usr_cpl_clb;
	fsdev_io->internal.usr_cpl_ctx = usr_cpl_ctx;
	fsdev_io->internal.caller_ctx = cb_arg;
	fsdev_io->internal.cb = cb;
	fsdev_io->internal.status = EIO;
	fsdev_io->internal.in_submit_request = false;

	return fsdev_io;
}

static inline void
fsdev_io_free(struct spdk_fsdev_io *fsdev_io)
{
	spdk_fsdev_free_io(fsdev_io);
}

static void
_spdk_fsdev_op_lookup_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_lookup_cpl_cb, &fsdev_io->u_out.lookup.entry);

	free(fsdev_io->u_in.lookup.name);
	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_lookup(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		     spdk_ino_t parent_ino, const char *name, spdk_fsdev_op_lookup_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_lookup_cb, ch,
					 SPDK_FSDEV_OP_LOOKUP);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.lookup.name = strdup(name);
	if (!fsdev_io->u_in.lookup.name) {
		fsdev_io_free(fsdev_io);
		return -ENOMEM;
	}

	fsdev_io->u_in.lookup.parent_ino = parent_ino;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_forget_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_forget_cpl_cb);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_forget(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		     spdk_ino_t ino, uint64_t nlookup, spdk_fsdev_op_forget_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_forget_cb, ch,
					 SPDK_FSDEV_OP_FORGET);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.forget.ino = ino;
	fsdev_io->u_in.forget.nlookup = nlookup;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_getattr_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_getattr_cpl_cb, &fsdev_io->u_out.getattr.attr,
		     fsdev_io->u_out.getattr.attr_timeout_ms);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_getattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		      uint64_t unique, spdk_ino_t ino, uint64_t fh, spdk_fsdev_op_getattr_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_getattr_cb, ch,
					 SPDK_FSDEV_OP_GETATTR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.getattr.ino = ino;
	fsdev_io->u_in.getattr.fh = fh;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_setattr_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_setattr_cpl_cb, &fsdev_io->u_out.setattr.attr,
		     fsdev_io->u_out.setattr.attr_timeout_ms);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_setattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		      uint64_t unique, spdk_ino_t ino, const struct stat *attr, uint32_t to_set, uint64_t fh,
		      spdk_fsdev_op_setattr_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_setattr_cb, ch,
					 SPDK_FSDEV_OP_SETATTR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.setattr.ino = ino;
	fsdev_io->u_in.setattr.attr = *attr;
	fsdev_io->u_in.setattr.to_set = to_set;
	fsdev_io->u_in.setattr.fh = fh;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_readlink_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_readlink_cpl_cb, fsdev_io->u_out.readlink.linkname);

	free(fsdev_io->u_out.readlink.linkname);
	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_readlink(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		       uint64_t unique, spdk_ino_t ino, spdk_fsdev_op_readlink_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_readlink_cb, ch,
					 SPDK_FSDEV_OP_READLINK);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.readlink.ino = ino;
	fsdev_io->u_out.readlink.linkname = NULL;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_symlink_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_symlink_cpl_cb, &fsdev_io->u_out.symlink.entry);

	free(fsdev_io->u_in.symlink.target);
	free(fsdev_io->u_in.symlink.linkpath);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_symlink(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		      uint64_t unique, spdk_ino_t parent_ino, const char *target, const char *linkpath,
		      uid_t euid, gid_t egid, spdk_fsdev_op_symlink_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_symlink_cb, ch,
					 SPDK_FSDEV_OP_SYMLINK);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.symlink.target = strdup(target);
	if (!fsdev_io) {
		fsdev_io_free(fsdev_io);
		return -ENOMEM;
	}

	fsdev_io->u_in.symlink.linkpath = strdup(linkpath);
	if (!fsdev_io) {
		fsdev_io_free(fsdev_io);
		free(fsdev_io->u_in.symlink.target);
		return -ENOMEM;
	}

	fsdev_io->u_in.symlink.parent_ino = parent_ino;
	fsdev_io->u_in.symlink.euid = euid;
	fsdev_io->u_in.symlink.egid = egid;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_mknod_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_mknod_cpl_cb, &fsdev_io->u_out.mknod.entry);

	free(fsdev_io->u_in.mknod.name);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_mknod(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		    spdk_ino_t parent_ino, const char *name, mode_t mode, dev_t rdev,
		    uid_t euid, gid_t egid, spdk_fsdev_op_mknod_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_mknod_cb, ch,
					 SPDK_FSDEV_OP_MKNOD);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.mknod.name = strdup(name);
	if (!fsdev_io->u_in.mknod.name) {
		fsdev_io_free(fsdev_io);
		return -ENOMEM;
	}

	fsdev_io->u_in.mknod.parent_ino = parent_ino;
	fsdev_io->u_in.mknod.mode = mode;
	fsdev_io->u_in.mknod.rdev = rdev;
	fsdev_io->u_in.mknod.euid = euid;
	fsdev_io->u_in.mknod.egid = egid;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_mkdir_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_mkdir_cpl_cb, &fsdev_io->u_out.mkdir.entry);

	free(fsdev_io->u_in.mkdir.name);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_mkdir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		    spdk_ino_t parent_ino, const char *name, mode_t mode,
		    uid_t euid, gid_t egid, spdk_fsdev_op_mkdir_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_mkdir_cb, ch,
					 SPDK_FSDEV_OP_MKDIR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.mkdir.name = strdup(name);
	if (!fsdev_io->u_in.mkdir.name) {
		fsdev_io_free(fsdev_io);
		return -ENOMEM;
	}

	fsdev_io->u_in.mkdir.parent_ino = parent_ino;
	fsdev_io->u_in.mkdir.mode = mode;
	fsdev_io->u_in.mkdir.euid = euid;
	fsdev_io->u_in.mkdir.egid = egid;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_unlink_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_unlink_cpl_cb);

	free(fsdev_io->u_in.unlink.name);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_unlink(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		     spdk_ino_t parent_ino, const char *name,
		     spdk_fsdev_op_unlink_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_unlink_cb, ch,
					 SPDK_FSDEV_OP_UNLINK);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.unlink.name = strdup(name);
	if (!fsdev_io->u_in.unlink.name) {
		fsdev_io_free(fsdev_io);
		return -ENOMEM;
	}

	fsdev_io->u_in.unlink.parent_ino = parent_ino;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_rmdir_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_rmdir_cpl_cb);

	free(fsdev_io->u_in.rmdir.name);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_rmdir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		    spdk_ino_t parent_ino, const char *name,
		    spdk_fsdev_op_rmdir_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_rmdir_cb, ch,
					 SPDK_FSDEV_OP_RMDIR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.rmdir.name = strdup(name);
	if (!fsdev_io->u_in.rmdir.name) {
		fsdev_io_free(fsdev_io);
		return -ENOMEM;
	}

	fsdev_io->u_in.rmdir.parent_ino = parent_ino;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_rename_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_rename_cpl_cb);

	free(fsdev_io->u_in.rename.name);
	free(fsdev_io->u_in.rename.new_name);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_rename(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		     spdk_ino_t parent_ino, const char *name, spdk_ino_t new_parent_ino, const char *new_name,
		     uint32_t flags, spdk_fsdev_op_rename_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_rename_cb, ch,
					 SPDK_FSDEV_OP_RENAME);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.rename.name = strdup(name);
	if (!fsdev_io->u_in.rename.name) {
		fsdev_io_free(fsdev_io);
		return -ENOMEM;
	}

	fsdev_io->u_in.rename.new_name = strdup(new_name);
	if (!fsdev_io->u_in.rename.new_name) {
		free(fsdev_io->u_in.rename.name);
		fsdev_io_free(fsdev_io);
		return -ENOMEM;
	}

	fsdev_io->u_in.rename.parent_ino = parent_ino;
	fsdev_io->u_in.rename.new_parent_ino = new_parent_ino;
	fsdev_io->u_in.rename.flags = flags;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_link_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_link_cpl_cb, &fsdev_io->u_out.link.entry);

	free(fsdev_io->u_in.link.name);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_link(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		   spdk_ino_t ino, spdk_ino_t new_parent_ino, const char *name,
		   spdk_fsdev_op_link_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_link_cb, ch,
					 SPDK_FSDEV_OP_LINK);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.link.name = strdup(name);
	if (!fsdev_io->u_in.link.name) {
		fsdev_io_free(fsdev_io);
		return -ENOMEM;
	}

	fsdev_io->u_in.link.ino = ino;
	fsdev_io->u_in.link.new_parent_ino = new_parent_ino;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_open_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_open_cpl_cb, fsdev_io->u_out.open.fh);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_open(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		   spdk_ino_t ino, uint32_t flags, spdk_fsdev_op_open_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_open_cb, ch,
					 SPDK_FSDEV_OP_OPEN);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.open.ino = ino;
	fsdev_io->u_in.open.flags = flags;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_read_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_read_cpl_cb, fsdev_io->u_out.read.data_size);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_read(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		   spdk_ino_t ino, uint64_t fh, size_t size, uint64_t offs, uint32_t flags,
		   struct iovec *iov, uint32_t iovcnt, struct spdk_fsdev_ext_op_opts *opts,
		   spdk_fsdev_op_read_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_read_cb, ch,
					 SPDK_FSDEV_OP_READ);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.read.ino = ino;
	fsdev_io->u_in.read.fh = fh;
	fsdev_io->u_in.read.size = size;
	fsdev_io->u_in.read.offs = offs;
	fsdev_io->u_in.read.flags = flags;
	fsdev_io->u_in.read.iov = iov;
	fsdev_io->u_in.read.iovcnt = iovcnt;
	fsdev_io->u_in.read.opts = opts;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_write_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_write_cpl_cb, fsdev_io->u_out.write.data_size);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_write(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		    spdk_ino_t ino, uint64_t fh, size_t size, uint64_t offs, uint64_t flags,
		    const struct iovec *iov, uint32_t iovcnt, struct spdk_fsdev_ext_op_opts *opts,
		    spdk_fsdev_op_write_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_write_cb, ch,
					 SPDK_FSDEV_OP_WRITE);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.write.ino = ino;
	fsdev_io->u_in.write.fh = fh;
	fsdev_io->u_in.write.size = size;
	fsdev_io->u_in.write.offs = offs;
	fsdev_io->u_in.write.flags = flags;
	fsdev_io->u_in.write.iov = iov;
	fsdev_io->u_in.write.iovcnt = iovcnt;
	fsdev_io->u_in.write.opts = opts;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_statfs_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_statfs_cpl_cb, &fsdev_io->u_out.statfs.stbuf);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_statfs(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		     spdk_ino_t ino, spdk_fsdev_op_statfs_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_statfs_cb, ch,
					 SPDK_FSDEV_OP_STATFS);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.statfs.ino = ino;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_release_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_release_cpl_cb);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_release(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		      uint64_t unique, spdk_ino_t ino, uint64_t fh,
		      spdk_fsdev_op_release_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_release_cb, ch,
					 SPDK_FSDEV_OP_RELEASE);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.release.ino = ino;
	fsdev_io->u_in.release.fh = fh;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_fsync_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_fsync_cpl_cb);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_fsync(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		    spdk_ino_t ino, uint64_t fh, bool datasync,
		    spdk_fsdev_op_fsync_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_fsync_cb, ch,
					 SPDK_FSDEV_OP_FSYNC);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.fsync.ino = ino;
	fsdev_io->u_in.fsync.fh = fh;
	fsdev_io->u_in.fsync.datasync = datasync;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_setxattr_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_setxattr_cpl_cb);

	free(fsdev_io->u_in.setxattr.value);
	free(fsdev_io->u_in.setxattr.name);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_setxattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		       uint64_t unique, spdk_ino_t ino, const char *name, const char *value, size_t size, uint32_t flags,
		       spdk_fsdev_op_setxattr_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_setxattr_cb, ch,
					 SPDK_FSDEV_OP_SETXATTR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.setxattr.name = strdup(name);
	if (!fsdev_io->u_in.setxattr.name) {
		fsdev_io_free(fsdev_io);
		return -ENOMEM;
	}

	fsdev_io->u_in.setxattr.value = malloc(size);
	if (!fsdev_io->u_in.setxattr.value) {
		free(fsdev_io->u_in.setxattr.name);
		fsdev_io_free(fsdev_io);
		return -ENOMEM;
	}

	memcpy(fsdev_io->u_in.setxattr.value, value, size);
	fsdev_io->u_in.setxattr.ino = ino;
	fsdev_io->u_in.setxattr.size = size;
	fsdev_io->u_in.setxattr.flags = flags;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_getxattr_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_getxattr_cpl_cb, fsdev_io->u_out.getxattr.value_size);

	free(fsdev_io->u_in.getxattr.name);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_getxattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		       uint64_t unique, spdk_ino_t ino, const char *name, char *buffer, size_t size,
		       spdk_fsdev_op_getxattr_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_getxattr_cb, ch,
					 SPDK_FSDEV_OP_GETXATTR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.getxattr.name = strdup(name);
	if (!fsdev_io->u_in.getxattr.name) {
		fsdev_io_free(fsdev_io);
		return -ENOMEM;
	}

	fsdev_io->u_in.getxattr.ino = ino;
	fsdev_io->u_in.getxattr.buffer = buffer;
	fsdev_io->u_in.getxattr.size = size;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_listxattr_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_listxattr_cpl_cb, fsdev_io->u_out.listxattr.data_size,
		     fsdev_io->u_out.listxattr.size_only);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_listxattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			uint64_t unique, spdk_ino_t ino, char *buffer, size_t size,
			spdk_fsdev_op_listxattr_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_listxattr_cb, ch,
					 SPDK_FSDEV_OP_LISTXATTR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.listxattr.ino = ino;
	fsdev_io->u_in.listxattr.buffer = buffer;
	fsdev_io->u_in.listxattr.size = size;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_removexattr_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_removexattr_cpl_cb);

	free(fsdev_io->u_in.removexattr.name);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_removexattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			  uint64_t unique, spdk_ino_t ino, const char *name,
			  spdk_fsdev_op_removexattr_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_removexattr_cb, ch,
					 SPDK_FSDEV_OP_REMOVEXATTR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.removexattr.name = strdup(name);
	if (!fsdev_io->u_in.removexattr.name) {
		fsdev_io_free(fsdev_io);
		return -ENOMEM;
	}

	fsdev_io->u_in.removexattr.ino = ino;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_flush_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_flush_cpl_cb);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_flush(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		    spdk_ino_t ino, uint64_t fh,
		    spdk_fsdev_op_flush_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_flush_cb, ch,
					 SPDK_FSDEV_OP_FLUSH);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.flush.ino = ino;
	fsdev_io->u_in.flush.fh = fh;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_opendir_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_opendir_cpl_cb, fsdev_io->u_out.opendir.fh);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_opendir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		      uint64_t unique, spdk_ino_t ino, uint32_t flags,
		      spdk_fsdev_op_opendir_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_opendir_cb, ch,
					 SPDK_FSDEV_OP_OPENDIR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.opendir.ino = ino;
	fsdev_io->u_in.opendir.flags = flags;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static int
_spdk_fsdev_op_readdir_entry_clb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	spdk_fsdev_op_readdir_entry_cb *usr_entry_clb = fsdev_io->u_in.readdir.usr_entry_clb;
	struct spdk_io_channel *ch = cb_arg;

	return usr_entry_clb(fsdev_io->internal.usr_cpl_ctx, ch, fsdev_io->u_out.readdir.name,
			     &fsdev_io->u_out.readdir.entry, fsdev_io->u_out.readdir.offset);
}

static void
_spdk_fsdev_op_readdir_emum_clb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_readdir_cpl_cb);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_readdir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		      uint64_t unique, spdk_ino_t ino, uint64_t fh, uint64_t offset,
		      spdk_fsdev_op_readdir_entry_cb entry_clb, spdk_fsdev_op_readdir_cpl_cb cpl_clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cpl_clb, ctx, _spdk_fsdev_op_readdir_emum_clb,
					 ch,
					 SPDK_FSDEV_OP_READDIR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.readdir.ino = ino;
	fsdev_io->u_in.readdir.fh = fh;
	fsdev_io->u_in.readdir.offset = offset;
	fsdev_io->u_in.readdir.entry_clb = _spdk_fsdev_op_readdir_entry_clb;
	fsdev_io->u_in.readdir.usr_entry_clb = entry_clb;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_releasedir_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_releasedir_cpl_cb);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_releasedir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			 uint64_t unique, spdk_ino_t ino, uint64_t fh,
			 spdk_fsdev_op_releasedir_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_releasedir_cb, ch,
					 SPDK_FSDEV_OP_RELEASEDIR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.releasedir.ino = ino;
	fsdev_io->u_in.releasedir.fh = fh;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_fsyncdir_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_fsyncdir_cpl_cb);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_fsyncdir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		       uint64_t unique, spdk_ino_t ino, uint64_t fh, bool datasync,
		       spdk_fsdev_op_fsyncdir_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_fsyncdir_cb, ch,
					 SPDK_FSDEV_OP_FSYNCDIR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.fsyncdir.ino = ino;
	fsdev_io->u_in.fsyncdir.fh = fh;
	fsdev_io->u_in.fsyncdir.datasync = datasync;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_flock_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_flock_cpl_cb);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_flock(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		    spdk_ino_t ino, uint64_t fh, int operation,
		    spdk_fsdev_op_flock_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_flock_cb, ch,
					 SPDK_FSDEV_OP_FLOCK);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.flock.ino = ino;
	fsdev_io->u_in.flock.fh = fh;
	fsdev_io->u_in.flock.operation = operation;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_create_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_create_cpl_cb, &fsdev_io->u_out.create.entry,
		     fsdev_io->u_out.create.fh);

	free(fsdev_io->u_in.create.name);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_create(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		     spdk_ino_t parent_ino, const char *name, mode_t mode, uint32_t flags, mode_t umask,
		     uid_t euid, gid_t egid, spdk_fsdev_op_create_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_create_cb, ch,
					 SPDK_FSDEV_OP_CREATE);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.create.name = strdup(name);
	if (!fsdev_io->u_in.create.name) {
		fsdev_io_free(fsdev_io);
		return -ENOMEM;
	}

	fsdev_io->u_in.create.parent_ino = parent_ino;
	fsdev_io->u_in.create.mode = mode;
	fsdev_io->u_in.create.flags = flags;
	fsdev_io->u_in.create.umask = umask;
	fsdev_io->u_in.create.euid = euid;
	fsdev_io->u_in.create.egid = egid;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_interrupt_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_interrupt_cpl_cb);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_abort(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		    uint64_t unique_to_abort, spdk_fsdev_op_interrupt_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, 0, clb, ctx, _spdk_fsdev_op_interrupt_cb, ch,
					 SPDK_FSDEV_OP_ABORT);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.abort.unique_to_abort = unique_to_abort;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_fallocate_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_fallocate_cpl_cb);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_fallocate(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			uint64_t unique, spdk_ino_t ino, uint64_t fh, int mode, off_t offset, off_t length,
			spdk_fsdev_op_fallocate_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_fallocate_cb, ch,
					 SPDK_FSDEV_OP_FALLOCATE);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.fallocate.ino = ino;
	fsdev_io->u_in.fallocate.fh = fh;
	fsdev_io->u_in.fallocate.mode = mode;
	fsdev_io->u_in.fallocate.offset = offset;
	fsdev_io->u_in.fallocate.length = length;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static void
_spdk_fsdev_op_copy_file_range_cb(struct spdk_fsdev_io *fsdev_io, void *cb_arg)
{
	struct spdk_io_channel *ch = cb_arg;

	CALL_USR_CLB(fsdev_io, ch, spdk_fsdev_op_copy_file_range_cpl_cb,
		     fsdev_io->u_out.copy_file_range.data_size);

	fsdev_io_free(fsdev_io);
}

int
spdk_fsdev_op_copy_file_range(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			      uint64_t unique, spdk_ino_t ino_in, uint64_t fh_in, off_t off_in,
			      spdk_ino_t ino_out, uint64_t fh_out, off_t off_out, size_t len, uint32_t flags,
			      spdk_fsdev_op_copy_file_range_cpl_cb clb, void *ctx)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, clb, ctx, _spdk_fsdev_op_copy_file_range_cb, ch,
					 SPDK_FSDEV_OP_COPY_FILE_RANGE);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.copy_file_range.ino_in = ino_in;
	fsdev_io->u_in.copy_file_range.fh_in = fh_in;
	fsdev_io->u_in.copy_file_range.off_in = off_in;
	fsdev_io->u_in.copy_file_range.ino_out = ino_out;
	fsdev_io->u_in.copy_file_range.fh_out = fh_out;
	fsdev_io->u_in.copy_file_range.off_out = off_out;
	fsdev_io->u_in.copy_file_range.len = len;
	fsdev_io->u_in.copy_file_range.flags = flags;

	fsdev_io_submit(fsdev_io);
	return 0;
}
