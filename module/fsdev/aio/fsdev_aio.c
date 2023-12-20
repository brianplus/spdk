/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */
#include "spdk/stdinc.h"
#include "spdk/event.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/config.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "spdk/thread.h"
#include "spdk_internal/spdk_htable.h"
#include "aio_mgr.h"
#include "fsdev_aio.h"
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <sys/file.h>

#define OP_STATUS_ASYNC INT_MIN

#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

/* See https://libfuse.github.io/doxygen/structfuse__conn__info.html */
#define MAX_BACKGROUND (100)
#define TIME_GRAN (1)
#define MAX_AIOS 256
#define DEFAULT_MAX_WRITE 0x00020000
#define DEFAULT_XATTR_ENABLED false
#define DEFAULT_TIMEOUT_MS 86400000
#define INODES_HTABLE_SIZE 32

struct lo_cred {
	uid_t euid;
	gid_t egid;
};

/** Inode number type */
typedef uint64_t spdk_ino_t;

struct lo_map_elem {
	union {
		struct lo_inode *inode;
		struct lo_dirp *dirp;
		int fd;
		ssize_t freelist;
	};
	bool in_use;
};

/* Maps FUSE fh or ino values to internal objects */
struct lo_map {
	struct lo_map_elem *elems;
	size_t nelems;
	ssize_t freelist;
};

struct lo_key {
	ino_t ino;
	dev_t dev;
};

struct lo_inode {
	int fd;
	bool is_symlink;
	struct lo_key key;
	uint64_t refcount; /* protected by lo->mutex */
	spdk_ino_t fuse_ino;
	SPDK_HTABLE_ENTRY(lo_inode) link;
};

struct lo_dirp {
	int fd;
	DIR *dp;
	struct dirent *entry;
	off_t offset;
};

struct aio_fsdev {
	struct spdk_fsdev fsdev;
	char *root_path;
	int proc_self_fd;
	pthread_mutex_t mutex;
	SPDK_HTABLE_DECLARE(, lo_inode, INODES_HTABLE_SIZE) inodes; /* protected by aio_fsdev->mutex */
	struct lo_map ino_map; /* protected by aio_fsdev->mutex */
	struct lo_map dirp_map; /* protected by aio_fsdev->mutex */
	struct lo_map fd_map; /* protected by aio_fsdev->mutex */
	struct lo_inode root;
	TAILQ_ENTRY(aio_fsdev) tailq;
	bool xattr_enabled;
};

struct aio_fsdev_io {
	struct spdk_aio_mgr_io *aio;
	struct aio_io_channel *ch;
	TAILQ_ENTRY(aio_fsdev_io) link;
};

struct aio_io_channel {
	struct spdk_poller *poller;
	struct spdk_aio_mgr *mgr;
	TAILQ_HEAD(, aio_fsdev_io) ios_in_progress;
};

static TAILQ_HEAD(, aio_fsdev) g_aio_fsdev_head = TAILQ_HEAD_INITIALIZER(
			g_aio_fsdev_head);

static inline struct aio_fsdev *
fsdev_to_aio_fsdev(struct spdk_fsdev *fsdev)
{
	return SPDK_CONTAINEROF(fsdev, struct aio_fsdev, fsdev);
}

static inline struct spdk_fsdev_io *
aio_to_fsdev_io(const struct aio_fsdev_io *aio_io)
{
	return SPDK_CONTAINEROF(aio_io, struct spdk_fsdev_io, driver_ctx);
}

static inline struct aio_fsdev_io *
fsdev_to_aio_io(const struct spdk_fsdev_io *fsdev_io)
{
	return (struct aio_fsdev_io *)fsdev_io->driver_ctx;
}

static int
is_dot_or_dotdot(const char *name)
{
	return name[0] == '.' && (name[1] == '\0' ||
				  (name[1] == '.' && name[2] == '\0'));
}

/* Is `path` a single path component that is not "." or ".."? */
static int
is_safe_path_component(const char *path)
{
	if (strchr(path, '/')) {
		return 0;
	}

	return !is_dot_or_dotdot(path);
}

static void
lo_map_init(struct lo_map *map)
{
	map->elems = NULL;
	map->nelems = 0;
	map->freelist = -1;
}

static void
lo_map_destroy(struct lo_map *map)
{
	free(map->elems);
}

static int
lo_map_grow(struct lo_map *map, size_t new_nelems)
{
	struct lo_map_elem *new_elems;
	size_t i;

	if (new_nelems <= map->nelems) {
		return 1;
	}

	new_elems = realloc(map->elems, sizeof(map->elems[0]) * new_nelems);
	if (!new_elems) {
		return 0;
	}

	for (i = map->nelems; i < new_nelems; i++) {
		new_elems[i].freelist = i + 1;
		new_elems[i].in_use = false;
	}
	new_elems[new_nelems - 1].freelist = -1;

	map->elems = new_elems;
	map->freelist = map->nelems;
	map->nelems = new_nelems;
	return 1;
}

static struct lo_map_elem *
lo_map_alloc_elem(struct lo_map *map)
{
	struct lo_map_elem *elem;

	if (map->freelist == -1 && !lo_map_grow(map, map->nelems + 256)) {
		return NULL;
	}

	elem = &map->elems[map->freelist];
	map->freelist = elem->freelist;

	elem->in_use = true;

	return elem;
}

static struct lo_map_elem *
lo_map_reserve(struct lo_map *map, size_t key)
{
	ssize_t *prev;

	if (!lo_map_grow(map, key + 1)) {
		return NULL;
	}

	for (prev = &map->freelist;
	     *prev != -1;
	     prev = &map->elems[*prev].freelist) {
		if (*prev == (ssize_t)key) {
			struct lo_map_elem *elem = &map->elems[key];

			*prev = elem->freelist;
			elem->in_use = true;
			return elem;
		}
	}
	return NULL;
}

static struct lo_map_elem *
lo_map_get(struct lo_map *map, size_t key)
{
	if (key >= map->nelems) {
		return NULL;
	}
	if (!map->elems[key].in_use) {
		return NULL;
	}
	return &map->elems[key];
}

static void
lo_map_remove(struct lo_map *map, size_t key)
{
	struct lo_map_elem *elem;

	if (key >= map->nelems) {
		return;
	}

	elem = &map->elems[key];
	if (!elem->in_use) {
		return;
	}

	elem->in_use = false;

	elem->freelist = map->freelist;
	map->freelist = key;
}

/* Assumes lo->mutex is held */
static ssize_t
lo_add_fd_mapping(struct aio_fsdev *vfsdev, int fd)
{
	struct lo_map_elem *elem;

	elem = lo_map_alloc_elem(&vfsdev->fd_map);
	if (!elem) {
		return -1;
	}

	elem->fd = fd;
	return elem - vfsdev->fd_map.elems;
}

/* Assumes lo->mutex is held */
static ssize_t
lo_add_dirp_mapping(struct aio_fsdev *vfsdev, struct lo_dirp *dirp)
{
	struct lo_map_elem *elem;

	elem = lo_map_alloc_elem(&vfsdev->dirp_map);
	if (!elem) {
		return -1;
	}

	elem->dirp = dirp;
	return elem - vfsdev->dirp_map.elems;
}

/* Assumes lo->mutex is held */
static ssize_t
lo_add_inode_mapping(struct aio_fsdev *vfsdev, struct lo_inode *inode)
{
	struct lo_map_elem *elem;

	elem = lo_map_alloc_elem(&vfsdev->ino_map);
	if (!elem) {
		return -1;
	}

	elem->inode = inode;
	return elem - vfsdev->ino_map.elems;
}

static struct lo_inode *
lo_inode(struct aio_fsdev *vfsdev, spdk_ino_t ino)
{
	struct lo_map_elem *elem;

	pthread_mutex_lock(&vfsdev->mutex);
	elem = lo_map_get(&vfsdev->ino_map, ino);
	pthread_mutex_unlock(&vfsdev->mutex);

	if (!elem) {
		return NULL;
	}

	return elem->inode;
}

static int
lo_fd(struct aio_fsdev *vfsdev, spdk_ino_t ino)
{
	struct lo_inode *inode = lo_inode(vfsdev, ino);
	return inode ? inode->fd : -1;
}

static struct lo_dirp *
lo_dirp(struct aio_fsdev *vfsdev, uint64_t fh)
{
	struct lo_map_elem *elem;

	pthread_mutex_lock(&vfsdev->mutex);
	elem = lo_map_get(&vfsdev->dirp_map, fh);
	pthread_mutex_unlock(&vfsdev->mutex);
	if (!elem) {
		return NULL;
	}

	return elem->dirp;
}

static struct lo_inode *
lo_find_unsafe(struct aio_fsdev *vfsdev, const struct stat *st)
{
	struct lo_inode *inode;
	size_t bkt;
	spdk_htable_foreach(&vfsdev->inodes, bkt, inode, link) {
		if (inode->key.ino == st->st_ino && inode->key.dev == st->st_dev) {
			assert(inode->refcount > 0);
			inode->refcount++;
			return inode;
		}
	}
	return NULL;
}

static struct lo_inode *
lo_find(struct aio_fsdev *vfsdev, const struct stat *st)
{
	struct lo_inode *inode;

	pthread_mutex_lock(&vfsdev->mutex);
	inode = lo_find_unsafe(vfsdev, st);
	pthread_mutex_unlock(&vfsdev->mutex);

	return inode;
}

static void
unref_inode(struct aio_fsdev *vfsdev, struct lo_inode *inode, uint64_t n)
{
	if (!inode) {
		return;
	}

	pthread_mutex_lock(&vfsdev->mutex);
	assert(inode->refcount >= n);
	inode->refcount -= n;
	if (!inode->refcount) {
		spdk_htable_del(inode, link);
		pthread_mutex_unlock(&vfsdev->mutex);
		close(inode->fd);
		free(inode);
	} else {
		pthread_mutex_unlock(&vfsdev->mutex);
	}
}

static inline size_t
lo_inode_hkey(struct lo_inode *inode)
{
	return (size_t)(inode->key.dev * inode->key.dev) % INODES_HTABLE_SIZE;
}

static struct lo_inode *
lookup_name(struct aio_fsdev *vfsdev, spdk_ino_t parent, const char *name)
{
	int res;
	struct stat attr;

	res = fstatat(lo_fd(vfsdev, parent), name, &attr,
		      AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1) {
		return NULL;
	}

	return lo_find(vfsdev, &attr);
}

static int
lo_parent_and_name(struct aio_fsdev *vfsdev, struct lo_inode *inode,
		   char path[PATH_MAX], struct lo_inode **parent)
{
	char procname[64];
	char *last;
	struct stat stat;
	struct lo_inode *p;
	int retries = 2;
	int res;

retry:
	sprintf(procname, "%i", inode->fd);

	res = readlinkat(vfsdev->proc_self_fd, procname, path, PATH_MAX);
	if (res < 0) {
		SPDK_WARNLOG("lo_parent_and_name: readlink failed");
		goto fail_noretry;
	}

	if (res >= PATH_MAX) {
		SPDK_WARNLOG("lo_parent_and_name: readlink overflowed");
		goto fail_noretry;
	}
	path[res] = '\0';

	last = strrchr(path, '/');
	if (last == NULL) {
		/* Shouldn't happen */
		SPDK_WARNLOG("lo_parent_and_name: INTERNAL ERROR: bad path read from proc");
		goto fail_noretry;
	}
	if (last == path) {
		p = &vfsdev->root;
		pthread_mutex_lock(&vfsdev->mutex);
		p->refcount++;
		pthread_mutex_unlock(&vfsdev->mutex);
	} else {
		*last = '\0';
		res = fstatat(AT_FDCWD, last == path ? "/" : path, &stat, 0);
		if (res == -1) {
			if (!retries) {
				SPDK_WARNLOG("lo_parent_and_name: failed to stat parent");
			}
			goto fail;
		}
		p = lo_find(vfsdev, &stat);
		if (p == NULL) {
			if (!retries) {
				SPDK_WARNLOG("lo_parent_and_name: failed to find parent");
			}
			goto fail;
		}
	}
	last++;
	res = fstatat(p->fd, last, &stat, AT_SYMLINK_NOFOLLOW);
	if (res == -1) {
		if (!retries) {
			SPDK_WARNLOG("lo_parent_and_name: failed to stat last");
		}
		goto fail_unref;
	}
	if (stat.st_dev != inode->key.dev || stat.st_ino != inode->key.ino) {
		if (!retries) {
			SPDK_WARNLOG("lo_parent_and_name: filed to match last");
		}
		goto fail_unref;
	}
	*parent = p;
	memmove(path, last, strlen(last) + 1);

	return 0;

fail_unref:
	unref_inode(vfsdev, p, 1);
fail:
	if (retries) {
		retries--;
		goto retry;
	}
fail_noretry:
	errno = EIO;
	return -1;
}

static int
utimensat_empty(struct aio_fsdev *vfsdev, struct lo_inode *inode,
		const struct timespec *tv)
{
	int res;
	struct lo_inode *parent;
	char path[PATH_MAX];

	if (inode->is_symlink) {
		res = utimensat(inode->fd, "", tv, AT_EMPTY_PATH);
		if (res == -1 && errno == EINVAL) {
			/* Sorry, no race free way to set times on symlink. */
			goto fallback;
		}
		return res;
	}
	sprintf(path, "%i", inode->fd);

	return utimensat(vfsdev->proc_self_fd, path, tv, 0);

fallback:
	res = lo_parent_and_name(vfsdev, inode, path, &parent);
	if (res != -1) {
		res = utimensat(parent->fd, path, tv, AT_SYMLINK_NOFOLLOW);
	}

	return res;
}

static int
lo_fi_fd(struct aio_fsdev *vfsdev, uint64_t fh)
{
	struct lo_map_elem *elem;

	pthread_mutex_lock(&vfsdev->mutex);
	elem = lo_map_get(&vfsdev->fd_map, fh);
	pthread_mutex_unlock(&vfsdev->mutex);

	if (!elem) {
		return -1;
	}

	return elem->fd;
}

static int
lo_fill_getattr(struct aio_fsdev *vfsdev, spdk_ino_t ino, struct stat *attr)
{
	int fd = lo_fd(vfsdev, ino);
	int res = fstatat(fd, "", attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1) {
		res = errno;
		SPDK_ERRLOG("Cannot fstat %" PRIu64 " (fd=%d, err=%d)\n", ino, fd, res);
		return res;
	}

	SPDK_DEBUGLOG(fsdev_aio, "fstatat succeded for %" PRIu64 " (fd=%d)\n", ino, fd);
	return 0;
}

static int
lo_getattr(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	int res;
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	spdk_ino_t ino = fsdev_io->u_in.getattr.ino;

	res = lo_fill_getattr(vfsdev, ino, &fsdev_io->u_out.getattr.attr);
	if (res) {
		SPDK_ERRLOG("Cannot fstat %" PRIu64 " (err=%d)\n", ino, res);
		return res;
	}

	fsdev_io->u_out.getattr.attr_timeout_ms = DEFAULT_TIMEOUT_MS;

	SPDK_DEBUGLOG(fsdev_aio, "GETATTR succeded for %" PRIu64 "\n", ino);
	return 0;
}

static int
lo_opendir(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int error;
	struct lo_dirp *d;
	ssize_t fh;
	int fd;
	spdk_ino_t ino = fsdev_io->u_in.opendir.ino;

	d = calloc(1, sizeof(struct lo_dirp));
	if (d == NULL) {
		error = ENOMEM;
		SPDK_ERRLOG("Cannot allocate lo_dirp object\n");
		goto out_err;
	}

	fd = lo_fd(vfsdev, ino);
	d->fd = openat(fd, ".", O_RDONLY);
	if (d->fd == -1) {
		error = errno;
		SPDK_ERRLOG("openat failed for %" PRIu64 "(fd=%d)\n", ino, fd);
		goto out_err;
	}

	d->dp = fdopendir(d->fd);
	if (d->dp == NULL) {
		error = errno;
		SPDK_ERRLOG("fdopendir failed for %" PRIu64 "(fd=%d)\n", ino, fd);
		goto out_err;
	}

	d->offset = 0;
	d->entry = NULL;

	fh = lo_add_dirp_mapping(vfsdev, d);
	if (fh == -1) {
		error = ENOMEM;
		SPDK_ERRLOG("lo_add_dirp_mapping failed for %" PRIu64 "(fd=%d)\n", ino, fd);
		goto out_err;
	}

	SPDK_DEBUGLOG(fsdev_aio, "OPENDIR succeded for %" PRIu64 " (fd=%d, fh=0x%" PRIu64 ")\n",
		      ino, fd, fh);

	fsdev_io->u_out.opendir.fh = fh;

	return 0;

out_err:
	if (d) {
		if (d->dp) {
			closedir(d->dp);
		}
		if (d->fd != -1) {
			close(d->fd);
		}
		free(d);
	}

	return error;
}

static int
lo_releasedir(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	struct lo_dirp *d;
	uint64_t fh = fsdev_io->u_in.releasedir.fh;
	spdk_ino_t ino = fsdev_io->u_in.releasedir.ino;

	d = lo_dirp(vfsdev, fh);
	if (!d) {
		SPDK_ERRLOG("lo_dirp failed for %" PRIu64 " (fh=0x%" PRIu64 ")\n", ino, fh);
		return EBADF;
	}

	pthread_mutex_lock(&vfsdev->mutex);
	lo_map_remove(&vfsdev->dirp_map, fh);
	pthread_mutex_unlock(&vfsdev->mutex);

	closedir(d->dp);
	free(d);

	SPDK_DEBUGLOG(fsdev_aio, "RELEASEDIR succeded for %" PRIu64 " (fh=0x%" PRIu64 ")\n", ino, fh);

	return 0;
}


static int
lo_do_lookup(struct aio_fsdev *vfsdev, spdk_ino_t parent_ino, const char *name,
	     struct spdk_fsdev_entry *e)
{
	int newfd;
	int res;
	int saverr;
	struct lo_inode *inode, *dir = lo_inode(vfsdev, parent_ino);

	memset(e, 0, sizeof(*e));
	e->attr_timeout_ms = DEFAULT_TIMEOUT_MS;
	e->entry_timeout_ms = DEFAULT_TIMEOUT_MS;

	/* Do not allow escaping root directory */
	if (dir == &vfsdev->root && strcmp(name, "..") == 0) {
		name = ".";
	}

	newfd = openat(dir->fd, name, O_PATH | O_NOFOLLOW);
	if (newfd == -1) {
		saverr = errno;
		SPDK_DEBUGLOG(fsdev_aio, "openat(%d, %s) failed with %d\n", dir->fd, name, saverr);
		goto out_err;
	}

	res = fstatat(newfd, "", &e->attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1) {
		saverr = errno;
		SPDK_ERRLOG("fstatat(%s) failed with %d\n", name, saverr);
		goto out_err;
	}

	pthread_mutex_lock(&vfsdev->mutex);
	inode = lo_find_unsafe(vfsdev, &e->attr);
	if (inode) {
		close(newfd);
		newfd = -1;
	} else {
		saverr = ENOMEM;
		inode = calloc(1, sizeof(struct lo_inode));
		if (!inode) {
			SPDK_ERRLOG("calloc(lo_inode)) failed\n");
			pthread_mutex_unlock(&vfsdev->mutex);
			goto out_err;
		}

		inode->is_symlink = S_ISLNK(e->attr.st_mode);
		inode->refcount = 1;
		inode->fd = newfd;
		newfd = -1;
		inode->key.ino = e->attr.st_ino;
		inode->key.dev = e->attr.st_dev;

		inode->fuse_ino = lo_add_inode_mapping(vfsdev, inode);
		spdk_htable_add(&vfsdev->inodes, inode, link, lo_inode_hkey(inode));
	}
	pthread_mutex_unlock(&vfsdev->mutex);

	res = fstatat(inode->fd, "", &e->attr,
		      AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1) {
		saverr = errno;
		SPDK_ERRLOG("2nd fstatat(%s) failed with %d\n",
			    name, saverr);
		unref_inode(vfsdev, inode, 1);
		goto out_err;
	}

	e->ino = inode->fuse_ino;

	SPDK_DEBUGLOG(fsdev_aio, "OPEN (%s) succeeded in dir %" PRIu64 " (ino=%" PRIu64 ", fd=%d)\n",
		      name, parent_ino, e->ino, inode->fd);
	return 0;

out_err:
	if (newfd != -1) {
		close(newfd);
	}
	return saverr;
}

static void
lo_forget_one(struct aio_fsdev *vfsdev, spdk_ino_t ino, uint64_t nlookup)
{
	struct lo_inode *inode;

	inode = lo_inode(vfsdev, ino);
	if (!inode) {
		return;
	}

	SPDK_DEBUGLOG(fsdev_aio, "  forget %" PRIu64 " %" PRIu64 " -%" PRIu64 "\n",
		      ino, inode->refcount, nlookup);

	unref_inode(vfsdev, inode, nlookup);
}

static int
lo_lookup(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int err;
	spdk_ino_t parent_ino = fsdev_io->u_in.lookup.parent_ino;
	char *name = fsdev_io->u_in.lookup.name;

	SPDK_DEBUGLOG(fsdev_aio, "  name %s\n", name);

	/* Don't use is_safe_path_component(), allow "." and ".." for NFS export
	 * support.
	 */
	if (strchr(name, '/')) {
		return EINVAL;
	}

	err = lo_do_lookup(vfsdev, parent_ino, name, &fsdev_io->u_out.lookup.entry);
	if (err) {
		SPDK_DEBUGLOG(fsdev_aio, "lo_do_lookup(%s) failed with err=%d\n", name, err);
		return err;
	}

	return 0;
}

/*
 * Change to uid/gid of caller so that file is created with ownership of caller.
 */
static int
lo_change_cred(const struct lo_cred *new, struct lo_cred *old)
{
	int res;

	old->euid = geteuid();
	old->egid = getegid();

	res = syscall(SYS_setresgid, -1, new->egid, -1);
	if (res == -1) {
		return errno;
	}

	res = syscall(SYS_setresuid, -1, new->euid, -1);
	if (res == -1) {
		int errno_save = errno;

		syscall(SYS_setresgid, -1, old->egid, -1);
		return errno_save;
	}

	return 0;
}

/* Regain Privileges */
static void
lo_restore_cred(struct lo_cred *old)
{
	int res;

	res = syscall(SYS_setresuid, -1, old->euid, -1);
	if (res == -1) {
		SPDK_ERRLOG("seteuid(%u)", old->euid);
	}

	res = syscall(SYS_setresgid, -1, old->egid, -1);
	if (res == -1) {
		SPDK_ERRLOG("setegid(%u)", old->egid);
	}
}

/*
static void
lo_do_readdir(struct spdk_fuse_fsdev_ctx *ctx, struct spdk_fsdev_io *fsdev_io, uint64_t fh,
	      uint32_t size, uint64_t offset, bool plus)*/
static int
lo_readdir(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	struct lo_dirp *d;
	struct lo_inode *dinode;
	spdk_ino_t ino = fsdev_io->u_in.readdir.ino;
	uint64_t fh = fsdev_io->u_in.readdir.fh;
	uint64_t offset = fsdev_io->u_in.readdir.offset;

	dinode = lo_inode(vfsdev, ino);
	if (!dinode) {
		SPDK_ERRLOG("Cannot find inode dor ino=%" PRIu64 "\n", ino);
		return EBADF;
	}

	d = lo_dirp(vfsdev, fh);
	if (!d) {
		SPDK_ERRLOG("Cannot find dirp dor fh=%" PRIu64 "\n", fh);
		return EBADF;
	}

	if (((off_t)offset) != d->offset) {
		seekdir(d->dp, offset);
		d->entry = NULL;
		d->offset = offset;
	}

	while (1) {
		off_t nextoff;
		const char *name;
		int res;

		if (!d->entry) {
			errno = 0;
			d->entry = readdir(d->dp);
			if (!d->entry) {
				if (errno) {  // Error
					res = errno;
					SPDK_ERRLOG("readdir failed with err=%d", res);
					return res;
				} else {  // End of stream
					break;
				}
			}
		}
		nextoff = d->entry->d_off;
		name = d->entry->d_name;

		spdk_ino_t entry_ino = 0;
		struct spdk_fsdev_entry *e = &fsdev_io->u_out.readdir.entry;

		memset(e, 0, sizeof(*e));

		e->attr.st_ino = d->entry->d_ino;
		e->attr.st_mode = d->entry->d_type << 12;

		/* Hide root's parent directory */
		if (dinode == &vfsdev->root && strcmp(name, "..") == 0) {
			e->attr.st_ino = vfsdev->root.key.ino;
			e->attr.st_mode = DT_DIR << 12;
		}

		if (!is_dot_or_dotdot(name)) {
			res = lo_do_lookup(vfsdev, ino, name, e);
			if (res) {
				SPDK_ERRLOG("lo_do_lookup failed with err=%d", res);
				return res;
			}
			entry_ino = e->ino;
		}

		fsdev_io->u_out.readdir.name = name;
		fsdev_io->u_out.readdir.offset = nextoff;

		res = fsdev_io->u_in.readdir.entry_clb(fsdev_io, fsdev_io->internal.caller_ctx);
		if (res) {
			if (entry_ino != 0) {
				lo_forget_one(vfsdev, entry_ino, 1);
			}
			return res;
		}

		d->entry = NULL;
		d->offset = nextoff;
	}

	SPDK_DEBUGLOG(fsdev_aio, "READDIR succeded for %" PRIu64 " (fh=0x%" PRIu64 ")\n",
		      ino, fh);
	return 0;
}

static int
lo_forget(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);

	lo_forget_one(vfsdev, fsdev_io->u_in.forget.ino, fsdev_io->u_in.forget.nlookup);

	return 0;
}

static int
lo_open(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int fd, saverr;
	ssize_t fh;
	char buf[64];
	spdk_ino_t ino = fsdev_io->u_in.open.ino;
	uint32_t flags = fsdev_io->u_in.open.flags;

	SPDK_DEBUGLOG(fsdev_aio, "lo_open(ino=%" PRIu64 ", flags=0x%08" PRIx32 ")\n", ino, flags);

	/* With writeback cache, kernel may send read requests even
	   when userspace opened write-only */
	if (vfsdev->fsdev.opts.writeback_cache_enabled && (flags & O_ACCMODE) == O_WRONLY) {
		flags &= ~O_ACCMODE;
		flags |= O_RDWR;
	}

	/* With writeback cache, O_APPEND is handled by the kernel.
	   This breaks atomicity (since the file may change in the
	   underlying filesystem, so that the kernel's idea of the
	   end of the file isn't accurate anymore). In this example,
	   we just accept that. A more rigorous filesystem may want
	   to return an error here */
	if (vfsdev->fsdev.opts.writeback_cache_enabled && (flags & O_APPEND)) {
		flags &= ~O_APPEND;
	}

	sprintf(buf, "%i", lo_fd(vfsdev, ino));
	fd = openat(vfsdev->proc_self_fd, buf, flags & ~O_NOFOLLOW);
	if (fd == -1) {
		saverr = errno;
		SPDK_ERRLOG("openat(%d, %s, 0x%08" PRIx32 "failed with err=%d)\n",
			    vfsdev->proc_self_fd, buf, flags, saverr);
		return saverr;
	}

	fh = lo_add_fd_mapping(vfsdev, fd);
	if (fh == -1) {
		SPDK_ERRLOG("lo_add_fd_mapping(fd=%d) failed\n", fd);
		close(fd);
		return ENOMEM;
	}

	fsdev_io->u_out.open.fh = fh;

	SPDK_DEBUGLOG(fsdev_aio, "OPEN succeded for %" PRIu64 " (fd=%d, fh=%" PRIu64 ")\n", ino, fd,
		      fh);

	return 0;
}

static int
lo_flush(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	uint64_t fh = fsdev_io->u_in.flush.fh;
	int res, saverr, fd;

	fd = lo_fi_fd(vfsdev, fh);
	if (fd == -1) {
		SPDK_ERRLOG("lo_fi_fd failed for (fh=%" PRIu64 ")\n", fh);
		return EBADF;
	}

	res = close(dup(fd));
	if (res) {
		saverr = errno;
		SPDK_ERRLOG("close(dup(%d)) (fh=%" PRIu64 ") failed with err=%d)\n",
			    fd, fh, saverr);
		return saverr;
	}

	SPDK_DEBUGLOG(fsdev_aio, "FLUSH succeded (fd=%d, fh=%" PRIu64 ")\n",
		      fd, fh);

	return 0;
}

static int
lo_setattr(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int saverr;
	char procname[64];
	struct lo_inode *inode;
	int ifd;
	int res;
	int fd = -1;
	spdk_ino_t ino = fsdev_io->u_in.setattr.ino;
	uint64_t fh = fsdev_io->u_in.setattr.fh;
	uint32_t to_set = fsdev_io->u_in.setattr.to_set;
	struct stat *attr = &fsdev_io->u_in.setattr.attr;

	inode = lo_inode(vfsdev, ino);
	if (!inode) {
		SPDK_ERRLOG("lo_inode failed for (ino=%" PRIu64 ")\n", ino);
		return EBADF;
	}

	ifd = inode->fd;

	/* If fh is invalid we'll report EBADF later */
	if (fh != UINT64_MAX) {
		fd = lo_fi_fd(vfsdev, fh);
	}

	if (to_set & FSDEV_SET_ATTR_MODE) {
		if (fh != UINT64_MAX) {
			res = fchmod(fd, attr->st_mode);
		} else {
			sprintf(procname, "%i", ifd);
			res = fchmodat(vfsdev->proc_self_fd, procname,
				       attr->st_mode, 0);
		}
		if (res == -1) {
			saverr = errno;
			SPDK_ERRLOG("fchmod failed for (ino=%" PRIu64 ", fd=%d)\n", ino, fd);
			return saverr;
		}
	}
	if (to_set & (FSDEV_SET_ATTR_UID | FSDEV_SET_ATTR_GID)) {
		uid_t uid = (to_set & FSDEV_SET_ATTR_UID) ?
			    attr->st_uid : (uid_t) -1;
		gid_t gid = (to_set & FSDEV_SET_ATTR_GID) ?
			    attr->st_gid : (gid_t) -1;

		res = fchownat(ifd, "", uid, gid, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
		if (res == -1) {
			saverr = errno;
			SPDK_ERRLOG("fchownat failed for (ino=%" PRIu64 ", fd=%d)\n", ino, fd);
			return saverr;
		}
	}
	if (to_set & FSDEV_SET_ATTR_SIZE) {
		int truncfd;

		if (fh != UINT64_MAX) {
			truncfd = fd;
		} else {
			sprintf(procname, "%i", ifd);
			truncfd = openat(vfsdev->proc_self_fd, procname, O_RDWR);
			if (truncfd < 0) {
				saverr = errno;
				SPDK_ERRLOG("openat failed for (ino=%" PRIu64 ", fd=%d)\n", ino, fd);
				return saverr;
			}
		}

		res = ftruncate(truncfd, attr->st_size);
		if (fh == UINT64_MAX) {
			saverr = errno;
			close(truncfd);
			errno = saverr;
		}
		if (res == -1) {
			saverr = errno;
			SPDK_ERRLOG("ftruncate failed for (ino=%" PRIu64 ", fd=%d, size=%" PRIu64")\n",
				    ino, fd, attr->st_size);
			return saverr;
		}
	}
	if (to_set & (FSDEV_SET_ATTR_ATIME | FSDEV_SET_ATTR_MTIME)) {
		struct timespec tv[2];

		tv[0].tv_sec = 0;
		tv[1].tv_sec = 0;
		tv[0].tv_nsec = UTIME_OMIT;
		tv[1].tv_nsec = UTIME_OMIT;

		if (to_set & FSDEV_SET_ATTR_ATIME_NOW) {
			tv[0].tv_nsec = UTIME_NOW;
		} else if (to_set & FSDEV_SET_ATTR_ATIME) {
			tv[0] = attr->st_atim;
		}

		if (to_set & FSDEV_SET_ATTR_MTIME_NOW) {
			tv[1].tv_nsec = UTIME_NOW;
		} else if (to_set & FSDEV_SET_ATTR_MTIME) {
			tv[1] = attr->st_mtim;
		}

		if (fh != UINT64_MAX) {
			res = futimens(fd, tv);
		} else {
			res = utimensat_empty(vfsdev, inode, tv);
		}
		if (res == -1) {
			saverr = errno;
			SPDK_ERRLOG("futimens/utimensat_empty failed for (ino=%" PRIu64 ", fd=%d)\n",
				    ino, fd);
			return saverr;
		}
	}

	res = lo_fill_getattr(vfsdev, ino,  &fsdev_io->u_out.setattr.attr);
	if (res) {
		SPDK_ERRLOG("lo_fill_getattr failed for ino=%" PRIu64 " (err=%d)\n", ino, res);
		return res;
	}

	fsdev_io->u_out.setattr.attr_timeout_ms = DEFAULT_TIMEOUT_MS;

	SPDK_DEBUGLOG(fsdev_aio, "SETATTR succeded (ifd=%d, fh=%" PRIu64 ")\n",
		      ifd, fh);

	return 0;
}

static int
lo_create(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int fd;
	ssize_t fh = 0;
	int err;
	spdk_ino_t parent_ino = fsdev_io->u_in.create.parent_ino;
	const char *name = fsdev_io->u_in.create.name;
	uint32_t mode = fsdev_io->u_in.create.mode;
	uint32_t flags = fsdev_io->u_in.create.flags;
	uint32_t umask = fsdev_io->u_in.create.umask;
	struct lo_cred old_cred, new_cred = {
		.euid = fsdev_io->u_in.create.euid,
		.egid = fsdev_io->u_in.create.egid,
	};

	UNUSED(umask);

	SPDK_DEBUGLOG(fsdev_aio, "lo_create(parent=%" PRIu64 ", name=%s)\n",
		      parent_ino, name);

	if (!is_safe_path_component(name)) {
		SPDK_ERRLOG("CREATE: %s not a safe component\n", name);
		return EINVAL;
	}

	err = lo_change_cred(&new_cred, &old_cred);
	if (err) {
		SPDK_ERRLOG("CREATE: cannot change credentials\n");
		return err;
	}

	/* Promote O_WRONLY to O_RDWR. Otherwise later mmap(PROT_WRITE) fails */
	if ((flags & O_ACCMODE) == O_WRONLY) {
		flags &= ~O_ACCMODE;
		flags |= O_RDWR;
	}

	fd = openat(lo_fd(vfsdev, parent_ino), name, (flags | O_CREAT) & ~O_NOFOLLOW, mode);
	err = fd == -1 ? errno : 0;
	lo_restore_cred(&old_cred);

	if (err) {
		SPDK_ERRLOG("CREATE: openat failed with %d\n", err);
		return err;
	}

	fh = lo_add_fd_mapping(vfsdev, fd);
	if (fh == -1) {
		close(fd);
		SPDK_ERRLOG("CREATE: cannot add mapping\n");
		return EINVAL;
	}

	err = lo_do_lookup(vfsdev, parent_ino, name, &fsdev_io->u_out.create.entry);
	if (err) {
		SPDK_ERRLOG("CREATE: loockup failed with %d\n", err);
		return err;
	}

	SPDK_DEBUGLOG(fsdev_aio, "CREATE: succeded (name=%s, fh=%" PRIu64 ")\n", name, (uint64_t)fh);

	fsdev_io->u_out.create.fh = fh;

	return 0;
}

static int
lo_release(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int fd;
	spdk_ino_t ino = fsdev_io->u_in.release.ino;
	uint64_t fh = fsdev_io->u_in.release.fh;

	UNUSED(ino);

	fd = lo_fi_fd(vfsdev, fh);

	pthread_mutex_lock(&vfsdev->mutex);
	lo_map_remove(&vfsdev->fd_map, fh);
	pthread_mutex_unlock(&vfsdev->mutex);

	close(fd);
	SPDK_DEBUGLOG(fsdev_aio, "RELEASE succeded (fd=%d, fh=%" PRIu64 ")\n",
		      fd, fh);
	return 0;
}

static void
lo_read_cb(void *ctx, uint32_t data_size, int error)
{
	struct spdk_fsdev_io *fsdev_io = ctx;
	struct aio_fsdev_io *vfsdev_io = fsdev_to_aio_io(fsdev_io);

	if (vfsdev_io->aio) {
		TAILQ_REMOVE(&vfsdev_io->ch->ios_in_progress, vfsdev_io, link);
	}

	fsdev_io->u_out.read.data_size = data_size;

	spdk_fsdev_io_complete(fsdev_io, error);
}

static int
lo_read(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	struct aio_io_channel *ch = spdk_io_channel_get_ctx(_ch);
	struct aio_fsdev_io *vfsdev_io = fsdev_to_aio_io(fsdev_io);
	int fd;
	spdk_ino_t ino = fsdev_io->u_in.read.ino;
	uint64_t fh = fsdev_io->u_in.read.fh;
	size_t size = fsdev_io->u_in.read.size;
	uint64_t offs = fsdev_io->u_in.read.offs;
	uint32_t flags = fsdev_io->u_in.read.flags;
	struct iovec *outvec = fsdev_io->u_in.read.iov;
	uint32_t outcnt =  fsdev_io->u_in.read.iovcnt;

	/* we don't suport the memory domains at the moment */
	assert(!fsdev_io->u_in.read.opts || !fsdev_io->u_in.read.opts->memory_domain);

	UNUSED(ino);
	UNUSED(flags);

	if (!outcnt || !outvec) {
		SPDK_ERRLOG("bad outvec: iov=%p outcnt=%" PRIu32 "\n", outvec, outcnt);
		return EINVAL;
	}

	fd = lo_fi_fd(vfsdev, fh);
	if (fd == -1) {
		SPDK_ERRLOG("lo_fi_fd failed for (fh=%" PRIu64 ")\n", fh);
		return EBADF;
	}

	vfsdev_io->aio = spdk_aio_mgr_read(ch->mgr, lo_read_cb, fsdev_io, fd, offs, size, outvec,
					   outcnt);
	if (vfsdev_io->aio) {
		vfsdev_io->ch = ch;
		TAILQ_INSERT_TAIL(&ch->ios_in_progress, vfsdev_io, link);
	}

	return OP_STATUS_ASYNC;
}

static void
lo_write_cb(void *ctx, uint32_t data_size, int error)
{
	struct spdk_fsdev_io *fsdev_io = ctx;
	struct aio_fsdev_io *vfsdev_io = fsdev_to_aio_io(fsdev_io);

	if (vfsdev_io->aio) {
		TAILQ_REMOVE(&vfsdev_io->ch->ios_in_progress, vfsdev_io, link);
	}

	fsdev_io->u_out.write.data_size = data_size;

	spdk_fsdev_io_complete(fsdev_io, error);
}

static int
lo_write(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	struct aio_io_channel *ch = spdk_io_channel_get_ctx(_ch);
	struct aio_fsdev_io *vfsdev_io = fsdev_to_aio_io(fsdev_io);
	int fd;
	spdk_ino_t ino = fsdev_io->u_in.write.ino;
	uint64_t fh = fsdev_io->u_in.write.fh;
	size_t size = fsdev_io->u_in.write.size;
	uint64_t offs = fsdev_io->u_in.write.offs;
	uint32_t flags = fsdev_io->u_in.write.flags;
	const struct iovec *invec = fsdev_io->u_in.write.iov;
	uint32_t incnt =  fsdev_io->u_in.write.iovcnt;

	 /* we don't suport the memory domains at the moment */
	assert(!fsdev_io->u_in.write.opts || !fsdev_io->u_in.write.opts->memory_domain);

	UNUSED(ino);
	UNUSED(flags);

	if (!incnt || !invec) { /* there should be at least one iovec with data */
		SPDK_ERRLOG("bad invec: iov=%p cnt=%" PRIu32 "\n", invec, incnt);
		return EINVAL;
	}

	fd = lo_fi_fd(vfsdev, fh);
	if (fd == -1) {
		SPDK_ERRLOG("lo_fi_fd failed for (fh=%" PRIu64 ")\n", fh);
		return EBADF;
	}

	vfsdev_io->aio = spdk_aio_mgr_write(ch->mgr, lo_write_cb, fsdev_io,
					    fd, offs, size, invec, incnt);
	if (vfsdev_io->aio) {
		vfsdev_io->ch = ch;
		TAILQ_INSERT_TAIL(&ch->ios_in_progress, vfsdev_io, link);
	}

	return OP_STATUS_ASYNC;
}

static int
lo_readlink(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int res;
	char *buf;
	spdk_ino_t ino = fsdev_io->u_in.readlink.ino;
	int fd = lo_fd(vfsdev, ino);

	buf = malloc(PATH_MAX + 1);
	if (!buf) {
		SPDK_ERRLOG("malloc(%zu) failed\n", (size_t)(PATH_MAX + 1));
		return ENOMEM;
	}

	res = readlinkat(fd, "", buf, PATH_MAX + 1);
	if (res == -1) {
		int saverr = errno;
		SPDK_ERRLOG("readlinkat(%d) failed with %d\n", fd, saverr);
		free(buf);
		return saverr;
	}

	if (((uint32_t)res) == PATH_MAX + 1) {
		SPDK_ERRLOG("buffer is too short\n");
		free(buf);
		return ENAMETOOLONG;
	}

	buf[res] = 0;
	fsdev_io->u_out.readlink.linkname = buf;

	return 0;
}

static int
lo_statfs(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int res;
	spdk_ino_t ino = fsdev_io->u_in.statfs.ino;

	res = fstatvfs(lo_fd(vfsdev, ino), &fsdev_io->u_out.statfs.stbuf);
	if (res == -1) {
		int saverr = errno;
		SPDK_ERRLOG("fstatvfs failed with %d\n", saverr);
		return saverr;
	}

	return 0;
}

static int
lo_mknod_symlink(struct spdk_fsdev_io *fsdev_io, spdk_ino_t parent_ino, const char *name,
		 mode_t mode, dev_t rdev, const char *link, uid_t euid, gid_t egid, struct spdk_fsdev_entry *e)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int res;
	int saverr;
	struct lo_inode *dir;
	struct lo_cred old_cred, new_cred = {
		.euid = euid,
		.egid = egid,
	};

	if (!is_safe_path_component(name)) {
		SPDK_ERRLOG("%s isn'h safe\n", name);
		return EINVAL;
	}

	dir = lo_inode(vfsdev, parent_ino);
	if (!dir) {
		SPDK_ERRLOG("cannot find parent dir\n");
		return EBADF;
	}

	res = lo_change_cred(&new_cred, &old_cred);
	if (res) {
		SPDK_ERRLOG("cannot change cred (err=%d)\n", res);
		return res;
	}

	if (S_ISDIR(mode)) {
		res = mkdirat(dir->fd, name, mode);
	} else if (S_ISLNK(mode)) {
		res = symlinkat(link, dir->fd, name);
	} else {
		res = mknodat(dir->fd, name, mode, rdev);
	}
	saverr = errno;

	lo_restore_cred(&old_cred);

	if (res == -1) {
		SPDK_ERRLOG("cannot mkdirat/symlinkat/mknodat (err=%d)\n", saverr);
		return saverr;
	}

	res = lo_do_lookup(vfsdev, parent_ino, name, e);
	if (res) {
		SPDK_ERRLOG("lookup failed (err=%d)\n", res);
		return res;
	}

	SPDK_DEBUGLOG(fsdev_aio, "  %" PRIu64 "/%s -> %" PRIu64 "\n",
		      parent_ino, name, e->ino);

	return 0;
}

static int
lo_mknod(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	spdk_ino_t parent_ino = fsdev_io->u_in.mknod.parent_ino;
	char *name = fsdev_io->u_in.mknod.name;
	mode_t mode = fsdev_io->u_in.mknod.mode;
	dev_t rdev = fsdev_io->u_in.mknod.rdev;
	uid_t euid = fsdev_io->u_in.mknod.euid;
	gid_t egid = fsdev_io->u_in.mknod.egid;
	struct spdk_fsdev_entry *e = &fsdev_io->u_out.mknod.entry;

	return lo_mknod_symlink(fsdev_io, parent_ino, name, mode, rdev, NULL, euid, egid, e);
}

static int
lo_mkdir(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	spdk_ino_t parent_ino = fsdev_io->u_in.mkdir.parent_ino;
	char *name = fsdev_io->u_in.mkdir.name;
	mode_t mode = fsdev_io->u_in.mkdir.mode;
	uid_t euid = fsdev_io->u_in.mkdir.euid;
	gid_t egid = fsdev_io->u_in.mkdir.egid;
	struct spdk_fsdev_entry *e = &fsdev_io->u_out.mkdir.entry;

	return lo_mknod_symlink(fsdev_io, parent_ino, name, S_IFDIR | mode, 0, NULL, euid, egid, e);
}

static int
lo_symlink(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	spdk_ino_t parent_ino = fsdev_io->u_in.symlink.parent_ino;
	char *target = fsdev_io->u_in.symlink.target;
	char *linkpath = fsdev_io->u_in.symlink.linkpath;
	uid_t euid = fsdev_io->u_in.symlink.euid;
	gid_t egid = fsdev_io->u_in.symlink.egid;
	struct spdk_fsdev_entry *e = &fsdev_io->u_out.symlink.entry;

	return lo_mknod_symlink(fsdev_io, parent_ino, target, S_IFLNK, 0, linkpath, euid, egid, e);
}

static int
lo_unlink(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int res, saverr;
	struct lo_inode *inode;
	spdk_ino_t parent_ino = fsdev_io->u_in.unlink.parent_ino;
	char *name = fsdev_io->u_in.unlink.name;

	if (!is_safe_path_component(name)) {
		SPDK_ERRLOG("%s isn't safe\n", name);
		return EINVAL;
	}

	inode = lookup_name(vfsdev, parent_ino, name);
	if (!inode) {
		SPDK_ERRLOG("can't find '%s'\n", name);
		return EIO;
	}

	res = unlinkat(lo_fd(vfsdev, parent_ino), name, 0);
	saverr = errno;
	unref_inode(vfsdev, inode, 1);

	if (res == -1) {
		SPDK_ERRLOG("unlinkat(%s) failed (err=%d)\n", name, saverr);
		return saverr;
	}

	return 0;
}

static int
lo_rmdir(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int res, saverr;
	struct lo_inode *inode;
	spdk_ino_t parent_ino = fsdev_io->u_in.rmdir.parent_ino;
	char *name = fsdev_io->u_in.rmdir.name;


	if (!is_safe_path_component(name)) {
		SPDK_ERRLOG("%s isn't safe\n", name);
		return EINVAL;
	}

	inode = lookup_name(vfsdev, parent_ino, name);
	if (!inode) {
		SPDK_ERRLOG("can't find '%s'\n", name);
		return EIO;
	}

	res = unlinkat(lo_fd(vfsdev, parent_ino), name, AT_REMOVEDIR);
	saverr = errno;
	unref_inode(vfsdev, inode, 1);

	if (res == -1) {
		SPDK_ERRLOG("unlinkat(%s) failed (err=%d)\n", name, saverr);
		return saverr;
	}

	return 0;
}

static int
lo_rename(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int res, saverr;
	struct lo_inode *oldinode;
	struct lo_inode *newinode;
	spdk_ino_t parent_ino = fsdev_io->u_in.rename.parent_ino;
	char *name = fsdev_io->u_in.rename.name;
	spdk_ino_t new_parent_ino = fsdev_io->u_in.rename.new_parent_ino;
	char *new_name = fsdev_io->u_in.rename.new_name;
	uint32_t flags = fsdev_io->u_in.rename.flags;

	if (!is_safe_path_component(name)) {
		SPDK_ERRLOG("name '%s' isn't safe\n", name);
		return EINVAL;
	}

	if (!is_safe_path_component(new_name)) {
		SPDK_ERRLOG("newname '%s' isn't safe\n", new_name);
		return EINVAL;
	}

	oldinode = lookup_name(vfsdev, parent_ino, name);
	if (!oldinode) {
		SPDK_ERRLOG("can't find '%s'\n", name);
		return EIO;
	}

	newinode = lookup_name(vfsdev, new_parent_ino, new_name);

	saverr = 0;
	if (flags) {
#ifndef SYS_renameat2
		SPDK_ERRLOG("flags are not supported\n");
		return EPROTONSUPOPORT;
#else
		res = syscall(SYS_renameat2, lo_fd(vfsdev, parent_ino), name, lo_fd(vfsdev, new_parent_ino),
			      new_name, flags);
		if (res == -1 && errno == ENOSYS) {
			SPDK_ERRLOG("SYS_renameat2 returned ENOSYS\n");
			saverr = EINVAL;
		} else if (res == -1) {
			saverr = errno;
			SPDK_ERRLOG("SYS_renameat2 failed (err=%d))\n", saverr);
		}
#endif
	} else {
		res = renameat(lo_fd(vfsdev, parent_ino), name, lo_fd(vfsdev, new_parent_ino), new_name);
		if (res == -1) {
			saverr = errno;
			SPDK_ERRLOG("renameat failed (err=%d)\n", saverr);
		}
	}

	unref_inode(vfsdev, oldinode, 1);
	unref_inode(vfsdev, newinode, 1);

	return saverr;
}

static int
linkat_empty_nofollow(struct aio_fsdev *vfsdev, struct lo_inode *inode,
		      int dfd, const char *name)
{
	int res;
	struct lo_inode *parent;
	char path[PATH_MAX];

	if (inode->is_symlink) {
		res = linkat(inode->fd, "", dfd, name, AT_EMPTY_PATH);
		if (res == -1 && (errno == ENOENT || errno == EINVAL)) {
			/* Sorry, no race free way to hard-link a symlink. */
			goto fallback;
		}
		return res;
	}

	sprintf(path, "%i", inode->fd);

	return linkat(vfsdev->proc_self_fd, path, dfd, name, AT_SYMLINK_FOLLOW);

fallback:
	res = lo_parent_and_name(vfsdev, inode, path, &parent);
	if (res != -1) {
		res = linkat(parent->fd, path, dfd, name, 0);
	}

	return res;
}

static int
lo_link(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int res;
	struct lo_inode *inode;
	int saverr;
	spdk_ino_t ino = fsdev_io->u_in.link.ino;
	spdk_ino_t new_parent_ino = fsdev_io->u_in.link.new_parent_ino;
	char *name = fsdev_io->u_in.link.name;
	struct spdk_fsdev_entry *e = &fsdev_io->u_out.link.entry;

	if (!is_safe_path_component(name)) {
		SPDK_ERRLOG("%s is not a safe component\n", name);
		return EINVAL;
	}

	inode = lo_inode(vfsdev, ino);
	if (!inode) {
		SPDK_ERRLOG("Cannot find inode with id=%" PRIu64 "\n", ino);
		return EBADF;
	}

	memset(e, 0, sizeof(*e));
	e->attr_timeout_ms = DEFAULT_TIMEOUT_MS;
	e->entry_timeout_ms = DEFAULT_TIMEOUT_MS;

	res = linkat_empty_nofollow(vfsdev, inode, lo_fd(vfsdev, new_parent_ino), name);
	if (res == -1) {
		saverr = errno;
		SPDK_ERRLOG("linkat_empty_nofollow failed (errno=%d)\n", saverr);
		return saverr;
	}

	res = fstatat(inode->fd, "", &e->attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1) {
		saverr = errno;
		SPDK_ERRLOG("fstatat failed (errno=%d)" PRIu64 "\n", saverr);
		return saverr;
	}

	pthread_mutex_lock(&vfsdev->mutex);
	inode->refcount++;
	pthread_mutex_unlock(&vfsdev->mutex);
	e->ino = inode->fuse_ino;

	SPDK_DEBUGLOG(fsdev_aio, "  %" PRIu64 "/%s -> %" PRIu64  "\n",
		      new_parent_ino, name, e->ino);

	return 0;
}

static int
lo_fsync(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int res, saverr;
	int fd;
	char *buf;
	spdk_ino_t ino = fsdev_io->u_in.fsync.ino;
	uint64_t fh = fsdev_io->u_in.fsync.fh;
	bool datasync = fsdev_io->u_in.fsync.datasync;

	SPDK_DEBUGLOG(fsdev_aio, "lo_fsync(ino=%" PRIu64 " fh=%" PRIu64 " datasync=%d)\n",
		      ino, fh, datasync);

	if (fh == (uint64_t) -1) {
		res = asprintf(&buf, "%i", lo_fd(vfsdev, ino));
		if (res == -1) {
			saverr = errno;
			SPDK_ERRLOG("asprintf failed (errno=%d)\n", saverr);
			return saverr;
		}

		fd = openat(vfsdev->proc_self_fd, buf, O_RDWR);
		saverr = errno;
		free(buf);
		if (fd == -1) {
			SPDK_ERRLOG("openat failed (errno=%d)\n", saverr);
			return saverr;
		}
	} else {
		fd = lo_fi_fd(vfsdev, fh);
	}

	if (datasync) {
		res = fdatasync(fd);
	} else {
		res = fsync(fd);
	}

	saverr = errno;
	if (fh == (uint64_t) -1) {
		close(fd);
	}

	if (res == -1) {
		SPDK_ERRLOG("fdatasync/fsync failed (errno=%d)\n", saverr);
		return saverr;
	}

	return 0;
}

static int
lo_setxattr(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	char procname[64];
	struct lo_inode *inode;
	ssize_t ret;
	int saverr;
	int fd = -1;
	spdk_ino_t ino = fsdev_io->u_in.setxattr.ino;
	char *name = fsdev_io->u_in.setxattr.name;
	char *value = fsdev_io->u_in.setxattr.value;
	uint32_t size = fsdev_io->u_in.setxattr.size;
	uint32_t flags = fsdev_io->u_in.setxattr.flags;

	if (!vfsdev->xattr_enabled) {
		SPDK_INFOLOG(fsdev_aio, "xattr is disabled by config\n");
		return ENOSYS;
	}

	inode = lo_inode(vfsdev, ino);
	if (!inode) {
		SPDK_ERRLOG("cannot find inode for id=%" PRIu64 "\n", ino);
		return EBADF;
	}

	SPDK_DEBUGLOG(fsdev_aio, "lo_setxattr(ino=%" PRIu64 ", name=%s value=%s size=%" PRIu32 ")\n",
		      ino, name, value, size);

	if (inode->is_symlink) {
		/* Sorry, no race free way to removexattr on symlink. */
		SPDK_ERRLOG("cannot set xattr for symlink\n");
		return EPERM;
	}

	sprintf(procname, "%i", inode->fd);
	fd = openat(vfsdev->proc_self_fd, procname, O_RDWR);
	if (fd < 0) {
		saverr = errno;
		SPDK_ERRLOG("openat failed with errno=%d\n", saverr);
		return saverr;
	}

	ret = fsetxattr(fd, name, value, size, flags);
	saverr = errno;
	close(fd);
	if (ret == -1) {
		if (saverr == ENOTSUP) {
			SPDK_INFOLOG(fsdev_aio, "flistxattr: extended attributes are not supported or disabled\n");
		} else {
			SPDK_ERRLOG("flistxattr failed with errno=%d\n", saverr);
		}
		return saverr;
	}

	return 0;
}

static int
lo_getxattr(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	char procname[64];
	struct lo_inode *inode;
	ssize_t ret;
	int saverr;
	int fd = -1;
	spdk_ino_t ino = fsdev_io->u_in.getxattr.ino;
	char *name = fsdev_io->u_in.getxattr.name;
	char *buffer = fsdev_io->u_in.getxattr.buffer;
	size_t size = fsdev_io->u_in.getxattr.size;

	if (!vfsdev->xattr_enabled) {
		SPDK_INFOLOG(fsdev_aio, "xattr is disabled by config\n");
		return ENOSYS;
	}

	inode = lo_inode(vfsdev, ino);
	if (!inode) {
		SPDK_ERRLOG("cannot find inode for id=%" PRIu64 "\n", ino);
		return EBADF;
	}

	SPDK_DEBUGLOG(fsdev_aio, "lo_getxattr(ino=%" PRIu64 ", name=%s size=%zu)\n",
		      ino, name, size);

	if (inode->is_symlink) {
		/* Sorry, no race free way to getxattr on symlink. */
		SPDK_ERRLOG("cannot get xattr for symlink\n");
		return EPERM;
	}

	sprintf(procname, "%i", inode->fd);
	fd = openat(vfsdev->proc_self_fd, procname, O_RDWR);
	if (fd < 0) {
		saverr = errno;
		SPDK_ERRLOG("openat failed with errno=%d\n", saverr);
		return saverr;
	}

	ret = fgetxattr(fd, name, buffer, size);
	saverr = errno;
	close(fd);
	if (ret == -1) {
		if (saverr == ENODATA) {
			SPDK_INFOLOG(fsdev_aio, "fgetxattr: no extended attribute '%s' found\n", name);
		} else if (saverr == ENOTSUP) {
			SPDK_INFOLOG(fsdev_aio, "fgetxattr: extended attributes are not supported or disabled\n");
		} else {
			SPDK_ERRLOG("fgetxattr failed with errno=%d\n", saverr);
		}
		return saverr;
	}

	fsdev_io->u_out.getxattr.value_size = ret;
	return 0;
}

static int
lo_listxattr(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	char procname[64];
	struct lo_inode *inode;
	ssize_t ret;
	int saverr;
	int fd = -1;
	spdk_ino_t ino = fsdev_io->u_in.listxattr.ino;
	char *buffer = fsdev_io->u_in.listxattr.buffer;
	size_t size = fsdev_io->u_in.listxattr.size;

	if (!vfsdev->xattr_enabled) {
		SPDK_INFOLOG(fsdev_aio, "xattr is disabled by config\n");
		return ENOSYS;
	}

	inode = lo_inode(vfsdev, ino);
	if (!inode) {
		SPDK_ERRLOG("cannot find inode for id=%" PRIu64 "\n", ino);
		return EBADF;
	}

	SPDK_DEBUGLOG(fsdev_aio, "lo_listxattr(ino=%" PRIu64 " size=%zu)\n",
		      ino, size);

	if (inode->is_symlink) {
		/* Sorry, no race free way to listxattr on symlink. */
		SPDK_ERRLOG("cannot list xattr for symlink\n");
		return EPERM;
	}

	sprintf(procname, "%i", inode->fd);
	fd = openat(vfsdev->proc_self_fd, procname, O_RDONLY);
	if (fd < 0) {
		saverr = errno;
		SPDK_ERRLOG("openat failed with errno=%d\n", saverr);
		return saverr;
	}

	ret = flistxattr(fd, buffer, size);
	saverr = errno;
	close(fd);
	if (ret == -1) {
		if (saverr == ENOTSUP) {
			SPDK_INFOLOG(fsdev_aio, "flistxattr: extended attributes are not supported or disabled\n");
		} else {
			SPDK_ERRLOG("flistxattr failed with errno=%d\n", saverr);
		}
		return saverr;
	}

	fsdev_io->u_out.listxattr.data_size = ret;
	fsdev_io->u_out.listxattr.size_only = (size == 0);
	return 0;
}

static int
lo_removexattr(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	char procname[64];
	struct lo_inode *inode;
	ssize_t ret;
	int saverr;
	int fd = -1;
	spdk_ino_t ino = fsdev_io->u_in.removexattr.ino;
	char *name = fsdev_io->u_in.removexattr.name;

	if (!vfsdev->xattr_enabled) {
		SPDK_INFOLOG(fsdev_aio, "xattr is disabled by config\n");
		return ENOSYS;
	}

	inode = lo_inode(vfsdev, ino);
	if (!inode) {
		SPDK_ERRLOG("cannot find inode for id=%" PRIu64 "\n", ino);
		return EBADF;
	}

	SPDK_DEBUGLOG(fsdev_aio, "lo_removexattr(ino=%" PRIu64 " name=%s\n", ino, name);

	if (inode->is_symlink) {
		/* Sorry, no race free way to setxattr on symlink. */
		SPDK_ERRLOG("cannot list xattr for symlink\n");
		return EPERM;
	}

	sprintf(procname, "%i", inode->fd);
	fd = openat(vfsdev->proc_self_fd, procname, O_RDONLY);
	if (fd < 0) {
		saverr = errno;
		SPDK_ERRLOG("openat failed with errno=%d\n", saverr);
		return saverr;
	}

	ret = fremovexattr(fd, name);
	saverr = errno;
	close(fd);
	if (ret == -1) {
		if (saverr == ENODATA) {
			SPDK_INFOLOG(fsdev_aio, "fremovexattr: no extended attribute '%s' found\n", name);
		} else if (saverr == ENOTSUP) {
			SPDK_INFOLOG(fsdev_aio, "fremovexattr: extended attributes are not supported or disabled\n");
		} else {
			SPDK_ERRLOG("fremovexattr failed with errno=%d\n", saverr);
		}
		return saverr;
	}

	return 0;
}

static int
lo_fsyncdir(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int res;
	struct lo_dirp *d;
	int fd;
	int saverr = 0;
	spdk_ino_t ino = fsdev_io->u_in.fsyncdir.ino;
	uint64_t fh = fsdev_io->u_in.fsyncdir.fh;
	bool datasync = fsdev_io->u_in.fsyncdir.datasync;

	UNUSED(ino);

	d = lo_dirp(vfsdev, fh);
	if (!d) {
		SPDK_ERRLOG("lo_dirp failed for fh=%" PRIu64 "\n", fh);
		return EBADF;
	}

	fd = dirfd(d->dp);
	if (datasync) {
		res = fdatasync(fd);
	} else {
		res = fsync(fd);
	}

	if (res == -1) {
		saverr = errno;
		SPDK_ERRLOG("%s failed for fd=%d (fh=%" PRIu64 ") with err=%d\n",
			    datasync ? "fdatasync" : "fsync", fd, fh, saverr);
		return saverr;
	}

	return 0;
}

static int
lo_flock(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int fd;
	int res;
	int saverr = 0;
	spdk_ino_t ino = fsdev_io->u_in.flock.ino;
	uint64_t fh = fsdev_io->u_in.flock.fh;
	int operation = fsdev_io->u_in.flock.operation;

	UNUSED(ino);

	fd = lo_fi_fd(vfsdev, fh);
	if (fd == -1) {
		SPDK_ERRLOG("lo_fi_fd failed for (fh=%" PRIu64 ")\n", fh);
		return EBADF;
	}

	res = flock(fd, operation | LOCK_NB);
	if (res == -1) {
		saverr = errno;
		SPDK_ERRLOG("flock failed for fd=%d (fh=%" PRIu64 ") with err=%d\n", fd, fh, saverr);
		return saverr;
	}

	return 0;
}

static int
lo_fallocate(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int err;
	int fd;
	spdk_ino_t ino = fsdev_io->u_in.fallocate.ino;
	uint64_t fh = fsdev_io->u_in.fallocate.fh;
	uint32_t mode = fsdev_io->u_in.fallocate.mode;
	uint64_t offset  = fsdev_io->u_in.fallocate.offset;
	uint64_t length = fsdev_io->u_in.fallocate.length;

	UNUSED(ino);

	if (mode) {
		SPDK_ERRLOG("non-zero mode is not suppored\n");
		return EOPNOTSUPP;
	}

	fd = lo_fi_fd(vfsdev, fh);
	if (fd == -1) {
		SPDK_ERRLOG("lo_fi_fd failed for (fh=%" PRIu64 ")\n", fh);
		return EBADF;
	}

	err = posix_fallocate(fd, offset, length);
	if (err) {
		SPDK_ERRLOG("posix_fallocate failed for fd=%d (fh=%" PRIu64 ") with err=%d\n",
			    fd, fh, err);
	}

	return err;
}

static int
lo_copy_file_range(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
#ifdef SPDK_CONFIG_COPY_FILE_RANGE
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev_io->fsdev);
	int in_fd, out_fd;
	ssize_t res;
	int saverr = 0;
	spdk_ino_t ino_in = fsdev_io->u_in.copy_file_range.ino_in;
	uint64_t fh_in = fsdev_io->u_in.copy_file_range.fh_in;
	off_t off_in = fsdev_io->u_in.copy_file_range.off_in;
	spdk_ino_t ino_out = fsdev_io->u_in.copy_file_range.ino_out;
	uint64_t fh_out = fsdev_io->u_in.copy_file_range.fh_out;
	off_t off_out = fsdev_io->u_in.copy_file_range.off_out;
	size_t len = fsdev_io->u_in.copy_file_range.len;
	uint32_t flags = fsdev_io->u_in.copy_file_range.flags;

	UNUSED(ino_in);
	UNUSED(ino_out);

	in_fd = lo_fi_fd(vfsdev, fh_in);
	out_fd = lo_fi_fd(vfsdev, fh_out);

	SPDK_DEBUGLOG(fsdev_aio, "lo_copy_file_range(fh_in=%" PRIu64 "/fd=%d, off_in=%" PRIu64
		      ", fh_out=%" PRIu64 "/fd=%d, off_out=%" PRIu64
		      ", len=%zu, flags=0x%" PRIx32 "\n",
		      fh_in, in_fd, off_in, fh_out, out_fd, off_out, len, flags);

	res = copy_file_range(in_fd, &off_in, out_fd, &off_out, len, flags);
	if (res < 0) {
		saverr = errno;
		SPDK_ERRLOG("copy_file_range failed with err=%d\n", saverr);
		return saverr;
	}

	return 0;
#else
	return ENOSYS;
#endif
}

static int
lo_abort(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
	struct aio_io_channel *ch = spdk_io_channel_get_ctx(_ch);
	struct aio_fsdev_io *vfsdev_io;
	uint64_t unique_to_abort = fsdev_io->u_in.abort.unique_to_abort;

	TAILQ_FOREACH(vfsdev_io, &ch->ios_in_progress, link) {
		struct spdk_fsdev_io *_fsdev_io = aio_to_fsdev_io(vfsdev_io);
		if (spdk_fsdev_io_get_unuqie(_fsdev_io) == unique_to_abort) {
			spdk_aio_mgr_cancel(ch->mgr, vfsdev_io->aio);
			return 0;
		}
	}

	return 0;
}

static int
aio_io_poll(void *arg)
{
	struct aio_io_channel *ch = arg;

	spdk_aio_mgr_poll(ch->mgr);

	return SPDK_POLLER_IDLE;
}

static int
aio_fsdev_create_cb(void *io_device, void *ctx_buf)
{
	struct aio_io_channel *ch = ctx_buf;
	struct spdk_thread *thread = spdk_get_thread();

	ch->mgr = spdk_aio_mgr_create(MAX_AIOS);
	if (!ch->mgr) {
		SPDK_ERRLOG("aoi manager init for failed (thread=%s)\n", spdk_thread_get_name(thread));
		return ENOMEM;
	}

	ch->poller = SPDK_POLLER_REGISTER(aio_io_poll, ch, 0);
	TAILQ_INIT(&ch->ios_in_progress);

	SPDK_DEBUGLOG(fsdev_aio, "Created aio fsdev IO channel: thread %s, thread id %" PRIu64
		      "\n",
		      spdk_thread_get_name(thread), spdk_thread_get_id(thread));
	return 0;
}

static void
aio_fsdev_destroy_cb(void *io_device, void *ctx_buf)
{
	struct aio_io_channel *ch = ctx_buf;
	struct spdk_thread *thread = spdk_get_thread();

	UNUSED(thread);

	spdk_poller_unregister(&ch->poller);
	spdk_aio_mgr_delete(ch->mgr);

	SPDK_DEBUGLOG(fsdev_aio, "Destroyed aio fsdev IO channel: thread %s, thread id %" PRIu64
		      "\n",
		      spdk_thread_get_name(thread), spdk_thread_get_id(thread));
}

static int
fsdev_aio_initialize(void)
{
	/*
	 * We need to pick some unique address as our "io device" - so just use the
	 *  address of the global tailq.
	 */
	spdk_io_device_register(&g_aio_fsdev_head,
				aio_fsdev_create_cb, aio_fsdev_destroy_cb,
				sizeof(struct aio_io_channel), "aio_fsdev");

	return 0;
}

static void
_fsdev_aio_finish_cb(void *arg)
{
	/* @todo: handle async module fini */
	/* spdk_fsdev_module_fini_done(); */
}

static void
fsdev_aio_finish(void)
{
	spdk_io_device_unregister(&g_aio_fsdev_head, _fsdev_aio_finish_cb);
}

static int
fsdev_aio_get_ctx_size(void)
{
	return sizeof(struct aio_fsdev_io);
}

static struct spdk_fsdev_module aio_fsdev_module = {
	.name = "aio",
	.module_init = fsdev_aio_initialize,
	.module_fini = fsdev_aio_finish,
	.get_ctx_size	= fsdev_aio_get_ctx_size,
};

SPDK_FSDEV_MODULE_REGISTER(aio, &aio_fsdev_module);

static void
fsdev_aio_free(struct aio_fsdev *vfsdev)
{
	if (vfsdev->proc_self_fd != -1) {
		close(vfsdev->proc_self_fd);
	}

	if (vfsdev->root.fd != -1) {
		close(vfsdev->root.fd);
	}

	free(vfsdev->fsdev.name);
	free(vfsdev->root_path);

	free(vfsdev);
}

static int
fsdev_aio_destruct(void *ctx)
{
	struct aio_fsdev *vfsdev = ctx;
	size_t bkt;
	struct lo_inode *inode, *tmp;

	TAILQ_REMOVE(&g_aio_fsdev_head, vfsdev, tailq);

	lo_map_destroy(&vfsdev->fd_map);
	lo_map_destroy(&vfsdev->dirp_map);
	lo_map_destroy(&vfsdev->ino_map);

	spdk_htable_foreach_safe(&vfsdev->inodes, bkt, inode, link, tmp) {
		spdk_htable_del(inode, link);
		close(inode->fd);
		free(inode);
	}

	pthread_mutex_destroy(&vfsdev->mutex);

	fsdev_aio_free(vfsdev);
	return 0;
}

typedef int (*fsdev_op_handler_func)(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io);

static fsdev_op_handler_func handlers[] = {
	[SPDK_FSDEV_OP_LOOKUP] = lo_lookup,
	[SPDK_FSDEV_OP_FORGET] = lo_forget,
	[SPDK_FSDEV_OP_GETATTR] = lo_getattr,
	[SPDK_FSDEV_OP_SETATTR] = lo_setattr,
	[SPDK_FSDEV_OP_READLINK] = lo_readlink,
	[SPDK_FSDEV_OP_SYMLINK] = lo_symlink,
	[SPDK_FSDEV_OP_MKNOD] = lo_mknod,
	[SPDK_FSDEV_OP_MKDIR] = lo_mkdir,
	[SPDK_FSDEV_OP_UNLINK] = lo_unlink,
	[SPDK_FSDEV_OP_RMDIR] = lo_rmdir,
	[SPDK_FSDEV_OP_RENAME] = lo_rename,
	[SPDK_FSDEV_OP_LINK] = lo_link,
	[SPDK_FSDEV_OP_OPEN] = lo_open,
	[SPDK_FSDEV_OP_READ] = lo_read,
	[SPDK_FSDEV_OP_WRITE] = lo_write,
	[SPDK_FSDEV_OP_STATFS] =  lo_statfs,
	[SPDK_FSDEV_OP_RELEASE] = lo_release,
	[SPDK_FSDEV_OP_FSYNC] = lo_fsync,
	[SPDK_FSDEV_OP_SETXATTR] =  lo_setxattr,
	[SPDK_FSDEV_OP_GETXATTR] =  lo_getxattr,
	[SPDK_FSDEV_OP_LISTXATTR] = lo_listxattr,
	[SPDK_FSDEV_OP_REMOVEXATTR] =  lo_removexattr,
	[SPDK_FSDEV_OP_FLUSH] =  lo_flush,
	[SPDK_FSDEV_OP_OPENDIR] =  lo_opendir,
	[SPDK_FSDEV_OP_READDIR] =  lo_readdir,
	[SPDK_FSDEV_OP_RELEASEDIR] = lo_releasedir,
	[SPDK_FSDEV_OP_FSYNCDIR] = lo_fsyncdir,
	[SPDK_FSDEV_OP_FLOCK] = lo_flock,
	[SPDK_FSDEV_OP_CREATE] = lo_create,
	[SPDK_FSDEV_OP_ABORT] = lo_abort,
	[SPDK_FSDEV_OP_FALLOCATE] = lo_fallocate,
	[SPDK_FSDEV_OP_COPY_FILE_RANGE] = lo_copy_file_range,
};

static void
fsdev_aio_submit_request(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	int status;
	enum spdk_fsdev_op op = spdk_fsdev_io_get_op(fsdev_io);

	assert(op >= 0 && op < __SPDK_FSDEV_OP_LAST);

	status = handlers[op](ch, fsdev_io);
	if (status != OP_STATUS_ASYNC) {
		spdk_fsdev_io_complete(fsdev_io, status);
	}
}

static struct spdk_io_channel *
fsdev_aio_get_io_channel(void *ctx)
{
	return spdk_get_io_channel(&g_aio_fsdev_head);
}

static int
fsdev_aio_negotiate_opts(void *ctx, struct spdk_fsdev_instance_opts *opts)
{
	struct aio_fsdev *vfsdev = ctx;

	assert(opts != 0);
	assert(opts->opts_size != 0);

	/* The AIO doesn't apply any additional restrictions, so we just accept the requested opts */
	SPDK_DEBUGLOG(fsdev_aio,
		      "aio filesystem %s: opts updated: writeback_cache=%" PRIu8 " max_write=%" PRIu32 ")\n",
		      vfsdev->fsdev.name, opts->writeback_cache_enabled, opts->max_write);

	return 0;
}

static void
fsdev_aio_write_config_json(struct spdk_fsdev *fsdev, struct spdk_json_write_ctx *w)
{
	struct aio_fsdev *vfsdev = fsdev_to_aio_fsdev(fsdev);

	spdk_json_write_object_begin(w);
	spdk_json_write_named_string(w, "method", "fsdev_aio_create");
	spdk_json_write_named_object_begin(w, "params");
	spdk_json_write_named_string(w, "name", fsdev->name);
	spdk_json_write_named_string(w, "root_path", vfsdev->root_path);
	spdk_json_write_named_uint8(w, "xattr_enabled", vfsdev->xattr_enabled ? 1 : 0);
	spdk_json_write_named_uint8(w, "writeback_cache", vfsdev->fsdev.opts.writeback_cache_enabled);
	spdk_json_write_named_uint32(w, "max_write", vfsdev->fsdev.opts.max_write);
	spdk_json_write_object_end(w); /* params */
	spdk_json_write_object_end(w);
}

static const struct spdk_fsdev_fn_table aio_fn_table = {
	.destruct		= fsdev_aio_destruct,
	.submit_request		= fsdev_aio_submit_request,
	.get_io_channel		= fsdev_aio_get_io_channel,
	.negotiate_opts		= fsdev_aio_negotiate_opts,
	.write_config_json	= fsdev_aio_write_config_json,
};

static int
setup_root(struct aio_fsdev *vfsdev)
{
	int fd, res;
	struct stat stat;

	fd = open(vfsdev->root_path, O_PATH);
	if (fd == -1) {
		res = errno;
		SPDK_ERRLOG("Cannot open root %s (err=%d)\n", vfsdev->root_path, res);
		return res;
	}

	res = fstatat(fd, "", &stat, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1) {
		res = errno;
		SPDK_ERRLOG("Cannot get root fstatat of %s (err=%d)\n", vfsdev->root_path, res);
		close(fd);
		return res;
	}

	vfsdev->root.fd = fd;
	vfsdev->root.key.ino = stat.st_ino;
	vfsdev->root.key.dev = stat.st_dev;
	vfsdev->root.refcount = 2;
	SPDK_INFOLOG(fsdev_aio, "root (%s) fd=%d\n", vfsdev->root_path, fd);
	return 0;
}

static int
setup_proc_self_fd(struct aio_fsdev *vfsdev)
{
	vfsdev->proc_self_fd = open("/proc/self/fd", O_PATH);
	return (vfsdev->proc_self_fd != -1) ? 0 : errno;
}

int
spdk_fsdev_aio_create(struct spdk_fsdev **fsdev, const char *name, const char *root_path,
		      enum spdk_aio_bool_param xattr_enabled, enum spdk_aio_bool_param writeback_cache_enabled,
		      uint32_t max_write)
{
	struct aio_fsdev *vfsdev;
	int rc;
	struct lo_map_elem *root_elem;

	vfsdev = calloc(1, sizeof(*vfsdev));
	if (!vfsdev) {
		SPDK_ERRLOG("Could not allocate aio_fsdev\n");
		return -ENOMEM;
	}

	vfsdev->root.fd = vfsdev->proc_self_fd = -1;

	vfsdev->fsdev.name = strdup(name);
	if (!vfsdev->fsdev.name) {
		SPDK_ERRLOG("Could not strdup fsdev name: %s\n", name);
		fsdev_aio_free(vfsdev);
		return -ENOMEM;
	}

	vfsdev->root_path = strdup(root_path);
	if (!vfsdev->root_path) {
		SPDK_ERRLOG("Could not strdup root path: %s\n", root_path);
		fsdev_aio_free(vfsdev);
		return -ENOMEM;
	}

	vfsdev->root.fuse_ino = SPDK_FUSE_ROOT_ID;
	rc = setup_root(vfsdev);
	if (rc) {
		SPDK_ERRLOG("Could not setup root: %s (err=%d)\n", root_path, rc);
		fsdev_aio_free(vfsdev);
		return -rc;
	}

	rc = setup_proc_self_fd(vfsdev);
	if (rc) {
		SPDK_ERRLOG("Could not setup proc_self_fd (err=%d)\n", rc);
		fsdev_aio_free(vfsdev);
		return -rc;
	}

	vfsdev->xattr_enabled = (xattr_enabled == SPDK_AIO_UNDEFINED) ?
				DEFAULT_XATTR_ENABLED : !!xattr_enabled;
	vfsdev->fsdev.ctxt = vfsdev;
	vfsdev->fsdev.fn_table = &aio_fn_table;
	vfsdev->fsdev.module = &aio_fsdev_module;

	pthread_mutex_init(&vfsdev->mutex, NULL);

	spdk_htable_init(&vfsdev->inodes);

	/* Set up the ino map like this:
	 * [0] Reserved (will not be used)
	 * [1] Root inode
	 */
	lo_map_init(&vfsdev->ino_map);
	lo_map_reserve(&vfsdev->ino_map, 0)->in_use = false;
	root_elem = lo_map_reserve(&vfsdev->ino_map, vfsdev->root.fuse_ino);
	root_elem->inode = &vfsdev->root;

	lo_map_init(&vfsdev->dirp_map);
	lo_map_init(&vfsdev->fd_map);

	rc = spdk_fsdev_register(&vfsdev->fsdev);
	if (rc) {
		fsdev_aio_free(vfsdev);
		return rc;
	}

	vfsdev->fsdev.opts.writeback_cache_enabled = (writeback_cache_enabled == SPDK_AIO_UNDEFINED) ?
			false : !!writeback_cache_enabled;
	vfsdev->fsdev.opts.max_write = (max_write == SPDK_AIO_MAX_WRITE_UNDEFINED) ?
				       DEFAULT_MAX_WRITE : max_write;

	*fsdev = &(vfsdev->fsdev);
	TAILQ_INSERT_TAIL(&g_aio_fsdev_head, vfsdev, tailq);
	SPDK_DEBUGLOG(fsdev_aio, "Created aio filesystem %s (xattr_enabled=%" PRIu8 " writeback_cache=%"
		      PRIu8 " max_write=%" PRIu32 ")\n",
		      vfsdev->fsdev.name, vfsdev->xattr_enabled, vfsdev->fsdev.opts.writeback_cache_enabled,
		      vfsdev->fsdev.opts.max_write);
	return rc;
}
void
spdk_fsdev_aio_delete(const char *name,
		      spdk_delete_aio_fsdev_complete cb_fn, void *cb_arg)
{
	int rc;

	rc = spdk_fsdev_unregister_by_name(name, &aio_fsdev_module, cb_fn, cb_arg);
	if (rc != 0) {
		cb_fn(cb_arg, rc);
	}

	SPDK_DEBUGLOG(fsdev_aio, "Deleted aio filesystem %s\n", name);
}

SPDK_LOG_REGISTER_COMPONENT(fsdev_aio)
