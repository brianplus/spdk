/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

/** \file
 * Filesystem device abstraction layer
 */

#ifndef SPDK_FSDEV_H
#define SPDK_FSDEV_H

#include "spdk/stdinc.h"
#include "spdk/json.h"
#include "spdk/assert.h"
#include "spdk/dma.h"

#include <sys/statvfs.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief SPDK filesystem device.
 *
 * This is a virtual representation of a filesystem device that is exported by the backend.
 */
struct spdk_fsdev;

/** Asynchronous event type */
enum spdk_fsdev_event_type {
	SPDK_FSDEV_EVENT_REMOVE,
};

/**
 * Filesystem device event callback.
 *
 * \param type Event type.
 * \param fsdev Filesystem device that triggered event.
 * \param event_ctx Context for the filesystem device event.
 */
typedef void (*spdk_fsdev_event_cb_t)(enum spdk_fsdev_event_type type,
				      struct spdk_fsdev *fsdev,
				      void *event_ctx);

struct spdk_fsdev_fn_table;
struct spdk_io_channel;

/** fsdev status */
enum spdk_fsdev_status {
	SPDK_FSDEV_STATUS_INVALID,
	SPDK_FSDEV_STATUS_READY,
	SPDK_FSDEV_STATUS_UNREGISTERING,
	SPDK_FSDEV_STATUS_REMOVING,
};

/** global fsdev options */
struct spdk_fsdev_opts {
	/**
	 * The size of spdk_fsdev_opts according to the caller of this library is used for ABI
	 * compatibility.  The library uses this field to know how many fields in this
	 * structure are valid. And the library will populate any remaining fields with default values.
	 * New added fields should be put at the end of the struct.
	 */
	uint32_t opts_size;
	/**
	 * Size of fsdev IO objects pool
	 */
	uint32_t fsdev_io_pool_size;
	/**
	 * Size of fsdev IO objects cache per thread
	 */
	uint32_t fsdev_io_cache_size;
} __attribute__((packed));
SPDK_STATIC_ASSERT(sizeof(struct spdk_fsdev_opts) == 12, "Incorrect size");

/** fsdev instance options */
struct spdk_fsdev_instance_opts {
	/**
	 * The size of spdk_fsdev_instance_opts according to the caller of this library is used for ABI
	 * compatibility.  The library uses this field to know how many fields in this
	 * structure are valid. And the library will populate any remaining fields with default values.
	 * New added fields should be put at the end of the struct.
	 */
	uint32_t opts_size;

	/**
	 * Maximum size of the write buffer
	 */
	uint32_t max_write;

	/**
	 * Indicates that writeback caching should be enabled. This means that
	 * individual write request may be buffered and merged in the kernel
	 * before they are send to the filesystem.
	 *
	 * This feature is disabled by default.
	 */
	uint8_t writeback_cache_enabled;

} __attribute__((packed));
SPDK_STATIC_ASSERT(sizeof(struct spdk_fsdev_instance_opts) == 9, "Incorrect size");

/**
 * Structure with optional File Operation parameters
 * The content of this structure must be valid until the File Operation is completed
 */
struct spdk_fsdev_ext_op_opts {
	/** Size of this structure in bytes */
	size_t size;
	/** Memory domain which describes payload in this File Operation. fsdev must support DMA device type that
	 * can access this memory domain, refer to \ref spdk_fsdev_get_memory_domains and \ref spdk_memory_domain_get_dma_device_type
	 * If set, that means that data buffers can't be accessed directly and the memory domain must
	 * be used to fetch data to local buffers or to translate data to another memory domain */
	struct spdk_memory_domain *memory_domain;
	/** Context to be passed to memory domain operations */
	void *memory_domain_ctx;
} __attribute__((packed));
SPDK_STATIC_ASSERT(sizeof(struct spdk_fsdev_ext_op_opts) == 24, "Incorrect size");

/**
 * \brief Handle to an opened SPDK filesystem device.
 */
struct spdk_fsdev_desc;

/**
 * Filesystem device initialization callback.
 *
 * \param cb_arg Callback argument.
 * \param rc 0 if filesystem device initialized successfully or negative errno if it failed.
 */
typedef void (*spdk_fsdev_init_cb)(void *cb_arg, int rc);

/**
 * Filesystem device finish callback.
 *
 * \param cb_arg Callback argument.
 */
typedef void (*spdk_fsdev_fini_cb)(void *cb_arg);

/**
 * Initialize filesystem device modules.
 *
 * \param cb_fn Called when the initialization is complete.
 * \param cb_arg Argument passed to function cb_fn.
 */
void spdk_fsdev_initialize(spdk_fsdev_init_cb cb_fn, void *cb_arg);

/**
 * Perform cleanup work to remove the registered filesystem device modules.
 *
 * \param cb_fn Called when the removal is complete.
 * \param cb_arg Argument passed to function cb_fn.
 */
void spdk_fsdev_finish(spdk_fsdev_fini_cb cb_fn, void *cb_arg);

/**
 * Get the full configuration options for the registered filesystem device modules and created fsdevs.
 *
 * \param w pointer to a JSON write context where the configuration will be written.
 */
void spdk_fsdev_subsystem_config_json(struct spdk_json_write_ctx *w);

/**
 * Get filesystem device module name.
 *
 * \param fsdev Filesystem device to query.
 * \return Name of fsdev module as a null-terminated string.
 */
const char *spdk_fsdev_get_module_name(const struct spdk_fsdev *fsdev);

/**
 * Get filesystem device by the filesystem device name.
 *
 * \param fsdev_name The name of the filesystem device.
 * \return Filesystem device associated with the name or NULL if no filesysten device with
 * fsdev_name is currently registered.
 */
struct spdk_fsdev *spdk_fsdev_get_by_name(const char *fsdev_name);

/**
 * Open a filesystem device for I/O operations.
 *
 * \param fsdev_name Filesystem device name to open.
 * \param event_cb notification callback to be called when the fsdev triggers
 * asynchronous event such as fsdev removal. This will always be called on the
 * same thread that spdk_fsdev_open() was called on. In case of removal event
 * the descriptor will have to be manually closed to make the fsdev unregister
 * proceed.
 * \param event_ctx param for event_cb.
 * \param desc output parameter for the descriptor when operation is successful
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int spdk_fsdev_open(const char *fsdev_name, spdk_fsdev_event_cb_t event_cb,
		    void *event_ctx, struct spdk_fsdev_desc **_desc);

/**
 * Close a previously opened filesystem device.
 *
 * Must be called on the same thread that the spdk_fsdev_open()
 * was performed on.
 *
 * \param desc Filesystem device descriptor to close.
 */
void spdk_fsdev_close(struct spdk_fsdev_desc *desc);

/**
 * Get filesystem device name.
 *
 * \param fsdev filesystem device to query.
 * \return Name of fsdev as a null-terminated string.
 */
const char *spdk_fsdev_get_name(const struct spdk_fsdev *fsdev);

/**
 * Get the fsdev associated with a fsdev descriptor.
 *
 * \param desc Open filesystem device descriptor
 * \return fsdev associated with the descriptor
 */
struct spdk_fsdev *spdk_fsdev_desc_get_fsdev(struct spdk_fsdev_desc *desc);

/**
 * Obtain an I/O channel for the filesystem device opened by the specified
 * descriptor. I/O channels are bound to threads, so the resulting I/O
 * channel may only be used from the thread it was originally obtained
 * from.
 *
 * \param desc Filesystem device descriptor.
 *
 * \return A handle to the I/O channel or NULL on failure.
 */
struct spdk_io_channel *spdk_fsdev_get_io_channel(struct spdk_fsdev_desc *desc);

/**
 * Set the options for the fsdev module.
 *
 * \param opts options to set
 * \return 0 on success.
 * \return -EINVAL if the options are invalid.
 */
int spdk_fsdev_set_opts(const struct spdk_fsdev_opts *opts);

/**
 * Get the options for the fsdev module.
 *
 * \param opts Output parameter for options.
 * \param opts_size sizeof(*opts)
 */
int spdk_fsdev_get_opts(struct spdk_fsdev_opts *opts, size_t opts_size);

/**
 * Set fsdev instance options
 *
 * \param fsdev filesystem device to query.
 * \param opts options to set
 * \return 0 on success.
 * \return -EINVAL if the options are invalid.
 */
int spdk_fsdev_set_instance_opts(struct spdk_fsdev *fsdev,
				 const struct spdk_fsdev_instance_opts *opts);

/**
 * Get fsdev instance options
 *
 * \param fsdev filesystem device to query.
 * \param opts Output parameter for options.
 * \param opts_size sizeof(*opts)
 * \return 0 on success.
 * \return -EINVAL if the options are invalid.
 */
int spdk_fsdev_get_instance_opts(const struct spdk_fsdev *fsdev,
				 struct spdk_fsdev_instance_opts *opts, size_t opts_size);

/**
 * Get SPDK memory domains used by the given fsdev. If fsdev reports that it uses memory domains
 * that means that it can work with data buffers located in those memory domains.
 *
 * The user can call this function with \b domains set to NULL and \b array_size set to 0 to get the
 * number of memory domains used by fsdev
 *
 * \param fsdev filesystem device
 * \param domains pointer to an array of memory domains to be filled by this function. The user should allocate big enough
 * array to keep all memory domains used by fsdev and all underlying fsdevs
 * \param array_size size of \b domains array
 * \return the number of entries in \b domains array or negated errno. If returned value is bigger than \b array_size passed by the user
 * then the user should increase the size of \b domains array and call this function again. There is no guarantees that
 * the content of \b domains array is valid in that case.
 *         -EINVAL if input parameters were invalid
 */
int spdk_fsdev_get_memory_domains(struct spdk_fsdev *fsdev, struct spdk_memory_domain **domains,
				  int array_size);


typedef uint64_t spdk_ino_t;

/** Directory entry info */
struct spdk_fsdev_entry {
	/** Unique inode number */
	spdk_ino_t ino;

	/** Inode attributes */
	struct stat attr;

	/** Validity timeout (in msec) for inode attributes */
	uint64_t attr_timeout_ms;

	/** Validity timeout (in msec) for for the name */
	uint64_t entry_timeout_ms;
};

/* 'to_set' flags in spdk_fsdev_op_setattr */
#define FSDEV_SET_ATTR_MODE	(1 << 0)
#define FSDEV_SET_ATTR_UID	(1 << 1)
#define FSDEV_SET_ATTR_GID	(1 << 2)
#define FSDEV_SET_ATTR_SIZE	(1 << 3)
#define FSDEV_SET_ATTR_ATIME	(1 << 4)
#define FSDEV_SET_ATTR_MTIME	(1 << 5)
#define FSDEV_SET_ATTR_ATIME_NOW	(1 << 7)
#define FSDEV_SET_ATTR_MTIME_NOW	(1 << 8)
#define FSDEV_SET_ATTR_CTIME	(1 << 10)


/* Additional flag in spdk_fsdev_op_write. indicates if this was caused by a delayed write
 * from the page cache. If so, then the context's pid, uid, and gid fields will not be valid,
 * and the fh value may not match the fh value that would have been sent with the corresponding
 * individual write requests if write caching had been disabled. */
#define FSDEV_WRITE_PAGE_CACHE 0x80000000

/**
 * Lookup file operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param entry Entry info.
 */
typedef void (spdk_fsdev_op_lookup_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status,
		const struct spdk_fsdev_entry *entry);

/**
 * Look up a directory entry by name and get its attributes
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param parent_ino Inode of the parent directory.
 * \param name The name to look up.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_op_lookup(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
			 spdk_ino_t parent_ino, const char *name, spdk_fsdev_op_lookup_cpl_cb clb, void *ctx);

/**
 * Look up file operation completion callback
 *
 * NOTE: this operation doesn't have status.
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status Operation result. 0 if the operation succeeded, an error code otherwice.
*/
typedef void (spdk_fsdev_op_forget_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status);

/**
 * Remove inode from internal cache
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino Inode.
 * \param nlookup Number of lookups to forget.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_forget(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
			 spdk_ino_t ino, uint64_t nlookup, spdk_fsdev_op_forget_cpl_cb clb, void *ctx);

/**
 * Get file attributes operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status Operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param attr Inode attributes.
 * \param attr_timeout_ms Calidity timeout (in ms) for inode attributes.
 */
typedef void (spdk_fsdev_op_getattr_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status,
		const struct stat *attr, uint64_t attr_timeout_ms);

/**
 * Get file attributes
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino Inode.
 * \param fh File handle id
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_getattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			  uint64_t unique, spdk_ino_t ino,
			  uint64_t fh, spdk_fsdev_op_getattr_cpl_cb clb, void *ctx);

/**
 * Set file attributes operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status Operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param attr Inode attributes.
 * \param attr_timeout_ms Calidity timeout (in ms) for inode attributes.
 */
typedef void (spdk_fsdev_op_setattr_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status,
		const struct stat *attr, uint64_t attr_timeout_ms);

/**
 * Set file attributes
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino Inode.
 * \param attr Inode attributes to set.
 * \param to_set Bit mask of attributes which should be set.
 * \param fh File handle id.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_setattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			  uint64_t unique, spdk_ino_t ino, const struct stat *attr, uint32_t to_set, uint64_t fh,
			  spdk_fsdev_op_setattr_cpl_cb clb, void *ctx);

/**
 * Read symbolic link operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status Operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param linkname symbolic link contents
 */
typedef void (spdk_fsdev_op_readlink_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status,
		const char *linkname);

/**
 * Read symbolic link
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino Inode.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_readlink(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			   uint64_t unique, spdk_ino_t ino, spdk_fsdev_op_readlink_cpl_cb clb, void *ctx);

/**
 * Create a symbolic link operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param entry Entry info.
 */
typedef void (spdk_fsdev_op_symlink_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status,
		const struct spdk_fsdev_entry *entry);

/**
 * Create a symbolic link
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param parent_ino Inode of the parent directory.
 * \param target symbolic link's content
 * \param linkpath symbolic link's name
 * \param euid Effective user ID of the calling process.
 * \param egid Effective group ID of the calling process.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_op_symlink(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			  uint64_t unique, spdk_ino_t parent_ino, const char *target, const char *linkpath,
			  uid_t euid, gid_t egid, spdk_fsdev_op_symlink_cpl_cb clb, void *ctx);

/**
 * Create file node operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param entry Entry info.
 */
typedef void (spdk_fsdev_op_mknod_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status,
		const struct spdk_fsdev_entry *entry);

/**
 * Create file node
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param parent_ino Inode of the parent directory.
 * \param name File name to create.
 * \param mode File type and mode with which to create the new file.
 * \param rdev The device number (only valid if created file is a device)
 * \param euid Effective user ID of the calling process.
 * \param egid Effective group ID of the calling process.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_op_mknod(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
			spdk_ino_t parent_ino, const char *name, mode_t mode, dev_t rdev,
			uid_t euid, gid_t egid, spdk_fsdev_op_mknod_cpl_cb clb, void *ctx);

/**
 * Create a directory operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param entry Entry info.
 */
typedef void (spdk_fsdev_op_mkdir_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status,
		const struct spdk_fsdev_entry *entry);

/**
 * Create a directory
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param parent_ino Inode of the parent directory.
 * \param name Directory name to create.
 * \param mode Directory type and mode with which to create the new directory.
 * \param euid Effective user ID of the calling process.
 * \param egid Effective group ID of the calling process.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_op_mkdir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
			spdk_ino_t parent_ino, const char *name, mode_t mode,
			uid_t euid, gid_t egid, spdk_fsdev_op_mkdir_cpl_cb clb, void *ctx);


/**
 * Remove a file operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_op_unlink_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status);

/**
 * Remove a file
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param parent_ino Inode of the parent directory.
 * \param name Name to remove.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_op_unlink(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
			 spdk_ino_t parent_ino, const char *name,
			 spdk_fsdev_op_unlink_cpl_cb clb, void *ctx);

/**
 * Remove a directory operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_op_rmdir_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status);

/**
 * Remove a directory
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param parent_ino Inode of the parent directory.
 * \param name Name to remove.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_op_rmdir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
			spdk_ino_t parent_ino, const char *name,
			spdk_fsdev_op_rmdir_cpl_cb clb, void *ctx);

/**
 * Rename a file operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_op_rename_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status);

/**
 * Rename a file
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param parent_ino Inode of the old parent directory.
 * \param name Old rename.
 * \param new_parent_ino Inode of the new parent directory.
 * \param new_name New name.
 * \param flags Operation flags.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_op_rename(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
			 spdk_ino_t parent_ino, const char *name, spdk_ino_t new_parent_ino, const char *new_name,
			 uint32_t flags, spdk_fsdev_op_rename_cpl_cb clb, void *ctx);

/**
 * Create a hard link operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param entry Entry info.
 */
typedef void (spdk_fsdev_op_link_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status,
		const struct spdk_fsdev_entry *entry);

/**
 * Create a hard link
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino Old inode.
 * \param new_parent_ino Inode of the new parent directory.
 * \param name Link name.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_op_link(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		       spdk_ino_t ino, spdk_ino_t new_parent_ino, const char *name,
		       spdk_fsdev_op_link_cpl_cb clb, void *ctx);

/**
 * Open a file operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param fh File handle id
 */
typedef void (spdk_fsdev_op_open_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status,
		uint64_t fh);

/**
 * Open a file
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino Inode.
 * \param flags Operation flags.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_open(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		       spdk_ino_t ino, uint32_t flags, spdk_fsdev_op_open_cpl_cb clb, void *ctx);

/**
 * Read data operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 * \param data_size Number of bytes read.
 */
typedef void (spdk_fsdev_op_read_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status,
		uint32_t data_size);

/**
 * Read data
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino Inode.
 * \param fh File handle id.
 * \param size Number of bytes to read.
 * \param offs Offset to read from.
 * \param flags Operation flags.
 * \param iov Array of iovec to be used for the data.
 * \param iovcnt Size of the @iov array.
 * \param opts Optional structure with extended File Operation options. If set, this structure must be
 * valid until the operation is completed. `size` member of this structure is used for ABI compatibility and
 * must be set to sizeof(struct spdk_fsdev_ext_op_opts).
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_read(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		       spdk_ino_t ino, uint64_t fh, size_t size, uint64_t offs, uint32_t flags,
		       struct iovec *iov, uint32_t iovcnt, struct spdk_fsdev_ext_op_opts *opts,
		       spdk_fsdev_op_read_cpl_cb clb, void *ctx);

/**
 * Write data operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 * \param data_size Number of bytes written.
 */
typedef void (spdk_fsdev_op_write_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status,
		uint32_t data_size);

/**
 * Write data
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino Inode.
 * \param fh File handle id.
 * \param size Number of bytes to write.
 * \param offs Offset to read from.
 * \param flags Operation flags.
 * \param iov Array of iovec to where the data is stored.
 * \param iovcnt Size of the @iov array.
 * \param opts Optional structure with extended File Operation options. If set, this structure must be
 * valid until the operation is completed. `size` member of this structure is used for ABI compatibility and
 * must be set to sizeof(struct spdk_fsdev_ext_op_opts).
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_write(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
			spdk_ino_t ino, uint64_t fh, size_t size, uint64_t offs, uint64_t flags,
			const struct iovec *iov, uint32_t iovcnt, struct spdk_fsdev_ext_op_opts *opts,
			spdk_fsdev_op_write_cpl_cb clb, void *ctx);

/**
 * Get file system statistic operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param stbuf filesystem statistics
 */
typedef void (spdk_fsdev_op_statfs_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status,
		const struct statvfs *stbuf);

/**
 * Get file system statistics
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino the inode number, zero means "undefined"
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_statfs(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
			 spdk_ino_t ino, spdk_fsdev_op_statfs_cpl_cb clb, void *ctx);

/**
 * Release an open file operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_op_release_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status);

/**
 * Release an open file
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino the inode number
 * \param fh File handle id.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_release(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			  uint64_t unique, spdk_ino_t ino, uint64_t fh,
			  spdk_fsdev_op_release_cpl_cb clb, void *ctx);

/**
 * Synchronize file contents operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_op_fsync_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status);

/**
 * Synchronize file contents
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino the inode number
 * \param fh File handle id.
 * \param datasync Flag indicating if only data should be flushed.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_fsync(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
			spdk_ino_t ino, uint64_t fh, bool datasync,
			spdk_fsdev_op_fsync_cpl_cb clb, void *ctx);

/**
 * Set an extended attribute operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_op_setxattr_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status);

/**
 * Set an extended attribute
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino the inode number
 * \param name Name of an extended attribute.
 * \param value Buffer that contains value of an extended attribute.
 * \param size Size of an extended attribute.
 * \param flags Operation flags.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_op_setxattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			   uint64_t unique, spdk_ino_t ino, const char *name, const char *value, size_t size, uint32_t flags,
			   spdk_fsdev_op_setxattr_cpl_cb clb, void *ctx);
/**
 * Get an extended attribute operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param value_size Size of an data copied to the value buffer.
 */
typedef void (spdk_fsdev_op_getxattr_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status,
		size_t value_size);

/**
 * Get an extended attribute
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino the inode number
 * \param name Name of an extended attribute.
 * \param buffer Buffer to put the extended attribute's value.
 * \param size Size of value's buffer.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_op_getxattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			   uint64_t unique, spdk_ino_t ino, const char *name, char *buffer, size_t size,
			   spdk_fsdev_op_getxattr_cpl_cb clb, void *ctx);

/**
 * List extended attribute names operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param size Size of an extended attribute list.
 * \param size_only true if buffer was NULL or size was 0 upon the @spdk_fsdev_op_listxattr call
 */
typedef void (spdk_fsdev_op_listxattr_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status,
		size_t size, bool size_only);

/**
 * List extended attribute names
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino the inode number
 * \param buffer Buffer to to be used for the attribute names.
 * \param iovcnt Size of the @buffer.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_listxattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			    uint64_t unique, spdk_ino_t ino, char *buffer, size_t size,
			    spdk_fsdev_op_listxattr_cpl_cb clb, void *ctx);

/**
 * Remove an extended attribute operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_op_removexattr_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status);

/**
 * Remove an extended attribute
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino the inode number
 * \param name Name of an extended attribute.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_op_removexattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			      uint64_t unique, spdk_ino_t ino, const char *name,
			      spdk_fsdev_op_removexattr_cpl_cb clb, void *ctx);

/**
 * Flush operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_op_flush_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status);

/**
 * Flush
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino the inode number
 * \param fh File handle id.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_flush(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
			spdk_ino_t ino, uint64_t fh, spdk_fsdev_op_flush_cpl_cb clb, void *ctx);

/**
 * Open a directory operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param fh File handle id
 */
typedef void (spdk_fsdev_op_opendir_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status,
		ssize_t fh);

/**
 * Open a directory
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino the inode number
 * \param flags Operation flags.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_opendir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			  uint64_t unique, spdk_ino_t ino, uint32_t flags,
			  spdk_fsdev_op_opendir_cpl_cb clb, void *ctx);

/**
 * Read directory per-entry callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param name Name of the entry
 * \param entry Entry info
 * \param offset Offset of the next entry
 */
typedef int (spdk_fsdev_op_readdir_entry_cb)(void *ctx, struct spdk_io_channel *ch,
		const char *name, const struct spdk_fsdev_entry *entry, off_t offset);

/**
 * Read directory operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_op_readdir_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status);

/**
 * Read directory
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino the inode number
 * \param fh File handle id
 * \param offset Offset to continue reading the directory stream
 * \param entry_clb Per-entry callback.
 * \param cpl_clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_readdir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			  uint64_t unique, spdk_ino_t ino, uint64_t fh, uint64_t offset,
			  spdk_fsdev_op_readdir_entry_cb entry_clb, spdk_fsdev_op_readdir_cpl_cb cpl_clb, void *ctx);

/**
 * Open a directory operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_op_releasedir_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status);

/**
 * Open a directory
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino the inode number
 * \param fh File handle id
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_releasedir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			     uint64_t unique, spdk_ino_t ino, uint64_t fh,
			     spdk_fsdev_op_releasedir_cpl_cb clb, void *ctx);

/**
 * Synchronize directory contents operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_op_fsyncdir_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status);

/**
 * Synchronize directory contents
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino the inode number
 * \param fh File handle id
 * \param datasync Flag indicating if only data should be flushed.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_fsyncdir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			   uint64_t unique, spdk_ino_t ino, uint64_t fh, bool datasync,
			   spdk_fsdev_op_fsyncdir_cpl_cb clb, void *ctx);

/**
 * Acquire, modify or release a BSD file lock operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_op_flock_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status);

/**
 * Acquire, modify or release a BSD file lock
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino the inode number.
 * \param fh File handle id.
 * \param operation Lock operation (see man flock, LOCK_NB will always be added).
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_flock(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
			spdk_ino_t ino, uint64_t fh, int operation,
			spdk_fsdev_op_flock_cpl_cb clb, void *ctx);

/**
 * Create and open a file operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 * \param entry Entry info.
 * \param fh File handle id.
 */
typedef void (spdk_fsdev_op_create_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status,
		const struct spdk_fsdev_entry *entry, uint64_t fh);

/**
 * Create and open a file
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param parent_ino Inode of the parent directory.
 * \param name Name to create.
 * \param mode File type and mode with which to create the new file.
 * \param flags Operation flags.
 * \param umask Umask of the calling process.
 * \param euid Effective user ID of the calling process.
 * \param egid Effective group ID of the calling process.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_op_create(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
			 spdk_ino_t parent_ino, const char *name, mode_t mode, uint32_t flags, mode_t umask,
			 uid_t euid, gid_t egid, spdk_fsdev_op_create_cpl_cb clb, void *ctx);

/**
 * Interrupt an I/O operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_op_interrupt_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status);

/**
 * Abort an I/O
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique_to_abort Unique I/O id of the IO to abort.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_abort(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			uint64_t unique_to_abort, spdk_fsdev_op_interrupt_cpl_cb clb, void *ctx);

/**
 * Allocate requested space operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_op_fallocate_cpl_cb)(void *ctx, struct spdk_io_channel *ch, int status);

/**
 * Allocate requested space.
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino the inode number.
 * \param fh File handle id.
 * \param mode determines the operation to be performed on the given range, see fallocate(2)
 * \param offset starting point for allocated region.
 * \param length size of allocated region.
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_fallocate(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			    uint64_t unique, spdk_ino_t ino, uint64_t fh, int mode, off_t offset, off_t length,
			    spdk_fsdev_op_fallocate_cpl_cb clb, void *ctx);

/**
 * Copy a range of data from one file to another operation completion callback
 *
 * \param ctx Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 * \param data_size Number of bytes written.
 */
typedef void (spdk_fsdev_op_copy_file_range_cpl_cb)(void *ctx, struct spdk_io_channel *ch,
		int status, uint32_t data_size);

/**
 * Copy a range of data from one file to another.
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param ino_in The inode number or the source file.
 * \param fh_in Source file handle id.
 * \param off_in Starting point from were the data should be read.
 * \param ino_out The inode number or the destination file.
 * \param fh_out Destination file handle id.
 * \param off_out Starting point from were the data should be written.
 * \param len Maximum size of the data to copy.
 * \param flags Operation flags, see the copy_file_range()
 * \param clb Completion callback.
 * \param ctx Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_op_copy_file_range(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				  uint64_t unique, spdk_ino_t ino_in, uint64_t fh_in, off_t off_in,
				  spdk_ino_t ino_out, uint64_t fh_out, off_t off_out, size_t len, uint32_t flags,
				  spdk_fsdev_op_copy_file_range_cpl_cb clb, void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SPDK_FSDEV_H */
