/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

/** \file
 * Operations on a FUSE fsdev dispatcher
 */

#ifndef SPDK_FUSE_DISPATCHER_H
#define SPDK_FUSE_DISPATCHER_H

#include "spdk/stdinc.h"

struct spdk_fuse_dispatcher;

typedef void (*spdk_fuse_dispatcher_submit_cpl_cb)(void *cb_arg, uint32_t error);

/**
 * Create a FUSE fsdev dispatcher
 *
 * \param desc Filesystem device descriptor.
 *
 * \return pointer to dispatcher object on success, otherwise - NULL.
 */
struct spdk_fuse_dispatcher *spdk_fuse_dispatcher_create(struct spdk_fsdev_desc *desc);

/**
 * Submit FUSE request
 *
 * \param disp FUSE fsdev dispatcher object.
 * \param ch I/O channel.
 * \param in_iov Input IO vectors array.
 * \param in_iovcnt Size of the input IO vectors array.
 * \param out_iov Output IO vectors array.
 * \param out_iovcnt Size of the output IO vectors array.
 * \param cb Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - the request cannot be submitted due to a lack of the internal IO objects
 *  -EINVAL - the request cannot be submitted as some FUSE request data is incorrect
 */
int spdk_fuse_dispatcher_submit_request(struct spdk_fuse_dispatcher *disp,
					struct spdk_io_channel *ch,
					struct iovec *in_iov, int in_iovcnt,
					struct iovec *out_iov, int out_iovcnt,
					spdk_fuse_dispatcher_submit_cpl_cb cb, void *cb_arg);

/**
 * Delete a FUSE fsdev dispatcher
 *
 * \param disp FUSE fsdev dispatcher object.
 */
void spdk_fuse_dispatcher_delete(struct spdk_fuse_dispatcher *disp);

#endif /* SPDK_FUSE_DISPATCHER_H */
