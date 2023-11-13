#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

SPDK_ROOT_DIR := $(abspath $(CURDIR)/../../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk
include $(SPDK_ROOT_DIR)/mk/spdk.modules.mk

APP = fsdevio

C_SRCS := fsdevio.c
CFLAGS += -I$(SPDK_ROOT_DIR)/lib/fsdev

SPDK_LIB_LIST = $(ALL_MODULES_LIST) $(FSDEV_MODULES_LIST) event event_fsdev fuse_dispatcher
SYS_LIBS += $(FSDEV_MODULES_PRIVATE_LIBS)
LIBS += -lcunit

include $(SPDK_ROOT_DIR)/mk/spdk.app.mk
