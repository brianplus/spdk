#!/usr/bin/env bash
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2023 NVIDIA CORPORATION & AFFILIATES
#  All rights reserved.

testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../..)
source $rootdir/test/common/autotest_common.sh

shopt -s nullglob extglob

rpc_py=rpc_cmd
conf_file="$testdir/fsdev.json"

FSDEV_TEST_STORAGE=/tmp

# Make sure the configuration is clean
: > "$conf_file"

function cleanup() {
	rm -rf "$SPDK_TEST_STORAGE/aio_root"
	rm -f "$conf_file"
}

function start_fsdevio() {
	"$testdir/fsdevio/fsdevio" -w &
	fsdevio_pid=$!
	trap 'killprocess "$fsdevio_pid"; exit 1' SIGINT SIGTERM EXIT
	waitforlisten "$fsdevio_pid"
}

function setup_fsdev_conf() {
	mkdir -p "$FSDEV_TEST_STORAGE/aio_root"
	"$rpc_py" <<- RPC
		fsdev_aio_create aio0 $FSDEV_TEST_STORAGE/aio_root
	RPC
}

function fsdev_bounds() {
	$testdir/fsdevio/fsdevio -w -s $PRE_RESERVED_MEM --json "$conf_file" &
	fsdevio_pid=$!
	trap 'cleanup; killprocess $fsdevio_pid; exit 1' SIGINT SIGTERM EXIT
	echo "Process fsdevio pid: $fsdevio_pid"
	waitforlisten $fsdevio_pid
	$testdir/fsdevio/tests.py perform_tests -f "$hello_world_fsdev"
	killprocess $fsdevio_pid
	trap - SIGINT SIGTERM EXIT
}

# Inital fsdev creation and configuration
#-----------------------------------------------------

if [ $(uname -s) = Linux ]; then
	# Test dynamic memory management. All hugepages will be reserved at runtime
	PRE_RESERVED_MEM=0
else
	# Dynamic memory management is not supported on BSD
	PRE_RESERVED_MEM=2048
fi

test_type=${1:-fsdev}

start_fsdevio
case "$test_type" in
	fsdev)
		setup_fsdev_conf
		;;
	*)
		echo "invalid test name"
		exit 1
		;;
esac

# Generate json config and use it throughout all the tests
cat <<- CONF > "$conf_file"
	        {"subsystems":[
	        $("$rpc_py" save_subsystem_config -n fsdev)
	        ]}
CONF

fsdevs_name="aio0"
fsdev_list=($fsdevs_name)
hello_world_fsdev=${fsdev_list[0]}
trap - SIGINT SIGTERM EXIT
killprocess "$fsdevio_pid"
# End fsdev configuration
#-----------------------------------------------------

trap "cleanup" SIGINT SIGTERM EXIT

run_test "fsdev_hello_world" $SPDK_EXAMPLE_DIR/hello_fsdev --json "$conf_file" -f "$hello_world_fsdev"
run_test "fsdev_bounds" fsdev_bounds

trap "cleanup" SIGINT SIGTERM EXIT

# Fsdev and configuration cleanup below this line
#-----------------------------------------------------

trap - SIGINT SIGTERM EXIT
cleanup
