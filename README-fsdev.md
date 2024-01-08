# SPDK File System Device Layer

## In this readme

* [High Level](#highlevel)
* [SPDK fsdev API](#api)
* [SPDK fsdev submodule RPC](#rpc)
* [SPDK AIO fsdev](#fsdev_aio)
* [SPDK FUSE Dispatcher](#fuse_dispatcher)
* [Example Code](#examples)
* [Known Issues](#known_issues)

<a id="highlevel"></a>
## High Level

The SPDK File System Device Layer (`fsdev`) implements the File System abstraction
within the SPDK. It was inspired by the [SPDK Block Device Layer](https://spdk.io/doc/bdev_pg.html)
and follows the same architechture guide lines.

<a id="api"></a>
## SPDK fsdev API

* For the application developers: `include/spdk/fsdev.h`
* For the SPDK fsdev module developers: `include/spdk/fsdev_module.h`

<a id="rpc"></a>
## SPDK fsdev submodule API

The following RPC calls can be issued for a SPDK fsdev submodule:

* `fsdev_set_opts` - sets the generic fsdev submodule options
* `fsdev_get_opts` - retreives the generic fsdev submodule options

<a id="fsdev_aio"></a>
## SPDK AIO fsdev

Currently, the only SPDK fsdev module implemented is the AIO. This is the
module that provides a pass-through access to a local folder using either
the [Linux-native async I/O](https://github.com/anlongfei/libaio) or
the [POSIX async I/O](https://www.man7.org/linux/man-pages/man7/aio.7.html).

The code can be found under the `module/fsdev/aio`.

An AIO fsdev can be created using the `fsdev_aio_create` RPC call and deleted
using the `fsdev_aio_delete` RPC call.

<a id="fuse_dispatcher"></a>
## SPDK FUSE Dispatcher

The SPDK `fuse_dispatcher` auxiliary library implements the FUSE <-> SPDK fsdev
API translation. The `fuse_dispatcher` API can be found under the `include/spdk/fuse_dispatcher.h`.

<a id="examples"></a>
## Example Code

Example code is located in the examples directory. 

* `examples/fsdev/hello_world/hello_fsdev.c` uses the [SPDK FUSE Dispatcher](#fuse_dispatcher)
to work with the SPDK fsdev.

<a id="known_issues"></a>
## Known Issues

* The [Memory Domains](https://spdk.io/doc/dma_8h.html) are currently only supported by the SPDK
 fsdev API and the SPDK fsdev modules. The [SPDK FUSE Dispatcher](#fuse_dispatcher) doesn't support
 them for now.
