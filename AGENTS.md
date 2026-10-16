# AGENTS.md

Working notes for agents modifying this repository. For the design read
`ARCHITECTURE.md`; for usage read `README.md`. This file covers the repo layout,
how to build and test, the invariants you must not break, and the traps that are
easy to fall into.

## Repo map

```
sha256.h                     Declares the SHA256 class (call operators, add(), getHash(), reset()). Header. Verbatim from Xapiand.
sha256.cc                    The compiled compression function, block buffering, and padding. Includes "endian.hh" for the byte-order macros. Extracted from Xapiand with the standalone include and corrected padding-pointer arithmetic and alignment-safe input word loads.
test/test.cc                 Runnable smoke test: published vectors, multi-block, block boundary, memory block, streaming, raw bytes, reuse.
examples/demo.cc             A runnable tour (not a test).
CMakeLists.txt               STATIC library `sha256` (+ alias sha256::sha256); FetchContent endian; CTest test `sha256`.
LICENSE                      MIT, Copyright (c) 2015-2019 Dubalu LLC; portions (c) 2014,2015 Stephan Brumme.
README.md                    What it is, install, quick start.
docs/API.md                  The API reference.
ARCHITECTURE.md              Internal design: block processing, byte order, padding, finalization.
```

This is not header-only. `sha256.cc` must be compiled and linked; the header only
declares the class. The CMake target is a `STATIC` library that links `endian` so
`"endian.hh"` resolves.

## Build and run the test

```sh
cmake -B build && cmake --build build && ctest --test-dir build
```

The first configure fetches `endian` over the network (FetchContent,
`GIT_TAG main`). Expected output ends with `all sha256 tests passed`, exit 0. The
test target is `sha256_test`; the registered CTest name is `sha256`. The test and
demo are only added when this repo is the top-level project (CMakeLists.txt), so
consumers vendoring it via `FetchContent` won't build them.

## Dependency

`sha256.cc` includes `"endian.hh"` for the byte-order macros (`__BYTE_ORDER`,
`__LITTLE_ENDIAN`, `__BIG_ENDIAN`) used to read 32-bit words big-endian. That
header lives in the sibling [endian](https://github.com/Kronuz/endian) library,
pulled in by CMake and linked `PUBLIC` so the include path resolves. We track its
tip with `GIT_TAG main`, like the rest of the family. This is the library's only
dependency: there was no `log.h` / opts / config / THROW coupling in the original.

## What this is for

SHA-256 here is a content **digest / checksum** primitive for content-addressing
and integrity checks, not a security or authentication mechanism. Keep the docs
framed that way. Don't describe it as cryptography or imply cryptographic
guarantees; it is the fast, stable fingerprint Xapiand reaches for.

## Conventions

- **C++20.** The target requests `cxx_std_20` `PUBLIC` to stay uniform with the
  sibling libraries. Don't drop the target below it.
- **Filenames are stable.** The header and source keep their original Xapiand
  names (`sha256.h`, `sha256.cc`) so a consumer that already `#include`s the
  header just needs this repo on the include path. Don't rename them.
- Tabs for indentation, double quotes in code, no em dashes in prose.
- MIT-licensed; keep the copyright header on source files (Copyright (c)
  2015-2019 Dubalu LLC; portions (c) 2014,2015 Stephan Brumme).

## Load-bearing invariants

- **The digest must match the published vectors.** `"abc"` is
  `ba7816bf...f20015ad` and the empty input is `e3b0c442...7852b855`. The test
  pins these. Any change to `processBlock` / `processBuffer` that moves them is a
  bug, full stop.
- **The input is consumed in 64-byte blocks; finalization pads the last one.**
  `add()` buffers partial blocks and runs full ones; `processBuffer()` appends the
  `0x80` terminator, zero fill, and the 64-bit big-endian length, spilling into a
  second block when needed. Don't shortcut the padding or the block boundary.
- **Reading the digest does not destroy state.** `getHash()` snapshots the eight
  hash words, finalizes, reads out, then restores the snapshot, so `add()` can
  continue. Keep that save/restore.
- **Words are loaded big-endian.** On a little-endian host each 32-bit word is
  byte-swapped on load; on big-endian it is a no-op. The branch is compile-time
  from `__BYTE_ORDER`. Don't drop the swap or you'll corrupt the digest on x86.

## Traps

- **Don't reimplement the byte swap locally.** It comes from `endian.hh` via the
  `__BYTE_ORDER` / `__LITTLE_ENDIAN` / `__BIG_ENDIAN` macros. Keep it coming from
  the sibling library so the family agrees on byte-order handling.
- **It is size-based, not NUL-terminated.** `add()` and the `(void*, size)` call
  operator hash exactly `numBytes` bytes, including embedded `\0`. Don't "optimize"
  to stop at a NUL.
- **The round constants and the unrolled rounds are the algorithm.** The long list
  of `0x428a2f98` ... `0xc67178f2` additions in `processBlock` is the SHA-256
  constant table inlined. Don't "tidy" it; a single transposed digit breaks the
  digest silently.

## Standalone vs. Xapiand

This is a standalone extraction from
[Xapiand](https://github.com/Kronuz/Xapiand). `sha256.h` and `sha256.cc` were
copied verbatim; the only change on extraction was resolving the one local
include, `"endian.h"`, against the standalone endian library as `"endian.hh"`
through CMake instead of Xapiand's source tree. Digest output is unchanged; padding-pointer arithmetic now subtracts the block size before forming a pointer. Keep it that way; any change here should be reconcilable with
upstream as a plain edit.

Input pointers have no alignment or integer-object requirement. Keep the fixed-size `memcpy` word loads; casting a byte buffer to `uint32_t*` and dereferencing reintroduces alignment and aliasing undefined behavior. The alignment fixtures cover offsets 0 through 15 and repeated finalization between appends. The fix changes no public layout or digest bytes.
