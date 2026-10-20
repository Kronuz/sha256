# AGENTS.md

Working notes for agents modifying this repository. For the design read
`ARCHITECTURE.md`; for usage read `README.md`. This file covers the repo layout,
how to build and test, the invariants you must not break, and the traps that are
easy to fall into.

## Repo map

```
sha256.h                     The SHA256 class (as extracted from Xapiand) and the kronuz::sha256 API: hasher, digest(), to_hex(), the kernel queries and the force_kernel()/reset_kernel() hook.
sha256_kernels.hh            Internal: kernel signature, round constants, compress() dispatch, absorb()/finish(). Not for consumers.
sha256.cc                    Portable kernel (the original round function), shared buffering and padding, dispatch, both front ends. Includes "endian.hh" for the byte-order macros.
sha256_x86.cc                SHA-NI kernel and CPUID check; empty unless x86_64.
sha256_arm.cc                ARMv8 SHA2 kernel and HWCAP/sysctl check; empty unless arm64.
test/test.cc                 The SHA256 class: published vectors, multi-block, block boundary, memory block, streaming, raw bytes, reuse, padding lengths, unaligned input.
test/kernels.cc              Every kernel the host has, forced in turn: NIST vectors, every split, 3000 random cases vs portable, the hook.
test/openssl.cc              Built when OpenSSL is found: one TU with <openssl/sha.h>, every kernel vs OpenSSL's SHA256().
fuzz/fuzz_stream.cc          libFuzzer: input-chosen chunking through every kernel and both APIs.
bench/bench.cc               GB/s per kernel and OpenSSL EVP at 64 B, 4 KiB, 64 MiB.
examples/demo.cc             A runnable tour (not a test).
CMakeLists.txt               STATIC library `sha256` (+ alias sha256::sha256); FetchContent endian; CTest tests `sha256`, `sha256_kernels`, `sha256_openssl` (when OpenSSL is found); options SHA256_HARDWARE, SHA256_FUZZ, SHA256_BUILD_BENCHMARKS.
LICENSE                      MIT, Copyright (c) 2015-2019 Dubalu LLC; portions (c) 2014,2015 Stephan Brumme.
README.md                    What it is, install, quick start.
docs/API.md                  The API reference.
ARCHITECTURE.md              Internal design: block processing, byte order, padding, finalization.
```

This is not header-only. The three `.cc` files must be compiled and linked; the header
only declares. The CMake target is a `STATIC` library that links `endian` so
`"endian.hh"` resolves.

## Build and run the test

```sh
cmake -B build && cmake --build build && ctest --test-dir build
```

The first configure fetches `endian` over the network (FetchContent, pinned).
`sha256_test` ends with `all sha256 tests passed`; `sha256_kernels_test` prints the
detected kernel, one line per kernel tested or skipped, and ends with `all sha256
kernel tests passed (N kernels)`. A host without SHA-NI or SHA2 tests the portable
kernel only, so read CI's logs (the `bench-*` jobs print the CPU and the kernels) to
know a hardware kernel ran. `SHA256_EXPECT_KERNEL=sha-ni` (or `armv8`) makes the
kernel test fail when that kernel is unavailable.

```sh
cmake -B build -DSHA256_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++ && ./build/sha256_fuzz -max_total_time=60
cmake -B build -DCMAKE_BUILD_TYPE=Release -DSHA256_BUILD_BENCHMARKS=ON && ./build/sha256_bench
```

On a shared host, run the fuzzer and the benchmark under `quiet run`. The test and
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
  pins these, `test/kernels.cc` pins them for every kernel. Any change to a kernel,
  `absorb()` or `finish()` that moves them is a bug, full stop.
- **The input is consumed in 64-byte blocks; finalization pads the last one.**
  `absorb()` buffers partial blocks and runs full ones; `finish()` appends the
  `0x80` terminator, zero fill, and the 64-bit big-endian length, spilling into a
  second block when needed. Don't shortcut the padding or the block boundary.
- **Reading the digest does not destroy state.** `getHash()` snapshots the eight
  hash words, finalizes, reads out, then restores the snapshot, so `add()` can
  continue. Keep that save/restore.
- **Every kernel computes the same function on the same eight words.** Between
  kernel calls the state is `uint32_t[8]` in A..H order, whatever layout a kernel
  uses inside (SHA-NI shuffles to ABEF/CDGH and back). That is what makes
  `force_kernel()` safe mid-stream and lets both front ends share `absorb()`.
- **A hardware kernel runs only after its check.** `kernel_fn()` returns a kernel
  pointer only when the build has it and the CPU reports it; `compress()` never
  returns anything else. Never call `compress_shani`/`compress_armv8` directly.
- **Detection runs once.** `compress()` is one relaxed atomic load; don't put
  CPUID or `getauxval` on the per-update path.
- **The portable round function's text is unchanged** from the extraction (only
  `m_hash` became a parameter, as `compressBlock`); it is the reference the other
  kernels are tested against.
- **The SHA256 class's layout and behaviour are frozen** (C1 of the consolidation
  audit): same members, same digests, `getHash()` still restores the state.
- **Words are loaded big-endian.** On a little-endian host each 32-bit word is
  byte-swapped on load; on big-endian it is a no-op. The branch is compile-time
  from `__BYTE_ORDER`. Don't drop the swap or you'll corrupt the digest on x86.

## Traps

- **Instruction-set flags stay on the kernel functions.** SHA-NI uses a
  per-function `target(...)` attribute; the ARMv8 file gets `-march=armv8-a+crypto`
  only on Linux/FreeBSD toolchains. Don't move either to the whole target: the rest
  of the library must run on a baseline CPU. Keep `sha256_arm.cc` free of standard
  headers whose inline functions could be emitted with the wider instruction set.
- **This Mac (i9-9980HK) has no SHA-NI and is not arm64.** Local tests prove the
  portable kernel only; hardware kernels are proven by CI. `.scratch/shani-emu`
  (untracked) shows how to run the SHA-NI kernel with emulated instructions.

- **Don't reimplement the byte swap locally.** It comes from `endian.hh` via the
  `__BYTE_ORDER` / `__LITTLE_ENDIAN` / `__BIG_ENDIAN` macros. Keep it coming from
  the sibling library so the family agrees on byte-order handling.
- **It is size-based, not NUL-terminated.** `add()` and the `(void*, size)` call
  operator hash exactly `numBytes` bytes, including embedded `\0`. Don't "optimize"
  to stop at a NUL.
- **The round constants and the unrolled rounds are the algorithm.** The long list
  of `0x428a2f98` ... `0xc67178f2` additions in `compressBlock` is the SHA-256
  constant table inlined; the hardware kernels read the same constants from
  `round_constants` in `sha256_kernels.hh` (16-byte aligned for `_mm_load_si128`).
  Don't "tidy" either; a single transposed digit breaks the digest silently.

## Standalone vs. Xapiand

This is a standalone extraction from
[Xapiand](https://github.com/Kronuz/Xapiand). The `SHA256` class in `sha256.h` and
the round function in `sha256.cc` were copied verbatim; the only change on extraction was resolving the one local
include, `"endian.h"`, against the standalone endian library as `"endian.hh"`
through CMake instead of Xapiand's source tree. Digest output is unchanged; padding-pointer arithmetic now subtracts the block size before forming a pointer. Keep it that way; any change here should be reconcilable with
upstream as a plain edit.

Input pointers have no alignment or integer-object requirement. Keep the fixed-size `memcpy` word loads in the portable kernel and unaligned vector loads in the others; casting a byte buffer to `uint32_t*` and dereferencing reintroduces alignment and aliasing undefined behavior. The alignment fixtures cover offsets 0 through 15 and repeated finalization between appends. The fix changes no public layout or digest bytes.
