# Architecture

The internals of `sha256`: how the SHA-256 compression function turns a stream of
bytes into a 32-byte digest, why the input is consumed in 64-byte blocks, and how
finalization pads the last block. For usage see `README.md`; for the repo map and
invariants see `AGENTS.md`.

## Shape

A public header, an internal one, and three compiled files:

```
  sha256.h           the SHA256 class and the kronuz::sha256 API (hasher, digest, kernels)
  sha256_kernels.hh  internal: kernel signatures, round constants, dispatch, absorb/finish
  sha256.cc          portable kernel, buffering, padding, dispatch, both front ends
  sha256_x86.cc      the SHA-NI kernel and its CPUID check (x86_64 only)
  sha256_arm.cc      the ARMv8 SHA2 kernel and its feature check (arm64 only)
```

Two front ends share one mechanism. `SHA256` keeps its original members: the eight
32-bit hash words, a 64-byte block buffer, the number of valid bytes in it, and the
bytes already compressed. `kronuz::sha256::hasher` keeps the eight words, the buffer,
and one total length (the buffered count is the length mod 64). Both call the same
`absorb()` and `finish()`, which call the active kernel.

## Consuming the input in blocks

SHA-256 processes data in 512-bit (64-byte) blocks. `absorb()` is the funnel behind
`add()` and `update()`: it tops up the buffer until it holds a full block,
compresses that block, then hands every whole block left in the caller's data to the
kernel in one call, without copying, and parks the tail in the buffer for next time.
That is what lets you stream arbitrary chunk sizes and get the same answer as
hashing the whole thing at once. One call per run of blocks lets a hardware kernel
keep the state in vector registers across the run.

A kernel is `void(uint32_t state[8], const unsigned char* data, size_t blocks)`. The
portable one is the original round function: it loads the 16 input words,
big-endian, runs the 64 rounds (the eight unrolled round groups, with the message
schedule extended in place from 16 to 64 words), and folds the result into the
eight hash words, once per block.

## Kernels and dispatch

- **SHA-NI** (`sha256_x86.cc`). `sha256rnds2` runs two rounds; `sha256msg1` and
  `sha256msg2` extend the schedule four words at a time. The state is shuffled into
  the ABEF/CDGH register layout the instruction expects on entry and back on exit,
  so between calls it is the same eight words as the portable kernel's. The
  function carries `target("sha,sse4.1,ssse3")`, so the rest of the library stays
  baseline x86_64. It runs only when CPUID leaf 1 ECX reports SSSE3 (bit 9) and
  SSE4.1 (bit 19) and leaf 7 EBX reports SHA (bit 29).
- **ARMv8 SHA2** (`sha256_arm.cc`). `vsha256hq`/`vsha256h2q` run four rounds on
  ABCD and EFGH; `vsha256su0q`/`vsha256su1q` extend the schedule. Apple's and
  MSVC's toolchains enable the extension by default; on Linux and FreeBSD CMake
  compiles this one file with `-march=armv8-a+crypto` and defines
  `SHA256_ARMV8_KERNEL`. It runs when `getauxval(AT_HWCAP)` (Linux) or
  `elf_aux_info` (FreeBSD) has `HWCAP_SHA2`, on every Apple arm64 core, and when
  Windows reports `PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE`.
- **Portable** everywhere else, and always available to force.

`detail::compress()` returns the active kernel: one relaxed atomic load of a
function pointer, filled on first use by `detect()`. A race on that first fill
stores the same pointer twice. `force_kernel()` stores another kernel's pointer and
`reset_kernel()` stores the detected one; since every kernel computes the same
function on the same state words, a switch between calls, even mid-stream, cannot
change a digest. `SHA256_HARDWARE=OFF` (CMake) compiles the portable kernel alone.

## Byte order

The block is read as 32-bit words in big-endian order, which is what SHA-256
specifies. On a little-endian host each word is byte-swapped on load via
`__builtin_bswap32`; on a big-endian host the load is a no-op. The branch is
selected at compile time from `__BYTE_ORDER == __BIG_ENDIAN`.

Those macros (`__BYTE_ORDER`, `__LITTLE_ENDIAN`, `__BIG_ENDIAN`) come from the
[endian](https://github.com/Kronuz/endian) sibling header, included as
`"endian.hh"`. It maps the per-OS spellings onto one common surface so this file
does not need its own platform `#ifdef` ladder. That is the one external
dependency, and the only reason this library is not header-only-trivial.

## Finalization and padding

When you ask for the digest, `finish()` pads the last partial block. SHA-256
padding appends a single `1` bit, then `0` bits until the length is 448 bits modulo
512, then the original message length as a 64-bit big-endian integer. `finish()`
copies the buffered tail into a 128-byte scratch block, writes the `0x80`
terminator and zero fill, lays the bit length in at the end of the first block when
55 or fewer bytes are buffered and of the second otherwise, and compresses one or
two blocks. The 55-, 56-, 63- and 64-byte cases in the tests exercise exactly that
overflow. The buffer itself is never written past its valid bytes.

`getHash()` snapshots the eight hash words, runs `processBuffer()` (which calls
`finish()`), reads out the 32 result bytes (big-endian), and then restores the
snapshot. `hasher::final()` does the same on a copy of the state. So reading the
digest does not destroy the running state: you can keep appending afterward. The
hex form just renders those 32 bytes as 64 lowercase hex characters through a
small `dec2hex` table.

## Why this shape

The portable kernel is the classic fully-unrolled SHA-256 from Stephan Brumme's
public-domain code, with a correction to intermediate padding-pointer arithmetic. Published digest vectors remain unchanged. The streaming `add()` / `getHash()` split is what Xapiand needs:
it hashes content it does not always hold in one contiguous buffer, and it wants a
stable fingerprint for content-addressing and dedup. The function is used as a
content digest / checksum, not for authentication, so the design goal is
throughput and a faithful, well-known digest, not the surrounding machinery of a
keyed or salted construction.

The hardware kernels exist because consumers were bypassing this library for
OpenSSL's EVP on bulk data (CL-10 of the 2026-10-19 consolidation audit). Runtime
dispatch, rather than a compile-time choice, keeps one binary correct on CPUs with
and without the instructions, and the namespaced API lets a file that includes
OpenSSL's headers use this library too.

Padding writes only into `finish()`'s fixed 128-byte scratch block at offsets computed from the buffered count, so no intermediate pointer leaves it; the caller's buffer and the class's own are read, never padded in place.

Input storage belongs to the caller and can be unaligned or contain byte objects rather than `uint32_t` objects. The portable kernel loads each initial word with a fixed-size `memcpy` into a local integer; the hardware kernels use unaligned vector loads (`_mm_loadu_si128`, `vld1q_u8`). The byte-order branch remains the same, and optimizing compilers can fold the copy into the appropriate load. The previous cast and dereference triggered UBSan on a buffer starting one byte after an aligned address; the offset and streaming fixtures preserve this regression.
