# Architecture

The internals of `sha256`: how the SHA-256 compression function turns a stream of
bytes into a 32-byte digest, why the input is consumed in 64-byte blocks, and how
finalization pads the last block. For usage see `README.md`; for the repo map and
invariants see `AGENTS.md`.

## Shape

A header declaring the class and a single compiled implementation:

```
  sha256.h    declares the SHA256 class: the call operators, add(), getHash(), reset()
  sha256.cc   the compression function, block buffering, and padding
```

`SHA256` keeps a small amount of running state: the eight 32-bit hash words, a
64-byte block buffer, the number of valid bytes in that buffer, and the running
total of bytes consumed. Everything else is computed.

## Consuming the input in blocks

SHA-256 processes data in 512-bit (64-byte) blocks. `add()` is the funnel: it
tops up the internal buffer until it holds a full block, processes that block,
then runs whole blocks straight from the caller's pointer without copying, and
finally parks any leftover tail bytes back in the buffer for next time. That is
what lets you stream arbitrary chunk sizes through `add()` and get the same answer
as hashing the whole thing at once.

`processBlock()` is the core. It loads the 16 input words, big-endian, runs the 64
rounds of the SHA-256 round function (the eight unrolled round groups, with the
message schedule extended in place from 16 to 64 words), and folds the result back
into the eight hash words. This is the only hot loop.

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

When you ask for the digest, `processBuffer()` finishes the last partial block.
SHA-256 padding appends a single `1` bit, then `0` bits until the length is 448
bits modulo 512, then the original message length as a 64-bit big-endian integer.
The code computes the padded length, writes the `0x80` terminator and zero fill,
and lays the length in at the end. If the `1` bit and the length don't both fit in
the current block, the padding spills into a second block and both are processed.
The 64-byte and 56-byte cases in the test exist to exercise exactly that overflow.

`getHash()` snapshots the eight hash words, runs the padding and final block(s),
reads out the 32 result bytes (big-endian), and then restores the snapshot. So
reading the digest does not destroy the running state: you can keep calling
`add()` afterward. The hex form just renders those 32 bytes as 64 lowercase hex
characters through a small `dec2hex` table.

## Why this shape

The implementation is the classic fully-unrolled SHA-256 from Stephan Brumme's
public-domain code, with a correction to intermediate padding-pointer arithmetic. Published digest vectors remain unchanged. The streaming `add()` / `getHash()` split is what Xapiand needs:
it hashes content it does not always hold in one contiguous buffer, and it wants a
stable fingerprint for content-addressing and dedup. The function is used as a
content digest / checksum, not for authentication, so the design goal is
throughput and a faithful, well-known digest, not the surrounding machinery of a
keyed or salted construction.

The padding length pointer is formed as `extra + (paddedLength - BlockSize)`. Subtracting before pointer formation keeps the intermediate pointer within the second block; the original left-associative expression could form an out-of-bounds pointer before returning to the correct address. Digest bytes and public interfaces are unchanged.

Input storage belongs to the caller and can be unaligned or contain byte objects rather than `uint32_t` objects. Each initial word uses a fixed-size `memcpy` into a local integer. The byte-order branch remains the same, and optimizing compilers can fold the copy into the appropriate load. The previous cast and dereference triggered UBSan on a buffer starting one byte after an aligned address; the offset and streaming fixtures preserve this regression.
