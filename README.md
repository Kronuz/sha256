# sha256

[![CI](https://github.com/Kronuz/sha256/actions/workflows/ci.yml/badge.svg)](https://github.com/Kronuz/sha256/actions/workflows/ci.yml)

A small C++20 utility that turns an arbitrary byte buffer into a fixed 32-byte
SHA-256 digest, rendered as 64 hex characters. Extracted from
[Xapiand](https://github.com/Kronuz/Xapiand), where it is used as a fast content
digest / checksum for content-addressing, not as a security primitive.

## What it is

One class, `SHA256`. You hand it raw bytes (a pointer and a size, or a
`std::string_view`) and it gives you back a `std::string` of 64 lowercase hex
characters: the digest of those bytes. The same input always produces the same
digest, which is what makes it useful as a content fingerprint for
content-addressing, deduplication, and integrity checks. You can hash a whole
buffer in one call, or stream it in chunks.

This is a hashing / digest function. In Xapiand it stands in for "the
fingerprint of this content," not for cryptographic authentication, and that is
how it is meant to be used here.

## Install

This is not header-only. It ships a compiled translation unit, `sha256.cc`, plus
the header `sha256.h`. You build and link the `.cc`; the header alone only
declares the `SHA256` class. It requires C++20.

It has one dependency: [endian](https://github.com/Kronuz/endian), the sibling
header that provides the byte-order macros (`__BYTE_ORDER`, `__LITTLE_ENDIAN`,
`__BIG_ENDIAN`) the compression function uses to read 32-bit words big-endian.
CMake pulls it in for you.

With CMake `FetchContent`:

```cmake
include(FetchContent)
FetchContent_Declare(
  sha256
  GIT_REPOSITORY https://github.com/Kronuz/sha256.git
  GIT_TAG        main
)
FetchContent_MakeAvailable(sha256)

target_link_libraries(your_target PRIVATE sha256::sha256)
```

`CMakeLists.txt` requests `cxx_std_20` `PUBLIC` and links `endian` `PUBLIC`, so
`"endian.hh"` resolves on the include path with no extra wiring on your side.
Then:

```cpp
#include "sha256.h"
```

The header keeps its original filename, so a codebase that already
`#include "sha256.h"` just needs this repo on its include path.

## Usage

```cpp
#include "sha256.h"

SHA256 sha256;

// Hash a string in one call. Returns 64 lowercase hex characters.
sha256(std::string_view("abc"));
// "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

// The empty input has a well-known digest.
sha256(std::string_view(""));
// "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// Hash a raw memory block. It is size-based, so embedded NULs are honored.
const unsigned char buf[] = {'x', 0x00, 'y'};
sha256(buf, sizeof(buf));

// Or stream it in chunks, then read the digest.
SHA256 streamed;
streamed.add("hello, ", 7);
streamed.add("world", 5);
streamed.getHash();   // same as hashing "hello, world" in one call

// Need the raw 32 bytes instead of hex?
unsigned char raw[SHA256::HashBytes];
streamed.getHash(raw);
```

## API reference

```cpp
class SHA256 {
public:
	enum { BlockSize = 64, HashBytes = 32 };

	std::string operator()(const void* data, size_t numBytes);
	std::string operator()(std::string_view text);

	void add(const void* data, size_t numBytes);

	std::string getHash();
	void        getHash(unsigned char buffer[HashBytes]);

	void reset();
};
```

- `operator()(data, numBytes)` / `operator()(text)` — one-shot: reset, hash the
  whole input, and return the 64-character hex digest. The instance is reset each
  call, so it is safe to reuse.
- `add(data, numBytes)` — append bytes to the running digest. Call it as many
  times as you like before reading the result.
- `getHash()` — finalize and return the digest as 64 lowercase hex characters.
  `getHash(buffer)` writes the raw 32 bytes instead. Both leave the running state
  intact, so you can keep adding after reading.
- `reset()` — clear the running state back to the empty-input starting point.

## Build & test

```sh
cmake -B build && cmake --build build && ctest --test-dir build
```

The first configure fetches `endian` over the network. The test checks the
digest against published vectors (the empty input and `"abc"`), a longer
multi-block message, the 64-byte one-full-block boundary, the `(void*, size)`
overload with embedded NULs, the streaming `add()` API (which must agree with the
one-shot form), the raw-byte `getHash()` overload, and instance reuse. It prints
`all sha256 tests passed` and exits 0.

## Examples

[`examples/demo.cc`](examples/demo.cc) is a runnable tour. A top-level CMake build
produces it next to the test:

```sh
cmake -B build && cmake --build build && ./build/sha256_demo
```

It hashes a few strings and prints their hex digests, shows how a one-byte change
flips the whole digest, and demonstrates that streaming `add()` matches hashing
the buffer in one shot.

## Provenance

Extracted from [Xapiand](https://github.com/Kronuz/Xapiand). `sha256.h` /
`sha256.cc` were copied verbatim; the only change was wiring its one local
include, `"endian.h"`, to the standalone
[endian](https://github.com/Kronuz/endian) library (`"endian.hh"`) through CMake.
The later padding-pointer fix changes no digest bytes or interfaces. See [ARCHITECTURE.md](ARCHITECTURE.md) for the
design and [AGENTS.md](AGENTS.md) for the repo map and invariants.

## License

MIT, Copyright (c) 2015-2019 Dubalu LLC; portions Copyright (c) 2014,2015 Stephan
Brumme. See [LICENSE](LICENSE).

Finalization subtracts the block size before forming the padding length pointer. This preserves digest output while avoiding out-of-bounds intermediate pointer arithmetic for two-block padding. Tests cover lengths 55 through 65 and 119 through 129 around the padding and block boundaries, including one-byte streaming and repeated digest reads.

Caller buffers may start at any byte alignment. Block words are loaded with `memcpy` into a local `uint32_t` before byte swapping, avoiding alignment and object-aliasing undefined behavior. Native and ASan/UBSan tests cover offsets 0 through 15, fixed digest vectors through 4096 bytes, arbitrary chunk boundaries, and digest reads between appends. The Clang `-O3` x86-64 assembly is identical to the previous implementation after excluding the source filename directive; this establishes unchanged generated instructions for that compiler and target, not a measured throughput gain. Digest bytes, public interfaces and class layout are unchanged.
