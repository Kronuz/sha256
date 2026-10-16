# sha256

[![CI](https://github.com/Kronuz/sha256/actions/workflows/ci.yml/badge.svg)](https://github.com/Kronuz/sha256/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)

SHA-256 for C++20 in one small class: hash a buffer in one call or stream it in
chunks, and get 64 hex characters or the raw 32 bytes. For content addressing,
deduplication, and integrity checks.

![sha256: bytes in any chunks become 64-byte blocks and a 32-byte digest](docs/sha256.svg)

## ✨ Highlights

- **One call or streaming.** `sha256("abc")`, or `add()` chunks and `getHash()`.
- **Hex or raw.** 64 lowercase hex characters, or 32 bytes into your buffer.
- **Any input.** Size-based, so embedded NULs count; buffers at any alignment are
  read safely.
- **Repeatable reads.** `getHash()` finalizes a copy, so you can keep adding.
- **Checked** against the standard vectors, every length around the padding
  boundaries, and unaligned offsets under ASan and UBSan.

## 📦 Installation

Requires a C++20 compiler and CMake 3.14 or newer; it fetches
[endian](https://github.com/Kronuz/endian) and compiles one source file. CI builds
it on Linux (x86_64, arm64), macOS (arm64, x86_64), and FreeBSD, plus ASan,
UBSan, and TSan builds.

```cmake
include(FetchContent)
FetchContent_Declare(sha256
  GIT_REPOSITORY https://github.com/Kronuz/sha256.git
  GIT_TAG        main)
FetchContent_MakeAvailable(sha256)

target_link_libraries(my_app PRIVATE sha256::sha256)
```

## 🚀 Quick start

```cpp
#include "sha256.h"

#include <cstdio>

int main() {
	SHA256 sha256;
	std::puts(sha256(std::string_view("abc")).c_str());
	// ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

	SHA256 streamed;
	streamed.add("hello, ", 7);
	streamed.add("world", 5);
	std::puts(streamed.getHash().c_str());   // same as hashing "hello, world" at once
}
```

[`examples/demo.cc`](examples/demo.cc) shows the avalanche from a one-byte change.

## 🎯 When to use it

- ✅ Fingerprints of content: cache keys, deduplication, checksums of stored
  data.
- ❌ Passwords, signatures, or MACs: use a reviewed cryptography library (with
  HMAC or a password hash); this implementation is not hardened against side
  channels.
- ❌ Raw speed on large data: it is portable C++, with no SHA instructions.

## 📚 Documentation

- [docs/API.md](docs/API.md): the `SHA256` class.
- [ARCHITECTURE.md](ARCHITECTURE.md): buffering, the compression function, and
  finalization.
- [AGENTS.md](AGENTS.md): repository map and invariants.

## 🛠️ Building and testing

```sh
cmake -B build && cmake --build build && ctest --test-dir build
./build/sha256_demo
```

## 🤝 Contributing

Issues and pull requests are welcome. Read [AGENTS.md](AGENTS.md) first. CI must
pass on every platform.

## 📄 License

MIT, Copyright (c) 2015-2018 Dubalu LLC; portions Copyright (c) 2014, 2015 Stephan
Brumme. See [LICENSE](LICENSE). Extracted from
[Xapiand](https://github.com/Kronuz/Xapiand).
