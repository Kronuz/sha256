# sha256

Part of [Kronuz C++ Libraries](https://github.com/Kronuz/cpp-libraries), a collection of small, reusable C++ libraries.

[![CI](https://github.com/Kronuz/sha256/actions/workflows/ci.yml/badge.svg)](https://github.com/Kronuz/sha256/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)

SHA-256 for C++20: one call or streaming, hex or raw digest, on the CPU's SHA instructions when it
has them. Blocks run on SHA-NI on x86_64 and the SHA2 extension on arm64, picked once at run time,
and on portable C++ otherwise. Reach for it for content addressing, deduplication and integrity
checks without linking OpenSSL.

## ✨ Highlights

- **One call or streaming.** `kronuz::sha256::digest("abc")`, or `update()` in chunks and
  `final()`; the `SHA256` class (`add()`, `getHash()`) keeps Xapiand's interface.
- **Hardware speed, one binary.** The SHA-NI and ARMv8 kernels are detected at first use. On the
  CI runners below they run within 1% of OpenSSL EVP on bulk data (6% behind with GCC on
  Neoverse-N2) and ahead of it on 64-byte messages.
- **No clash with OpenSSL.** The namespaced API compiles next to `<openssl/sha.h>`, whose global
  `SHA256()` hides the class of the same name.
- **Hex or raw.** 64 lowercase hex characters, or 32 bytes into your buffer.
- **Any input.** Size-based, so embedded NULs count; buffers at any alignment are read safely.
- **Repeatable reads.** `getHash()` finalizes a copy, so you can keep adding.
- **Checked** for every kernel the host has: NIST vectors, every split point, random inputs
  against the portable kernel, unaligned offsets under ASan and UBSan, and a libFuzzer target.

## 🚀 Quick start

```cpp
#include "sha256.h"

#include <cstdio>

int main() {
	namespace sha = kronuz::sha256;
	std::puts(sha::to_hex(sha::digest("abc")).c_str());
	// ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

	sha::hasher h;
	h.update("hello, ");
	h.update("world");
	std::puts(sha::to_hex(h.final()).c_str());  // the same as hashing "hello, world" at once
	// 09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b

	std::puts(sha::kernel_name(sha::active_kernel()));  // "sha-ni", "armv8" or "portable"

	SHA256 sha256;  // the Xapiand-compatible class, same digests
	std::puts(sha256(std::string_view("abc")).c_str());
	// ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
}
```

[`examples/demo.cc`](examples/demo.cc) shows the avalanche from a one-byte change.

## 📦 Installation

Requires a C++20 compiler and CMake 3.14 or newer. CMake fetches
[endian](https://github.com/Kronuz/endian) at a pinned commit; the library compiles three source
files, and `-DSHA256_HARDWARE=OFF` builds the portable kernel alone. CI builds and tests it on
Linux (x86_64 with GCC and Clang, arm64), macOS (arm64, x86_64) and FreeBSD, plus ASan + UBSan
and TSan builds.

```cmake
include(FetchContent)
FetchContent_Declare(sha256
  GIT_REPOSITORY https://github.com/Kronuz/sha256.git
  GIT_TAG        eb46cb6240e63bfae515bab4ee91784d6176528b)  # or main to track the tip
FetchContent_MakeAvailable(sha256)

target_link_libraries(my_app PRIVATE sha256::sha256)
```

```cpp
#include "sha256.h"
```

## 🎯 When to use it

Fingerprints of content (cache keys, deduplication, checksums of stored data), and bulk hashing of
segments or files without linking OpenSSL on CPUs with SHA instructions.

Not for:

- Passwords, signatures, or MACs: use a reviewed cryptography library, with HMAC or a password
  hash. This implementation is not hardened against side channels.
- Bulk hashing on x86_64 without SHA-NI (Intel cores before Ice Lake; every AMD Zen has it): the
  portable kernel is about 2.2x slower than OpenSSL's vectorized assembly there.

## ⚡ Performance

GB/s (1e9 bytes/s), one thread, best of five, from `sha256_bench` in a Release build against
OpenSSL EVP (`EVP_DigestInit_ex`/`Update`/`Final_ex` on a reused context). 64 B is a one-shot
digest of a cache-hot message, padding and final block included; 64 MiB is one digest. GitHub's
runners are shared VMs, so treat a few percent as noise; EVP in the same run is the reference.

| Host (compiler, OpenSSL) | Kernel | 64 B | 64 MiB | EVP 64 B | EVP 64 MiB | Portable 64 MiB |
|---|---|---:|---:|---:|---:|---:|
| AMD EPYC 9V74, Linux runner (GCC 13.3, 3.0.13) | sha-ni | **0.474** | **1.409** | 0.417 | 1.407 | 0.274 |
| Intel Xeon Platinum 8370C, Linux runner (GCC 13.3, 3.0.13) | sha-ni | **0.454** | **1.314** | 0.382 | 1.307 | 0.221 |
| Neoverse-N2, Linux arm64 runner (Clang 18.1, 3.0.13) | armv8 | **1.090** | **2.166** | 0.464 | 2.165 | 0.408 |
| Neoverse-N2, Linux arm64 runner (GCC 13.3, 3.0.13) | armv8 | **0.755** | **2.043** | 0.464 | 2.163 | 0.387 |
| Apple M1 (Virtual), macOS runner (Apple clang 17, 3.6.4) | armv8 | **1.167** | **2.263** | 0.926 | 2.284 | 0.277 |
| Intel Core i7-8700B, macOS runner, no SHA-NI (Apple clang 17, 3.6.3) | portable | 0.083 | 0.238 | 0.125 | 0.498 | 0.238 |
| Intel Core i9-9980HK, MacBook Pro, no SHA-NI (Apple clang 17, 4.0.3) | portable | 0.114 | 0.242 | 0.200 | 0.536 | 0.242 |

On SHA-NI and ARMv8 cores the hardware kernel is 5.1x to 8.2x faster than the portable one on
64 MiB and within 1% of EVP there (GCC on Neoverse-N2: EVP 1.06x faster), and 1.1x to 2.3x faster
than EVP on 64-byte messages, where EVP's per-call overhead dominates. Without SHA instructions
EVP's vectorized assembly is 2.1x to 2.2x faster than the portable kernel.

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release -DSHA256_BUILD_BENCHMARKS=ON
cmake --build build && ./build/sha256_bench
```

The bench also prints 4 KiB digests. With several OpenSSLs installed (Homebrew's `openssl@3` and
`openssl@4`), set `OPENSSL_ROOT_DIR` so the headers and the library come from the same one; the
bench prints the header's version. CI's `bench-*` jobs print the same table, with the runner's
CPU, on every manual run; the runner rows above come from runs 39356786780 and 39356305207 (the
Xeon row), whose kernels match this tree.

`SHA256` on a 16-byte input, hex string included, takes about 60 ns on an Apple M4 Pro (`-O3`);
`sha256_hex_bench`, built by the same option, measures it.

## 📚 Documentation

- [docs/API.md](docs/API.md): the `SHA256` class and `kronuz::sha256`.
- [ARCHITECTURE.md](ARCHITECTURE.md): buffering, the kernels and their dispatch, and finalization.
- [CHANGELOG.md](CHANGELOG.md): dated changes.
- [AGENTS.md](AGENTS.md): repository map and invariants.
- [Catalog entry](https://github.com/Kronuz/cpp-libraries/blob/main/AGENTS.md#sha256) in Kronuz C++
  Libraries.

## 🛠️ Building and testing

```sh
cmake -B build && cmake --build build && ctest --test-dir build
./build/sha256_demo
cmake -B build -DSHA256_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++ && cmake --build build && ./build/sha256_fuzz -max_total_time=60
cmake -B build -DCMAKE_BUILD_TYPE=Release -DSHA256_BUILD_BENCHMARKS=ON && cmake --build build && ./build/sha256_bench
```

CTest runs `sha256` (the class), `sha256_kernels` (every kernel the host has, plus the forced
portable fallback) and, when CMake finds OpenSSL, `sha256_openssl` (both headers in one file,
digests against OpenSSL's `SHA256()`). A host without SHA instructions tests the portable kernel
only; CI covers SHA-NI and ARMv8.

## 🤝 Contributing

Issues and pull requests are welcome. Read [AGENTS.md](AGENTS.md) and the catalog's
[rules of engagement](https://github.com/Kronuz/cpp-libraries/blob/main/AGENTS.md#rules-of-engagement)
first; CI must pass on every platform.

## 📄 License

MIT. See [LICENSE](LICENSE). Extracted from [Xapiand](https://github.com/Kronuz/Xapiand)
(Copyright © 2015-2020 Dubalu LLC); the portable kernel derives from Stephan Brumme's SHA-256
(Copyright © 2014, 2015 Stephan Brumme).
