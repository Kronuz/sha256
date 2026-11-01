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
  CI runners below they run within about 1% of OpenSSL EVP on bulk data (6% behind with GCC on
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
  portable kernel is about 2x slower than OpenSSL's vectorized assembly there.

## ⚡ Performance

GB/s (1e9 bytes/s) to hash one message on one thread, from `sha256_bench`: the best of five passes
in a Release build. *sha256* is this library on the kernel its CPU selects: `armv8` (the arm64 SHA2
instructions) or `sha-ni` (the x86-64 SHA extensions). *Portable* is this library's plain C++
rounds, forced with `force_kernel`, and the only kernel on a CPU with neither. *OpenSSL EVP* is
`EVP_DigestInit_ex`, `EVP_DigestUpdate` and `EVP_DigestFinal_ex` on a reused context from the
[OpenSSL](https://github.com/openssl/openssl) named in the first column. The bench checks that all
three return the same digests. A 64 B message is one cache-hot digest, padding included; 64 MiB is
one digest of a large buffer. The last column is sha256's throughput over EVP's, so above 1 is
faster than OpenSSL. The M4 Pro row is a laptop run on `main`; the other rows are GitHub's shared
runners from the bench jobs of [CI run 41331989169](https://github.com/Kronuz/sha256/actions/runs/41331989169),
whose kernels are the ones in this tree, so a few percent is noise.

| Machine, compiler, OpenSSL | Kernel | Message | sha256 | Portable | OpenSSL EVP | sha256 ÷ EVP |
|---|---|---|---:|---:|---:|---:|
| Apple M4 Pro, Apple clang 17, [3.5.9](https://github.com/openssl/openssl/tree/openssl-3.5.9) | armv8 | 64 B | 1.783 | 0.246 | 1.519 | 1.17 |
| | | 64 MiB | 2.980 | 0.506 | 3.012 | 0.99 |
| AMD EPYC 7763, GCC 13.3, [3.0.13](https://github.com/openssl/openssl/tree/openssl-3.0.13) | sha-ni | 64 B | 0.531 | 0.114 | 0.417 | 1.27 |
| | | 64 MiB | 1.586 | 0.258 | 1.587 | 1.00 |
| Neoverse-N2, Clang 18.1, 3.0.13 | armv8 | 64 B | 1.082 | 0.194 | 0.464 | 2.33 |
| | | 64 MiB | 2.167 | 0.408 | 2.166 | 1.00 |
| Intel Core i7-8700B (no SHA-NI), Apple clang 17, [3.6.3](https://github.com/openssl/openssl/tree/openssl-3.6.3) | portable | 64 B | 0.082 | 0.082 | 0.131 | 0.63 |
| | | 64 MiB | 0.175 | 0.175 | 0.360 | 0.49 |

On SHA-NI and ARMv8 the hardware kernel is 5.3x to 9.5x faster than the portable one on 64 MiB,
within about 1% of EVP on bulk data (4.5% ahead on the M1 runner, 6% behind with GCC on
Neoverse-N2) and 1.2x to 2.3x faster on 64-byte messages, where EVP's per-call overhead dominates. A CPU without SHA instructions
runs the portable kernel, and there EVP's vectorized assembly is 1.6x to 2.1x faster. [docs/perf/](docs/perf/README.md)
has 4 KiB messages and the other runners.

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release -DSHA256_BUILD_BENCHMARKS=ON
cmake --build build && ./build/sha256_bench
```

With several OpenSSLs installed (Homebrew's `openssl@3` and `openssl@4`), set `OPENSSL_ROOT_DIR`
so the headers and the library come from the same one; the bench prints the version of the library
that runs. `SHA256` on a 16-byte input, hex string included, takes 62 ns on the M4 Pro
(`sha256_hex_bench`, built by the same option).

## 📚 Documentation

- [docs/API.md](docs/API.md): the `SHA256` class and `kronuz::sha256`.
- [ARCHITECTURE.md](ARCHITECTURE.md): buffering, the kernels and their dispatch, and finalization.
- [docs/perf/README.md](docs/perf/README.md): every kernel and message size, on the laptop and the CI runners.
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
