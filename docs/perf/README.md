# sha256 performance

`sha256_bench` prints GB/s (1e9 bytes/s) for every kernel the host can run and for OpenSSL EVP
(`EVP_DigestInit_ex`, `EVP_DigestUpdate`, `EVP_DigestFinal_ex` on a reused context), one thread,
the best of five passes, in a Release build. *sha256 portable* is this library's plain C++ rounds;
*sha256 armv8* and *sha256 sha-ni* are the arm64 SHA2 and x86-64 SHA-NI kernels (the one the CPU
selects is named in the first line of the output). The 64 B column is one cache-hot digest, padding
included, repeated for 64 MiB in total; 64 MiB is one digest of a large buffer. The bench checks that
the digests of every column agree.

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release -DSHA256_BUILD_BENCHMARKS=ON
cmake --build build && ./build/sha256_bench
```

## Laptops

Apple M4 Pro, macOS 26, Apple clang 17, `-O3`, linked with Homebrew's `openssl@3` 3.5.9 ([openssl-3.5.9](https://github.com/openssl/openssl/tree/openssl-3.5.9)).

| Implementation | 64 B | 4 KiB | 64 MiB |
|---|---:|---:|---:|
| sha256 portable | 0.246 | 0.503 | 0.506 |
| sha256 armv8 | 1.783 | 2.955 | 2.980 |
| OpenSSL EVP | 1.519 | 2.972 | 3.012 |

Intel Core i9-9980HK (no SHA-NI), macOS 15, Apple clang 17, `-O3`, linked with Homebrew's `openssl@3` 3.6.5 ([openssl-3.6.5](https://github.com/openssl/openssl/tree/openssl-3.6.5)).

| Implementation | 64 B | 4 KiB | 64 MiB |
|---|---:|---:|---:|
| sha256 portable | 0.114 | 0.233 | 0.234 |
| OpenSSL EVP | 0.187 | 0.503 | 0.513 |

## GitHub runners

CI's `bench-*` jobs run the same program on every push to `main`. These are the jobs of
[run 41331989169](https://github.com/Kronuz/sha256/actions/runs/41331989169) (commit 607bb40; the
kernels have not changed since). The runners are shared VMs: a few percent is noise.

| Runner CPU, compiler, OpenSSL | Kernel | Message | sha256 | Portable | OpenSSL EVP |
|---|---|---|---:|---:|---:|
| AMD EPYC 7763, GCC 13.3, 3.0.13 | sha-ni | 64 B | 0.531 | 0.114 | 0.417 |
| | | 4 KiB | 1.544 | 0.252 | 1.526 |
| | | 64 MiB | 1.586 | 0.258 | 1.587 |
| Neoverse-N2, Clang 18.1.3, 3.0.13 | armv8 | 64 B | 1.082 | 0.194 | 0.464 |
| | | 4 KiB | 2.138 | 0.401 | 2.054 |
| | | 64 MiB | 2.167 | 0.408 | 2.166 |
| Neoverse-N2, GCC 13.3, 3.0.13 | armv8 | 64 B | 0.750 | 0.178 | 0.464 |
| | | 4 KiB | 1.995 | 0.380 | 2.055 |
| | | 64 MiB | 2.043 | 0.387 | 2.165 |
| Apple M1 (Virtual), Apple clang 17, 3.5.9 | armv8 | 64 B | 0.883 | 0.118 | 0.757 |
| | | 4 KiB | 1.802 | 0.209 | 1.871 |
| | | 64 MiB | 1.956 | 0.205 | 1.871 |
| Intel Core i7-8700B (no SHA-NI), Apple clang 17, 3.6.3 | portable | 64 B | 0.082 | 0.082 | 0.131 |
| | | 4 KiB | 0.162 | 0.162 | 0.344 |
| | | 64 MiB | 0.175 | 0.175 | 0.360 |

Where the CPU has SHA instructions the hardware kernel is within 1% of EVP on 64 MiB (4.5% ahead on
the M1 runner, 6% behind with GCC on Neoverse-N2) and faster on 64 B, where EVP's per-call
overhead dominates. Without them the portable kernel is 1.6x to 2.2x slower than EVP's vectorized
assembly.
