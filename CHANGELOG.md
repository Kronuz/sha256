# Changelog

Notable changes to `sha256`, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 2026-10-30

### Changed

- `SHA256::getHash()` and `kronuz::sha256::to_hex` size the hex string once
  and fill two characters per byte, instead of appending one character at a time
  with `+=`. Output is identical (a differential test against the byte-at-a-time
  conversion covers lengths 0 to 300). `SHA256` on a 16-byte input went from
  about 252 ns to 60 ns (Apple M4 Pro, -O3, `sha256_hex_bench`). The kernels are
  unchanged.

### Added

- `bench/hex_bench.cc` (`sha256_hex_bench`).

## 2026-10-28 and earlier

### Added

- Hardware kernels (SHA-NI on x86_64, the SHA2 extension on arm64) behind one
  cached atomic function pointer, picked at run time, plus the
  `kronuz::sha256` API (`hasher`, `digest()`, `to_hex()`, kernel queries).
  Consumers were bypassing this library for OpenSSL's EVP on bulk data
  (CL-10 of the 2026-10-19 consolidation audit). The `SHA256` class routes
  through the same `absorb()` / `finish()` with its layout and digests
  unchanged. The work log is `docs/status/cl-10.md`.
- Reordering the ARMv8 kernel's copies took Neoverse-N2 at 64 MiB from 1.667 to
  2.043 GB/s (GCC) and from 1.668 to 2.166 GB/s (Clang), against EVP's 2.16
  (CI runs 39356522009 and 39356786780).
- `sha256_bench`, the `sha256_kernels` and `sha256_openssl` tests, and the
  `sha256_fuzz` libFuzzer target.

### Fixed

- Intermediate padding-pointer arithmetic could form a pointer outside the
  buffer. It now subtracts the block size before forming a pointer. Published
  digest vectors are unchanged.
- The portable kernel cast the input to `uint32_t*` and dereferenced it, which
  UBSan flagged on a buffer starting one byte after an aligned address. It loads
  each word with a fixed-size `memcpy`; the offset and streaming fixtures keep
  the case covered. No public layout or digest bytes changed.
