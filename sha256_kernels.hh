/*
 * Copyright (c) 2026 Germán Méndez Bravo (Kronuz)
 * MIT License; see LICENSE.
 *
 * Internal: the SHA-256 compression kernels and the dispatch that picks one.
 * Not installed or included by consumers; sha256.h is the public surface.
 */

#pragma once

#include <cstddef>
#include <cstdint>

#if !defined(SHA256_NO_HARDWARE)
#  if (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__) || defined(_MSC_VER))
#    define SHA256_HAVE_SHANI 1
#  endif
#  if (defined(__aarch64__) || defined(_M_ARM64)) && \
      (defined(__ARM_FEATURE_SHA2) || defined(__ARM_FEATURE_CRYPTO) || defined(_MSC_VER) || \
       defined(SHA256_ARMV8_KERNEL)) && \
      (!defined(__BYTE_ORDER__) || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#    define SHA256_HAVE_ARMV8 1
#  endif
#endif

namespace kronuz::sha256::detail {

// Compresses `blocks` consecutive 64-byte blocks into the eight state words.
using compress_fn = void (*)(std::uint32_t state[8], const unsigned char* data, std::size_t blocks) noexcept;

alignas(16) inline constexpr std::uint32_t round_constants[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

void compress_portable(std::uint32_t state[8], const unsigned char* data, std::size_t blocks) noexcept;

#if defined(SHA256_HAVE_SHANI)
bool shani_supported() noexcept;
void compress_shani(std::uint32_t state[8], const unsigned char* data, std::size_t blocks) noexcept;
#endif

#if defined(SHA256_HAVE_ARMV8)
bool armv8_supported() noexcept;
void compress_armv8(std::uint32_t state[8], const unsigned char* data, std::size_t blocks) noexcept;
#endif

// The active kernel: detected once and cached, unless a test forced one.
compress_fn compress() noexcept;

// Absorbs bytes through a 64-byte buffer holding `buffered` bytes.
void absorb(std::uint32_t state[8], unsigned char buffer[64], std::size_t& buffered,
            const unsigned char* data, std::size_t size) noexcept;

// Pads the buffered tail of a `total`-byte message and compresses it into state.
void finish(std::uint32_t state[8], const unsigned char* buffer, std::size_t buffered,
            std::uint64_t total) noexcept;

}  // namespace kronuz::sha256::detail
