/*
 * Copyright © 2026 Germán Méndez Bravo (Kronuz)
 * Copyright (c) 2015-2019 Dubalu LLC
 * Copyright (c) 2014,2015 Stephan Brumme
 * see http://create.stephan-brumme.com/disclaimer.html
 *
 * This software is provided 'as-is', without any express or
 * implied warranty. In no event will the author be held liable
 * for any damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute
 * it freely, subject to the following restrictions:
 *    + The origin of this software must not be misrepresented; you must
 *      not claim that you wrote the original software.
 *    + If you use this software in a product, an acknowledgment in the
 *      product documentation would be appreciated but is not required.
 *    + Altered source versions must be plainly marked as such, and must
 *      not be misrepresented as being the original software.
 */

#include "sha256.h"

#include "sha256_kernels.hh"

#include "endian.hh"
#include <atomic>
#include <cstring>


/// same as reset()
SHA256::SHA256()
{
	reset();
}


/// restart
void SHA256::reset()
{
	m_numBytes   = 0;
	m_bufferSize = 0;

	// according to RFC 1321
	m_hash[0] = 0x6a09e667;
	m_hash[1] = 0xbb67ae85;
	m_hash[2] = 0x3c6ef372;
	m_hash[3] = 0xa54ff53a;
	m_hash[4] = 0x510e527f;
	m_hash[5] = 0x9b05688c;
	m_hash[6] = 0x1f83d9ab;
	m_hash[7] = 0x5be0cd19;
}


namespace
{
	inline uint32_t rotate(uint32_t a, uint32_t c)
	{
		return (a >> c) | (a << (32 - c));
	}

#if __BYTE_ORDER == __LITTLE_ENDIAN
	inline uint32_t swap(uint32_t x)
	{
#if defined(__GNUC__) || defined(__clang__)
		return __builtin_bswap32(x);
#endif
#ifdef MSC_VER
		return _byteswap_ulong(x);
#endif

		return (x >> 24) |
			((x >>  8) & 0x0000FF00) |
			((x <<  8) & 0x00FF0000) |
			(x << 24);
	}
#endif

	// mix functions for processBlock()
	inline uint32_t f1(uint32_t e, uint32_t f, uint32_t g)
	{
		uint32_t term1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
		uint32_t term2 = (e & f) ^ (~e & g); //(g ^ (e & (f ^ g)))
		return term1 + term2;
	}

	inline uint32_t f2(uint32_t a, uint32_t b, uint32_t c)
	{
		uint32_t term1 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
		uint32_t term2 = ((a | b) & c) | (a & b); //(a & (b ^ c)) ^ (b & c);
		return term1 + term2;
	}
}


namespace
{
/// process 64 bytes
inline void compressBlock(uint32_t m_hash[8], const void* data)
{
	// get last hash
	uint32_t a = m_hash[0];
	uint32_t b = m_hash[1];
	uint32_t c = m_hash[2];
	uint32_t d = m_hash[3];
	uint32_t e = m_hash[4];
	uint32_t f = m_hash[5];
	uint32_t g = m_hash[6];
	uint32_t h = m_hash[7];

	// data represented as 16x 32-bit words
	const auto* input = static_cast<const unsigned char*>(data);
	// convert to big endian
	uint32_t words[64];
	int i;
	for (i = 0; i < 16; ++i)
	{
		// Caller buffers may be unaligned and need not contain uint32_t objects.
		uint32_t word;
		std::memcpy(&word, input + i * sizeof(word), sizeof(word));
#if __BYTE_ORDER == __BIG_ENDIAN
		words[i] =      word;
#else
		words[i] = swap(word);
#endif
	}

	uint32_t x,y; // temporaries

	// first round
	x = h + f1(e,f,g) + 0x428a2f98 + words[ 0]; y = f2(a,b,c); d += x; h = x + y;
	x = g + f1(d,e,f) + 0x71374491 + words[ 1]; y = f2(h,a,b); c += x; g = x + y;
	x = f + f1(c,d,e) + 0xb5c0fbcf + words[ 2]; y = f2(g,h,a); b += x; f = x + y;
	x = e + f1(b,c,d) + 0xe9b5dba5 + words[ 3]; y = f2(f,g,h); a += x; e = x + y;
	x = d + f1(a,b,c) + 0x3956c25b + words[ 4]; y = f2(e,f,g); h += x; d = x + y;
	x = c + f1(h,a,b) + 0x59f111f1 + words[ 5]; y = f2(d,e,f); g += x; c = x + y;
	x = b + f1(g,h,a) + 0x923f82a4 + words[ 6]; y = f2(c,d,e); f += x; b = x + y;
	x = a + f1(f,g,h) + 0xab1c5ed5 + words[ 7]; y = f2(b,c,d); e += x; a = x + y;

	// secound round
	x = h + f1(e,f,g) + 0xd807aa98 + words[ 8]; y = f2(a,b,c); d += x; h = x + y;
	x = g + f1(d,e,f) + 0x12835b01 + words[ 9]; y = f2(h,a,b); c += x; g = x + y;
	x = f + f1(c,d,e) + 0x243185be + words[10]; y = f2(g,h,a); b += x; f = x + y;
	x = e + f1(b,c,d) + 0x550c7dc3 + words[11]; y = f2(f,g,h); a += x; e = x + y;
	x = d + f1(a,b,c) + 0x72be5d74 + words[12]; y = f2(e,f,g); h += x; d = x + y;
	x = c + f1(h,a,b) + 0x80deb1fe + words[13]; y = f2(d,e,f); g += x; c = x + y;
	x = b + f1(g,h,a) + 0x9bdc06a7 + words[14]; y = f2(c,d,e); f += x; b = x + y;
	x = a + f1(f,g,h) + 0xc19bf174 + words[15]; y = f2(b,c,d); e += x; a = x + y;

	// extend to 24 words
	for (; i < 24; ++i)
	{
		words[i] = words[i-16] +
				(rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
				words[i-7] +
				(rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));
	}

	// third round
	x = h + f1(e,f,g) + 0xe49b69c1 + words[16]; y = f2(a,b,c); d += x; h = x + y;
	x = g + f1(d,e,f) + 0xefbe4786 + words[17]; y = f2(h,a,b); c += x; g = x + y;
	x = f + f1(c,d,e) + 0x0fc19dc6 + words[18]; y = f2(g,h,a); b += x; f = x + y;
	x = e + f1(b,c,d) + 0x240ca1cc + words[19]; y = f2(f,g,h); a += x; e = x + y;
	x = d + f1(a,b,c) + 0x2de92c6f + words[20]; y = f2(e,f,g); h += x; d = x + y;
	x = c + f1(h,a,b) + 0x4a7484aa + words[21]; y = f2(d,e,f); g += x; c = x + y;
	x = b + f1(g,h,a) + 0x5cb0a9dc + words[22]; y = f2(c,d,e); f += x; b = x + y;
	x = a + f1(f,g,h) + 0x76f988da + words[23]; y = f2(b,c,d); e += x; a = x + y;

	// extend to 32 words
	for (; i < 32; ++i)
	{
		words[i] = words[i-16] +
				(rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
				words[i-7] +
				(rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));
	}

	// fourth round
	x = h + f1(e,f,g) + 0x983e5152 + words[24]; y = f2(a,b,c); d += x; h = x + y;
	x = g + f1(d,e,f) + 0xa831c66d + words[25]; y = f2(h,a,b); c += x; g = x + y;
	x = f + f1(c,d,e) + 0xb00327c8 + words[26]; y = f2(g,h,a); b += x; f = x + y;
	x = e + f1(b,c,d) + 0xbf597fc7 + words[27]; y = f2(f,g,h); a += x; e = x + y;
	x = d + f1(a,b,c) + 0xc6e00bf3 + words[28]; y = f2(e,f,g); h += x; d = x + y;
	x = c + f1(h,a,b) + 0xd5a79147 + words[29]; y = f2(d,e,f); g += x; c = x + y;
	x = b + f1(g,h,a) + 0x06ca6351 + words[30]; y = f2(c,d,e); f += x; b = x + y;
	x = a + f1(f,g,h) + 0x14292967 + words[31]; y = f2(b,c,d); e += x; a = x + y;

	// extend to 40 words
	for (; i < 40; ++i)
	{
		words[i] = words[i-16] +
				(rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
				words[i-7] +
				(rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));
	}

	// fifth round
	x = h + f1(e,f,g) + 0x27b70a85 + words[32]; y = f2(a,b,c); d += x; h = x + y;
	x = g + f1(d,e,f) + 0x2e1b2138 + words[33]; y = f2(h,a,b); c += x; g = x + y;
	x = f + f1(c,d,e) + 0x4d2c6dfc + words[34]; y = f2(g,h,a); b += x; f = x + y;
	x = e + f1(b,c,d) + 0x53380d13 + words[35]; y = f2(f,g,h); a += x; e = x + y;
	x = d + f1(a,b,c) + 0x650a7354 + words[36]; y = f2(e,f,g); h += x; d = x + y;
	x = c + f1(h,a,b) + 0x766a0abb + words[37]; y = f2(d,e,f); g += x; c = x + y;
	x = b + f1(g,h,a) + 0x81c2c92e + words[38]; y = f2(c,d,e); f += x; b = x + y;
	x = a + f1(f,g,h) + 0x92722c85 + words[39]; y = f2(b,c,d); e += x; a = x + y;

	// extend to 48 words
	for (; i < 48; ++i)
	{
		words[i] = words[i-16] +
				(rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
				words[i-7] +
				(rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));
	}

	// sixth round
	x = h + f1(e,f,g) + 0xa2bfe8a1 + words[40]; y = f2(a,b,c); d += x; h = x + y;
	x = g + f1(d,e,f) + 0xa81a664b + words[41]; y = f2(h,a,b); c += x; g = x + y;
	x = f + f1(c,d,e) + 0xc24b8b70 + words[42]; y = f2(g,h,a); b += x; f = x + y;
	x = e + f1(b,c,d) + 0xc76c51a3 + words[43]; y = f2(f,g,h); a += x; e = x + y;
	x = d + f1(a,b,c) + 0xd192e819 + words[44]; y = f2(e,f,g); h += x; d = x + y;
	x = c + f1(h,a,b) + 0xd6990624 + words[45]; y = f2(d,e,f); g += x; c = x + y;
	x = b + f1(g,h,a) + 0xf40e3585 + words[46]; y = f2(c,d,e); f += x; b = x + y;
	x = a + f1(f,g,h) + 0x106aa070 + words[47]; y = f2(b,c,d); e += x; a = x + y;

	// extend to 56 words
	for (; i < 56; ++i)
	{
		words[i] = words[i-16] +
				(rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
				words[i-7] +
				(rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));
	}

	// seventh round
	x = h + f1(e,f,g) + 0x19a4c116 + words[48]; y = f2(a,b,c); d += x; h = x + y;
	x = g + f1(d,e,f) + 0x1e376c08 + words[49]; y = f2(h,a,b); c += x; g = x + y;
	x = f + f1(c,d,e) + 0x2748774c + words[50]; y = f2(g,h,a); b += x; f = x + y;
	x = e + f1(b,c,d) + 0x34b0bcb5 + words[51]; y = f2(f,g,h); a += x; e = x + y;
	x = d + f1(a,b,c) + 0x391c0cb3 + words[52]; y = f2(e,f,g); h += x; d = x + y;
	x = c + f1(h,a,b) + 0x4ed8aa4a + words[53]; y = f2(d,e,f); g += x; c = x + y;
	x = b + f1(g,h,a) + 0x5b9cca4f + words[54]; y = f2(c,d,e); f += x; b = x + y;
	x = a + f1(f,g,h) + 0x682e6ff3 + words[55]; y = f2(b,c,d); e += x; a = x + y;

	// extend to 64 words
	for (; i < 64; ++i)
	{
		words[i] = words[i-16] +
				(rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
				words[i-7] +
				(rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));
	}

	// eigth round
	x = h + f1(e,f,g) + 0x748f82ee + words[56]; y = f2(a,b,c); d += x; h = x + y;
	x = g + f1(d,e,f) + 0x78a5636f + words[57]; y = f2(h,a,b); c += x; g = x + y;
	x = f + f1(c,d,e) + 0x84c87814 + words[58]; y = f2(g,h,a); b += x; f = x + y;
	x = e + f1(b,c,d) + 0x8cc70208 + words[59]; y = f2(f,g,h); a += x; e = x + y;
	x = d + f1(a,b,c) + 0x90befffa + words[60]; y = f2(e,f,g); h += x; d = x + y;
	x = c + f1(h,a,b) + 0xa4506ceb + words[61]; y = f2(d,e,f); g += x; c = x + y;
	x = b + f1(g,h,a) + 0xbef9a3f7 + words[62]; y = f2(c,d,e); f += x; b = x + y;
	x = a + f1(f,g,h) + 0xc67178f2 + words[63]; y = f2(b,c,d); e += x; a = x + y;

	// update hash
	m_hash[0] += a;
	m_hash[1] += b;
	m_hash[2] += c;
	m_hash[3] += d;
	m_hash[4] += e;
	m_hash[5] += f;
	m_hash[6] += g;
	m_hash[7] += h;
}
}


/// the portable kernel: process `blocks` consecutive 64-byte blocks
void kronuz::sha256::detail::compress_portable(uint32_t state[8], const unsigned char* data, size_t blocks) noexcept
{
	for (; blocks > 0; --blocks, data += 64)
	{
		compressBlock(state, data);
	}
}


/// process 64 bytes
void SHA256::processBlock(const void* data)
{
	kronuz::sha256::detail::compress()(m_hash, static_cast<const unsigned char*>(data), 1);
}


/// add arbitrary number of bytes
void SHA256::add(const void* data, size_t numBytes)
{
	const size_t before = m_bufferSize;
	kronuz::sha256::detail::absorb(m_hash, m_buffer, m_bufferSize, static_cast<const unsigned char*>(data), numBytes);
	m_numBytes += before + numBytes - m_bufferSize;
}


/// process final block, less than 64 bytes
void SHA256::processBuffer()
{
	kronuz::sha256::detail::finish(m_hash, m_buffer, m_bufferSize, m_numBytes + m_bufferSize);
}


/// return latest hash as 64 hex characters
std::string SHA256::getHash()
{
	// compute hash (as raw bytes)
	unsigned char rawHash[HashBytes];
	getHash(rawHash);

	// convert to hex string
	std::string result;
	result.reserve(2 * HashBytes);
	for (unsigned char i : rawHash)
	{
		static const char dec2hex[16+1] = "0123456789abcdef";
		result += dec2hex[(i >> 4) & 15];
		result += dec2hex[ i       & 15];
	}

	return result;
}


/// return latest hash as bytes
void SHA256::getHash(unsigned char buffer[SHA256::HashBytes])
{
	// save old hash if buffer is partially filled
	uint32_t oldHash[HashValues];
	for (int i = 0; i < HashValues; ++i)
	{
		oldHash[i] = m_hash[i];
	}

	// process remaining bytes
	processBuffer();

	unsigned char* current = buffer;
	for (int i = 0; i < HashValues; ++i)
	{
		*current++ = (m_hash[i] >> 24) & 0xFF;
		*current++ = (m_hash[i] >> 16) & 0xFF;
		*current++ = (m_hash[i] >>  8) & 0xFF;
		*current++ =  m_hash[i]        & 0xFF;

		// restore old hash
		m_hash[i] = oldHash[i];
	}
}


/// compute SHA256 of a memory block
std::string SHA256::operator()(const void* data, size_t numBytes)
{
	reset();
	add(data, numBytes);
	return getHash();
}


/// compute SHA256 of a string, excluding final zero
std::string SHA256::operator()(std::string_view text)
{
	reset();
	add(text.data(), text.size());
	return getHash();
}


namespace kronuz::sha256 {

namespace detail {

void absorb(uint32_t state[8], unsigned char buffer[64], size_t& buffered, const unsigned char* data, size_t size) noexcept
{
	if (size == 0)
	{
		return;
	}
	const compress_fn fn = compress();
	if (buffered > 0)
	{
		size_t take = 64 - buffered < size ? 64 - buffered : size;
		std::memcpy(buffer + buffered, data, take);
		buffered += take;
		data += take;
		size -= take;
		if (buffered < 64)
		{
			return;
		}
		fn(state, buffer, 1);
		buffered = 0;
	}
	if (size_t blocks = size / 64)
	{
		fn(state, data, blocks);
		data += blocks * 64;
		size -= blocks * 64;
	}
	if (size > 0)
	{
		std::memcpy(buffer, data, size);
		buffered = size;
	}
}


void finish(uint32_t state[8], const unsigned char* buffer, size_t buffered, uint64_t total) noexcept
{
	// 0x80, zeros to 56 mod 64, then the bit length big-endian: one block or two.
	unsigned char tail[128];
	std::memcpy(tail, buffer, buffered);
	tail[buffered] = 0x80;
	const size_t padded = buffered < 56 ? 64 : 128;
	std::memset(tail + buffered + 1, 0, padded - 8 - buffered - 1);
	const uint64_t bits = total * 8;
	for (int i = 0; i < 8; ++i)
	{
		tail[padded - 1 - i] = static_cast<unsigned char>(bits >> (8 * i));
	}
	compress()(state, tail, padded / 64);
}


namespace {

compress_fn kernel_fn(kernel k) noexcept
{
	switch (k)
	{
#if defined(SHA256_HAVE_SHANI)
		case kernel::sha_ni:
			return shani_supported() ? compress_shani : nullptr;
#endif
#if defined(SHA256_HAVE_ARMV8)
		case kernel::armv8:
			return armv8_supported() ? compress_armv8 : nullptr;
#endif
		case kernel::portable:
			return compress_portable;
		default:
			return nullptr;
	}
}

compress_fn detect() noexcept
{
	for (kernel k : {kernel::sha_ni, kernel::armv8})
	{
		if (compress_fn fn = kernel_fn(k))
		{
			return fn;
		}
	}
	return compress_portable;
}

// Null until first use; every kernel computes the same function, so a racing
// first store or a force mid-stream is harmless.
std::atomic<compress_fn> active{nullptr};

}  // namespace


compress_fn compress() noexcept
{
	compress_fn fn = active.load(std::memory_order_relaxed);
	if (fn == nullptr)
	{
		fn = detect();
		active.store(fn, std::memory_order_relaxed);
	}
	return fn;
}

}  // namespace detail


void hasher::init() noexcept
{
	static constexpr uint32_t initial[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	};
	std::memcpy(state_, initial, sizeof(state_));
	length_ = 0;
}


void hasher::update(const void* data, size_t size) noexcept
{
	size_t buffered = static_cast<size_t>(length_ % block_size);
	detail::absorb(state_, buffer_, buffered, static_cast<const unsigned char*>(data), size);
	length_ += size;
}


void hasher::final(unsigned char out[digest_size]) const noexcept
{
	uint32_t state[8];
	std::memcpy(state, state_, sizeof(state));
	detail::finish(state, buffer_, static_cast<size_t>(length_ % block_size), length_);
	for (int i = 0; i < 8; ++i)
	{
		out[4 * i + 0] = static_cast<unsigned char>(state[i] >> 24);
		out[4 * i + 1] = static_cast<unsigned char>(state[i] >> 16);
		out[4 * i + 2] = static_cast<unsigned char>(state[i] >> 8);
		out[4 * i + 3] = static_cast<unsigned char>(state[i]);
	}
}


digest_type hasher::final() const noexcept
{
	digest_type out;
	final(out.data());
	return out;
}


digest_type digest(const void* data, size_t size) noexcept
{
	hasher h;
	h.update(data, size);
	return h.final();
}


std::string to_hex(const digest_type& digest)
{
	static const char dec2hex[16 + 1] = "0123456789abcdef";
	std::string result;
	result.reserve(2 * digest.size());
	for (unsigned char byte : digest)
	{
		result += dec2hex[byte >> 4];
		result += dec2hex[byte & 15];
	}
	return result;
}


kernel active_kernel() noexcept
{
	const detail::compress_fn fn = detail::compress();
#if defined(SHA256_HAVE_SHANI)
	if (fn == detail::compress_shani)
	{
		return kernel::sha_ni;
	}
#endif
#if defined(SHA256_HAVE_ARMV8)
	if (fn == detail::compress_armv8)
	{
		return kernel::armv8;
	}
#endif
	(void)fn;
	return kernel::portable;
}


bool kernel_available(kernel k) noexcept
{
	return detail::kernel_fn(k) != nullptr;
}


const char* kernel_name(kernel k) noexcept
{
	switch (k)
	{
		case kernel::portable: return "portable";
		case kernel::sha_ni: return "sha-ni";
		case kernel::armv8: return "armv8";
	}
	return "unknown";
}


bool force_kernel(kernel k) noexcept
{
	detail::compress_fn fn = detail::kernel_fn(k);
	if (fn == nullptr)
	{
		return false;
	}
	detail::active.store(fn, std::memory_order_relaxed);
	return true;
}


void reset_kernel() noexcept
{
	detail::active.store(detail::detect(), std::memory_order_relaxed);
}

}  // namespace kronuz::sha256
