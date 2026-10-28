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

#pragma once

#include <array>        // for array
#include <cstdint>
#include <stddef.h>     // for size_t
#include <string>       // for string
#include <string_view>  // for string_view
#include <sys/types.h>  // for uint32_t, uint64_t, uint8_t


/*
 * Compute SHA256 hash
 *
 * Usage:
 *  SHA256 sha256;
 *  std::string myHash  = sha256("Hello World");     // std::string
 *  std::string myHash2 = sha256("How are you", 11); // arbitrary data, 11 bytes
 *
 *  or in a streaming fashion:
 *
 *  SHA256 sha256;
 *  while (more data available)
 *  	sha256.add(pointer to fresh data, number of new bytes);
 *  std::string myHash3 = sha256.getHash();
*/
class SHA256 {
public:
	/// split into 64 byte blocks (=> 512 bits), hash is 32 bytes long
	enum { BlockSize = 512 / 8, HashBytes = 32 };

	/// same as reset()
	SHA256();

	/// compute SHA256 of a memory block
	std::string operator()(const void* data, size_t numBytes);
	/// compute SHA256 of a string, excluding final zero
	std::string operator()(std::string_view text);

	/// add arbitrary number of bytes
	void add(const void* data, size_t numBytes);

	/// return latest hash as 64 hex characters
	std::string getHash();
	/// return latest hash as bytes
	void        getHash(unsigned char buffer[HashBytes]);

	/// restart
	void reset();

private:
	/// process 64 bytes
	void processBlock(const void* data);
	/// process everything left in the internal buffer
	void processBuffer();

	/// size of processed data in bytes
	uint64_t m_numBytes;
	/// valid bytes in m_buffer
	size_t   m_bufferSize;
	/// bytes not processed yet
	uint8_t  m_buffer[BlockSize];

	enum { HashValues = HashBytes / 4 };
	/// hash, stored as integers
	uint32_t m_hash[HashValues];
};


/*
 * The namespaced API: same digest, no clash with OpenSSL's SHA256() symbol.
 *
 *  auto d = kronuz::sha256::digest("abc");          // std::array of 32 bytes
 *
 *  kronuz::sha256::hasher h;
 *  while (more data available)
 *  	h.update(pointer to fresh data, number of new bytes);
 *  auto d2 = h.final();                              // state stays appendable
 *
 * Every block runs through the fastest kernel the CPU has (SHA-NI on x86_64,
 * the SHA2 extension on arm64, portable C++ otherwise), picked once at first use.
 */
namespace kronuz::sha256 {

inline constexpr std::size_t block_size = 64;
inline constexpr std::size_t digest_size = 32;
using digest_type = std::array<unsigned char, digest_size>;

class hasher {
public:
	hasher() noexcept { init(); }

	/// restart at the empty message
	void init() noexcept;

	/// append bytes
	void update(const void* data, std::size_t size) noexcept;
	void update(std::string_view text) noexcept { update(text.data(), text.size()); }

	/// digest of everything appended so far; does not end the stream
	digest_type final() const noexcept;
	void final(unsigned char out[digest_size]) const noexcept;

private:
	std::uint32_t state_[8];
	std::uint64_t length_;  // bytes appended
	unsigned char buffer_[block_size];
};

/// one-shot digest
digest_type digest(const void* data, std::size_t size) noexcept;
inline digest_type digest(std::string_view text) noexcept { return digest(text.data(), text.size()); }

/// 64 lowercase hex characters
std::string to_hex(const digest_type& digest);

enum class kernel : unsigned char { portable, sha_ni, armv8 };

/// the kernel that hashes now
kernel active_kernel() noexcept;
/// whether this build and CPU can run `k`
bool kernel_available(kernel k) noexcept;
/// "portable", "sha-ni" or "armv8"
const char* kernel_name(kernel k) noexcept;

/// Test and benchmark hook: pin a kernel process-wide; false (and no change)
/// when it is unavailable. reset_kernel() returns to the detected one.
bool force_kernel(kernel k) noexcept;
void reset_kernel() noexcept;

}  // namespace kronuz::sha256
