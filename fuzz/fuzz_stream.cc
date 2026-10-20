// libFuzzer target: any byte string, streamed in input-chosen chunk sizes through
// every available kernel and both APIs, digests to the portable one-shot result.
#include "sha256.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace sha = kronuz::sha256;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
	// The first byte seeds the chunk sizes; the rest is the message.
	const std::uint8_t seed = size ? data[0] : 0;
	const std::uint8_t* msg = size ? data + 1 : data;
	const std::size_t n = size ? size - 1 : 0;

	sha::force_kernel(sha::kernel::portable);
	const sha::digest_type expected = sha::digest(msg, n);

	for (sha::kernel k : {sha::kernel::portable, sha::kernel::sha_ni, sha::kernel::armv8}) {
		if (!sha::force_kernel(k)) continue;
		if (sha::digest(msg, n) != expected) std::abort();

		sha::hasher h;
		SHA256 old;
		std::uint32_t state = seed * 2654435761u + 1;
		for (std::size_t pos = 0; pos < n;) {
			state = state * 1103515245u + 12345u;
			std::size_t chunk = (state >> 16) % 200;  // zero-length updates included
			if (chunk > n - pos) chunk = n - pos;
			h.update(msg + pos, chunk);
			old.add(msg + pos, chunk);
			pos += chunk;
			if ((state & 7) == 0) (void)h.final();  // reading mid-stream must not end it
		}
		if (h.final() != expected) std::abort();
		unsigned char raw[SHA256::HashBytes];
		old.getHash(raw);
		if (std::memcmp(raw, expected.data(), sizeof(raw)) != 0) std::abort();
	}
	sha::reset_kernel();
	return 0;
}
