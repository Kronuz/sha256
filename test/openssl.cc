// Built only when CMake finds OpenSSL. One translation unit includes both headers:
// OpenSSL's global SHA256() hides the class, the namespaced API still compiles, and
// both agree with OpenSSL's one-shot SHA256() for every kernel the host has.
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>

#include "sha256.h"

#include <cstdio>
#include <cstring>
#include <vector>

namespace sha = kronuz::sha256;

int main() {
	std::vector<unsigned char> data(70000);
	std::uint64_t x = 0x243f6a8885a308d3ull;
	for (auto& b : data) {
		x = x * 6364136223846793005ull + 1442695040888963407ull;
		b = static_cast<unsigned char>(x >> 56);
	}
	int failures = 0, kernels = 0;
	for (sha::kernel k : {sha::kernel::portable, sha::kernel::sha_ni, sha::kernel::armv8}) {
		if (!sha::force_kernel(k)) continue;
		++kernels;
		for (std::size_t n = 0; n < data.size(); n = n < 300 ? n + 1 : n * 3 / 2) {
			unsigned char expected[SHA256_DIGEST_LENGTH];
			SHA256(data.data() + n % 7, n, expected);  // OpenSSL's function
			class SHA256 old;                          // the class, spelled out
			old.add(data.data() + n % 7, n);
			unsigned char raw[SHA256::HashBytes];
			old.getHash(raw);
			if (std::memcmp(sha::digest(data.data() + n % 7, n).data(), expected, 32) != 0 ||
			    std::memcmp(raw, expected, 32) != 0) {
				std::fprintf(stderr, "[%s] length %zu differs from OpenSSL\n", sha::kernel_name(k), n);
				++failures;
			}
		}
	}
	sha::reset_kernel();
	if (failures) return 1;
	std::printf("sha256 matches OpenSSL SHA256() for %d kernels\n", kernels);
	return 0;
}
