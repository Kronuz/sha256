/*
 * Copyright (c) 2026 Germán Méndez Bravo (Kronuz)
 * MIT License; see LICENSE.
 *
 * The arm64 SHA2-extension kernel and its feature check. CMake compiles this
 * file with +crypto where the toolchain does not enable it by default.
 */

#include "sha256_kernels.hh"

#if defined(SHA256_HAVE_ARMV8)

#include <arm_neon.h>

#if defined(__APPLE__)
#  include <sys/sysctl.h>
#elif defined(__linux__) || defined(__FreeBSD__)
#  include <sys/auxv.h>
#  if defined(__linux__)
#    include <asm/hwcap.h>
#  else
#    include <machine/elf.h>
#  endif
#  ifndef HWCAP_SHA2
#    define HWCAP_SHA2 (1 << 6)
#  endif
#elif defined(_WIN32)
#  include <windows.h>
#endif

#if defined(__GNUC__) || defined(__clang__)
#  define SHA256_SEPARATE(v) __asm__("" : "+w"(v))
#else
#  define SHA256_SEPARATE(v) ((void)0)
#endif

namespace kronuz::sha256::detail {

bool armv8_supported() noexcept
{
#if defined(__APPLE__)
	// Every Apple arm64 core has SHA2; ask anyway when the build does not assume it.
#  if defined(__ARM_FEATURE_SHA2) || defined(__ARM_FEATURE_CRYPTO)
	return true;
#  else
	int value = 0;
	size_t size = sizeof(value);
	return sysctlbyname("hw.optional.arm.FEAT_SHA256", &value, &size, nullptr, 0) == 0 && value != 0;
#  endif
#elif defined(__linux__)
	return (getauxval(AT_HWCAP) & HWCAP_SHA2) != 0;
#elif defined(__FreeBSD__)
	unsigned long hwcap = 0;
	return elf_aux_info(AT_HWCAP, &hwcap, sizeof(hwcap)) == 0 && (hwcap & HWCAP_SHA2) != 0;
#elif defined(_WIN32)
	return IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0;
#elif defined(__ARM_FEATURE_SHA2) || defined(__ARM_FEATURE_CRYPTO)
	return true;
#else
	return false;
#endif
}

void compress_armv8(std::uint32_t state[8], const unsigned char* data, std::size_t blocks) noexcept
{
	uint32x4_t s0 = vld1q_u32(&state[0]);  // ABCD
	uint32x4_t s1 = vld1q_u32(&state[4]);  // EFGH

	for (; blocks > 0; --blocks, data += 64)
	{
		const uint32x4_t abcd = s0;
		const uint32x4_t efgh = s1;
		uint32x4_t w0, w1, w2, w3, m, t;

		// Four rounds on message group w (words 4g..4g+3). The copy of ABCD feeds
		// only sha256h2, so sha256h updates s0 in place, off the copy's latency.
#define SHA256_ROUNDS(g, w)                              \
	m = vaddq_u32(w, vld1q_u32(&round_constants[4 * (g)])); \
	t = s0;                                              \
	SHA256_SEPARATE(t);                                  \
	s0 = vsha256hq_u32(s0, s1, m);                       \
	s1 = vsha256h2q_u32(s1, t, m)

		// W[t] for the group in a (t-16) from b (t-12), c (t-8) and d (t-4).
#define SHA256_SCHEDULE(a, b, c, d) a = vsha256su1q_u32(vsha256su0q_u32(a, b), c, d)

		// Big-endian words: reverse the bytes in each 32-bit lane.
		w0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 0)));
		SHA256_ROUNDS(0, w0);
		w1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 16)));
		SHA256_ROUNDS(1, w1);
		w2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 32)));
		SHA256_ROUNDS(2, w2);
		w3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 48)));
		SHA256_ROUNDS(3, w3);

		SHA256_SCHEDULE(w0, w1, w2, w3); SHA256_ROUNDS(4, w0);
		SHA256_SCHEDULE(w1, w2, w3, w0); SHA256_ROUNDS(5, w1);
		SHA256_SCHEDULE(w2, w3, w0, w1); SHA256_ROUNDS(6, w2);
		SHA256_SCHEDULE(w3, w0, w1, w2); SHA256_ROUNDS(7, w3);
		SHA256_SCHEDULE(w0, w1, w2, w3); SHA256_ROUNDS(8, w0);
		SHA256_SCHEDULE(w1, w2, w3, w0); SHA256_ROUNDS(9, w1);
		SHA256_SCHEDULE(w2, w3, w0, w1); SHA256_ROUNDS(10, w2);
		SHA256_SCHEDULE(w3, w0, w1, w2); SHA256_ROUNDS(11, w3);
		SHA256_SCHEDULE(w0, w1, w2, w3); SHA256_ROUNDS(12, w0);
		SHA256_SCHEDULE(w1, w2, w3, w0); SHA256_ROUNDS(13, w1);
		SHA256_SCHEDULE(w2, w3, w0, w1); SHA256_ROUNDS(14, w2);
		SHA256_SCHEDULE(w3, w0, w1, w2); SHA256_ROUNDS(15, w3);

#undef SHA256_SCHEDULE
#undef SHA256_ROUNDS

		s0 = vaddq_u32(s0, abcd);
		s1 = vaddq_u32(s1, efgh);
	}

	vst1q_u32(&state[0], s0);
	vst1q_u32(&state[4], s1);
}

}  // namespace kronuz::sha256::detail

#endif  // SHA256_HAVE_ARMV8
