/*
 * Copyright (c) 2026 Germán Méndez Bravo (Kronuz)
 * MIT License; see LICENSE.
 *
 * The x86_64 SHA-NI kernel and its CPUID check. Built for every x86_64 target;
 * the instructions run only after shani_supported() says the CPU has them.
 */

#include "sha256_kernels.hh"

#if defined(SHA256_HAVE_SHANI)

#include <immintrin.h>

#if defined(_MSC_VER) && !defined(__clang__)
#  include <intrin.h>
#  define SHA256_SHANI_TARGET
#else
#  include <cpuid.h>
#  define SHA256_SHANI_TARGET __attribute__((target("sha,sse4.1,ssse3")))
#endif

namespace kronuz::sha256::detail {

bool shani_supported() noexcept
{
	// Leaf 1 ECX: SSSE3 (bit 9), SSE4.1 (bit 19). Leaf 7 EBX: SHA (bit 29).
#if defined(_MSC_VER) && !defined(__clang__)
	int regs[4];
	__cpuid(regs, 0);
	if (regs[0] < 7) return false;
	__cpuid(regs, 1);
	const unsigned ecx1 = static_cast<unsigned>(regs[2]);
	__cpuidex(regs, 7, 0);
	const unsigned ebx7 = static_cast<unsigned>(regs[1]);
#else
	unsigned eax, ebx, ecx, edx;
	if (__get_cpuid_max(0, nullptr) < 7) return false;
	__cpuid(1, eax, ebx, ecx, edx);
	const unsigned ecx1 = ecx;
	__cpuid_count(7, 0, eax, ebx, ecx, edx);
	const unsigned ebx7 = ebx;
#endif
	return (ecx1 & (1u << 9)) && (ecx1 & (1u << 19)) && (ebx7 & (1u << 29));
}

SHA256_SHANI_TARGET
void compress_shani(std::uint32_t state[8], const unsigned char* data, std::size_t blocks) noexcept
{
	const __m128i bswap = _mm_set_epi64x(0x0c0d0e0f08090a0bLL, 0x0405060700010203LL);
	const auto* k = reinterpret_cast<const __m128i*>(round_constants);

	// The rounds take the state as ABEF and CDGH.
	__m128i tmp = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[0]));  // DCBA
	__m128i s1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[4]));   // HGFE
	tmp = _mm_shuffle_epi32(tmp, 0xB1);                                           // CDAB
	s1 = _mm_shuffle_epi32(s1, 0x1B);                                             // EFGH
	__m128i s0 = _mm_alignr_epi8(tmp, s1, 8);                                     // ABEF
	s1 = _mm_blend_epi16(s1, tmp, 0xF0);                                          // CDGH

	for (; blocks > 0; --blocks, data += 64)
	{
		const __m128i abef = s0;
		const __m128i cdgh = s1;
		__m128i w0, w1, w2, w3, m;

		// Four rounds on message group w (words 4g..4g+3).
#define SHA256_ROUNDS(g, w)                             \
	m = _mm_add_epi32(w, _mm_load_si128(k + (g)));      \
	s1 = _mm_sha256rnds2_epu32(s1, s0, m);              \
	m = _mm_shuffle_epi32(m, 0x0E);                     \
	s0 = _mm_sha256rnds2_epu32(s0, s1, m)

		// W[t] for the group in a (t-16) from b (t-12), c (t-8) and d (t-4).
#define SHA256_SCHEDULE(a, b, c, d) \
	a = _mm_sha256msg2_epu32(_mm_add_epi32(_mm_sha256msg1_epu32(a, b), _mm_alignr_epi8(d, c, 4)), d)

		w0 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 0)), bswap);
		SHA256_ROUNDS(0, w0);
		w1 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 16)), bswap);
		SHA256_ROUNDS(1, w1);
		w2 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 32)), bswap);
		SHA256_ROUNDS(2, w2);
		w3 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 48)), bswap);
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

		s0 = _mm_add_epi32(s0, abef);
		s1 = _mm_add_epi32(s1, cdgh);
	}

	tmp = _mm_shuffle_epi32(s0, 0x1B);   // FEBA
	s1 = _mm_shuffle_epi32(s1, 0xB1);    // DCHG
	s0 = _mm_blend_epi16(tmp, s1, 0xF0); // DCBA
	s1 = _mm_alignr_epi8(s1, tmp, 8);    // HGFE
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&state[0]), s0);
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&state[4]), s1);
}

}  // namespace kronuz::sha256::detail

#endif  // SHA256_HAVE_SHANI
