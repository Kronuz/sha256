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
#  define SHA256_AVX2_TARGET
#  define SHA256_UNROLL
#else
#  include <cpuid.h>
#  define SHA256_SHANI_TARGET __attribute__((target("sha,sse4.1,ssse3")))
#  define SHA256_AVX2_TARGET __attribute__((target("avx2,bmi2")))
// Full unrolling keeps the schedule slots in registers.
#  define SHA256_UNROLL _Pragma("GCC unroll 8")
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

bool avx2_supported() noexcept
{
	// Leaf 1 ECX: OSXSAVE (bit 27), AVX (bit 28). XCR0: XMM and YMM state (bits 1, 2).
	// Leaf 7 EBX: AVX2 (bit 5), BMI2 (bit 8).
#if defined(_MSC_VER) && !defined(__clang__)
	int regs[4];
	__cpuid(regs, 0);
	if (regs[0] < 7) return false;
	__cpuid(regs, 1);
	const unsigned ecx1 = static_cast<unsigned>(regs[2]);
	__cpuidex(regs, 7, 0);
	const unsigned ebx7 = static_cast<unsigned>(regs[1]);
	if (!(ecx1 & (1u << 27)) || !(ecx1 & (1u << 28))) return false;
	const unsigned long long xcr0 = _xgetbv(0);
#else
	unsigned eax, ebx, ecx, edx;
	if (__get_cpuid_max(0, nullptr) < 7) return false;
	__cpuid(1, eax, ebx, ecx, edx);
	const unsigned ecx1 = ecx;
	__cpuid_count(7, 0, eax, ebx, ecx, edx);
	const unsigned ebx7 = ebx;
	if (!(ecx1 & (1u << 27)) || !(ecx1 & (1u << 28))) return false;
	unsigned lo, hi;
	__asm__("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
	const unsigned long long xcr0 = (static_cast<unsigned long long>(hi) << 32) | lo;
#endif
	return (xcr0 & 0x6) == 0x6 && (ebx7 & (1u << 5)) && (ebx7 & (1u << 8));
}

namespace {

SHA256_AVX2_TARGET inline __m256i ror(__m256i x, int n) noexcept
{
	return _mm256_or_si256(_mm256_srli_epi32(x, n), _mm256_slli_epi32(x, 32 - n));
}

SHA256_AVX2_TARGET inline std::uint32_t ror(std::uint32_t x, int n) noexcept
{
	return (x >> n) | (x << (32 - n));
}

// The next four schedule words of each lane's block from the previous sixteen (x0 oldest).
SHA256_AVX2_TARGET inline __m256i schedule(__m256i x0, __m256i x1, __m256i x2, __m256i x3) noexcept
{
	const __m256i w15 = _mm256_alignr_epi8(x1, x0, 4);  // W[t-15..t-12]
	const __m256i w7 = _mm256_alignr_epi8(x3, x2, 4);   // W[t-7..t-4]
	const __m256i s0 = _mm256_xor_si256(_mm256_xor_si256(ror(w15, 7), ror(w15, 18)), _mm256_srli_epi32(w15, 3));
	__m256i t = _mm256_add_epi32(_mm256_add_epi32(x0, s0), w7);
	// sigma1 needs W[t-2] and W[t-1] for the low two words, then the two just computed for the high two.
	const __m256i lo_half = _mm256_set_epi32(0, 0, -1, -1, 0, 0, -1, -1);
	__m256i w2 = _mm256_shuffle_epi32(x3, 0xFE);  // W[t-2], W[t-1] in words 0 and 1
	__m256i s1 = _mm256_xor_si256(_mm256_xor_si256(ror(w2, 17), ror(w2, 19)), _mm256_srli_epi32(w2, 10));
	t = _mm256_add_epi32(t, _mm256_and_si256(s1, lo_half));
	w2 = _mm256_shuffle_epi32(t, 0x40);  // W[t], W[t+1] in words 2 and 3
	s1 = _mm256_xor_si256(_mm256_xor_si256(ror(w2, 17), ror(w2, 19)), _mm256_srli_epi32(w2, 10));
	return _mm256_add_epi32(t, _mm256_andnot_si256(lo_half, s1));
}

// One round on the named words, with this round's K + W.
#define SHA256_ROUND(a, b, c, d, e, f, g, h, kw)                                       \
	h += (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + (kw);           \
	d += h;                                                                            \
	h += (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) | (c & (a | b)))
// Rounds r to r + 7, from groups r / 4 and r / 4 + 1 of one lane's K + W.
#define SHA256_ROUNDS8(kw, r)                                                          \
	SHA256_ROUND(a, b, c, d, e, f, g, h, (kw)[(r) / 4 * 8 + 0]);                       \
	SHA256_ROUND(h, a, b, c, d, e, f, g, (kw)[(r) / 4 * 8 + 1]);                       \
	SHA256_ROUND(g, h, a, b, c, d, e, f, (kw)[(r) / 4 * 8 + 2]);                       \
	SHA256_ROUND(f, g, h, a, b, c, d, e, (kw)[(r) / 4 * 8 + 3]);                       \
	SHA256_ROUND(e, f, g, h, a, b, c, d, (kw)[(r) / 4 * 8 + 8]);                       \
	SHA256_ROUND(d, e, f, g, h, a, b, c, (kw)[(r) / 4 * 8 + 9]);                       \
	SHA256_ROUND(c, d, e, f, g, h, a, b, (kw)[(r) / 4 * 8 + 10]);                      \
	SHA256_ROUND(b, c, d, e, f, g, h, a, (kw)[(r) / 4 * 8 + 11])

// Stores group n's K + W for both lanes, then extends that slot's schedule.
SHA256_AVX2_TARGET inline void step(__m256i x[4], std::uint32_t* kw, int n) noexcept
{
	const __m128i k = _mm_load_si128(reinterpret_cast<const __m128i*>(round_constants) + n);
	const __m256i kk = _mm256_inserti128_si256(_mm256_castsi128_si256(k), k, 1);
	_mm256_store_si256(reinterpret_cast<__m256i*>(kw) + n, _mm256_add_epi32(x[n % 4], kk));
	if (n < 12)
		x[n % 4] = schedule(x[n % 4], x[(n + 1) % 4], x[(n + 2) % 4], x[(n + 3) % 4]);
}

}  // namespace

// Two blocks per pass: each 128-bit lane extends one block's schedule while the first
// block's rounds run scalar with BMI2 rotates; the second block's rounds then read the
// stored words. A lone last block shares the pass with a copy of itself.
SHA256_AVX2_TARGET
void compress_avx2(std::uint32_t state[8], const unsigned char* data, std::size_t blocks) noexcept
{
	const __m256i bswap = _mm256_set_epi64x(0x0c0d0e0f08090a0bLL, 0x0405060700010203LL,
	                                        0x0c0d0e0f08090a0bLL, 0x0405060700010203LL);
	alignas(32) std::uint32_t kw[64 * 2];  // group n: block 0's four words, then block 1's
	for (; blocks > 0; blocks -= blocks >= 2 ? 2 : 1, data += 128)
	{
		const unsigned char* second = blocks >= 2 ? data + 64 : data;
		__m256i x[4];
		for (int n = 0; n < 4; ++n)
		{
			const __m128i lo = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 16 * n));
			const __m128i hi = _mm_loadu_si128(reinterpret_cast<const __m128i*>(second + 16 * n));
			x[n] = _mm256_shuffle_epi8(_mm256_inserti128_si256(_mm256_castsi128_si256(lo), hi, 1), bswap);
		}
		std::uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
		std::uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
		SHA256_UNROLL
		for (int r = 0; r < 64; r += 8)
		{
			step(x, kw, r / 4);
			step(x, kw, r / 4 + 1);
			SHA256_ROUNDS8(kw, r);
		}
		state[0] += a; state[1] += b; state[2] += c; state[3] += d;
		state[4] += e; state[5] += f; state[6] += g; state[7] += h;
		if (blocks < 2)
			break;
		a = state[0], b = state[1], c = state[2], d = state[3];
		e = state[4], f = state[5], g = state[6], h = state[7];
		SHA256_UNROLL
		for (int r = 0; r < 64; r += 8)
		{
			SHA256_ROUNDS8(kw + 4, r);
		}
		state[0] += a; state[1] += b; state[2] += c; state[3] += d;
		state[4] += e; state[5] += f; state[6] += g; state[7] += h;
	}
}
#undef SHA256_ROUNDS8
#undef SHA256_ROUND

}  // namespace kronuz::sha256::detail

#endif  // SHA256_HAVE_SHANI
