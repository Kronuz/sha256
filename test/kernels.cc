// Every SHA-256 kernel the host can run, plus the forced portable fallback.
//
// Each kernel is forced in turn and checked against the FIPS 180-4 / NIST SHAVS
// vectors (short, the 448- and 896-bit messages, a million 'a'), streaming splits
// at every boundary through both APIs, and the portable kernel's digests of random
// inputs at random offsets and splits. Set SHA256_EXPECT_KERNEL=sha-ni (or armv8)
// to fail when that kernel is unavailable.
//
// Build via CMake: cmake -B build && cmake --build build && ctest --test-dir build
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "sha256.h"

namespace sha = kronuz::sha256;

namespace {

int failures = 0;
const char* current = "none";

#define CHECK(cond)                                                                       \
	do {                                                                                  \
		if (!(cond)) {                                                                    \
			std::fprintf(stderr, "%s:%d: [%s] CHECK(%s) failed\n", __FILE__, __LINE__, current, #cond); \
			if (++failures > 20) std::exit(1);                                            \
		}                                                                                 \
	} while (0)

struct Vector {
	std::string input;
	const char* hex;
};

std::vector<Vector> nist_vectors() {
	return {
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"\xd3", "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1"},
		{"\x11\xaf", "5ca7133fa735326081558ac312c620eeca9970d1e70a4b95533d956f072d1f98"},
		{"\x57\x38\xc9\x29\xc4\xf4\xcc\xb6", "963bb88f27f512777aab6c8b1a02c70ec0ad651d428f870036e1917120fb48bf"},
		{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
		{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		 "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"},
		{std::string(1000000, 'a'), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
	};
}

std::string old_api(std::string_view input) {
	SHA256 h;
	return h(input);
}

// xorshift64*: deterministic inputs, lengths, offsets and splits.
struct Random {
	std::uint64_t s = 0x9e3779b97f4a7c15ull;
	std::uint64_t next() {
		s ^= s >> 12;
		s ^= s << 25;
		s ^= s >> 27;
		return s * 0x2545f4914f6cdd1dull;
	}
	std::size_t below(std::size_t n) { return n ? static_cast<std::size_t>(next() % n) : 0; }
};

struct Case {
	std::size_t offset, length, split1, split2;
	sha::digest_type expected;
};

std::vector<unsigned char> random_bytes(std::size_t n) {
	Random r;
	std::vector<unsigned char> bytes(n);
	for (auto& b : bytes) b = static_cast<unsigned char>(r.next() >> 56);
	return bytes;
}

const std::vector<unsigned char>& pool() {
	static const std::vector<unsigned char> bytes = random_bytes(1 << 16);
	return bytes;
}

sha::digest_type streamed(const unsigned char* p, std::size_t n, std::size_t a, std::size_t b) {
	sha::hasher h;
	h.update(p, a);
	h.update(p + a, b - a);
	h.update(p + b, n - b);
	return h.final();
}

// Random cases with the portable kernel's digests as the reference.
std::vector<Case> reference_cases() {
	CHECK(sha::force_kernel(sha::kernel::portable));
	Random r;
	r.s = 0x0123456789abcdefull;
	std::vector<Case> cases;
	for (int i = 0; i < 3000; ++i) {
		Case c{};
		c.length = i < 600 ? static_cast<std::size_t>(i) : r.below(i < 2900 ? 4096 : 60000);
		c.offset = r.below(pool().size() - c.length + 1);
		c.split1 = r.below(c.length + 1);
		c.split2 = c.split1 + r.below(c.length - c.split1 + 1);
		c.expected = sha::digest(pool().data() + c.offset, c.length);
		cases.push_back(c);
	}
	return cases;
}

void check_vectors(const std::vector<Vector>& vectors) {
	for (const auto& v : vectors) {
		CHECK(sha::to_hex(sha::digest(v.input)) == v.hex);
		CHECK(old_api(v.input) == v.hex);
	}
}

// Two- and three-way splits at every boundary of the short vectors, byte at a time too.
void check_splits(const std::vector<Vector>& vectors) {
	for (const auto& v : vectors) {
		const std::string& in = v.input;
		if (in.size() > 200) continue;
		const auto* p = reinterpret_cast<const unsigned char*>(in.data());
		for (std::size_t i = 0; i <= in.size(); ++i) {
			sha::hasher h;
			h.update(p, i);
			h.update(p + i, in.size() - i);
			CHECK(sha::to_hex(h.final()) == v.hex);

			SHA256 old;
			old.add(p, i);
			old.add(p + i, in.size() - i);
			CHECK(old.getHash() == v.hex);

			for (std::size_t j = i; j <= in.size(); ++j) {
				CHECK(sha::to_hex(streamed(p, in.size(), i, j)) == v.hex);
			}
		}
		sha::hasher bytewise;
		for (char c : in) bytewise.update(&c, 1);
		CHECK(sha::to_hex(bytewise.final()) == v.hex);
	}
}

// Every split of one buffer across the first three blocks, through both APIs.
void check_block_boundaries() {
	const unsigned char* p = pool().data() + 1;  // unaligned on purpose
	for (std::size_t n : {63u, 64u, 65u, 127u, 128u, 129u, 191u, 192u, 193u}) {
		const sha::digest_type whole = sha::digest(p, n);
		for (std::size_t i = 0; i <= n; ++i) {
			for (std::size_t j = i; j <= n; ++j) {
				CHECK(streamed(p, n, i, j) == whole);
			}
		}
	}
}

void check_million_streamed() {
	const std::string a(1000000, 'a');
	const std::size_t chunks[] = {1, 3, 63, 64, 65, 127, 4096, 10007};
	sha::hasher h;
	SHA256 old;
	std::size_t pos = 0;
	for (std::size_t k = 0; pos < a.size(); ++k) {
		std::size_t n = chunks[k % 8] < a.size() - pos ? chunks[k % 8] : a.size() - pos;
		h.update(a.data() + pos, n);
		old.add(a.data() + pos, n);
		pos += n;
	}
	CHECK(sha::to_hex(h.final()) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
	CHECK(old.getHash() == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

// final() reads the digest without ending the stream; init() restarts it.
void check_final_keeps_state() {
	sha::hasher h;
	h.update("ab", 2);
	CHECK(sha::to_hex(h.final()) == sha::to_hex(sha::digest("ab")));
	h.update("c", 1);
	unsigned char raw[sha::digest_size];
	h.final(raw);
	CHECK(sha::to_hex(h.final()) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	CHECK(std::memcmp(raw, h.final().data(), sha::digest_size) == 0);
	h.update(nullptr, 0);
	CHECK(sha::to_hex(h.final()) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	h.init();
	CHECK(sha::to_hex(h.final()) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

void check_random(const std::vector<Case>& cases) {
	for (const auto& c : cases) {
		const unsigned char* p = pool().data() + c.offset;
		CHECK(sha::digest(p, c.length) == c.expected);
		CHECK(streamed(p, c.length, c.split1, c.split2) == c.expected);
		SHA256 old;
		old.add(p, c.split1);
		old.add(p + c.split1, c.length - c.split1);
		unsigned char raw[SHA256::HashBytes];
		old.getHash(raw);
		CHECK(std::memcmp(raw, c.expected.data(), sha::digest_size) == 0);
	}
}

void check_hooks(sha::kernel detected) {
	current = "hooks";
	CHECK(sha::kernel_available(sha::kernel::portable));
	CHECK(sha::force_kernel(sha::kernel::portable));
	CHECK(sha::active_kernel() == sha::kernel::portable);
	for (sha::kernel k : {sha::kernel::sha_ni, sha::kernel::armv8}) {
		if (!sha::kernel_available(k)) {
			CHECK(!sha::force_kernel(k));
			CHECK(sha::active_kernel() == sha::kernel::portable);
		}
	}
	sha::reset_kernel();
	CHECK(sha::active_kernel() == detected);
	CHECK(std::string(sha::kernel_name(sha::kernel::sha_ni)) == "sha-ni");
}

}  // namespace

int main() {
	const sha::kernel detected = sha::active_kernel();
	std::printf("detected kernel: %s\n", sha::kernel_name(detected));

	const auto vectors = nist_vectors();
	const auto cases = reference_cases();

	int ran = 0;
	for (sha::kernel k : {sha::kernel::portable, sha::kernel::sha_ni, sha::kernel::armv8}) {
		current = sha::kernel_name(k);
		if (!sha::force_kernel(k)) {
			std::printf("kernel %-8s unavailable here, skipped\n", current);
			continue;
		}
		CHECK(sha::active_kernel() == k);
		check_vectors(vectors);
		check_splits(vectors);
		check_block_boundaries();
		check_million_streamed();
		check_final_keeps_state();
		check_random(cases);
		++ran;
		std::printf("kernel %-8s OK: NIST vectors, every split, %zu random cases\n", current, cases.size());
	}
	check_hooks(detected);

	if (const char* expect = std::getenv("SHA256_EXPECT_KERNEL"); expect && *expect) {
		bool found = false;
		for (sha::kernel k : {sha::kernel::portable, sha::kernel::sha_ni, sha::kernel::armv8}) {
			if (std::string_view(expect) == sha::kernel_name(k)) found = sha::kernel_available(k);
		}
		current = expect;
		CHECK(found);
	}

	if (failures) {
		std::fprintf(stderr, "%d sha256 kernel checks failed\n", failures);
		return 1;
	}
	std::printf("all sha256 kernel tests passed (%d kernels)\n", ran);
	return 0;
}
