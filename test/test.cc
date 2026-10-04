// Smoke test for the standalone sha256 library.
//
// Exercises the SHA256 digest against published test vectors: the empty input,
// "abc", a longer multi-block message, the 64-byte (one full block) boundary, a
// raw memory block with the (void*, size) call operator, the streaming add() API
// (which must agree with the one-shot form), the raw-byte getHash() overload,
// and reuse of an instance across calls.
//
// Build via CMake: cmake -B build && cmake --build build && ctest --test-dir build
#include <cassert>
#include <cstdio>
#include <string>
#include <string_view>

#include "sha256.h"


// ---------------------------------------------------------------------------
// Published SHA-256 vectors: the digest of "" and of "abc".
// ---------------------------------------------------------------------------

static void test_known_vectors() {
	SHA256 sha256;

	// The digest of the empty input.
	assert(sha256(std::string_view("")) ==
	       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

	// FIPS 180-4 worked example: the digest of "abc".
	assert(sha256(std::string_view("abc")) ==
	       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

	std::printf("sha256 known vectors OK: \"\" and \"abc\"\n");
}


// ---------------------------------------------------------------------------
// A longer, multi-block message (the second FIPS 180-4 example, 56 bytes).
// ---------------------------------------------------------------------------

static void test_multi_block() {
	SHA256 sha256;

	// 56 bytes: long enough to exercise the padding overflow into a second
	// block during finalization.
	assert(sha256(std::string_view(
	           "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) ==
	       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

	std::printf("sha256 multi-block OK: 56-byte FIPS example\n");
}


// ---------------------------------------------------------------------------
// The 64-byte boundary: exactly one full block of input.
// ---------------------------------------------------------------------------

static void test_block_boundary() {
	SHA256 sha256;

	// 64 'a' characters == one full 512-bit block, so finalization padding
	// spills into a fresh second block.
	std::string sixtyfour(64, 'a');
	assert(sha256(std::string_view(sixtyfour)) ==
	       "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");

	std::printf("sha256 block boundary OK: 64 bytes (one full block)\n");
}


// ---------------------------------------------------------------------------
// The (void*, size) call operator agrees with the string_view one.
// ---------------------------------------------------------------------------

static void test_memory_block() {
	SHA256 sha256;

	const char* data = "abc";
	assert(sha256(data, 3) ==
	       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

	// Embedded NULs are honored: it is size-based, not NUL-terminated. The two
	// inputs below differ only past a NUL, so their digests must differ.
	const unsigned char a[] = {'x', 0x00, 'y'};
	const unsigned char b[] = {'x', 0x00, 'z'};
	assert(sha256(a, sizeof(a)) != sha256(b, sizeof(b)));

	std::printf("sha256 memory block OK: (void*, size), embedded NULs\n");
}


// ---------------------------------------------------------------------------
// Streaming add() must agree with the one-shot digest of the concatenation.
// ---------------------------------------------------------------------------

static void test_streaming() {
	// Feed "abc" one byte at a time and compare against the one-shot digest.
	SHA256 streamed;
	streamed.add("a", 1);
	streamed.add("b", 1);
	streamed.add("c", 1);
	assert(streamed.getHash() ==
	       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

	// Chunk a longer message across a block boundary and compare to one-shot.
	std::string msg(100, 'z');
	SHA256 chunked;
	chunked.add(msg.data(), 30);
	chunked.add(msg.data() + 30, 70);

	SHA256 oneshot;
	assert(chunked.getHash() == oneshot(std::string_view(msg)));

	std::printf("sha256 streaming OK: add() chunks match the one-shot digest\n");
}


// ---------------------------------------------------------------------------
// The raw-byte getHash() overload writes the same 32 bytes the hex encodes.
// ---------------------------------------------------------------------------

static void test_raw_bytes() {
	SHA256 sha256;
	sha256.add("abc", 3);

	unsigned char raw[SHA256::HashBytes];
	sha256.getHash(raw);

	// Hand-encode the 32 raw bytes to hex and compare to the known vector.
	static const char hex[] = "0123456789abcdef";
	std::string out;
	for (unsigned char c : raw) {
		out += hex[(c >> 4) & 15];
		out += hex[c & 15];
	}
	assert(out ==
	       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

	std::printf("sha256 raw bytes OK: getHash(buffer) matches the hex digest\n");
}


// ---------------------------------------------------------------------------
// An instance can be reused: the call operator resets state each time.
// ---------------------------------------------------------------------------

static void test_reuse() {
	SHA256 sha256;

	// Hash "abc", then "" with the same instance: the second must not carry
	// state from the first.
	std::string first = sha256(std::string_view("abc"));
	std::string second = sha256(std::string_view(""));
	assert(first ==
	       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	assert(second ==
	       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

	// And explicit reset() clears a streamed buffer back to the empty digest.
	SHA256 streamed;
	streamed.add("abc", 3);
	streamed.reset();
	assert(streamed.getHash() ==
	       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

	std::printf("sha256 reuse OK: call operator and reset() clear state\n");
}


static void test_padding_lengths() {
	struct Vector { std::size_t length; const char* digest; };
	const Vector vectors[] = {
		{55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"},
		{56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"},
		{57, "f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6"},
		{63, "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"},
		{64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"},
		{65, "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0"},
		{119, "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb"},
		{120, "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c"},
		{121, "e9615320128cc7a3d6078e9af05603188e5ccbf0d07d8b735d3df5e8e0c1281f"},
		{127, "c57e9278af78fa3cab38667bef4ce29d783787a2f731d4e12200270f0c32320a"},
		{128, "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e"},
		{129, "c12cb024a2e5551cca0e08fce8f1c5e314555cc3fef6329ee994a3db752166ae"},
	};
	for (const auto& vector : vectors) {
		std::string input(vector.length, 'a');
		SHA256 one;
		assert(one(std::string_view(input)) == vector.digest);
		SHA256 streamed;
		for (char byte : input) streamed.add(&byte, 1);
		assert(streamed.getHash() == vector.digest);
		assert(streamed.getHash() == vector.digest);
	}
}

int main() {
	test_known_vectors();
	test_padding_lengths();
	test_multi_block();
	test_block_boundary();
	test_memory_block();
	test_streaming();
	test_raw_bytes();
	test_reuse();
	std::printf("all sha256 tests passed\n");
	return 0;
}
