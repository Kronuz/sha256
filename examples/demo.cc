// A runnable tour of sha256.
//
// Build (when this repo is the top-level project):
//   cmake -B build && cmake --build build && ./build/sha256_demo
//
// The one idea worth taking away: SHA256 turns an arbitrary byte buffer into a
// fixed 32-byte digest, rendered here as 64 hex characters. It is a content
// digest / checksum primitive: feed it the same bytes and you get the same
// fingerprint, which is what content-addressing and dedup are built on. You can
// hash a whole string in one call, or stream it in chunks with add().
#include <cstdio>
#include <string>
#include <string_view>

#include "sha256.h"

static void rule(const char* title) {
	std::printf("\n\033[1m── %s ──\033[0m\n", title);
}

int main() {
	std::puts("sha256 demo");

	SHA256 sha256;

	// --- 1. hash a couple of strings -----------------------------------------
	rule("a string becomes a 64-hex-character digest");
	// The same bytes always produce the same digest, which is what makes this a
	// content fingerprint.
	std::printf("  %-14s -> %s\n", "\"\"", sha256(std::string_view("")).c_str());
	std::printf("  %-14s -> %s\n", "\"abc\"", sha256(std::string_view("abc")).c_str());
	std::printf("  %-14s -> %s\n", "\"hello, world\"",
	            sha256(std::string_view("hello, world")).c_str());

	// --- 2. a tiny change flips the whole digest -----------------------------
	rule("a one-byte change scrambles the whole digest");
	// Useful as a checksum: two nearly identical inputs map to unrelated
	// fingerprints, so any drift is easy to spot.
	std::printf("  %-14s -> %s\n", "\"checksum\"",
	            sha256(std::string_view("checksum")).c_str());
	std::printf("  %-14s -> %s\n", "\"checksuM\"",
	            sha256(std::string_view("checksuM")).c_str());

	// --- 3. streaming: feed the data in chunks -------------------------------
	rule("streaming add() matches hashing the whole buffer at once");
	// Hash a buffer you don't hold all at once: call add() per chunk, then
	// getHash(). The result is identical to the one-shot form.
	SHA256 streamed;
	streamed.add("hello, ", 7);
	streamed.add("world", 5);
	std::printf("  chunked  : %s\n", streamed.getHash().c_str());
	SHA256 oneshot;
	std::printf("  one-shot : %s\n",
	            oneshot(std::string_view("hello, world")).c_str());

	// --- 4. the namespaced API ------------------------------------------------
	rule("kronuz::sha256: raw bytes, and the kernel this CPU runs");
	// Same digest, returned as 32 bytes; no name clash with OpenSSL's SHA256().
	// Blocks go through SHA-NI or the ARMv8 SHA2 instructions when present.
	auto digest = kronuz::sha256::digest("hello, world");
	std::printf("  digest   : %s\n", kronuz::sha256::to_hex(digest).c_str());
	std::printf("  kernel   : %s\n",
	            kronuz::sha256::kernel_name(kronuz::sha256::active_kernel()));

	std::puts("\ndone.");
	return 0;
}
