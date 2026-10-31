// Legacy string API: ns per SHA256(data) -> 64-char hex. Run it against two builds to compare.
#include <chrono>
#include <cstdio>
#include <string>
#include "sha256.h"
int main() {
	for (size_t n : {16, 64, 1024}) {
		std::string data(n, 'x');
		SHA256 h;
		double best = 1e300;
		for (int w = 0; w < 7; ++w) {
			auto t0 = std::chrono::steady_clock::now();
			size_t sink = 0;
			const int B = 200000;
			for (int i = 0; i < B; ++i) { data[0] = char(i); sink += h(data.data(), n)[0]; }
			auto t1 = std::chrono::steady_clock::now();
			asm volatile("" :: "r"(sink));
			best = std::min(best, std::chrono::duration<double, std::nano>(t1 - t0).count() / B);
		}
		std::printf("SHA256 operator() %5zu B: %8.1f ns\n", n, best);
	}
}
