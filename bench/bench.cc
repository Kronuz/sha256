// SHA-256 throughput in GB/s (1e9 bytes per second), one thread, best of five: every
// kernel this host runs, and OpenSSL EVP when the build found it, at 64 B, 4 KiB and
// 64 MiB messages. Small messages repeat one cache-hot buffer; each timed pass hashes
// 64 MiB in total. Every column's digests are cross-checked; a mismatch exits 1.
//
//   cmake -B build -DCMAKE_BUILD_TYPE=Release -DSHA256_BUILD_BENCHMARKS=ON
//   cmake --build build && ./build/sha256_bench [--quick]
#include "../sha256.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#if defined(SHA256_BENCH_OPENSSL)
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#endif

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#include <cpuid.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#endif

namespace sha = kronuz::sha256;
using clk = std::chrono::steady_clock;

namespace {

std::string cpu_name() {
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
	unsigned regs[12] = {};
	if (__get_cpuid_max(0x80000000, nullptr) >= 0x80000004) {
		for (unsigned i = 0; i < 3; ++i) __cpuid(0x80000002 + i, regs[4 * i], regs[4 * i + 1], regs[4 * i + 2], regs[4 * i + 3]);
		std::string name(reinterpret_cast<const char*>(regs), sizeof(regs));
		name.resize(std::strlen(name.c_str()));
		while (!name.empty() && name.front() == ' ') name.erase(0, 1);
		return name;
	}
#elif defined(__APPLE__)
	char buf[256];
	size_t len = sizeof(buf);
	if (sysctlbyname("machdep.cpu.brand_string", buf, &len, nullptr, 0) == 0) return buf;
#endif
	std::ifstream cpuinfo("/proc/cpuinfo");
	for (std::string line; std::getline(cpuinfo, line);) {
		if (line.rfind("model name", 0) == 0 || line.rfind("CPU part", 0) == 0) return line.substr(line.find(':') + 2);
	}
	return "unknown";
}

// Hashes `count` messages of `size` bytes; returns the last digest.
using hash_fn = sha::digest_type (*)(const unsigned char* data, std::size_t size, std::size_t count);

sha::digest_type run_kronuz(const unsigned char* data, std::size_t size, std::size_t count) {
	sha::digest_type d{};
	for (std::size_t i = 0; i < count; ++i) d = sha::digest(data, size);
	return d;
}

#if defined(SHA256_BENCH_OPENSSL)
EVP_MD_CTX* evp_ctx = nullptr;
const EVP_MD* evp_md = nullptr;

sha::digest_type run_evp(const unsigned char* data, std::size_t size, std::size_t count) {
	sha::digest_type d{};
	unsigned len = 0;
	for (std::size_t i = 0; i < count; ++i) {
		EVP_DigestInit_ex(evp_ctx, evp_md, nullptr);
		EVP_DigestUpdate(evp_ctx, data, size);
		EVP_DigestFinal_ex(evp_ctx, d.data(), &len);
	}
	return d;
}
#endif

double gbps(hash_fn fn, const unsigned char* data, std::size_t size, std::size_t total, int reps, sha::digest_type& out) {
	const std::size_t count = total / size ? total / size : 1;
	out = fn(data, size, count);  // warm
	double best = 1e30;
	for (int r = 0; r < reps; ++r) {
		auto t0 = clk::now();
		out = fn(data, size, count);
		double s = std::chrono::duration<double>(clk::now() - t0).count();
		if (s < best) best = s;
	}
	return double(size) * double(count) / best / 1e9;
}

}  // namespace

int main(int argc, char** argv) {
	const bool quick = argc > 1 && std::strcmp(argv[1], "--quick") == 0;
	const std::size_t total = quick ? (16u << 20) : (64u << 20);
	const int reps = quick ? 3 : 5;
	const std::size_t sizes[] = {64, 4096, 64u << 20};

	std::vector<unsigned char> buf(64u << 20);
	for (std::size_t i = 0; i < buf.size(); ++i) buf[i] = static_cast<unsigned char>((i * 2654435761u) >> 13);

	struct Column {
		std::string name;
		hash_fn fn;
		sha::kernel k;
		bool kronuz;
	};
	std::vector<Column> columns;
	for (sha::kernel k : {sha::kernel::portable, sha::kernel::sha_ni, sha::kernel::armv8}) {
		if (sha::kernel_available(k)) columns.push_back({std::string("kronuz ") + sha::kernel_name(k), run_kronuz, k, true});
	}
	std::string evp_version = "not built";
#if defined(SHA256_BENCH_OPENSSL)
	evp_ctx = EVP_MD_CTX_new();
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	evp_md = EVP_MD_fetch(nullptr, "SHA256", nullptr);
#else
	evp_md = EVP_sha256();
#endif
	evp_version = OPENSSL_VERSION_TEXT;
	columns.push_back({"openssl evp", run_evp, sha::kernel::portable, false});
#endif

	std::printf("cpu: %s\n", cpu_name().c_str());
	std::printf("detected kernel: %s; openssl: %s\n", sha::kernel_name(sha::active_kernel()), evp_version.c_str());
	std::printf("GB/s, one thread, best of %d, %zu MiB hashed per pass\n\n", reps, total >> 20);
	std::printf("| %-16s |", "implementation");
	for (std::size_t size : sizes) std::printf(" %9s |", size == 64 ? "64 B" : size == 4096 ? "4 KiB" : "64 MiB");
	std::printf("\n|------------------|-----------|-----------|-----------|\n");

	bool same = true;
	sha::digest_type first[3];
	for (std::size_t c = 0; c < columns.size(); ++c) {
		if (columns[c].kronuz) sha::force_kernel(columns[c].k);
		std::printf("| %-16s |", columns[c].name.c_str());
		for (std::size_t s = 0; s < 3; ++s) {
			sha::digest_type d;
			double rate = gbps(columns[c].fn, buf.data(), sizes[s], total, reps, d);
			if (c == 0) first[s] = d;
			same = same && d == first[s];
			std::printf(" %9.3f |", rate);
			std::fflush(stdout);
		}
		std::printf("\n");
	}
	sha::reset_kernel();
	std::printf("\ndigests agree across columns: %s\n", same ? "yes" : "NO");
	return same ? 0 : 1;
}
