# sha256 API reference

```cpp
class SHA256 {
public:
	enum { BlockSize = 64, HashBytes = 32 };

	std::string operator()(const void* data, size_t numBytes);
	std::string operator()(std::string_view text);

	void add(const void* data, size_t numBytes);

	std::string getHash();
	void        getHash(unsigned char buffer[HashBytes]);

	void reset();
};
```

- `operator()(data, numBytes)` / `operator()(text)` — one-shot: reset, hash the
  whole input, and return the 64-character hex digest. The instance is reset each
  call, so it is safe to reuse.
- `add(data, numBytes)` — append bytes to the running digest. Call it as many
  times as you like before reading the result.
- `getHash()` — finalize and return the digest as 64 lowercase hex characters.
  `getHash(buffer)` writes the raw 32 bytes instead. Both leave the running state
  intact, so you can keep adding after reading.
- `reset()` — clear the running state back to the empty-input starting point.

## `kronuz::sha256`

The same digest under a namespace, so it never meets OpenSSL's global `SHA256()`.
Prefer it in new code; the `SHA256` class stays and computes identical bytes.

```cpp
namespace kronuz::sha256 {
	inline constexpr std::size_t block_size = 64, digest_size = 32;
	using digest_type = std::array<unsigned char, digest_size>;

	class hasher {
	public:
		hasher() noexcept;                    // same as init()
		void init() noexcept;
		void update(const void* data, std::size_t size) noexcept;
		void update(std::string_view text) noexcept;
		digest_type final() const noexcept;
		void final(unsigned char out[digest_size]) const noexcept;
	};

	digest_type digest(const void* data, std::size_t size) noexcept;
	digest_type digest(std::string_view text) noexcept;
	std::string to_hex(const digest_type& digest);

	enum class kernel : unsigned char { portable, sha_ni, armv8 };
	kernel      active_kernel() noexcept;
	bool        kernel_available(kernel k) noexcept;
	const char* kernel_name(kernel k) noexcept;
	bool        force_kernel(kernel k) noexcept;
	void        reset_kernel() noexcept;
}
```

- `hasher::update(data, size)`: append bytes; any chunking gives the same digest.
  A zero `size` is a no-op, with any pointer.
- `hasher::final()`: the digest of everything appended so far. It finalizes a copy,
  so the stream continues: `update()` after `final()` extends the same message.
  `init()` starts a new one.
- `digest(data, size)`: one-shot; `to_hex()` renders 64 lowercase hex characters.
- `active_kernel()`: the kernel blocks run through now. Detection runs once, on
  first use: SHA-NI on x86_64 when CPUID reports SHA, SSSE3 and SSE4.1; the SHA2
  extension on arm64; the portable C++ rounds otherwise.
- `force_kernel(k)`: a test and benchmark hook that pins `k` process-wide; it
  returns `false` and changes nothing when `k` is not available in this build or
  on this CPU. `reset_kernel()` returns to the detected kernel. Every kernel
  computes the same function on the same state, so switching mid-stream is safe.
