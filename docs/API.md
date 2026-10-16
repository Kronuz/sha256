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
