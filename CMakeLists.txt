cmake_minimum_required(VERSION 3.14)
project(sha256 LANGUAGES CXX)

include(FetchContent)

# --- Dependency: endian ---
# sha256.cc includes "endian.hh" for the byte-order macros (__BYTE_ORDER,
# __LITTLE_ENDIAN, __BIG_ENDIAN) and __builtin_bswap32 plumbing it uses to read
# 32-bit words big-endian. That header lives in the sibling endian library,
# pulled in here so the include resolves. We track its tip with GIT_TAG main,
# like the rest of the family.
FetchContent_Declare(
  endian
  GIT_REPOSITORY https://github.com/Kronuz/endian.git
  GIT_TAG        f6269f09da90bb3713018792003f01a67749b00c
)
FetchContent_MakeAvailable(endian)

# --- Library target ---
# sha256 is not header-only: sha256.cc carries the portable compression function,
# the buffering, and the kernel dispatch; sha256_x86.cc and sha256_arm.cc carry the
# SHA-NI and ARMv8 kernels (each compiles to nothing on the other architecture).
add_library(sha256 sha256.cc sha256_x86.cc sha256_arm.cc)

# The hardware kernels are chosen at run time, so a portable binary still runs on
# CPUs without them. OFF builds the portable kernel alone.
option(SHA256_HARDWARE "Build the SHA-NI and ARMv8 kernels (dispatched at run time)" ON)
if(NOT SHA256_HARDWARE)
  target_compile_definitions(sha256 PRIVATE SHA256_NO_HARDWARE)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$" AND NOT APPLE AND NOT MSVC)
  # Linux and FreeBSD toolchains default to plain ARMv8-A: enable the SHA2
  # intrinsics in the kernel's file only, so the rest stays baseline.
  include(CheckCXXCompilerFlag)
  check_cxx_compiler_flag("-march=armv8-a+crypto" SHA256_ARMV8_CRYPTO_FLAG)
  if(SHA256_ARMV8_CRYPTO_FLAG)
    set_source_files_properties(sha256_arm.cc PROPERTIES COMPILE_OPTIONS "-march=armv8-a+crypto")
    target_compile_definitions(sha256 PRIVATE SHA256_ARMV8_KERNEL)
  endif()
endif()
target_include_directories(sha256 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_features(sha256 PUBLIC cxx_std_20)

# Link endian so "endian.hh" is on the include path. PUBLIC because sha256.cc
# uses it; consumers don't need endian.hh themselves, but linking it PUBLIC keeps
# the include path consistent and harmless.
target_link_libraries(sha256 PUBLIC endian::endian)

# Alias so consumers can link `sha256::sha256` whether they add this via
# add_subdirectory or FetchContent.
add_library(sha256::sha256 ALIAS sha256)

# Only build the test and demo when this repo is the top-level project, so
# consumers (e.g. via FetchContent) don't build them.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  enable_testing()
  add_executable(sha256_test test/test.cc)
  target_link_libraries(sha256_test PRIVATE sha256)
  add_test(NAME sha256 COMMAND sha256_test)

  # Every kernel the host can run, plus the forced fallback, against NIST vectors
  # and each other.
  add_executable(sha256_kernels_test test/kernels.cc)
  target_link_libraries(sha256_kernels_test PRIVATE sha256)
  add_test(NAME sha256_kernels COMMAND sha256_kernels_test)

  # Next to OpenSSL's headers, and against its SHA256(), when OpenSSL is installed.
  find_package(OpenSSL QUIET COMPONENTS Crypto)
  if(OpenSSL_FOUND)
    add_executable(sha256_openssl_test test/openssl.cc)
    target_link_libraries(sha256_openssl_test PRIVATE sha256 OpenSSL::Crypto)
    add_test(NAME sha256_openssl COMMAND sha256_openssl_test)
  endif()

  # libFuzzer target (Clang): cmake -DSHA256_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++
  option(SHA256_FUZZ "Build the libFuzzer target" OFF)
  if(SHA256_FUZZ)
    add_executable(sha256_fuzz fuzz/fuzz_stream.cc)
    target_link_libraries(sha256_fuzz PRIVATE sha256)
    # the kernels are compiled in the library, so it needs coverage and the sanitizers too
    target_compile_options(sha256 PRIVATE -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all)
    target_compile_options(sha256_fuzz PRIVATE -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all)
    target_link_options(sha256_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
  endif()

  # GB/s per kernel at 64 B, 4 KiB and 64 MiB, against OpenSSL EVP when found:
  # cmake -B build -DCMAKE_BUILD_TYPE=Release -DSHA256_BUILD_BENCHMARKS=ON
  option(SHA256_BUILD_BENCHMARKS "Build the throughput benchmark" OFF)
  if(SHA256_BUILD_BENCHMARKS)
    add_executable(sha256_bench bench/bench.cc)
    target_link_libraries(sha256_bench PRIVATE sha256)
    if(OpenSSL_FOUND)
      target_link_libraries(sha256_bench PRIVATE OpenSSL::Crypto)
      target_compile_definitions(sha256_bench PRIVATE SHA256_BENCH_OPENSSL)
    else()
      message(STATUS "sha256_bench: OpenSSL not found, the EVP column is skipped")
    endif()
  endif()

  # A runnable tour of the library (not a test): build & run ./build/sha256_demo
  add_executable(sha256_demo examples/demo.cc)
  target_link_libraries(sha256_demo PRIVATE sha256)
endif()
