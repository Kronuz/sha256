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
  GIT_TAG        main
)
FetchContent_MakeAvailable(endian)

# --- Library target ---
# sha256 is not header-only: sha256.cc carries the compression function, so it
# must be compiled and linked. The header alone (sha256.h) only declares the
# SHA256 class.
add_library(sha256 sha256.cc)
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

  # A runnable tour of the library (not a test): build & run ./build/sha256_demo
  add_executable(sha256_demo examples/demo.cc)
  target_link_libraries(sha256_demo PRIVATE sha256)
endif()
