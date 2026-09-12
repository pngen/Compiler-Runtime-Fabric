#pragma once

// Shared fixtures for the Compiler Runtime Fabric test suites.

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#include "crf/runtime.hpp"

#ifndef CRF_TEST_WORKSPACE_ROOT
#  define CRF_TEST_WORKSPACE_ROOT "crf-test-work"
#endif

namespace crftest {

inline std::atomic<unsigned>& counter() {
  static std::atomic<unsigned> value{0};
  return value;
}

/// A unique, filesystem-safe label for a temporary directory.
inline std::string unique_label(const char* prefix) {
  const unsigned index = counter().fetch_add(1);
  return std::string(prefix) + "-" + std::to_string(index);
}

/// Removes a directory tree when it goes out of scope. Repository hygiene is a
/// hard requirement: every test cleans up after itself.
class ScopedTree {
 public:
  explicit ScopedTree(std::filesystem::path root) : root_(std::move(root)) {}
  ~ScopedTree() {
    std::error_code ec;
    std::filesystem::remove_all(root_, ec);
  }
  ScopedTree(const ScopedTree&) = delete;
  ScopedTree& operator=(const ScopedTree&) = delete;

  CRF_NODISCARD const std::filesystem::path& path() const noexcept { return root_; }

 private:
  std::filesystem::path root_;
};

/// Base directory for all test scratch state, removed by the caller.
inline std::filesystem::path test_root() {
  const std::filesystem::path root = crf::normalize_path(std::filesystem::path(CRF_TEST_WORKSPACE_ROOT));
  std::error_code ec;
  std::filesystem::create_directories(root, ec);
  return root;
}

inline crf::RuntimeOptions test_runtime_options(const std::string& name) {
  crf::RuntimeOptions options;
  options.runtime_name = name;
  options.state_directory = test_root() / (name + "-state");
  options.workspace_root = test_root() / (name + "-work");
  options.enable_persistence = true;
  options.ephemeral_state = false;
  options.recover_on_load = true;
  std::error_code ec;
  std::filesystem::remove_all(options.state_directory, ec);
  std::filesystem::remove_all(options.workspace_root, ec);
  return options;
}

/// Path of a real, installed MSVC toolchain; used by the real-compiler suites.
inline std::filesystem::path source_fixture_dir() {
  return std::filesystem::path(CRF_TEST_FIXTURE_DIR);
}

inline bool write_text(const std::filesystem::path& path, const std::string& contents) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) return false;
  stream.write(contents.data(), static_cast<std::streamsize>(contents.size()));
  return static_cast<bool>(stream);
}

inline std::string read_text(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) return {};
  std::string out;
  stream.seekg(0, std::ios::end);
  out.resize(static_cast<std::size_t>(stream.tellg()));
  stream.seekg(0, std::ios::beg);
  if (!out.empty()) stream.read(out.data(), static_cast<std::streamsize>(out.size()));
  return out;
}

}  // namespace crftest
