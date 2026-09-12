#pragma once

// Shared helpers for the Compiler Runtime Fabric examples.
//
// Examples create their scratch state outside the repository and remove it on
// exit, so running them never leaves the working tree dirty.

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#include "crf/runtime.hpp"

namespace crf::examples {

inline std::filesystem::path scratch_root(const char* name) {
  std::error_code ec;
  const std::filesystem::path root =
      std::filesystem::temp_directory_path(ec) / "compiler-runtime-fabric-examples" / name;
  std::filesystem::remove_all(root, ec);
  std::filesystem::create_directories(root, ec);
  return root;
}

class Scratch {
 public:
  explicit Scratch(const char* name) : root_(scratch_root(name)) {}
  ~Scratch() {
    std::error_code ec;
    std::filesystem::remove_all(root_, ec);
  }
  Scratch(const Scratch&) = delete;
  Scratch& operator=(const Scratch&) = delete;
  CRF_NODISCARD const std::filesystem::path& root() const noexcept { return root_; }

  CRF_NODISCARD std::filesystem::path write(const std::string& name,
                                            const std::string& contents) const {
    const std::filesystem::path path = root_ / name;
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (stream) stream.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    return path;
  }

 private:
  std::filesystem::path root_;
};

inline RuntimeOptions runtime_options(const Scratch& scratch, const char* name) {
  RuntimeOptions options;
  options.runtime_name = name;
  options.state_directory = scratch.root() / "state";
  options.workspace_root = scratch.root() / "workspaces";
  return options;
}

inline void banner(const char* title) {
  std::printf("\n=== %s ===\n", title);
  std::fflush(stdout);
}

inline void line(const std::string& text) {
  std::printf("%s\n", text.c_str());
  std::fflush(stdout);
}

inline void refusal(const char* what, const Status& status) {
  std::printf("REFUSED %s: %s\n", what, status.to_string().c_str());
  std::fflush(stdout);
}

inline std::string hello_source(const char* marker = "HELLO-FROM-CRF") {
  std::string out = "#include <cstdio>\nint main() { std::printf(\"";
  out += marker;
  out += "\\n\"); return 0; }\n";
  return out;
}

}  // namespace crf::examples
