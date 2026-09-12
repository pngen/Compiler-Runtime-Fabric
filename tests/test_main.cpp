#include "crf_test.hpp"

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

namespace crftest {
namespace {

std::vector<std::string>& filters() {
  static std::vector<std::string> value;
  return value;
}

}  // namespace

std::vector<Case>& registry() {
  static std::vector<Case> cases;
  return cases;
}

RunState& state() {
  static RunState value;
  return value;
}

void report_phase(const char* phase) {
  std::printf("  PHASE %s\n", phase);
  std::fflush(stdout);
}

void report_failure(const char* file, int line, const std::string& detail) {
  state().failed = true;
  std::printf("  FAIL %s:%d %s\n", file, line, detail.c_str());
  std::fflush(stdout);
}

int run_all(int argc, char** argv) {
  const char* filter = nullptr;
  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    if (argument == "--filter" && i + 1 < argc) {
      filter = argv[++i];
    } else if (argument.rfind("--filter=", 0) == 0) {
      filter = argv[i] + 9;
    } else if (argument == "--list") {
      for (const Case& entry : registry()) {
        std::printf("%s\n", entry.name.c_str());
      }
      return 0;
    }
  }

  std::vector<Case> selected;
  for (const Case& entry : registry()) {
    if (filter == nullptr || entry.name == filter) selected.push_back(entry);
  }
  std::sort(selected.begin(), selected.end(),
            [](const Case& a, const Case& b) { return a.name < b.name; });

  if (selected.empty()) {
    std::printf("no test case matched the filter\n");
    std::fflush(stdout);
    return 2;
  }

  std::size_t passed = 0;
  std::size_t failed = 0;
  for (const Case& entry : selected) {
    state() = RunState{};
    state().case_name = entry.name;
    std::printf("BEGIN %s\n", entry.name.c_str());
    std::fflush(stdout);
    const auto started = std::chrono::steady_clock::now();
    bool threw = false;
    std::string thrown;
    try {
      entry.function();
    } catch (const std::exception& error) {
      threw = true;
      thrown = error.what();
    } catch (...) {
      threw = true;
      thrown = "unknown exception";
    }
    const auto finished = std::chrono::steady_clock::now();
    const auto millis =
        std::chrono::duration_cast<std::chrono::milliseconds>(finished - started).count();
    if (threw) {
      report_failure(__FILE__, __LINE__, "unhandled exception: " + thrown);
    }
    if (state().failed) {
      ++failed;
      std::printf("FAIL %s (%lld ms, %d checks)\n", entry.name.c_str(),
                  static_cast<long long>(millis), state().checks);
    } else {
      ++passed;
      std::printf("PASS %s (%lld ms, %d checks)\n", entry.name.c_str(),
                  static_cast<long long>(millis), state().checks);
    }
    std::fflush(stdout);
  }
  std::printf("SUMMARY passed=%zu failed=%zu total=%zu\n", passed, failed, passed + failed);
  std::fflush(stdout);
  return failed == 0 ? 0 : 1;
}

}  // namespace crftest

int main(int argc, char** argv) { return crftest::run_all(argc, argv); }
