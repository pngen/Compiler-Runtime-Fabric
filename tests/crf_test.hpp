#pragma once

// Compiler Runtime Fabric test harness.
//
// Design goals:
//   * stable case names;
//   * exact-case execution via a command-line filter;
//   * flushed BEGIN / PASS / FAIL markers so a hang localises to one case;
//   * explicit phase markers inside a case;
//   * no artificial deadlines: a hang is a defect, not a timeout to tolerate.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <functional>
#include <string>
#include <vector>

namespace crftest {

using TestFn = void (*)();

struct Case {
  std::string name;
  TestFn function;
};

std::vector<Case>& registry();

struct Registrar {
  Registrar(const char* name, TestFn function) { registry().push_back(Case{name, function}); }
};

/// Current case state, used by the assertion macros.
struct RunState {
  bool failed = false;
  int checks = 0;
  std::string case_name;
};

RunState& state();

void report_phase(const char* phase);
void report_failure(const char* file, int line, const std::string& detail);

int run_all(int argc, char** argv);

}  // namespace crftest

#define CRF_TEST(name)                                                    \
  static void name();                                                     \
  static const ::crftest::Registrar crf_registrar_##name(#name, &name);   \
  static void name()

#define CRF_PHASE(phase) ::crftest::report_phase(phase)

#define CRF_FAIL(message)                                                     \
  do {                                                                        \
    ::crftest::report_failure(__FILE__, __LINE__, (message));                 \
  } while (false)

#define CRF_EXPECT(condition)                                                 \
  do {                                                                        \
    ++::crftest::state().checks;                                              \
    if (!(condition)) {                                                       \
      ::crftest::report_failure(__FILE__, __LINE__, "expected: " #condition); \
    }                                                                         \
  } while (false)

#define CRF_EXPECT_EQ(actual, expected)                                            \
  do {                                                                             \
    ++::crftest::state().checks;                                                    \
    const auto crf_actual = (actual);                                               \
    const auto crf_expected = (expected);                                           \
    if (!(crf_actual == crf_expected)) {                                            \
      ::crftest::report_failure(__FILE__, __LINE__,                                 \
                                std::string("expected " #actual " == " #expected)); \
    }                                                                               \
  } while (false)

#define CRF_EXPECT_NE(actual, unexpected)                                          \
  do {                                                                             \
    ++::crftest::state().checks;                                                    \
    if ((actual) == (unexpected)) {                                                 \
      ::crftest::report_failure(__FILE__, __LINE__,                                 \
                                std::string("expected " #actual " != " #unexpected)); \
    }                                                                               \
  } while (false)

#define CRF_REQUIRE(condition)                                                \
  do {                                                                        \
    ++::crftest::state().checks;                                              \
    if (!(condition)) {                                                       \
      ::crftest::report_failure(__FILE__, __LINE__, "required: " #condition); \
      return;                                                                 \
    }                                                                         \
  } while (false)

#define CRF_REQUIRE_OK(result)                                                \
  do {                                                                        \
    ++::crftest::state().checks;                                              \
    if (!(result)) {                                                          \
      ::crftest::report_failure(__FILE__, __LINE__,                           \
                                std::string("unexpected refusal: ") +         \
                                    (result).status().to_string());           \
      return;                                                                 \
    }                                                                         \
  } while (false)

#define CRF_EXPECT_OK(result)                                                 \
  do {                                                                        \
    ++::crftest::state().checks;                                              \
    if (!(result)) {                                                          \
      ::crftest::report_failure(__FILE__, __LINE__,                           \
                                std::string("unexpected refusal: ") +         \
                                    (result).status().to_string());           \
    }                                                                         \
  } while (false)

/// Expect a specific refusal code.
#define CRF_EXPECT_CODE(result, expected_code)                                     \
  do {                                                                             \
    ++::crftest::state().checks;                                                    \
    const auto& crf_result = (result);                                              \
    if (crf_result.has_value()) {                                                   \
      ::crftest::report_failure(__FILE__, __LINE__,                                 \
                                std::string("expected refusal " #expected_code));    \
    } else if (crf_result.code() != (expected_code)) {                              \
      ::crftest::report_failure(                                                    \
          __FILE__, __LINE__,                                                       \
          std::string("expected refusal " #expected_code " but observed ") +        \
              std::string(::crf::to_string(crf_result.code())));                     \
    }                                                                               \
  } while (false)
