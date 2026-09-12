#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

#include "crf/export.hpp"

namespace crf {

/// The complete refusal vocabulary of the runtime.
///
/// Every operation that can refuse returns one of these codes. New codes are
/// appended; existing values are part of the persisted schema and the wire
/// protocol and must not be renumbered.
enum class StatusCode : std::uint16_t {
  ok = 0,

  // Request / argument shape
  invalid_argument = 1,
  invalid_identity = 2,
  invalid_enum = 3,
  capacity_exceeded = 4,

  // Existence and access
  not_found = 5,
  already_exists = 6,
  permission_denied = 7,

  // Path and workspace defence
  path_traversal = 8,
  workspace_escape = 9,
  path_not_absolute = 10,
  reparse_point_rejected = 11,

  // Capability
  unsupported = 12,
  not_implemented = 13,
  policy_refused = 14,

  // Authority staleness - one code per authority domain so refusals explain
  // exactly which generation moved.
  stale_session_generation = 20,
  stale_compilation_generation = 21,
  stale_attempt_generation = 22,
  stale_phase_generation = 23,
  stale_invocation = 24,
  stale_toolchain_generation = 25,
  stale_component_generation = 26,
  stale_target_generation = 27,
  stale_source_generation = 28,
  stale_ir_generation = 29,
  stale_environment_generation = 30,
  stale_policy_generation = 31,
  stale_lease_generation = 32,
  stale_artifact_generation = 33,
  stale_epoch = 34,
  stale_worker_generation = 35,

  // Lifecycle
  illegal_transition = 40,
  phase_not_ready = 41,
  phase_already_running = 42,
  phase_retired = 43,
  duplicate_completion = 44,
  divergent_completion = 45,
  not_authoritative = 46,
  session_not_active = 47,
  session_retired = 48,
  fan_in_incomplete = 49,
  fan_in_inconsistent = 50,
  cancelled = 51,
  shutting_down = 52,

  // Output validation
  output_missing = 60,
  output_empty = 61,
  output_corrupt = 62,
  output_unexpected_format = 63,
  output_wrong_target = 64,
  output_incompatible = 65,
  output_validation_failed = 66,
  smoke_test_failed = 67,

  // Process execution
  process_launch_failed = 70,
  process_exited_nonzero = 71,
  process_crashed = 72,
  process_cancelled = 73,
  process_capture_truncated = 74,
  process_orphaned = 75,

  // Retry / recovery
  retry_not_permitted = 80,
  retry_exhausted = 81,
  recovery_unsupported = 82,
  manual_resolution_required = 83,
  integrity_unproven = 84,
  unknown_outcome = 85,

  // Persistence
  persistence_io = 90,
  persistence_corrupt = 91,
  persistence_truncated = 92,
  persistence_schema_mismatch = 93,
  persistence_bounds_exceeded = 94,

  // Protocol
  protocol_malformed = 100,
  protocol_frame_too_large = 101,
  protocol_frame_truncated = 102,
  protocol_version_mismatch = 103,
  protocol_duplicate_request = 104,
  protocol_unknown_operation = 105,
  protocol_peer_closed = 106,
  protocol_io = 107,
  protocol_replay_rejected = 108,

  // Environment / toolchain probing
  toolchain_not_found = 110,
  toolchain_ambiguous = 111,
  component_not_found = 112,
  component_mutated = 113,
  probe_failed = 114,
  target_unsupported = 115,

  internal_error = 200,
};

CRF_NODISCARD CRF_API std::string_view to_string(StatusCode code) noexcept;

/// True when the condition may be retried after fresh invocation authority is
/// granted. This is a *classification*, not a decision: the retry policy applies
/// its own ceilings on top.
CRF_NODISCARD CRF_API bool is_transient(StatusCode code) noexcept;

/// A refusal with human-readable context. The message is diagnostic text only;
/// control flow must branch on the code.
class CRF_API Status {
 public:
  Status() noexcept = default;
  Status(StatusCode code, std::string message) : code_(code), message_(std::move(message)) {}
  explicit Status(StatusCode code) : code_(code) {}

  CRF_NODISCARD StatusCode code() const noexcept { return code_; }
  CRF_NODISCARD bool ok() const noexcept { return code_ == StatusCode::ok; }
  CRF_NODISCARD const std::string& message() const noexcept { return message_; }

  /// Deterministic single-line rendering: "<code>: <message>".
  CRF_NODISCARD std::string to_string() const;

  CRF_NODISCARD static Status success() noexcept { return Status(); }

 private:
  StatusCode code_ = StatusCode::ok;
  std::string message_;
};

/// Result carrying either a value or a refusal.
///
/// The runtime never throws for expected refusals. Exceptions are reserved for
/// unrecoverable allocation failures.
template <class T>
class Result {
 public:
  Result(T value) : storage_(std::move(value)) {}          // NOLINT(google-explicit-constructor)
  Result(Status status) : storage_(std::move(status)) {}   // NOLINT(google-explicit-constructor)

  CRF_NODISCARD bool has_value() const noexcept { return storage_.index() == 0; }
  explicit operator bool() const noexcept { return has_value(); }

  CRF_NODISCARD T& value() & { return std::get<0>(storage_); }
  CRF_NODISCARD const T& value() const& { return std::get<0>(storage_); }
  CRF_NODISCARD T&& value() && { return std::get<0>(std::move(storage_)); }

  CRF_NODISCARD const Status& status() const noexcept {
    static const Status kOk{};
    return storage_.index() == 1 ? std::get<1>(storage_) : kOk;
  }
  CRF_NODISCARD StatusCode code() const noexcept { return status().code(); }

  CRF_NODISCARD T value_or(T fallback) const {
    return has_value() ? std::get<0>(storage_) : std::move(fallback);
  }

 private:
  std::variant<T, Status> storage_;
};

/// Specialisation for operations that only succeed or refuse.
template <>
class Result<void> {
 public:
  Result() = default;
  Result(Status status) : status_(std::move(status)) {}  // NOLINT(google-explicit-constructor)

  CRF_NODISCARD bool has_value() const noexcept { return status_.ok(); }
  explicit operator bool() const noexcept { return has_value(); }
  CRF_NODISCARD const Status& status() const noexcept { return status_; }
  CRF_NODISCARD StatusCode code() const noexcept { return status_.code(); }

 private:
  Status status_;
};

using VoidResult = Result<void>;

/// Propagate a refusal from an inner call, keeping the original Status.
#define CRF_TRY(expr)                        \
  do {                                       \
    auto crf_try_result = (expr);            \
    if (!crf_try_result.has_value()) {       \
      return crf_try_result.status();        \
    }                                        \
  } while (false)

/// Same as CRF_TRY but returns the value of the inner call.
#define CRF_TRY_ASSIGN(name, expr)           \
  auto crf_try_##name = (expr);              \
  if (!crf_try_##name.has_value()) {         \
    return crf_try_##name.status();          \
  }                                          \
  auto name = std::move(crf_try_##name).value()

}  // namespace crf
