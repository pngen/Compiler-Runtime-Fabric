#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "crf/phase.hpp"
#include "crf/policy.hpp"
#include "crf/status.hpp"
#include "crf/strong_id.hpp"

namespace crf {

enum class RetryDecisionKind : std::uint8_t {
  permitted = 0,
  /// The failure class is not retryable at all.
  classification_refuses = 1,
  /// A ceiling was reached.
  exhausted = 2,
  /// The phase already committed; a retry would duplicate authoritative work.
  already_committed = 3,
  /// The phase is fenced, cancelled, or retired, so no new authority is granted.
  authority_withdrawn = 4,
  /// The outcome is UNKNOWN. Never automatically retryable.
  manual_resolution_required = 5,
  /// The session is not active.
  session_not_active = 6,
};

CRF_NODISCARD CRF_API std::string_view to_string(RetryDecisionKind value) noexcept;

struct CRF_API RetryDecision {
  RetryDecisionKind kind = RetryDecisionKind::classification_refuses;
  bool legal = false;
  FailureClass failure = FailureClass::none;
  std::uint32_t attempts_used = 0;
  std::uint32_t session_retries_used = 0;
  /// The generation the new attempt receives. A retry always creates fresh
  /// invocation authority: new AttemptId, new AttemptGeneration, new
  /// InvocationId, new LeaseId.
  AttemptGeneration next_attempt_generation{};
  bool creates_new_invocation = true;
  StatusCode refusal = StatusCode::ok;
  std::string reason;

  CRF_NODISCARD std::string describe() const;
};

/// Decide whether a phase may be retried.
///
/// A retry that is legal still requires re-validation of every authority
/// generation at reservation time. A retry never reuses the previous
/// invocation's identity, so late output from the previous invocation can never
/// satisfy it.
CRF_NODISCARD CRF_API RetryDecision evaluate_retry(const PhaseRecord& phase,
                                                   const PolicySpec& policy,
                                                   std::uint32_t session_retries_used) noexcept;

}  // namespace crf
