#include "crf/retry.hpp"
#include "crf/canonical.hpp"

namespace crf {

std::string_view to_string(RetryDecisionKind value) noexcept {
  switch (value) {
    case RetryDecisionKind::permitted: return "PERMITTED";
    case RetryDecisionKind::classification_refuses: return "CLASSIFICATION_REFUSES";
    case RetryDecisionKind::exhausted: return "EXHAUSTED";
    case RetryDecisionKind::already_committed: return "ALREADY_COMMITTED";
    case RetryDecisionKind::authority_withdrawn: return "AUTHORITY_WITHDRAWN";
    case RetryDecisionKind::manual_resolution_required: return "MANUAL_RESOLUTION_REQUIRED";
    case RetryDecisionKind::session_not_active: return "SESSION_NOT_ACTIVE";
  }
  return "UNKNOWN";
}

std::string RetryDecision::describe() const {
  std::string out(to_string(kind));
  out.append(" failure=");
  out.append(to_string(failure));
  out.append(" attempts=");
  out.append(std::to_string(attempts_used));
  if (legal) {
    out.append(" next-attempt-generation=");
    out.append(next_attempt_generation.to_string());
  }
  if (!reason.empty()) {
    out.append(" reason=");
    out.append(reason);
  }
  return out;
}

RetryDecision evaluate_retry(const PhaseRecord& phase, const PolicySpec& policy,
                             std::uint32_t session_retries_used) noexcept {
  RetryDecision decision;
  decision.failure = phase.failure;
  decision.attempts_used = phase.attempt_count();
  decision.session_retries_used = session_retries_used;
  decision.next_attempt_generation = phase.attempt_generation;

  if (phase.state == PhaseState::committed) {
    decision.kind = RetryDecisionKind::already_committed;
    decision.legal = false;
    decision.creates_new_invocation = false;
    decision.refusal = StatusCode::duplicate_completion;
    decision.reason = "the phase already committed an authoritative result";
    return decision;
  }
  if (phase.state == PhaseState::fenced || phase.state == PhaseState::cancelled ||
      phase.state == PhaseState::retired) {
    decision.kind = RetryDecisionKind::authority_withdrawn;
    decision.legal = false;
    decision.creates_new_invocation = false;
    decision.refusal = StatusCode::phase_retired;
    decision.reason = std::string("the phase is ") + std::string(to_string(phase.state)) +
                      " and no longer retains commit authority";
    return decision;
  }
  if (phase.state == PhaseState::running || phase.state == PhaseState::preparing ||
      phase.state == PhaseState::produced || phase.state == PhaseState::validating ||
      phase.state == PhaseState::commit_ready) {
    decision.kind = RetryDecisionKind::authority_withdrawn;
    decision.legal = false;
    decision.creates_new_invocation = false;
    decision.refusal = StatusCode::phase_already_running;
    decision.reason = "the phase is still in flight; retry requires the current attempt to conclude";
    return decision;
  }
  if (phase.state != PhaseState::failed && phase.state != PhaseState::recovery_required &&
      phase.state != PhaseState::ready && phase.state != PhaseState::pending) {
    decision.kind = RetryDecisionKind::authority_withdrawn;
    decision.legal = false;
    decision.refusal = StatusCode::illegal_transition;
    decision.reason = "the phase state does not admit a retry";
    return decision;
  }
  if (phase.failure == FailureClass::unknown_outcome) {
    decision.kind = RetryDecisionKind::manual_resolution_required;
    decision.legal = false;
    decision.creates_new_invocation = true;
    decision.refusal = StatusCode::manual_resolution_required;
    decision.reason =
        "the outcome of the previous attempt is UNKNOWN; the runtime fails closed rather than "
        "retrying an unproven failure";
    return decision;
  }
  if (phase.failure == FailureClass::authority_invalidated) {
    decision.kind = RetryDecisionKind::permitted;
    decision.legal = true;
    decision.creates_new_invocation = true;
    decision.next_attempt_generation = phase.attempt_generation.next();
    decision.reason =
        "authority moved while the phase was executing; a fresh invocation under current authority "
        "is permitted";
    return decision;
  }
  if (!policy.permits_retry(phase.failure)) {
    decision.kind = RetryDecisionKind::classification_refuses;
    decision.legal = false;
    decision.refusal = StatusCode::retry_not_permitted;
    decision.reason = std::string("failure class ") + std::string(to_string(phase.failure)) +
                      " is not retryable";
    return decision;
  }
  if (phase.attempt_count() > policy.max_retries_per_phase) {
    decision.kind = RetryDecisionKind::exhausted;
    decision.legal = false;
    decision.refusal = StatusCode::retry_exhausted;
    decision.reason = "the per-phase retry ceiling has been reached";
    return decision;
  }
  if (session_retries_used >= policy.max_retries_per_session) {
    decision.kind = RetryDecisionKind::exhausted;
    decision.legal = false;
    decision.refusal = StatusCode::retry_exhausted;
    decision.reason = "the per-session retry ceiling has been reached";
    return decision;
  }
  decision.kind = RetryDecisionKind::permitted;
  decision.legal = true;
  decision.creates_new_invocation = true;
  decision.next_attempt_generation = phase.attempt_generation.next();
  decision.reason = "failure class is retryable and both retry ceilings permit another attempt";
  return decision;
}

}  // namespace crf
