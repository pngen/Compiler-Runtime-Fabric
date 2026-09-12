#include "crf/status.hpp"

namespace crf {

std::string_view to_string(StatusCode code) noexcept {
  switch (code) {
    case StatusCode::ok: return "ok";
    case StatusCode::invalid_argument: return "invalid-argument";
    case StatusCode::invalid_identity: return "invalid-identity";
    case StatusCode::invalid_enum: return "invalid-enum";
    case StatusCode::capacity_exceeded: return "capacity-exceeded";
    case StatusCode::not_found: return "not-found";
    case StatusCode::already_exists: return "already-exists";
    case StatusCode::permission_denied: return "permission-denied";
    case StatusCode::path_traversal: return "path-traversal";
    case StatusCode::workspace_escape: return "workspace-escape";
    case StatusCode::path_not_absolute: return "path-not-absolute";
    case StatusCode::reparse_point_rejected: return "reparse-point-rejected";
    case StatusCode::unsupported: return "unsupported";
    case StatusCode::not_implemented: return "not-implemented";
    case StatusCode::policy_refused: return "policy-refused";
    case StatusCode::stale_session_generation: return "stale-session-generation";
    case StatusCode::stale_compilation_generation: return "stale-compilation-generation";
    case StatusCode::stale_attempt_generation: return "stale-attempt-generation";
    case StatusCode::stale_phase_generation: return "stale-phase-generation";
    case StatusCode::stale_invocation: return "stale-invocation";
    case StatusCode::stale_toolchain_generation: return "stale-toolchain-generation";
    case StatusCode::stale_component_generation: return "stale-component-generation";
    case StatusCode::stale_target_generation: return "stale-target-generation";
    case StatusCode::stale_source_generation: return "stale-source-generation";
    case StatusCode::stale_ir_generation: return "stale-ir-generation";
    case StatusCode::stale_environment_generation: return "stale-environment-generation";
    case StatusCode::stale_policy_generation: return "stale-policy-generation";
    case StatusCode::stale_lease_generation: return "stale-lease-generation";
    case StatusCode::stale_artifact_generation: return "stale-artifact-generation";
    case StatusCode::stale_epoch: return "stale-epoch";
    case StatusCode::stale_worker_generation: return "stale-worker-generation";
    case StatusCode::illegal_transition: return "illegal-transition";
    case StatusCode::phase_not_ready: return "phase-not-ready";
    case StatusCode::phase_already_running: return "phase-already-running";
    case StatusCode::phase_retired: return "phase-retired";
    case StatusCode::duplicate_completion: return "duplicate-completion";
    case StatusCode::divergent_completion: return "divergent-completion";
    case StatusCode::not_authoritative: return "not-authoritative";
    case StatusCode::session_not_active: return "session-not-active";
    case StatusCode::session_retired: return "session-retired";
    case StatusCode::fan_in_incomplete: return "fan-in-incomplete";
    case StatusCode::fan_in_inconsistent: return "fan-in-inconsistent";
    case StatusCode::cancelled: return "cancelled";
    case StatusCode::shutting_down: return "shutting-down";
    case StatusCode::output_missing: return "output-missing";
    case StatusCode::output_empty: return "output-empty";
    case StatusCode::output_corrupt: return "output-corrupt";
    case StatusCode::output_unexpected_format: return "output-unexpected-format";
    case StatusCode::output_wrong_target: return "output-wrong-target";
    case StatusCode::output_incompatible: return "output-incompatible";
    case StatusCode::output_validation_failed: return "output-validation-failed";
    case StatusCode::smoke_test_failed: return "smoke-test-failed";
    case StatusCode::process_launch_failed: return "process-launch-failed";
    case StatusCode::process_exited_nonzero: return "process-exited-nonzero";
    case StatusCode::process_crashed: return "process-crashed";
    case StatusCode::process_cancelled: return "process-cancelled";
    case StatusCode::process_capture_truncated: return "process-capture-truncated";
    case StatusCode::process_orphaned: return "process-orphaned";
    case StatusCode::retry_not_permitted: return "retry-not-permitted";
    case StatusCode::retry_exhausted: return "retry-exhausted";
    case StatusCode::recovery_unsupported: return "recovery-unsupported";
    case StatusCode::manual_resolution_required: return "manual-resolution-required";
    case StatusCode::integrity_unproven: return "integrity-unproven";
    case StatusCode::unknown_outcome: return "unknown-outcome";
    case StatusCode::persistence_io: return "persistence-io";
    case StatusCode::persistence_corrupt: return "persistence-corrupt";
    case StatusCode::persistence_truncated: return "persistence-truncated";
    case StatusCode::persistence_schema_mismatch: return "persistence-schema-mismatch";
    case StatusCode::persistence_bounds_exceeded: return "persistence-bounds-exceeded";
    case StatusCode::protocol_malformed: return "protocol-malformed";
    case StatusCode::protocol_frame_too_large: return "protocol-frame-too-large";
    case StatusCode::protocol_frame_truncated: return "protocol-frame-truncated";
    case StatusCode::protocol_version_mismatch: return "protocol-version-mismatch";
    case StatusCode::protocol_duplicate_request: return "protocol-duplicate-request";
    case StatusCode::protocol_unknown_operation: return "protocol-unknown-operation";
    case StatusCode::protocol_peer_closed: return "protocol-peer-closed";
    case StatusCode::protocol_io: return "protocol-io";
    case StatusCode::protocol_replay_rejected: return "protocol-replay-rejected";
    case StatusCode::toolchain_not_found: return "toolchain-not-found";
    case StatusCode::toolchain_ambiguous: return "toolchain-ambiguous";
    case StatusCode::component_not_found: return "component-not-found";
    case StatusCode::component_mutated: return "component-mutated";
    case StatusCode::probe_failed: return "probe-failed";
    case StatusCode::target_unsupported: return "target-unsupported";
    case StatusCode::internal_error: return "internal-error";
  }
  return "unknown-status";
}

bool is_transient(StatusCode code) noexcept {
  switch (code) {
    case StatusCode::process_crashed:
    case StatusCode::process_cancelled:
    case StatusCode::process_orphaned:
    case StatusCode::persistence_io:
    case StatusCode::protocol_io:
    case StatusCode::protocol_peer_closed:
    case StatusCode::probe_failed:
    case StatusCode::component_mutated:
      return true;
    default:
      return false;
  }
}

std::string Status::to_string() const {
  std::string out(crf::to_string(code_));
  if (!message_.empty()) {
    out.append(": ");
    out.append(message_);
  }
  return out;
}

}  // namespace crf
