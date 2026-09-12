#include "crf/phase.hpp"
#include "crf/canonical.hpp"

namespace crf {

std::string_view to_string(PhaseKind value) noexcept {
  switch (value) {
    case PhaseKind::unknown: return "UNKNOWN";
    case PhaseKind::input_validate: return "INPUT_VALIDATE";
    case PhaseKind::preprocess: return "PREPROCESS";
    case PhaseKind::frontend: return "FRONTEND";
    case PhaseKind::parse: return "PARSE";
    case PhaseKind::semantic_analysis: return "SEMANTIC_ANALYSIS";
    case PhaseKind::ir_generate: return "IR_GENERATE";
    case PhaseKind::ir_optimize: return "IR_OPTIMIZE";
    case PhaseKind::codegen: return "CODEGEN";
    case PhaseKind::assemble: return "ASSEMBLE";
    case PhaseKind::device_compile: return "DEVICE_COMPILE";
    case PhaseKind::device_link: return "DEVICE_LINK";
    case PhaseKind::link: return "LINK";
    case PhaseKind::postprocess: return "POSTPROCESS";
    case PhaseKind::validate: return "VALIDATE";
    case PhaseKind::finalize: return "FINALIZE";
    case PhaseKind::custom: return "CUSTOM";
  }
  return "UNKNOWN";
}

bool parse_phase_kind(std::string_view text, PhaseKind& out) noexcept {
  static constexpr PhaseKind kValues[] = {
      PhaseKind::unknown,       PhaseKind::input_validate, PhaseKind::preprocess,
      PhaseKind::frontend,      PhaseKind::parse,          PhaseKind::semantic_analysis,
      PhaseKind::ir_generate,   PhaseKind::ir_optimize,    PhaseKind::codegen,
      PhaseKind::assemble,      PhaseKind::device_compile, PhaseKind::device_link,
      PhaseKind::link,          PhaseKind::postprocess,    PhaseKind::validate,
      PhaseKind::finalize,      PhaseKind::custom};
  for (PhaseKind value : kValues) {
    if (equals_ascii_ci(text, to_string(value))) {
      out = value;
      return true;
    }
  }
  return false;
}

std::string_view to_string(PhaseState value) noexcept {
  switch (value) {
    case PhaseState::pending: return "PENDING";
    case PhaseState::ready: return "READY";
    case PhaseState::preparing: return "PREPARING";
    case PhaseState::running: return "RUNNING";
    case PhaseState::produced: return "PRODUCED";
    case PhaseState::validating: return "VALIDATING";
    case PhaseState::commit_ready: return "COMMIT_READY";
    case PhaseState::committed: return "COMMITTED";
    case PhaseState::failed: return "FAILED";
    case PhaseState::cancelled: return "CANCELLED";
    case PhaseState::fenced: return "FENCED";
    case PhaseState::recovery_required: return "RECOVERY_REQUIRED";
    case PhaseState::retired: return "RETIRED";
  }
  return "UNKNOWN";
}

bool parse_phase_state(std::string_view text, PhaseState& out) noexcept {
  static constexpr PhaseState kValues[] = {
      PhaseState::pending,  PhaseState::ready,      PhaseState::preparing, PhaseState::running,
      PhaseState::produced, PhaseState::validating, PhaseState::commit_ready,
      PhaseState::committed, PhaseState::failed,    PhaseState::cancelled, PhaseState::fenced,
      PhaseState::recovery_required, PhaseState::retired};
  for (PhaseState value : kValues) {
    if (equals_ascii_ci(text, to_string(value))) {
      out = value;
      return true;
    }
  }
  return false;
}

bool is_legal_phase_transition(PhaseState from, PhaseState to) noexcept {
  if (from == to) return false;
  switch (from) {
    case PhaseState::pending:
      return to == PhaseState::ready || to == PhaseState::cancelled || to == PhaseState::retired;
    case PhaseState::ready:
      return to == PhaseState::preparing || to == PhaseState::cancelled ||
             to == PhaseState::retired || to == PhaseState::recovery_required ||
             to == PhaseState::failed;
    case PhaseState::preparing:
      return to == PhaseState::running || to == PhaseState::failed || to == PhaseState::cancelled ||
             to == PhaseState::fenced || to == PhaseState::recovery_required;
    case PhaseState::running:
      return to == PhaseState::produced || to == PhaseState::failed || to == PhaseState::cancelled ||
             to == PhaseState::fenced || to == PhaseState::recovery_required;
    case PhaseState::produced:
      return to == PhaseState::validating || to == PhaseState::failed ||
             to == PhaseState::cancelled || to == PhaseState::fenced ||
             to == PhaseState::recovery_required;
    case PhaseState::validating:
      return to == PhaseState::commit_ready || to == PhaseState::failed ||
             to == PhaseState::cancelled || to == PhaseState::fenced ||
             to == PhaseState::recovery_required;
    case PhaseState::commit_ready:
      // The only forward edge out of COMMIT_READY is the authoritative commit.
      return to == PhaseState::committed || to == PhaseState::failed ||
             to == PhaseState::cancelled || to == PhaseState::fenced ||
             to == PhaseState::recovery_required;
    case PhaseState::committed:
      // A committed phase may only be fenced (authority withdrawn by a later
      // generation) or retired (removed from the executable plan).
      return to == PhaseState::fenced || to == PhaseState::retired;
    case PhaseState::failed:
      // A retry advances the phase generation and re-enters through READY. A
      // failed phase may never move directly to RUNNING or COMMITTED.
      return to == PhaseState::ready || to == PhaseState::cancelled ||
             to == PhaseState::retired || to == PhaseState::recovery_required ||
             to == PhaseState::fenced;
    case PhaseState::cancelled:
      return to == PhaseState::retired;
    case PhaseState::fenced:
      return to == PhaseState::retired;
    case PhaseState::recovery_required:
      return to == PhaseState::ready || to == PhaseState::failed ||
             to == PhaseState::cancelled || to == PhaseState::retired;
    case PhaseState::retired:
      return false;
  }
  return false;
}

bool phase_state_is_terminal(PhaseState state) noexcept {
  return state == PhaseState::committed || state == PhaseState::cancelled ||
         state == PhaseState::retired || state == PhaseState::fenced;
}

bool phase_state_retains_commit_authority(PhaseState state) noexcept {
  switch (state) {
    case PhaseState::pending:
    case PhaseState::ready:
    case PhaseState::preparing:
    case PhaseState::running:
    case PhaseState::produced:
    case PhaseState::validating:
    case PhaseState::commit_ready:
      return true;
    default:
      return false;
  }
}

bool phase_state_may_hold_process(PhaseState state) noexcept {
  return state == PhaseState::preparing || state == PhaseState::running;
}

std::string_view to_string(FailureClass value) noexcept {
  switch (value) {
    case FailureClass::none: return "NONE";
    case FailureClass::process_crash: return "PROCESS_CRASH";
    case FailureClass::process_interrupted: return "PROCESS_INTERRUPTED";
    case FailureClass::transient_workspace_failure: return "TRANSIENT_WORKSPACE_FAILURE";
    case FailureClass::transient_storage_failure: return "TRANSIENT_STORAGE_FAILURE";
    case FailureClass::retry_safe_tool_invocation_failure: return "RETRY_SAFE_TOOL_INVOCATION_FAILURE";
    case FailureClass::external_cancellation: return "EXTERNAL_CANCELLATION";
    case FailureClass::invalid_source: return "INVALID_SOURCE";
    case FailureClass::deterministic_compiler_error: return "DETERMINISTIC_COMPILER_ERROR";
    case FailureClass::unsupported_target: return "UNSUPPORTED_TARGET";
    case FailureClass::unsupported_option: return "UNSUPPORTED_OPTION";
    case FailureClass::invalid_toolchain: return "INVALID_TOOLCHAIN";
    case FailureClass::policy_refusal: return "POLICY_REFUSAL";
    case FailureClass::output_invalid: return "OUTPUT_INVALID";
    case FailureClass::authority_invalidated: return "AUTHORITY_INVALIDATED";
    case FailureClass::unknown_outcome: return "UNKNOWN_OUTCOME";
  }
  return "UNKNOWN_OUTCOME";
}

bool parse_failure_class(std::string_view text, FailureClass& out) noexcept {
  static constexpr FailureClass kValues[] = {
      FailureClass::none,
      FailureClass::process_crash,
      FailureClass::process_interrupted,
      FailureClass::transient_workspace_failure,
      FailureClass::transient_storage_failure,
      FailureClass::retry_safe_tool_invocation_failure,
      FailureClass::external_cancellation,
      FailureClass::invalid_source,
      FailureClass::deterministic_compiler_error,
      FailureClass::unsupported_target,
      FailureClass::unsupported_option,
      FailureClass::invalid_toolchain,
      FailureClass::policy_refusal,
      FailureClass::output_invalid,
      FailureClass::authority_invalidated,
      FailureClass::unknown_outcome};
  for (FailureClass value : kValues) {
    if (equals_ascii_ci(text, to_string(value))) {
      out = value;
      return true;
    }
  }
  return false;
}

bool is_retryable(FailureClass value) noexcept {
  switch (value) {
    case FailureClass::process_crash:
    case FailureClass::process_interrupted:
    case FailureClass::transient_workspace_failure:
    case FailureClass::transient_storage_failure:
    case FailureClass::retry_safe_tool_invocation_failure:
    case FailureClass::external_cancellation:
      return true;
    default:
      // Everything else - including UNKNOWN_OUTCOME - is not retryable by
      // classification. UNKNOWN fails closed.
      return false;
  }
}

FailureClass classify_status(StatusCode code) noexcept {
  switch (code) {
    case StatusCode::ok:
      return FailureClass::none;
    case StatusCode::process_crashed:
      return FailureClass::process_crash;
    case StatusCode::process_cancelled:
    case StatusCode::cancelled:
    case StatusCode::shutting_down:
      return FailureClass::external_cancellation;
    case StatusCode::process_launch_failed:
    case StatusCode::process_orphaned:
      return FailureClass::transient_workspace_failure;
    case StatusCode::persistence_io:
    case StatusCode::persistence_truncated:
      return FailureClass::transient_storage_failure;
    case StatusCode::stale_session_generation:
    case StatusCode::stale_compilation_generation:
    case StatusCode::stale_attempt_generation:
    case StatusCode::stale_phase_generation:
    case StatusCode::stale_invocation:
    case StatusCode::stale_toolchain_generation:
    case StatusCode::stale_component_generation:
    case StatusCode::stale_target_generation:
    case StatusCode::stale_source_generation:
    case StatusCode::stale_ir_generation:
    case StatusCode::stale_environment_generation:
    case StatusCode::stale_policy_generation:
    case StatusCode::stale_lease_generation:
    case StatusCode::stale_artifact_generation:
    case StatusCode::stale_epoch:
    case StatusCode::stale_worker_generation:
      return FailureClass::authority_invalidated;
    case StatusCode::output_missing:
    case StatusCode::output_empty:
    case StatusCode::output_corrupt:
    case StatusCode::output_unexpected_format:
    case StatusCode::output_wrong_target:
    case StatusCode::output_incompatible:
    case StatusCode::output_validation_failed:
    case StatusCode::smoke_test_failed:
      return FailureClass::output_invalid;
    case StatusCode::toolchain_not_found:
    case StatusCode::component_not_found:
    case StatusCode::component_mutated:
    case StatusCode::toolchain_ambiguous:
      return FailureClass::invalid_toolchain;
    case StatusCode::target_unsupported:
    case StatusCode::unsupported:
    case StatusCode::not_implemented:
      return FailureClass::unsupported_target;
    case StatusCode::policy_refused:
    case StatusCode::invalid_argument:
    case StatusCode::invalid_identity:
    case StatusCode::invalid_enum:
    case StatusCode::path_traversal:
    case StatusCode::workspace_escape:
    case StatusCode::path_not_absolute:
    case StatusCode::reparse_point_rejected:
    case StatusCode::permission_denied:
    case StatusCode::retry_not_permitted:
    case StatusCode::retry_exhausted:
      return FailureClass::policy_refusal;
    case StatusCode::process_exited_nonzero:
    case StatusCode::not_found:
      return FailureClass::deterministic_compiler_error;
    default:
      // Anything the runtime cannot prove about is UNKNOWN and fails closed.
      return FailureClass::unknown_outcome;
  }
}

const PhaseAttempt* PhaseRecord::find_attempt(AttemptId attempt) const noexcept {
  for (const PhaseAttempt& entry : attempts) {
    if (entry.id == attempt) return &entry;
  }
  return nullptr;
}

Digest PhaseRecord::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(id.to_string());
  writer.u64(generation.value());
  writer.text(to_string(kind));
  writer.text(adapter_phase);
  writer.text(to_string(state));
  writer.boolean(mandatory);
  writer.u64(session_generation.value());
  writer.u64(compilation_generation.value());
  writer.u64(attempt_generation.value());
  writer.text(toolchain.to_string());
  writer.text(target.to_string());
  writer.text(environment.to_string());
  writer.text(policy.to_string());
  writer.text(source.to_string());
  writer.u64(ir_generation.value());
  writer.text(lease.to_string());
  writer.text(active_invocation.to_string());
  writer.u64(active_process.value());
  writer.u64(active_process_generation.value());
  writer.text(commit.to_string());
  writer.text(committed_output_digest.to_hex());
  writer.u64(committed_at_nanos);
  writer.text(to_string(failure));
  writer.text(to_string(last_status));
  writer.text(last_detail);
  for (const Ref<IntermediateArtifactId>& input : inputs) writer.text(input.to_string());
  for (const Ref<IntermediateArtifactId>& output : outputs) writer.text(output.to_string());
  for (const PhaseAttempt& attempt : attempts) {
    writer.text(attempt.id.to_string());
    writer.u64(attempt.generation.value());
    writer.text(attempt.invocation.to_string());
    writer.text(to_string(attempt.failure));
    writer.text(to_string(attempt.status));
    writer.i32(attempt.exit_code);
    writer.text(attempt.observed_output_digest.to_hex());
  }
  return Digest::of(writer.bytes());
}

}  // namespace crf
