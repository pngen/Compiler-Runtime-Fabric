#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "crf/digest.hpp"
#include "crf/evidence.hpp"
#include "crf/status.hpp"
#include "crf/strong_id.hpp"

namespace crf {

/// Generic compiler phases. An adapter declares which of these it actually
/// implements; a phase is never claimed just because the vocabulary contains it.
enum class PhaseKind : std::uint8_t {
  unknown = 0,
  input_validate = 1,
  preprocess = 2,
  frontend = 3,
  parse = 4,
  semantic_analysis = 5,
  ir_generate = 6,
  ir_optimize = 7,
  codegen = 8,
  assemble = 9,
  device_compile = 10,
  device_link = 11,
  link = 12,
  postprocess = 13,
  validate = 14,
  finalize = 15,
  /// Adapter-defined phase with an adapter-specific name.
  custom = 16,
};

CRF_NODISCARD CRF_API std::string_view to_string(PhaseKind value) noexcept;
CRF_NODISCARD CRF_API bool parse_phase_kind(std::string_view text, PhaseKind& out) noexcept;

/// Explicit phase lifecycle.
///
///   Pending -> Ready -> Preparing -> Running -> Produced -> Validating
///           -> CommitReady -> Committed
///
/// Off-path states: Failed, Cancelled, Fenced, RecoveryRequired, Retired.
/// Produced is *not* Committed: an exit code of zero only advances to Produced.
enum class PhaseState : std::uint8_t {
  pending = 0,
  ready = 1,
  preparing = 2,
  running = 3,
  produced = 4,
  validating = 5,
  commit_ready = 6,
  committed = 7,
  failed = 8,
  cancelled = 9,
  fenced = 10,
  recovery_required = 11,
  retired = 12,
};

CRF_NODISCARD CRF_API std::string_view to_string(PhaseState value) noexcept;
CRF_NODISCARD CRF_API bool parse_phase_state(std::string_view text, PhaseState& out) noexcept;

/// True only for transitions the lifecycle permits. Committed -> Running is not
/// legal; Retired -> Ready is not legal; a Fenced phase can never reach
/// Committed; Cancelled can never reach Committed.
CRF_NODISCARD CRF_API bool is_legal_phase_transition(PhaseState from, PhaseState to) noexcept;

/// Terminal states cannot be left by any transition.
CRF_NODISCARD CRF_API bool phase_state_is_terminal(PhaseState state) noexcept;
/// True when the state still permits the phase to reach Committed.
CRF_NODISCARD CRF_API bool phase_state_retains_commit_authority(PhaseState state) noexcept;
/// True when a phase in this state has a live compiler process expected.
CRF_NODISCARD CRF_API bool phase_state_may_hold_process(PhaseState state) noexcept;

/// Failure classification. Retryability is a property of the class, not of the
/// call site, so the same failure is classified identically everywhere.
enum class FailureClass : std::uint8_t {
  none = 0,
  process_crash = 1,
  process_interrupted = 2,
  transient_workspace_failure = 3,
  transient_storage_failure = 4,
  retry_safe_tool_invocation_failure = 5,
  external_cancellation = 6,
  invalid_source = 7,
  deterministic_compiler_error = 8,
  unsupported_target = 9,
  unsupported_option = 10,
  invalid_toolchain = 11,
  policy_refusal = 12,
  output_invalid = 13,
  authority_invalidated = 14,
  /// The runtime could not determine the outcome. Never automatically
  /// retryable: UNKNOWN fails closed.
  unknown_outcome = 15,
};

CRF_NODISCARD CRF_API std::string_view to_string(FailureClass value) noexcept;
CRF_NODISCARD CRF_API bool parse_failure_class(std::string_view text, FailureClass& out) noexcept;
CRF_NODISCARD CRF_API bool is_retryable(FailureClass value) noexcept;
CRF_NODISCARD CRF_API FailureClass classify_status(StatusCode code) noexcept;

/// One physical attempt at a phase. Multiple attempts may share a phase
/// generation when retry policy permits, but at most one commit exists.
struct CRF_API PhaseAttempt {
  AttemptId id{};
  AttemptGeneration generation{};
  Ref<InvocationId> invocation{};
  ProcessGeneration process_generation{};
  std::uint32_t os_process_id = 0;
  PhaseState terminal_state = PhaseState::pending;
  FailureClass failure = FailureClass::none;
  StatusCode status = StatusCode::ok;
  std::int32_t exit_code = 0;
  std::uint64_t started_at_nanos = 0;
  std::uint64_t finished_at_nanos = 0;
  Digest observed_output_digest{};
  std::string detail;

  CRF_NODISCARD bool retryable() const noexcept { return is_retryable(failure); }
};

struct CRF_API PhaseTransition {
  PhaseState from = PhaseState::pending;
  PhaseState to = PhaseState::pending;
  std::uint64_t at_nanos = 0;
  std::string reason;
};

/// The complete governed state of one phase of one session.
struct CRF_API PhaseRecord {
  CompilerPhaseId id{};
  CompilerPhaseGeneration generation{};
  PhaseKind kind = PhaseKind::unknown;
  std::string adapter_phase;
  PhaseState state = PhaseState::pending;
  bool mandatory = true;

  std::vector<CompilerPhaseId> depends_on;

  // Generations bound at reservation. Commit revalidates every one of them.
  CompilerSessionGeneration session_generation{};
  CompilationGeneration compilation_generation{};
  AttemptGeneration attempt_generation{};
  Ref<ToolchainId> toolchain{};
  Ref<TargetId> target{};
  Ref<EnvironmentId> environment{};
  Ref<PolicyId> policy{};
  Ref<SourceId> source{};
  IRGeneration ir_generation{};
  Ref<LeaseId> lease{};

  // Live execution state.
  Ref<InvocationId> active_invocation{};
  ProcessId active_process{};
  ProcessGeneration active_process_generation{};

  std::vector<Ref<IntermediateArtifactId>> inputs;
  std::vector<Ref<IntermediateArtifactId>> outputs;
  Ref<DiagnosticSetId> diagnostics{};

  CommitId commit{};
  Digest committed_output_digest{};
  std::uint64_t committed_at_nanos = 0;

  std::vector<PhaseAttempt> attempts;
  std::vector<PhaseTransition> history;
  FailureClass failure = FailureClass::none;
  StatusCode last_status = StatusCode::ok;
  std::string last_detail;

  RecoveryId recovery{};
  RecoveryGeneration recovery_generation{};

  CRF_NODISCARD std::uint32_t attempt_count() const noexcept {
    return static_cast<std::uint32_t>(attempts.size());
  }
  CRF_NODISCARD bool committed() const noexcept { return state == PhaseState::committed; }
  /// A phase that produced output but may not commit it.
  CRF_NODISCARD bool produced_pending_commit() const noexcept {
    return state == PhaseState::produced || state == PhaseState::validating ||
           state == PhaseState::commit_ready;
  }
  CRF_NODISCARD const PhaseAttempt* find_attempt(AttemptId attempt) const noexcept;
  CRF_NODISCARD Digest canonical_digest() const;
};

/// Maximum retained history entries per phase; bounded so that a hostile or
/// pathological retry loop cannot grow state without limit.
inline constexpr std::size_t kMaxPhaseAttempts = 64;
inline constexpr std::size_t kMaxPhaseTransitions = 256;

}  // namespace crf
