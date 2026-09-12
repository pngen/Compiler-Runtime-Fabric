#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "crf/artifact.hpp"
#include "crf/authority.hpp"
#include "crf/diagnostics.hpp"
#include "crf/environment.hpp"
#include "crf/phase.hpp"
#include "crf/phase_plan.hpp"
#include "crf/policy.hpp"
#include "crf/provenance.hpp"
#include "crf/retry.hpp"
#include "crf/source.hpp"
#include "crf/strong_id.hpp"
#include "crf/toolchain.hpp"

namespace crf {

enum class SessionState : std::uint8_t {
  created = 0,
  active = 1,
  /// In-flight state was fenced after a restart; recovery must decide the
  /// restart boundary before new authority is granted.
  recovering = 2,
  committed = 3,
  failed = 4,
  cancelled = 5,
  retired = 6,
};

CRF_NODISCARD CRF_API std::string_view to_string(SessionState value) noexcept;
CRF_NODISCARD CRF_API bool parse_session_state(std::string_view text, SessionState& out) noexcept;
/// True when the session may be granted new phase authority.
CRF_NODISCARD CRF_API bool session_state_admits_new_authority(SessionState value) noexcept;

enum class RecoveryState : std::uint8_t {
  none = 0,
  required = 1,
  planned = 2,
  in_progress = 3,
  resolved = 4,
  manual_required = 5,
  unsupported = 6,
};

CRF_NODISCARD CRF_API std::string_view to_string(RecoveryState value) noexcept;

/// A compilation request already admitted for execution.
///
/// This is the public boundary a Distributed Compilation coordinator submits
/// through. The request carries the distributed attempt identity so that the
/// local runtime never invents its own claim to distributed authority.
struct CRF_API CompileRequest {
  RequestId request{};
  CompilationId compilation{};
  CompilationGeneration compilation_generation{};
  AttemptId attempt{};
  AttemptGeneration attempt_generation{};

  ToolchainFamily toolchain_family = ToolchainFamily::unknown;
  /// Optional pin to an exact toolchain generation. Empty selects the newest
  /// current toolchain of the requested family.
  ToolchainId toolchain{};
  /// Optional explicit target. An unknown architecture is resolved from the
  /// host when exactly one architecture is unambiguous.
  TargetSpec target{};

  std::vector<std::filesystem::path> sources;
  /// In-memory sources, used by tests and by callers that already hold the
  /// translation unit. Each entry is (name, contents).
  std::vector<std::pair<std::string, std::string>> inline_sources;

  std::filesystem::path output_directory;
  std::string final_artifact_name;

  PolicySpec policy{};
  /// Environment overrides merged onto the toolchain's environment contract.
  EnvironmentSpec environment{};
  bool stage_inputs = false;
  bool run_smoke_test = true;
  /// Adapter-specific request options, e.g. "cuda.device_arch=sm_120".
  std::vector<EnvironmentVariable> adapter_options;

  CRF_NODISCARD Digest canonical_digest() const;
  CRF_NODISCARD std::string describe() const;
};

/// The runtime's governed state for one compilation attempt.
struct CRF_API CompilerSession {
  CompilerSessionId id{};
  CompilerSessionGeneration generation = CompilerSessionGeneration::initial();
  SessionState state = SessionState::created;
  RecoveryState recovery_state = RecoveryState::none;

  RequestId request{};
  CompilationId compilation{};
  CompilationGeneration compilation_generation{};
  AttemptId attempt{};
  AttemptGeneration attempt_generation{};

  Ref<ToolchainId> toolchain{};
  std::vector<Ref<ToolchainId>> cooperating_toolchains{};
  Ref<TargetId> target{};
  Ref<EnvironmentId> environment{};
  Ref<PolicyId> policy{};
  Ref<SourceId> source{};
  std::vector<Ref<SourceId>> sources{};
  IRGeneration ir_generation{};

  std::string adapter_name;
  /// Name the finalize phase must produce.
  std::string final_artifact_name;
  /// Adapter-specific request options carried into every phase execution.
  std::vector<EnvironmentVariable> adapter_options;
  PhasePlan plan;
  std::unordered_map<std::uint64_t, PhaseRecord> phases;
  CompilerPhaseId current_phase{};

  std::vector<Ref<IntermediateArtifactId>> intermediates;
  FinalCandidate candidate{};
  bool candidate_present = false;

  RecoveryId recovery{};
  RecoveryGeneration recovery_generation{};
  EvidenceGeneration evidence_generation{};

  EpochId epoch{};
  std::string failure_detail;
  std::uint64_t created_at_nanos = 0;
  std::uint64_t updated_at_nanos = 0;
  std::uint32_t session_retries_used = 0;
  /// Fingerprint of the request that created the session, so recovery can prove
  /// it is resuming the same compilation request.
  Digest request_digest{};

  CRF_NODISCARD PhaseRecord* find_phase(CompilerPhaseId id) noexcept;
  CRF_NODISCARD const PhaseRecord* find_phase(CompilerPhaseId id) const noexcept;
  CRF_NODISCARD std::vector<CompilerPhaseId> committed_phases() const;
  CRF_NODISCARD bool has_committed(CompilerPhaseId id) const noexcept;
  CRF_NODISCARD bool all_mandatory_committed() const;
  CRF_NODISCARD const PhaseRecord* final_phase() const noexcept;
  CRF_NODISCARD Digest canonical_digest() const;
};

/// Result of running one phase.
struct CRF_API PhaseRunReport {
  Ref<CompilerPhaseId> phase{};
  PhaseState state = PhaseState::pending;
  StatusCode status = StatusCode::ok;
  FailureClass failure = FailureClass::none;
  RetryDecision retry{};
  Ref<DiagnosticSetId> diagnostics{};
  Ref<InvocationId> invocation{};
  ProcessId process{};
  std::vector<Ref<IntermediateArtifactId>> outputs{};
  std::uint64_t compiler_nanos = 0;
  std::uint64_t governance_nanos = 0;
  AuthorityVerdict authority = AuthorityVerdict::valid;
  std::string detail;

  CRF_NODISCARD bool committed() const noexcept { return state == PhaseState::committed; }
};

/// Result of driving a whole session to its final candidate.
struct CRF_API CompileOutcome {
  Ref<CompilerSessionId> session{};
  FinalCandidate candidate{};
  Ref<DiagnosticSetId> diagnostics{};
  std::vector<Ref<IntermediateArtifactId>> intermediates{};
  Digest lineage_digest{};
  std::uint64_t compiler_nanos = 0;
  std::uint64_t governance_nanos = 0;
  bool smoke_test_passed = false;
  EvidenceClass evidence = EvidenceClass::unknown;
  std::vector<PhaseRunReport> phases;
  StatusCode status = StatusCode::ok;
  std::string detail;
};

}  // namespace crf
