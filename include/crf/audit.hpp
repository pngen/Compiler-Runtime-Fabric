#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "crf/artifact.hpp"
#include "crf/diagnostics.hpp"
#include "crf/evidence.hpp"
#include "crf/phase_plan.hpp"
#include "crf/process.hpp"
#include "crf/provenance.hpp"
#include "crf/session.hpp"

namespace crf {

/// Every property the auditor can report as violated.
enum class ViolationCode : std::uint8_t {
  none = 0,
  duplicate_session_id = 1,
  non_monotonic_generation = 2,
  multiple_current_phase_states = 3,
  committed_phase_without_invocation = 4,
  committed_phase_stale_authority = 5,
  stale_invocation_retains_authority = 6,
  phase_consumes_uncommitted_input = 7,
  orphan_intermediate_authoritative = 8,
  final_candidate_incomplete_lineage = 9,
  duplicate_logical_phase_commit = 10,
  retired_phase_executable = 11,
  cancelled_phase_committed = 12,
  stale_process_result_current = 13,
  invalid_fan_in = 14,
  corrupt_persisted_state_accepted = 15,
  artifact_without_provenance = 16,
  plan_defect = 17,
  session_generation_regression = 18,
  authority_binding_mismatch = 19,
  diagnostic_set_orphan = 20,
  intermediate_consumable_without_valid_state = 21,
  candidate_without_validation_evidence = 22,
  illegal_phase_transition_recorded = 23,
  fenced_phase_committed = 24,
  lease_outstanding_after_retire = 25,
  live_process_for_retired_phase = 26,
  attempt_history_unbounded = 27,
  session_state_inconsistent = 28,
  recovery_state_inconsistent = 29,
};

CRF_NODISCARD CRF_API std::string_view to_string(ViolationCode value) noexcept;

struct CRF_API AuditViolation {
  ViolationCode code = ViolationCode::none;
  /// Deterministic subject rendering (session / phase / artifact identity).
  std::string subject;
  std::string detail;
};

/// Aggregate view presented to the auditor. The auditor never mutates state, so
/// it can run while the runtime is live.
struct CRF_API AuditSubject {
  const std::vector<CompilerSession>* sessions = nullptr;
  const ArtifactRegistry* artifacts = nullptr;
  const DiagnosticStore* diagnostics = nullptr;
  const ProvenanceLog* provenance = nullptr;
  const ToolchainRegistry* toolchains = nullptr;
  const TargetRegistry* targets = nullptr;
  const EnvironmentRegistry* environments = nullptr;
  const PolicyRegistry* policies = nullptr;
  const SourceRegistry* sources = nullptr;
  const LeaseTable* leases = nullptr;
  const ProcessSupervisor* processes = nullptr;
  /// Persisted records the caller loaded and validated before auditing.
  std::size_t persisted_records_checked = 0;
  std::size_t persisted_defects = 0;
  std::uint64_t runtime_epoch = 0;
};

struct CRF_API AuditReport {
  std::vector<AuditViolation> violations;
  std::size_t checks_run = 0;
  std::size_t sessions_audited = 0;
  std::size_t phases_audited = 0;
  std::size_t artifacts_audited = 0;
  std::uint64_t runtime_epoch = 0;
  std::uint64_t completed_at_nanos = 0;

  CRF_NODISCARD bool zero_violations() const noexcept { return violations.empty(); }
  /// Deterministic multi-line rendering, sorted by (code, subject, detail).
  CRF_NODISCARD std::string render() const;
};

class CRF_API InvariantAuditor {
 public:
  CRF_NODISCARD AuditReport audit(const AuditSubject& subject) const;

 private:
  void audit_session(const AuditSubject& subject, const CompilerSession& session,
                     AuditReport& report) const;
};

}  // namespace crf
