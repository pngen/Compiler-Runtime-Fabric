#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "crf/artifact.hpp"
#include "crf/authority.hpp"
#include "crf/digest.hpp"
#include "crf/phase_plan.hpp"
#include "crf/status.hpp"

namespace crf {

/// What the runtime will do to bring a session back to a legal state.
enum class RecoveryOutcome : std::uint8_t {
  /// No recovery needed; every mandatory phase is committed.
  none = 0,
  /// Restart one phase from its own boundary because no output of it committed.
  restart_phase = 1,
  /// Continue from the last committed phase boundary.
  resume_from_committed_phase = 2,
  /// A committed intermediate must be re-hashed and re-validated before use.
  revalidate_intermediate = 3,
  /// A committed intermediate is unusable and must be rebuilt.
  rebuild_intermediate = 4,
  /// Session-level state is unusable; build a fresh session.
  restart_session = 5,
  cancel = 6,
  terminal_failure = 7,
  /// A human must decide. The runtime will not guess.
  manual_resolution_required = 8,
  /// The runtime cannot express this recovery. Explicitly unsupported.
  unsupported = 9,
};

CRF_NODISCARD CRF_API std::string_view to_string(RecoveryOutcome value) noexcept;
CRF_NODISCARD CRF_API bool parse_recovery_outcome(std::string_view text, RecoveryOutcome& out) noexcept;

struct CRF_API RecoveryStep {
  RecoveryOutcome outcome = RecoveryOutcome::none;
  CompilerPhaseId phase{};
  std::string reason;
  bool requires_toolchain_revalidation = false;
  bool requires_environment_revalidation = false;
  bool requires_intermediate_revalidation = false;
  std::vector<Ref<IntermediateArtifactId>> affected_artifacts;
};

/// The plan is deterministic: the same durable state yields the same plan.
struct CRF_API RecoveryPlan {
  RecoveryId id{};
  RecoveryGeneration generation{};
  Ref<CompilerSessionId> session{};
  RecoveryOutcome headline = RecoveryOutcome::none;
  std::vector<RecoveryStep> steps;
  bool legal = false;
  bool requires_operator = false;
  std::string rationale;
  Digest canonical_digest() const;
  CRF_NODISCARD std::string describe() const;
};

struct CRF_API RecoveryInputs {
  const PhasePlan* plan = nullptr;
  const std::vector<PhaseRecord>* phases = nullptr;
  const ArtifactRegistry* artifacts = nullptr;
  AuthorityObservation authority{};
  /// True when the session was loaded from durable state after a runtime
  /// restart. In-flight process state from before the restart is never
  /// considered resumable.
  bool after_runtime_restart = false;
  /// True when the previous runtime epoch differed from the current one.
  bool epoch_advanced = false;
};

/// Conservative local recovery.
///
/// The runtime never claims mid-process compiler continuation: process death
/// means the phase restarts from the last authoritative phase boundary.
class CRF_API RecoveryPlanner {
 public:
  CRF_NODISCARD RecoveryPlan plan(const RecoveryInputs& inputs) const;
  /// Apply the plan's pure revalidation steps against the artifact registry.
  /// Returns the number of artifacts whose state changed.
  CRF_NODISCARD Result<std::size_t> apply_revalidation(const RecoveryPlan& plan,
                                                       ArtifactRegistry& artifacts) const;
};

/// Determine the phase a recovered session must restart from.
///
/// Returns the first mandatory phase, in plan order, that is not committed with
/// current authority. Returns absent when every mandatory phase is committed.
CRF_NODISCARD CRF_API Result<CompilerPhaseId> recovery_restart_phase(
    const PhasePlan& plan, const std::vector<PhaseRecord>& phases,
    const AuthorityObservation& authority);

}  // namespace crf
