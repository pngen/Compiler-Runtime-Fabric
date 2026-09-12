#include "crf/audit.hpp"
#include "crf/canonical.hpp"
#include "crf/process.hpp"
#include "crf/toolchain.hpp"

#include <algorithm>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace crf {

std::string_view to_string(ViolationCode value) noexcept {
  switch (value) {
    case ViolationCode::none: return "none";
    case ViolationCode::duplicate_session_id: return "duplicate-session-id";
    case ViolationCode::non_monotonic_generation: return "non-monotonic-generation";
    case ViolationCode::multiple_current_phase_states: return "multiple-current-phase-states";
    case ViolationCode::committed_phase_without_invocation: return "committed-phase-without-invocation";
    case ViolationCode::committed_phase_stale_authority: return "committed-phase-stale-authority";
    case ViolationCode::stale_invocation_retains_authority: return "stale-invocation-retains-authority";
    case ViolationCode::phase_consumes_uncommitted_input: return "phase-consumes-uncommitted-input";
    case ViolationCode::orphan_intermediate_authoritative: return "orphan-intermediate-authoritative";
    case ViolationCode::final_candidate_incomplete_lineage: return "final-candidate-incomplete-lineage";
    case ViolationCode::duplicate_logical_phase_commit: return "duplicate-logical-phase-commit";
    case ViolationCode::retired_phase_executable: return "retired-phase-executable";
    case ViolationCode::cancelled_phase_committed: return "cancelled-phase-committed";
    case ViolationCode::stale_process_result_current: return "stale-process-result-current";
    case ViolationCode::invalid_fan_in: return "invalid-fan-in";
    case ViolationCode::corrupt_persisted_state_accepted: return "corrupt-persisted-state-accepted";
    case ViolationCode::artifact_without_provenance: return "artifact-without-provenance";
    case ViolationCode::plan_defect: return "plan-defect";
    case ViolationCode::session_generation_regression: return "session-generation-regression";
    case ViolationCode::authority_binding_mismatch: return "authority-binding-mismatch";
    case ViolationCode::diagnostic_set_orphan: return "diagnostic-set-orphan";
    case ViolationCode::intermediate_consumable_without_valid_state:
      return "intermediate-consumable-without-valid-state";
    case ViolationCode::candidate_without_validation_evidence:
      return "candidate-without-validation-evidence";
    case ViolationCode::illegal_phase_transition_recorded: return "illegal-phase-transition-recorded";
    case ViolationCode::fenced_phase_committed: return "fenced-phase-committed";
    case ViolationCode::lease_outstanding_after_retire: return "lease-outstanding-after-retire";
    case ViolationCode::live_process_for_retired_phase: return "live-process-for-retired-phase";
    case ViolationCode::attempt_history_unbounded: return "attempt-history-unbounded";
    case ViolationCode::session_state_inconsistent: return "session-state-inconsistent";
    case ViolationCode::recovery_state_inconsistent: return "recovery-state-inconsistent";
  }
  return "unknown";
}

std::string AuditReport::render() const {
  std::vector<AuditViolation> sorted = violations;
  std::sort(sorted.begin(), sorted.end(), [](const AuditViolation& a, const AuditViolation& b) {
    if (a.code != b.code) return a.code < b.code;
    if (a.subject != b.subject) return a.subject < b.subject;
    return a.detail < b.detail;
  });
  std::string out;
  out.append("audit: sessions=");
  out.append(std::to_string(sessions_audited));
  out.append(" phases=");
  out.append(std::to_string(phases_audited));
  out.append(" artifacts=");
  out.append(std::to_string(artifacts_audited));
  out.append(" checks=");
  out.append(std::to_string(checks_run));
  out.append(" violations=");
  out.append(std::to_string(sorted.size()));
  out.append("\n");
  for (const AuditViolation& violation : sorted) {
    out.append("VIOLATION ");
    out.append(to_string(violation.code));
    out.append(" subject=");
    out.append(violation.subject);
    out.append(" detail=");
    out.append(violation.detail);
    out.append("\n");
  }
  if (sorted.empty()) out.append("VIOLATIONS none\n");
  return out;
}

AuditReport InvariantAuditor::audit(const AuditSubject& subject) const {
  AuditReport report;
  report.runtime_epoch = subject.runtime_epoch;
  report.completed_at_nanos = monotonic_nanos();

  if (subject.persisted_defects != 0) {
    report.violations.push_back(AuditViolation{
        ViolationCode::corrupt_persisted_state_accepted, "runtime",
        "persisted state reported " + std::to_string(subject.persisted_defects) + " defects"});
  }
  report.checks_run += 1;

  if (subject.sessions == nullptr) {
    return report;
  }

  std::set<std::uint64_t> session_ids;
  for (const CompilerSession& session : *subject.sessions) {
    report.checks_run += 5;
    report.sessions_audited += 1;
    if (!session_ids.insert(session.id.value()).second) {
      report.violations.push_back(AuditViolation{ViolationCode::duplicate_session_id,
                                                 session.id.to_string(),
                                                 "two sessions share one identity"});
    }
    if (!session.id.present() || session.generation.value() == 0) {
      report.violations.push_back(AuditViolation{ViolationCode::session_generation_regression,
                                                 session.id.to_string(),
                                                 "session identity or generation is not established"});
    }
    if (session.plan.size() == 0) {
      report.violations.push_back(AuditViolation{ViolationCode::plan_defect, session.id.to_string(),
                                                 "session has an empty phase plan"});
      continue;
    }
    audit_session(subject, session, report);
  }

  if (subject.artifacts != nullptr) {
    for (const IntermediateArtifact& artifact : subject.artifacts->list()) {
      report.checks_run += 3;
      report.artifacts_audited += 1;
      const std::string name = artifact.id.to_string();
      if (!artifact.current && artifact.authority == AuthorityState::authoritative) {
        report.violations.push_back(AuditViolation{
            ViolationCode::intermediate_consumable_without_valid_state, name,
            "artifact is authoritative but not marked current"});
      }
      if (artifact.current &&
          (artifact.authority != AuthorityState::authoritative ||
           !artifact_state_is_consumable(artifact.state))) {
        report.violations.push_back(AuditViolation{
            ViolationCode::intermediate_consumable_without_valid_state, name,
            "artifact is current while its state is " + std::string(to_string(artifact.state))});
      }
      if (artifact.authority == AuthorityState::authoritative) {
        if (!artifact.provenance.present()) {
          report.violations.push_back(AuditViolation{ViolationCode::artifact_without_provenance, name,
                                                     "authoritative artifact has no provenance"});
        } else if (subject.provenance != nullptr &&
                   subject.provenance->find(artifact.provenance) == nullptr) {
          report.violations.push_back(AuditViolation{
              ViolationCode::artifact_without_provenance, name,
              "authoritative artifact references an unknown provenance record"});
        }
      }
    }
  }

  if (subject.processes != nullptr) {
    report.checks_run += 1;
    if (subject.processes->total_spawned() > 0 && subject.processes->live_count() > 0) {
      // A live compiler process is legal only while a phase is in a state that
      // may hold one. That relationship is checked per session above.
    }
  }

  return report;
}

void InvariantAuditor::audit_session(const AuditSubject& subject, const CompilerSession& session,
                                     AuditReport& report) const {
  const std::string session_name = session.id.to_string();
  std::set<std::uint64_t> commit_ids;
  std::size_t in_flight = 0;
  std::size_t live_process_phases = 0;

  for (const CompilerPhaseId phase_id : session.plan.topological_order()) {
    const PhaseRecord* phase = session.find_phase(phase_id);
    report.checks_run += 12;
    report.phases_audited += 1;
    if (phase == nullptr) {
      report.violations.push_back(AuditViolation{ViolationCode::plan_defect,
                                                 session_name + "/" + phase_id.to_string(),
                                                 "plan declares a phase with no phase record"});
      continue;
    }
    const std::string name = session_name + "/" + phase->id.to_string();

    if (phase_state_may_hold_process(phase->state)) ++live_process_phases;
    if (phase_state_retains_commit_authority(phase->state) &&
        phase->state != PhaseState::pending && phase->state != PhaseState::ready) {
      ++in_flight;
    }
    if (phase->attempts.size() > kMaxPhaseAttempts) {
      report.violations.push_back(AuditViolation{ViolationCode::attempt_history_unbounded, name,
                                                 "phase retained more attempts than the ceiling"});
    }

    // Recorded transitions must all be legal and must land on the current state.
    for (std::size_t i = 0; i < phase->history.size(); ++i) {
      const PhaseTransition& transition = phase->history[i];
      if (!is_legal_phase_transition(transition.from, transition.to)) {
        report.violations.push_back(AuditViolation{
            ViolationCode::illegal_phase_transition_recorded, name,
            std::string("recorded transition ") + std::string(to_string(transition.from)) + " -> " +
                std::string(to_string(transition.to)) + " is not legal"});
      }
      if (i != 0 && phase->history[i - 1].to != transition.from) {
        report.violations.push_back(AuditViolation{
            ViolationCode::illegal_phase_transition_recorded, name,
            "phase transition history is not contiguous"});
      }
    }
    if (!phase->history.empty() && phase->history.back().to != phase->state) {
      report.violations.push_back(AuditViolation{ViolationCode::illegal_phase_transition_recorded,
                                                 name,
                                                 "phase state disagrees with its transition history"});
    }

    if (phase->state == PhaseState::committed) {
      if (!phase->commit.present() || !phase->active_invocation.id.present() ||
          phase->attempts.empty()) {
        report.violations.push_back(AuditViolation{
            ViolationCode::committed_phase_without_invocation, name,
            "committed phase has no commit identity, invocation, or attempt record"});
      }
      if (phase->commit.present() && !commit_ids.insert(phase->commit.value()).second) {
        report.violations.push_back(AuditViolation{ViolationCode::duplicate_logical_phase_commit,
                                                   name,
                                                   "two phases share one commit identity"});
      }
      // A committed phase must still be bound to the session's current
      // authority. The session generation is excluded on purpose: it advances
      // as the session makes progress.
      const bool authority_mismatch = phase->toolchain != session.toolchain ||
                                      phase->target != session.target ||
                                      phase->environment != session.environment ||
                                      phase->policy != session.policy ||
                                      phase->compilation_generation != session.compilation_generation;
      if (authority_mismatch) {
        report.violations.push_back(AuditViolation{
            ViolationCode::committed_phase_stale_authority, name,
            "committed phase is bound to authority generations the session no longer holds"});
      }
      // A committed phase's binding was current at commit time. A later
      // generation of the same toolchain does not retroactively invalidate it;
      // that a phase in flight is fenced when its toolchain moves is enforced by
      // the commit path itself. What must always hold is that the toolchain the
      // phase names is still registered.
      if (subject.toolchains != nullptr && phase->toolchain.id.present() &&
          subject.toolchains->find(phase->toolchain.id) == nullptr) {
        report.violations.push_back(AuditViolation{
            ViolationCode::authority_binding_mismatch, name,
            "committed phase references a toolchain that is not registered"});
      }
    }
    if (phase->state == PhaseState::cancelled && phase->commit.present()) {
      report.violations.push_back(AuditViolation{ViolationCode::cancelled_phase_committed, name,
                                                 "cancelled phase carries a commit identity"});
    }
    if (phase->state == PhaseState::fenced && phase->commit.present()) {
      report.violations.push_back(AuditViolation{ViolationCode::fenced_phase_committed, name,
                                                 "fenced phase carries a commit identity"});
    }
    if (phase->state == PhaseState::retired && phase->mandatory &&
        !session.has_committed(phase->id)) {
      report.violations.push_back(AuditViolation{ViolationCode::retired_phase_executable, name,
                                                 "mandatory phase was retired without committing"});
    }
    if (phase->produced_pending_commit() && !phase->active_invocation.id.present()) {
      report.violations.push_back(AuditViolation{
          ViolationCode::stale_invocation_retains_authority, name,
          "phase holds pending output without an invocation identity"});
    }
    if (phase->active_process.present() && !phase->active_process_generation.present()) {
      report.violations.push_back(AuditViolation{ViolationCode::stale_process_result_current, name,
                                                 "phase records a process without a generation"});
    }
    if (phase->state == PhaseState::running && phase->active_invocation.id.present() &&
        phase->attempts.empty()) {
      report.violations.push_back(AuditViolation{
          ViolationCode::stale_invocation_retains_authority, name,
          "running phase has an invocation but no attempt record"});
    }
    if (phase->diagnostics.id.present() && subject.diagnostics != nullptr &&
        subject.diagnostics->find(phase->diagnostics.id) == nullptr) {
      report.violations.push_back(AuditViolation{ViolationCode::diagnostic_set_orphan, name,
                                                 "phase references an unknown diagnostic set"});
    }
    if (phase->toolchain.id.present() && subject.toolchains != nullptr &&
        subject.toolchains->find(phase->toolchain.id) == nullptr) {
      report.violations.push_back(AuditViolation{ViolationCode::authority_binding_mismatch, name,
                                                 "phase references an unregistered toolchain"});
    }

    for (const Ref<IntermediateArtifactId>& input : phase->inputs) {
      if (subject.artifacts == nullptr) break;
      const IntermediateArtifact* artifact = subject.artifacts->find(input.id);
      if (artifact == nullptr) {
        report.violations.push_back(AuditViolation{ViolationCode::phase_consumes_uncommitted_input,
                                                   name,
                                                   "phase consumes an unregistered artifact"});
        continue;
      }
      const PhaseRecord* producer = session.find_phase(artifact->producer_phase.id);
      if (producer == nullptr || producer->state != PhaseState::committed ||
          producer->generation != artifact->producer_phase.generation) {
        report.violations.push_back(AuditViolation{
            ViolationCode::phase_consumes_uncommitted_input, name,
            "phase consumes output from a producer phase that is not committed"});
      }
      if (artifact->authority != AuthorityState::authoritative) {
        report.violations.push_back(AuditViolation{
            ViolationCode::phase_consumes_uncommitted_input, name,
            "phase consumes artifact " + artifact->id.to_string() + " which carries authority " +
                std::string(to_string(artifact->authority)) + " and state " +
                std::string(to_string(artifact->state)) + " (producer " +
                artifact->producer_phase.to_string() + ")"});
      }
    }

    if (phase->state == PhaseState::committed) {
      const PhaseNode* node = session.plan.find(phase->id);
      if (node != nullptr && node->fan_in && phase->inputs.size() < node->required_inputs) {
        report.violations.push_back(AuditViolation{
            ViolationCode::invalid_fan_in, name,
            "fan-in phase committed with fewer authoritative inputs than it declared"});
      }
    }

    for (const Ref<IntermediateArtifactId>& output : phase->outputs) {
      if (subject.artifacts == nullptr) break;
      const IntermediateArtifact* artifact = subject.artifacts->find(output.id);
      if (artifact == nullptr) {
        report.violations.push_back(AuditViolation{ViolationCode::orphan_intermediate_authoritative,
                                                   name, "phase references an unregistered output"});
        continue;
      }
      if (artifact->authority == AuthorityState::authoritative &&
          phase->state != PhaseState::committed) {
        report.violations.push_back(AuditViolation{
            ViolationCode::orphan_intermediate_authoritative, name,
            "phase that never committed produced an authoritative artifact"});
      }
    }
  }

  if (session.state == SessionState::committed) {
    if (!session.all_mandatory_committed() || !session.candidate_present) {
      report.violations.push_back(AuditViolation{
          ViolationCode::session_state_inconsistent, session_name,
          "session is COMMITTED without every mandatory phase committed and a candidate present"});
    }
  }
  if (session.candidate_present) {
    report.checks_run += 2;
    if (!session.candidate.complete_lineage) {
      report.violations.push_back(AuditViolation{ViolationCode::final_candidate_incomplete_lineage,
                                                 session_name,
                                                 "final candidate has incomplete lineage"});
    }
    if (session.candidate.validation_evidence.empty()) {
      report.violations.push_back(AuditViolation{
          ViolationCode::candidate_without_validation_evidence, session_name,
          "final candidate carries no validation evidence"});
    }
  }
  if (session.recovery_state == RecoveryState::resolved && !session.recovery.present()) {
    report.violations.push_back(AuditViolation{ViolationCode::recovery_state_inconsistent,
                                               session_name,
                                               "recovery is marked resolved without a recovery id"});
  }
  // An ACTIVE session with in-flight phases must have at least one phase that
  // is allowed to hold a process; anything else means a phase was left dangling.
  report.checks_run += 1;
  if (session.state == SessionState::active && in_flight > 0 && live_process_phases == 0) {
    report.violations.push_back(AuditViolation{
        ViolationCode::stale_process_result_current, session_name,
        "session has in-flight phases but none is in a state that may hold a compiler process"});
  }
  if ((session.state == SessionState::retired || session.state == SessionState::committed) &&
      subject.leases != nullptr) {
    for (const Lease& lease : subject.leases->list()) {
      if (lease.session.id == session.id && lease.held) {
        report.violations.push_back(AuditViolation{
            ViolationCode::lease_outstanding_after_retire, session_name,
            "session finished with a lease still held: " + lease.id.to_string()});
      }
    }
  }
  if (subject.processes != nullptr && subject.processes->live_count() > 0 &&
      session.state == SessionState::retired) {
    report.violations.push_back(AuditViolation{ViolationCode::live_process_for_retired_phase,
                                               session_name,
                                               "retired session still has live compiler processes"});
  }
}

}  // namespace crf
