#include "crf/recovery.hpp"
#include "crf/canonical.hpp"

#include <algorithm>

namespace crf {

std::string_view to_string(RecoveryOutcome value) noexcept {
  switch (value) {
    case RecoveryOutcome::none: return "NONE";
    case RecoveryOutcome::restart_phase: return "RESTART_PHASE";
    case RecoveryOutcome::resume_from_committed_phase: return "RESUME_FROM_COMMITTED_PHASE";
    case RecoveryOutcome::revalidate_intermediate: return "REVALIDATE_INTERMEDIATE";
    case RecoveryOutcome::rebuild_intermediate: return "REBUILD_INTERMEDIATE";
    case RecoveryOutcome::restart_session: return "RESTART_SESSION";
    case RecoveryOutcome::cancel: return "CANCEL";
    case RecoveryOutcome::terminal_failure: return "TERMINAL_FAILURE";
    case RecoveryOutcome::manual_resolution_required: return "MANUAL_RESOLUTION_REQUIRED";
    case RecoveryOutcome::unsupported: return "UNSUPPORTED";
  }
  return "UNKNOWN";
}

bool parse_recovery_outcome(std::string_view text, RecoveryOutcome& out) noexcept {
  static constexpr RecoveryOutcome kValues[] = {
      RecoveryOutcome::none,
      RecoveryOutcome::restart_phase,
      RecoveryOutcome::resume_from_committed_phase,
      RecoveryOutcome::revalidate_intermediate,
      RecoveryOutcome::rebuild_intermediate,
      RecoveryOutcome::restart_session,
      RecoveryOutcome::cancel,
      RecoveryOutcome::terminal_failure,
      RecoveryOutcome::manual_resolution_required,
      RecoveryOutcome::unsupported};
  for (RecoveryOutcome value : kValues) {
    if (equals_ascii_ci(text, to_string(value))) {
      out = value;
      return true;
    }
  }
  return false;
}

Digest RecoveryPlan::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(id.to_string());
  writer.u64(generation.value());
  writer.text(session.to_string());
  writer.text(to_string(headline));
  writer.boolean(legal);
  writer.boolean(requires_operator);
  writer.text(rationale);
  for (const RecoveryStep& step : steps) {
    writer.text(to_string(step.outcome));
    writer.text(step.phase.to_string());
    writer.text(step.reason);
    writer.boolean(step.requires_toolchain_revalidation);
    writer.boolean(step.requires_environment_revalidation);
    writer.boolean(step.requires_intermediate_revalidation);
    std::vector<std::string> affected;
    affected.reserve(step.affected_artifacts.size());
    for (const Ref<IntermediateArtifactId>& entry : step.affected_artifacts) {
      affected.push_back(entry.to_string());
    }
    std::sort(affected.begin(), affected.end());
    for (const std::string& entry : affected) writer.text(entry);
  }
  return Digest::of(writer.bytes());
}

std::string RecoveryPlan::describe() const {
  std::string out(to_string(headline));
  out.append(" legal=");
  out.append(legal ? "yes" : "no");
  out.append(" steps=");
  out.append(std::to_string(steps.size()));
  if (!rationale.empty()) {
    out.append(" rationale=");
    out.append(rationale);
  }
  return out;
}

Result<CompilerPhaseId> recovery_restart_phase(const PhasePlan& plan,
                                               const std::vector<PhaseRecord>& phases,
                                               const AuthorityObservation& authority) {
  for (const CompilerPhaseId id : plan.topological_order()) {
    const PhaseNode* node = plan.find(id);
    if (node == nullptr || !node->mandatory) continue;
    const auto found = std::find_if(phases.begin(), phases.end(),
                                    [id](const PhaseRecord& phase) { return phase.id == id; });
    if (found == phases.end()) return id;
    if (found->state != PhaseState::committed) return id;
    // A committed phase whose bound authority has moved is not a legal boundary.
    PhaseAuthority bound;
    bound.session_generation = found->session_generation;
    bound.compilation_generation = found->compilation_generation;
    bound.attempt_generation = found->attempt_generation;
    bound.phase_generation = found->generation;
    bound.toolchain = found->toolchain;
    bound.target = found->target;
    bound.environment = found->environment;
    bound.policy = found->policy;
    bound.source = found->source;
    bound.ir_generation = found->ir_generation;
    bound.lease = found->lease;
    AuthorityObservation observed = authority;
    observed.phase_generation = found->generation;
    observed.attempt_generation = found->attempt_generation;
    // The session generation advances as the session makes progress, so it is
    // not part of a committed phase's boundary test. The domains that must still
    // hold are the toolchain, target, environment, policy, source, and IR.
    observed.session_generation = found->session_generation;
    if (!authority_verdict_is_current(compare_authority(bound, observed))) return id;
  }
  return Status(StatusCode::not_found, "every mandatory phase is already committed");
}

RecoveryPlan RecoveryPlanner::plan(const RecoveryInputs& inputs) const {
  RecoveryPlan plan;
  plan.legal = false;

  if (inputs.plan == nullptr || inputs.phases == nullptr || inputs.artifacts == nullptr) {
    plan.headline = RecoveryOutcome::manual_resolution_required;
    plan.rationale = "recovery inputs are incomplete";
    plan.requires_operator = true;
    return plan;
  }

  // Intermediate revalidation first: a committed phase boundary is only a legal
  // restart point if the artifacts it produced still hash to what was recorded.
  std::vector<Ref<IntermediateArtifactId>> suspect;
  for (const PhaseRecord& phase : *inputs.phases) {
    if (phase.state != PhaseState::committed) continue;
    for (const Ref<IntermediateArtifactId>& output : phase.outputs) {
      const IntermediateArtifact* artifact = inputs.artifacts->find(output.id);
      if (artifact == nullptr) {
        suspect.push_back(output);
        continue;
      }
      if (artifact->authority != AuthorityState::authoritative) {
        suspect.push_back(output);
      }
    }
  }

  const Result<CompilerPhaseId> restart =
      recovery_restart_phase(*inputs.plan, *inputs.phases, inputs.authority);

  RecoveryStep step;
  step.requires_toolchain_revalidation = inputs.after_runtime_restart;
  step.requires_environment_revalidation = inputs.after_runtime_restart;

  if (!suspect.empty()) {
    step.outcome = RecoveryOutcome::revalidate_intermediate;
    step.requires_intermediate_revalidation = true;
    step.affected_artifacts = suspect;
    step.reason =
        "committed intermediates must be re-hashed before they may feed a later phase";
    plan.steps.push_back(step);
    plan.headline = RecoveryOutcome::revalidate_intermediate;
    plan.legal = true;
  }

  if (!restart.has_value()) {
    if (plan.steps.empty()) {
      plan.headline = RecoveryOutcome::none;
      plan.legal = true;
      plan.rationale = "every mandatory phase is committed under current authority";
      return plan;
    }
    plan.rationale = "revalidation is required before the session can be considered complete";
    return plan;
  }

  const CompilerPhaseId phase = restart.value();
  RecoveryStep restart_step;
  restart_step.phase = phase;
  restart_step.reason = inputs.after_runtime_restart
                            ? "runtime restart: in-flight process state is not resumable, so the "
                              "phase restarts from the last authoritative boundary"
                            : "phase is not committed under current authority";
  const auto found = std::find_if(inputs.phases->begin(), inputs.phases->end(),
                                  [phase](const PhaseRecord& entry) { return entry.id == phase; });
  if (found != inputs.phases->end() && found->state == PhaseState::committed) {
    // The phase committed, but its authority moved. Its output is revoked and
    // the phase must be rebuilt, not merely restarted.
    restart_step.outcome = RecoveryOutcome::rebuild_intermediate;
    restart_step.affected_artifacts = found->outputs;
    restart_step.reason =
        "phase committed under an authority generation that has since moved; its outputs are "
        "revoked and must be rebuilt";
  } else if (found != inputs.phases->end() && found->state == PhaseState::failed &&
             found->failure == FailureClass::unknown_outcome) {
    restart_step.outcome = RecoveryOutcome::manual_resolution_required;
    restart_step.reason = "previous attempt outcome is UNKNOWN; a human must decide";
    plan.requires_operator = true;
  } else {
    restart_step.outcome = RecoveryOutcome::restart_phase;
  }
  plan.steps.push_back(restart_step);
  if (!plan.legal) {
    plan.headline = restart_step.outcome;
    plan.legal = restart_step.outcome != RecoveryOutcome::manual_resolution_required &&
                 restart_step.outcome != RecoveryOutcome::unsupported;
  }
  plan.rationale = "restart boundary determined by the first non-committed mandatory phase";
  return plan;
}

Result<std::size_t> RecoveryPlanner::apply_revalidation(const RecoveryPlan& plan,
                                                        ArtifactRegistry& artifacts) const {
  std::size_t changed = 0;
  for (const RecoveryStep& step : plan.steps) {
    if (!step.requires_intermediate_revalidation) continue;
    for (const Ref<IntermediateArtifactId>& reference : step.affected_artifacts) {
      const Result<ArtifactState> outcome = artifacts.revalidate(reference.id);
      if (!outcome) return outcome.status();
      if (outcome.value() != ArtifactState::valid) ++changed;
    }
  }
  return changed;
}

}  // namespace crf
