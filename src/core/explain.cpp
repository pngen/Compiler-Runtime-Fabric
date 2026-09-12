#include "crf/explain.hpp"
#include "crf/canonical.hpp"
#include "crf/version.hpp"

#include <algorithm>
#include <string>

namespace crf {
namespace {

CRF_NODISCARD std::string yes_no(bool value) { return value ? "yes" : "no"; }

CRF_NODISCARD std::string severity_summary(const DiagnosticSet& set) {
  return std::to_string(set.error_count) + " error(s), " + std::to_string(set.warning_count) +
         " warning(s), " + std::to_string(set.entries.size()) + " normalised entr(ies)";
}

}  // namespace

std::string Explanation::render() const {
  std::string out;
  if (!title.empty()) {
    out.append(title);
    out.append("\n");
  }
  for (const std::string& line : lines) {
    out.append(line);
    out.append("\n");
  }
  return out;
}

void Explanation::add(std::string line) { lines.push_back(std::move(line)); }

Explanation explain_runtime(const Runtime& runtime, const ExplainOptions& options) {
  (void)options;
  Explanation explanation;
  explanation.title = "COMPILER RUNTIME FABRIC " + std::string(version_string);
  explanation.add("runtime          " + runtime.options().runtime_name);
  explanation.add("epoch            " + std::to_string(runtime.epoch()));
  explanation.add("state-directory  " + runtime.options().state_directory.string());
  explanation.add("workspace-root   " + runtime.options().workspace_root.string());
  explanation.add("sessions         " + std::to_string(runtime.list_sessions().size()));
  explanation.add("toolchains       " + std::to_string(runtime.toolchains().size()));
  explanation.add("targets          " + std::to_string(runtime.targets().list().size()));
  explanation.add("environments     " + std::to_string(runtime.environments().list().size()));
  explanation.add("policies         " + std::to_string(runtime.policies().list().size()));
  explanation.add("artifacts        " + std::to_string(runtime.artifacts().size()));
  explanation.add("diagnostic-sets  " + std::to_string(runtime.diagnostics().size()));
  explanation.add("provenance       " + std::to_string(runtime.provenance().size()));
  explanation.add("leases-held      " +
                  std::to_string([&runtime]() {
                    std::size_t held = 0;
                    for (const Lease& lease : runtime.leases().list()) {
                      if (lease.held) ++held;
                    }
                    return held;
                  }()));
  explanation.add("live-processes   " + std::to_string(runtime.processes().live_count()));
  explanation.add("authoritative-commits " + std::to_string(runtime.commit_count()));
  explanation.add("refused-stale-commits " + std::to_string(runtime.stale_commit_count()));
  explanation.add("executor         " + runtime.describe());
  return explanation;
}

Explanation explain_session(const Runtime& runtime, CompilerSessionId session,
                            const ExplainOptions& options) {
  Explanation explanation;
  const Result<CompilerSession> found = runtime.require_session(session);
  if (!found) {
    explanation.title = "session " + session.to_string();
    explanation.add("REFUSED " + found.status().to_string());
    return explanation;
  }
  const CompilerSession& value = found.value();
  explanation.title = "SESSION " + value.id.to_string();
  explanation.add("state                " + std::string(to_string(value.state)));
  explanation.add("session-generation   " + value.generation.to_string());
  explanation.add("request              " + value.request.to_string());
  explanation.add("compilation          " + value.compilation.to_string() + "@" +
                  value.compilation_generation.to_string());
  explanation.add("attempt              " + value.attempt.to_string() + "@" +
                  value.attempt_generation.to_string());
  explanation.add("adapter              " + value.adapter_name);
  explanation.add("toolchain            " + value.toolchain.to_string());
  explanation.add("target               " + value.target.to_string());
  explanation.add("environment          " + value.environment.to_string());
  explanation.add("policy               " + value.policy.to_string());
  explanation.add("source               " + value.source.to_string());
  explanation.add("current-phase        " + value.current_phase.to_string());
  explanation.add("recovery-state       " + std::string(to_string(value.recovery_state)));
  explanation.add("session-retries-used " + std::to_string(value.session_retries_used));
  explanation.add("created-at-nanos     " + std::to_string(value.created_at_nanos));
  explanation.add("request-digest       " + value.request_digest.to_hex());
  if (!value.failure_detail.empty()) {
    explanation.add("failure-detail       " + value.failure_detail);
  }
  if (const TargetIdentity* target = runtime.targets().find(value.target.id)) {
    explanation.add("target-spec          arch=" + std::string(to_string(target->spec.architecture)) +
                    " os=" + std::string(to_string(target->spec.os)) +
                    " triple=" + target->spec.triple +
                    (target->spec.device_arch.empty() ? std::string{}
                                                      : " device=" + target->spec.device_arch));
  }
  if (const ToolchainIdentity* toolchain = runtime.toolchains().find(value.toolchain.id)) {
    explanation.add("toolchain-detail     " + toolchain->describe());
  }
  explanation.add("--- phase plan ---");
  for (const CompilerPhaseId id : value.plan.topological_order()) {
    const PhaseRecord* phase = value.find_phase(id);
    if (phase == nullptr) continue;
    std::string line = "  " + id.to_string() + " ";
    line.append(to_string(phase->kind));
    line.append(" ");
    line.append(to_string(phase->state));
    line.append(" generation=");
    line.append(phase->generation.to_string());
    line.append(" attempts=");
    line.append(std::to_string(phase->attempt_count()));
    if (!phase->adapter_phase.empty()) {
      line.append(" [");
      line.append(phase->adapter_phase);
      line.append("]");
    }
    if (!phase->mandatory) line.append(" (optional)");
    if (phase->commit.present()) {
      line.append(" commit=");
      line.append(phase->commit.to_string());
    }
    explanation.add(line);
  }
  if (value.candidate_present) {
    explanation.add("--- final candidate ---");
    explanation.add("  id            " + value.candidate.id.to_string());
    explanation.add("  path          " + value.candidate.path.string());
    explanation.add("  format        " + std::string(to_string(value.candidate.format)));
    explanation.add("  sha256        " + value.candidate.content.to_hex());
    explanation.add("  size-bytes    " + std::to_string(value.candidate.size_bytes));
    explanation.add("  lineage       " + std::to_string(value.candidate.lineage.size()) +
                    " artifact(s)");
    explanation.add("  lineage-digest " + value.candidate.lineage_digest.to_hex());
    explanation.add("  complete      " + yes_no(value.candidate.complete_lineage));
  }
  if (options.include_evidence) {
    explanation.add("--- evidence ---");
    for (const EvidenceRecord& record : runtime.evidence().records()) {
      explanation.add("  " + std::string(to_string(record.evidence_class)) + " " + record.kind +
                      " " + record.detail);
    }
  }
  return explanation;
}

Explanation explain_authority(const Runtime& runtime, CompilerSessionId session,
                              CompilerPhaseId phase) {
  Explanation explanation;
  explanation.title = "AUTHORITY " + session.to_string() + " / " + phase.to_string();
  const Result<CompilerSession> found = runtime.require_session(session);
  if (!found) {
    explanation.add("REFUSED " + found.status().to_string());
    return explanation;
  }
  const PhaseRecord* record = found.value().find_phase(phase);
  if (record == nullptr) {
    explanation.add("REFUSED phase is not part of the session plan");
    return explanation;
  }
  explanation.add("bound  session=" + record->session_generation.to_string() +
                  " compilation=" + record->compilation_generation.to_string() +
                  " attempt=" + record->attempt_generation.to_string() +
                  " phase=" + record->generation.to_string());
  explanation.add("bound  toolchain=" + record->toolchain.to_string());
  explanation.add("bound  target=" + record->target.to_string());
  explanation.add("bound  environment=" + record->environment.to_string());
  explanation.add("bound  policy=" + record->policy.to_string());
  explanation.add("bound  source=" + record->source.to_string());
  explanation.add("bound  lease=" + record->lease.to_string());
  const Result<AuthorityVerdict> verdict = runtime.check_authority(session, phase);
  if (!verdict) {
    explanation.add("REFUSED " + verdict.status().to_string());
    return explanation;
  }
  explanation.add("verdict " + std::string(to_string(verdict.value())));
  explanation.add(std::string("legal-to-commit ") +
                  yes_no(authority_verdict_is_current(verdict.value())));
  return explanation;
}

Explanation explain_phase(const Runtime& runtime, CompilerSessionId session, CompilerPhaseId phase,
                          const ExplainOptions& options) {
  Explanation explanation;
  const Result<CompilerSession> found = runtime.require_session(session);
  if (!found) {
    explanation.title = "phase " + phase.to_string();
    explanation.add("REFUSED " + found.status().to_string());
    return explanation;
  }
  const PhaseRecord* record = found.value().find_phase(phase);
  if (record == nullptr) {
    explanation.title = "phase " + phase.to_string();
    explanation.add("REFUSED phase is not part of the session plan");
    return explanation;
  }
  explanation.title = "PHASE " + record->id.to_string();
  explanation.add("kind             " + std::string(to_string(record->kind)));
  explanation.add("adapter-phase    " + record->adapter_phase);
  explanation.add("state            " + std::string(to_string(record->state)));
  explanation.add("generation       " + record->generation.to_string());
  explanation.add("mandatory        " + yes_no(record->mandatory));
  explanation.add("attempts         " + std::to_string(record->attempt_count()));
  explanation.add("failure-class    " + std::string(to_string(record->failure)));
  explanation.add("last-status      " + std::string(to_string(record->last_status)));
  if (!record->last_detail.empty()) explanation.add("last-detail      " + record->last_detail);
  explanation.add("requires         " +
                  std::to_string(record->depends_on.size()) + " dependency phase(s)");
  explanation.add("inputs           " + std::to_string(record->inputs.size()) +
                  " authoritative artifact(s)");
  explanation.add("outputs          " + std::to_string(record->outputs.size()) + " artifact(s)");
  explanation.add("diagnostics      " + record->diagnostics.to_string());
  if (options.include_history) {
    explanation.add("--- transition history ---");
    for (const PhaseTransition& transition : record->history) {
      explanation.add("  " + std::string(to_string(transition.from)) + " -> " +
                      std::string(to_string(transition.to)) + " @ " +
                      std::to_string(transition.at_nanos) + " : " + transition.reason);
    }
    explanation.add("--- attempts ---");
    for (const PhaseAttempt& attempt : record->attempts) {
      explanation.add("  " + attempt.id.to_string() + " generation=" +
                      attempt.generation.to_string() + " invocation=" +
                      attempt.invocation.to_string() + " exit=" + std::to_string(attempt.exit_code) +
                      " failure=" + std::string(to_string(attempt.failure)) + " state=" +
                      std::string(to_string(attempt.terminal_state)));
    }
  }
  explanation.add("--- authority ---");
  const Explanation authority = explain_authority(runtime, session, phase);
  for (const std::string& line : authority.lines) explanation.add(line);
  return explanation;
}

Explanation explain_toolchain(const Runtime& runtime, ToolchainId toolchain,
                              const ExplainOptions& options) {
  (void)options;
  Explanation explanation;
  const ToolchainIdentity* identity = runtime.toolchains().find(toolchain);
  if (identity == nullptr) {
    explanation.title = "toolchain " + toolchain.to_string();
    explanation.add("REFUSED toolchain is not registered");
    return explanation;
  }
  explanation.title = "TOOLCHAIN " + identity->id.to_string();
  explanation.add("family           " + std::string(to_string(identity->family)));
  explanation.add("display-name     " + identity->display_name);
  explanation.add("version          " + identity->version);
  explanation.add("generation       " + identity->generation.to_string());
  explanation.add("evidence-class   " + std::string(to_string(identity->evidence_class)));
  explanation.add("evidence-digest  " + identity->evidence_digest.to_hex());
  explanation.add("toolkit-root     " + identity->toolkit_root.string());
  explanation.add("sdk-root         " + identity->sdk_root.string());
  explanation.add("stdlib-identity  " + identity->standard_library_identity);
  std::string architectures;
  for (const Architecture architecture : identity->target_support) {
    if (!architectures.empty()) architectures.append(",");
    architectures.append(to_string(architecture));
  }
  explanation.add("target-support   " + architectures);
  explanation.add("--- components ---");
  for (const ComponentIdentity& component : identity->components) {
    explanation.add("  " + component.id.to_string() + " " + component.name + " [" +
                    std::string(to_string(component.kind)) + "] version=" + component.version);
    explanation.add("      " + component.file.describe());
  }
  if (!identity->attributes.empty()) {
    explanation.add("--- adapter attributes ---");
    for (const EnvironmentVariable& attribute : identity->attributes) {
      explanation.add("  " + attribute.name + "=" + attribute.value);
    }
  }
  explanation.add("--- environment contract ---");
  for (const EnvironmentVariable& variable : identity->environment_contract) {
    explanation.add("  " + variable.name + "=" + variable.value);
  }
  return explanation;
}

Explanation explain_component(const Runtime& runtime, ToolchainId toolchain,
                              CompilerComponentId component) {
  Explanation explanation;
  const ToolchainIdentity* identity = runtime.toolchains().find(toolchain);
  if (identity == nullptr) {
    explanation.title = "component " + component.to_string();
    explanation.add("REFUSED toolchain is not registered");
    return explanation;
  }
  for (const ComponentIdentity& candidate : identity->components) {
    if (candidate.id != component) continue;
    explanation.title = "COMPONENT " + candidate.id.to_string();
    explanation.add("toolchain        " + identity->id.to_string());
    explanation.add("name             " + candidate.name);
    explanation.add("kind             " + std::string(to_string(candidate.kind)));
    explanation.add("version          " + candidate.version);
    explanation.add("generation       " + candidate.generation.to_string());
    explanation.add("path             " + candidate.file.canonical_path.string());
    explanation.add("size-bytes       " + std::to_string(candidate.file.size_bytes));
    explanation.add("sha256           " +
                    (candidate.file.content_hashed ? candidate.file.content.to_hex()
                                                   : std::string("<unhashed>")));
    explanation.add("volume-serial    " + candidate.file.volume_serial_hex);
    explanation.add("file-index       " + candidate.file.file_index_hex);
    const ComponentRevalidation revalidation = revalidate_component(candidate, true);
    explanation.add("current          " + yes_no(revalidation.current));
    explanation.add("replaced-same-path " + yes_no(revalidation.replaced_at_same_path));
    explanation.add("detail           " + revalidation.detail);
    return explanation;
  }
  explanation.title = "component " + component.to_string();
  explanation.add("REFUSED component is not part of the toolchain");
  return explanation;
}

Explanation explain_artifact(const Runtime& runtime, IntermediateArtifactId artifact,
                             const ExplainOptions& options) {
  (void)options;
  Explanation explanation;
  const IntermediateArtifact* value = runtime.artifacts().find(artifact);
  if (value == nullptr) {
    explanation.title = "artifact " + artifact.to_string();
    explanation.add("REFUSED artifact is not registered");
    return explanation;
  }
  explanation.title = "INTERMEDIATE " + value->id.to_string();
  explanation.add("generation       " + value->generation.to_string());
  explanation.add("format           " + std::string(to_string(value->format)));
  explanation.add("path             " + value->path.string());
  explanation.add("sha256           " + value->content.to_hex());
  explanation.add("size-bytes       " + std::to_string(value->size_bytes));
  explanation.add("state            " + std::string(to_string(value->state)));
  explanation.add("authority        " + std::string(to_string(value->authority)));
  explanation.add("current          " + yes_no(value->current));
  explanation.add("consumable       " + yes_no(value->consumable()));
  explanation.add("producer-phase   " + value->producer_phase.to_string());
  explanation.add("producer-invoke  " + value->producer_invocation.to_string());
  explanation.add("toolchain        " + value->toolchain.to_string());
  explanation.add("target           " + value->target.to_string());
  explanation.add("provenance       " + value->provenance.to_string());
  explanation.add("lineage-inputs   " + std::to_string(value->lineage_inputs.size()));
  explanation.add("validation       " + value->validation_detail);
  return explanation;
}

Explanation explain_candidate(const Runtime& runtime, CompilerSessionId session) {
  Explanation explanation;
  const FinalCandidate* candidate = runtime.find_candidate(session);
  if (candidate == nullptr) {
    explanation.title = "candidate " + session.to_string();
    explanation.add("NO CANDIDATE this session has not registered a final candidate");
    return explanation;
  }
  explanation.title = "FINAL CANDIDATE " + candidate->id.to_string();
  explanation.add("session          " + candidate->session.to_string());
  explanation.add("compilation      " + candidate->compilation.to_string() + "@" +
                  candidate->compilation_generation.to_string());
  explanation.add("attempt          generation=" + candidate->attempt_generation.to_string());
  explanation.add("toolchain        " + candidate->toolchain.to_string());
  explanation.add("target           " + candidate->target.to_string());
  explanation.add("environment      " + candidate->environment.to_string());
  explanation.add("policy           " + candidate->policy.to_string());
  explanation.add("source           " + candidate->source.to_string());
  explanation.add("format           " + std::string(to_string(candidate->format)));
  explanation.add("path             " + candidate->path.string());
  explanation.add("sha256           " + candidate->content.to_hex());
  explanation.add("size-bytes       " + std::to_string(candidate->size_bytes));
  explanation.add("lineage-digest   " + candidate->lineage_digest.to_hex());
  explanation.add("complete-lineage " + yes_no(candidate->complete_lineage));
  explanation.add("handed-off       " + yes_no(candidate->handed_off));
  explanation.add("--- lineage ---");
  for (const Ref<IntermediateArtifactId>& reference : candidate->lineage) {
    const IntermediateArtifact* artifact = runtime.artifacts().find(reference.id);
    if (artifact == nullptr) {
      explanation.add("  " + reference.to_string() + " <unregistered>");
      continue;
    }
    explanation.add("  " + artifact->id.to_string() + " " +
                    std::string(to_string(artifact->format)) + " " +
                    std::string(to_string(artifact->state)) + " " +
                    std::string(to_string(artifact->authority)) + " " +
                    artifact->content.to_short_hex());
  }
  return explanation;
}

Explanation explain_diagnostics(const Runtime& runtime, DiagnosticSetId set,
                                const ExplainOptions& options) {
  (void)options;
  Explanation explanation;
  const DiagnosticSet* value = runtime.diagnostics().find(set);
  if (value == nullptr) {
    explanation.title = "diagnostics " + set.to_string();
    explanation.add("REFUSED diagnostic set is not registered");
    return explanation;
  }
  explanation.title = "DIAGNOSTICS " + value->id.to_string();
  explanation.add("invocation       " + value->invocation.to_string());
  explanation.add("phase            " + value->phase.to_string());
  explanation.add("toolchain        " + value->toolchain.to_string());
  explanation.add("target           " + value->target.to_string());
  explanation.add("exit-code        " + std::to_string(value->exit_code));
  explanation.add("crashed          " + yes_no(value->process_crashed));
  explanation.add("normalised       " + yes_no(value->normalized));
  explanation.add("truncated        " + yes_no(value->truncated));
  explanation.add("raw-bytes        stdout=" + std::to_string(value->raw_stdout_bytes) +
                  " stderr=" + std::to_string(value->raw_stderr_bytes));
  explanation.add("dropped-bytes    stdout=" + std::to_string(value->dropped_stdout_bytes) +
                  " stderr=" + std::to_string(value->dropped_stderr_bytes));
  explanation.add("summary          " + severity_summary(*value));
  for (const Diagnostic& entry : value->entries) {
    std::string line = "  ";
    line.append(to_string(entry.severity));
    line.push_back(' ');
    if (!entry.code.empty()) {
      line.append(entry.code);
      line.push_back(' ');
    }
    if (!entry.file.empty()) {
      line.append(entry.file);
      line.push_back('(');
      line.append(std::to_string(entry.line));
      if (entry.column != 0) {
        line.push_back(',');
        line.append(std::to_string(entry.column));
      }
      line.append(") ");
    }
    line.append(entry.message);
    explanation.add(line);
  }
  return explanation;
}

Explanation explain_retry(const Runtime& runtime, CompilerSessionId session,
                          CompilerPhaseId phase) {
  Explanation explanation;
  explanation.title = "RETRY " + session.to_string() + " / " + phase.to_string();
  const Result<CompilerSession> found = runtime.require_session(session);
  if (!found) {
    explanation.add("REFUSED " + found.status().to_string());
    return explanation;
  }
  const PhaseRecord* record = found.value().find_phase(phase);
  if (record == nullptr) {
    explanation.add("REFUSED phase is not part of the session plan");
    return explanation;
  }
  const PolicyIdentity* policy = runtime.policies().find(found.value().policy.id);
  const RetryDecision decision =
      evaluate_retry(*record, policy != nullptr ? policy->spec : PolicySpec{},
                     found.value().session_retries_used);
  explanation.add("legal            " + yes_no(decision.legal));
  explanation.add("kind             " + std::string(to_string(decision.kind)));
  explanation.add("failure-class    " + std::string(to_string(decision.failure)));
  explanation.add("attempts-used    " + std::to_string(decision.attempts_used));
  explanation.add("session-retries  " + std::to_string(decision.session_retries_used));
  explanation.add("creates-new-invocation " + yes_no(decision.creates_new_invocation));
  if (decision.legal) {
    explanation.add("next-attempt-generation " + decision.next_attempt_generation.to_string());
  }
  explanation.add("reason           " + decision.reason);
  return explanation;
}

Explanation explain_recovery(const Runtime& runtime, CompilerSessionId session) {
  Explanation explanation;
  explanation.title = "RECOVERY " + session.to_string();
  const Result<RecoveryPlan> plan = runtime.plan_recovery(session);
  if (!plan) {
    explanation.add("REFUSED " + plan.status().to_string());
    return explanation;
  }
  explanation.add("headline         " + std::string(to_string(plan.value().headline)));
  explanation.add("legal            " + yes_no(plan.value().legal));
  explanation.add("requires-operator " + yes_no(plan.value().requires_operator));
  explanation.add("rationale        " + plan.value().rationale);
  for (const RecoveryStep& step : plan.value().steps) {
    explanation.add("  step " + std::string(to_string(step.outcome)) + " phase=" +
                    step.phase.to_string() + " reason=" + step.reason);
  }
  const Result<CompilerSession> found = runtime.require_session(session);
  if (found) {
    explanation.add("session-state    " + std::string(to_string(found.value().state)));
    explanation.add("recovery-state   " + std::string(to_string(found.value().recovery_state)));
    const std::vector<CompilerPhaseId> committed = found.value().committed_phases();
    std::string committed_text;
    for (const CompilerPhaseId id : committed) {
      if (!committed_text.empty()) committed_text.append(",");
      committed_text.append(id.to_string());
    }
    explanation.add("committed-phases " +
                    (committed_text.empty() ? std::string("<none>") : committed_text));
  }
  explanation.add("note             process death means phase restart from the last authoritative "
                  "phase boundary; the runtime never claims mid-process compiler continuation");
  return explanation;
}

Explanation explain_provenance(const Runtime& runtime, IntermediateArtifactId artifact) {
  Explanation explanation;
  explanation.title = "PROVENANCE " + artifact.to_string();
  const Result<std::vector<Ref<IntermediateArtifactId>>> lineage =
      runtime.provenance().trace_lineage(runtime.artifacts(), artifact);
  if (!lineage) {
    explanation.add("REFUSED " + lineage.status().to_string());
    return explanation;
  }
  for (const Ref<IntermediateArtifactId>& reference : lineage.value()) {
    explanation.add("  " + reference.to_string());
  }
  explanation.add("authoritative-lineage " +
                  yes_no(runtime.provenance().lineage_is_authoritative(runtime.artifacts(), artifact)));
  for (const ProvenanceRecord& record : runtime.provenance().records()) {
    bool mentions = false;
    for (const Ref<IntermediateArtifactId>& output : record.outputs) {
      if (output.id == artifact) mentions = true;
    }
    if (!mentions) continue;
    explanation.add("  record " + record.id.to_string() + " kind=" + record.kind +
                    " verdict=" + std::string(to_string(record.verdict)) + " at=" +
                    std::to_string(record.at_nanos) + " detail=" + record.detail);
  }
  return explanation;
}

Explanation explain_refusal(StatusCode code, std::string_view context) {
  Explanation explanation;
  explanation.title = "REFUSAL " + std::string(to_string(code));
  if (!context.empty()) explanation.add("context          " + std::string(context));
  const FailureClass failure = classify_status(code);
  explanation.add("failure-class    " + std::string(to_string(failure)));
  explanation.add("retryable        " + yes_no(is_retryable(failure)));
  explanation.add("transient        " + yes_no(is_transient(code)));
  switch (code) {
    case StatusCode::stale_toolchain_generation:
      explanation.add("meaning          the toolchain generation moved after the phase was "
                      "reserved; the phase may have finished physically but its output cannot "
                      "become current");
      break;
    case StatusCode::stale_environment_generation:
      explanation.add("meaning          the environment generation moved after the phase was "
                      "reserved; the output was produced under superseded conditions");
      break;
    case StatusCode::duplicate_completion:
      explanation.add("meaning          an equivalent completion already committed this phase "
                      "generation; the existing authoritative result stands");
      break;
    case StatusCode::divergent_completion:
      explanation.add("meaning          a different completion already committed this phase "
                      "generation; the runtime refuses to choose a winner");
      break;
    case StatusCode::stale_invocation:
      explanation.add("meaning          the reported invocation is not the current one for this "
                      "phase generation, so its evidence cannot satisfy the phase");
      break;
    case StatusCode::unknown_outcome:
      explanation.add("meaning          the runtime could not prove the outcome; UNKNOWN fails "
                      "closed and is never retried automatically");
      break;
    case StatusCode::workspace_escape:
      explanation.add("meaning          a path resolved outside the workspace that owns it");
      break;
    case StatusCode::path_traversal:
      explanation.add("meaning          a path contained a parent component and was refused");
      break;
    default:
      explanation.add("meaning          see the runtime documentation for this refusal code");
      break;
  }
  return explanation;
}

Explanation explain_plan(const PhasePlan& plan) {
  Explanation explanation;
  explanation.title = "PHASE PLAN";
  explanation.add("phases           " + std::to_string(plan.size()));
  explanation.add("plan-digest      " + plan.canonical_digest().to_hex());
  for (const CompilerPhaseId id : plan.topological_order()) {
    const PhaseNode* node = plan.find(id);
    if (node == nullptr) continue;
    std::string line = "  " + id.to_string() + " " + std::string(to_string(node->kind));
    if (!node->adapter_phase.empty()) line.append(" [" + node->adapter_phase + "]");
    line.append(node->mandatory ? " mandatory" : " optional");
    if (node->fan_in) line.append(" fan-in>=" + std::to_string(node->required_inputs));
    explanation.add(line);
  }
  return explanation;
}

}  // namespace crf
