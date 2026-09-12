#include "crf/runtime.hpp"
#include "crf/canonical.hpp"
#include "crf/explain.hpp"
#include "crf/version.hpp"

#include <algorithm>
#include <atomic>
#include <fstream>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace crf {
namespace {

/// Durable projection of a session: the session plus the artifacts and
/// diagnostic sets it owns.
struct AuthorityBundle {
  const ToolchainRegistry* toolchains = nullptr;
  const TargetRegistry* targets = nullptr;
  const EnvironmentRegistry* environments = nullptr;
  const PolicyRegistry* policies = nullptr;
  const SourceRegistry* sources = nullptr;
  const ProvenanceLog* provenance = nullptr;
};

CRF_NODISCARD std::string encode_session_bundle(const CompilerSession& session,
                                                const ArtifactRegistry& artifacts,
                                                const DiagnosticStore& diagnostics,
                                                const AuthorityBundle& authority) {
  CanonicalWriter writer;
  writer.text(encode_session(session));

  // The authority a session is bound to travels with it, so a restarted runtime
  // can revalidate the generations that committed phases were bound to instead
  // of trusting an empty registry.
  const ToolchainIdentity* toolchain =
      authority.toolchains != nullptr ? authority.toolchains->find(session.toolchain.id) : nullptr;
  writer.text(toolchain != nullptr ? encode_toolchain(*toolchain) : std::string{});
  const TargetIdentity* target =
      authority.targets != nullptr ? authority.targets->find(session.target.id) : nullptr;
  writer.text(target != nullptr ? encode_target_identity(*target) : std::string{});
  const EnvironmentIdentity* environment =
      authority.environments != nullptr ? authority.environments->find(session.environment.id)
                                        : nullptr;
  writer.text(environment != nullptr ? encode_environment_identity(*environment) : std::string{});
  const PolicyIdentity* policy =
      authority.policies != nullptr ? authority.policies->find(session.policy.id) : nullptr;
  writer.text(policy != nullptr ? encode_policy_identity(*policy) : std::string{});
  writer.u64(session.sources.size());
  for (const Ref<SourceId>& reference : session.sources) {
    const SourceUnit* unit =
        authority.sources != nullptr ? authority.sources->find(reference.id) : nullptr;
    writer.text(unit != nullptr ? encode_source_unit(*unit) : std::string{});
  }
  std::vector<const IntermediateArtifact*> owned;
  for (const Ref<IntermediateArtifactId>& reference : session.intermediates) {
    const IntermediateArtifact* artifact = artifacts.find(reference.id);
    if (artifact != nullptr) owned.push_back(artifact);
  }
  std::sort(owned.begin(), owned.end(),
            [](const IntermediateArtifact* a, const IntermediateArtifact* b) { return a->id < b->id; });
  writer.u64(owned.size());
  for (const IntermediateArtifact* artifact : owned) writer.text(encode_artifact(*artifact));

  std::vector<const DiagnosticSet*> sets;
  for (const CompilerPhaseId phase_id : session.plan.topological_order()) {
    const PhaseRecord* phase = session.find_phase(phase_id);
    if (phase == nullptr || !phase->diagnostics.id.present()) continue;
    const DiagnosticSet* set = diagnostics.find(phase->diagnostics.id);
    if (set != nullptr) sets.push_back(set);
  }
  std::sort(sets.begin(), sets.end(),
            [](const DiagnosticSet* a, const DiagnosticSet* b) { return a->id < b->id; });
  writer.u64(sets.size());
  for (const DiagnosticSet* set : sets) writer.text(encode_diagnostic_set(*set));

  // Provenance is what makes an authoritative artifact explainable after the
  // process that produced it has exited, so the records an artifact cites are
  // persisted with it.
  std::vector<const ProvenanceRecord*> provenance;
  if (authority.provenance != nullptr) {
    for (const IntermediateArtifact* artifact : owned) {
      if (!artifact->provenance.present()) continue;
      const ProvenanceRecord* record = authority.provenance->find(artifact->provenance);
      if (record != nullptr) provenance.push_back(record);
    }
  }
  std::sort(provenance.begin(), provenance.end(),
            [](const ProvenanceRecord* a, const ProvenanceRecord* b) { return a->id < b->id; });
  provenance.erase(std::unique(provenance.begin(), provenance.end(),
                               [](const ProvenanceRecord* a, const ProvenanceRecord* b) {
                                 return a->id == b->id;
                               }),
                   provenance.end());
  writer.u64(provenance.size());
  for (const ProvenanceRecord* record : provenance) writer.text(encode_provenance(*record));
  return writer.take();
}

struct SessionBundle {
  CompilerSession session;
  std::vector<IntermediateArtifact> artifacts;
  std::vector<DiagnosticSet> diagnostics;
  std::string toolchain;
  std::string target;
  std::string environment;
  std::string policy;
  std::vector<std::string> sources;
  std::vector<std::string> provenance;
};

CRF_NODISCARD Result<SessionBundle> decode_session_bundle(std::string_view bytes) {
  CanonicalReader reader(bytes);
  SessionBundle bundle;
  std::string session_bytes;
  if (!reader.text(session_bytes, 8u << 20)) {
    return Status(StatusCode::persistence_corrupt, "session bundle is truncated");
  }
  const Result<CompilerSession> session = decode_session(session_bytes);
  if (!session) return session.status();
  bundle.session = session.value();

  if (!reader.text(bundle.toolchain, 8u << 20) || !reader.text(bundle.target, 8u << 20) ||
      !reader.text(bundle.environment, 8u << 20) || !reader.text(bundle.policy, 8u << 20)) {
    return Status(StatusCode::persistence_corrupt, "session bundle authority section is truncated");
  }
  std::uint64_t source_count = 0;
  if (!reader.u64(source_count) || source_count > SourceRegistry::kMaxSources) {
    return Status(StatusCode::persistence_corrupt, "session bundle source count is invalid");
  }
  for (std::uint64_t i = 0; i < source_count; ++i) {
    std::string entity;
    if (!reader.text(entity, 8u << 20)) {
      return Status(StatusCode::persistence_corrupt, "session bundle source is truncated");
    }
    bundle.sources.push_back(std::move(entity));
  }

  std::uint64_t artifact_count = 0;
  if (!reader.u64(artifact_count) || artifact_count > ArtifactRegistry::kMaxArtifacts) {
    return Status(StatusCode::persistence_corrupt, "session bundle artifact count is invalid");
  }
  for (std::uint64_t i = 0; i < artifact_count; ++i) {
    std::string entity;
    if (!reader.text(entity, 8u << 20)) {
      return Status(StatusCode::persistence_corrupt, "session bundle artifact is truncated");
    }
    const Result<IntermediateArtifact> artifact = decode_artifact(entity);
    if (!artifact) return artifact.status();
    bundle.artifacts.push_back(artifact.value());
  }
  std::uint64_t diagnostic_count = 0;
  if (!reader.u64(diagnostic_count) || diagnostic_count > DiagnosticStore::kMaxSets) {
    return Status(StatusCode::persistence_corrupt, "session bundle diagnostic count is invalid");
  }
  for (std::uint64_t i = 0; i < diagnostic_count; ++i) {
    std::string entity;
    if (!reader.text(entity, 8u << 20)) {
      return Status(StatusCode::persistence_corrupt, "session bundle diagnostic set is truncated");
    }
    const Result<DiagnosticSet> set = decode_diagnostic_set(entity);
    if (!set) return set.status();
    bundle.diagnostics.push_back(set.value());
  }
  std::uint64_t provenance_count = 0;
  if (!reader.u64(provenance_count) || provenance_count > ProvenanceLog::kMaxRecords) {
    return Status(StatusCode::persistence_corrupt, "session bundle provenance count is invalid");
  }
  for (std::uint64_t i = 0; i < provenance_count; ++i) {
    std::string entity;
    if (!reader.text(entity, 8u << 20)) {
      return Status(StatusCode::persistence_corrupt, "session bundle provenance is truncated");
    }
    bundle.provenance.push_back(std::move(entity));
  }
  if (!reader.exhausted()) {
    return Status(StatusCode::persistence_corrupt, "session bundle has trailing bytes");
  }
  return bundle;
}

/// Deterministic digest of a reported output set. Two completions that describe
/// the same bytes produce the same digest even when they arrive in a different
/// order.
CRF_NODISCARD Digest output_set_digest(const std::vector<OutputDescriptor>& outputs) {
  std::vector<std::string> entries;
  entries.reserve(outputs.size());
  for (const OutputDescriptor& output : outputs) {
    entries.push_back(output.logical_name + "|" + output.content.to_hex());
  }
  std::sort(entries.begin(), entries.end());
  CanonicalWriter writer;
  writer.u64(entries.size());
  for (const std::string& entry : entries) writer.text(entry);
  return Digest::of(writer.bytes());
}

CRF_NODISCARD PhaseAuthority authority_from_session(const CompilerSession& session,
                                                    const PhaseRecord& phase) {
  PhaseAuthority authority;
  authority.session_generation = session.generation;
  authority.compilation_generation = session.compilation_generation;
  authority.attempt_generation = phase.attempt_generation;
  authority.phase_generation = phase.generation;
  authority.toolchain = session.toolchain;
  authority.cooperating_toolchains = session.cooperating_toolchains;
  authority.target = session.target;
  authority.environment = session.environment;
  authority.policy = session.policy;
  authority.source = session.source;
  authority.ir_generation = session.ir_generation;
  authority.lease = phase.lease;
  return authority;
}

}  // namespace

Digest OutputDescriptor::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(logical_name);
  writer.text(canonical_path_key(path));
  writer.text(to_string(format));
  writer.text(content.to_hex());
  writer.u64(size_bytes);
  writer.boolean(exists);
  return Digest::of(writer.bytes());
}

Digest ExecutionReport::evidence_digest() const {
  CanonicalWriter writer;
  writer.boolean(executed);
  writer.text(process.capture.standard_output);
  writer.text(process.capture.standard_error);
  writer.u32(process.exit_code);
  writer.u8(static_cast<std::uint8_t>(process.termination));
  writer.u64(process.started_at_nanos);
  writer.u64(process.finished_at_nanos);
  for (const OutputDescriptor& output : outputs) writer.text(output.canonical_digest().to_hex());
  for (const Diagnostic& diagnostic : diagnostics) {
    writer.text(diagnostic.canonical_digest().to_hex());
  }
  return Digest::of(writer.bytes());
}

PhaseExecutor::~PhaseExecutor() = default;

namespace {

/// Executes a validated invocation in this process using the runtime's own
/// process supervisor. The child inherits nothing but the explicit environment.
class LocalPhaseExecutor final : public PhaseExecutor {
 public:
  explicit LocalPhaseExecutor(Runtime& runtime) : runtime_(&runtime) {}

  Result<ExecutionReport> execute(const InvocationSpec& invocation, const ProcessSpec& process,
                                  const Workspace& workspace, std::string_view phase_label) override {
    (void)phase_label;
    ExecutionReport report;
    report.workspace_root = workspace.root;
    report.workspace_marker = workspace.marker_digest;

    ProcessSpec effective = process;
    if (effective.working_directory.empty()) effective.working_directory = workspace.root;
    if (effective.environment.empty()) effective.environment = invocation.environment_variables;
    if (const VoidResult valid = effective.validate(); !valid) {
      report.status = valid.code();
      report.detail = valid.status().message();
      return report;
    }

    const Ref<InvocationId> reference{invocation.id, invocation.generation};
    const std::shared_ptr<std::atomic<bool>> session_cancel =
        runtime_->session_cancel_flag(invocation.session.id);
    auto cancellation = std::make_shared<std::atomic<bool>>(false);
    {
      const std::lock_guard<std::recursive_mutex> guard(mutex_);
      active_[reference.id.value()] = Entry{reference, nullptr, cancellation};
    }
    const Result<std::shared_ptr<ProcessHandle>> spawned =
        runtime_->processes().spawn(effective, reference);
    if (!spawned) {
      forget(reference);
      report.status = spawned.code();
      report.detail = spawned.status().message();
      return report;
    }
    {
      const std::lock_guard<std::recursive_mutex> guard(mutex_);
      active_[reference.id.value()].handle = spawned.value();
    }
    while (spawned.value()->running()) {
      if (cancellation->load() || (session_cancel != nullptr && session_cancel->load())) {
        const VoidResult terminated =
            spawned.value()->terminate("cancellation requested while the compiler was running");
        (void)terminated;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    const Result<ProcessOutcome> outcome = spawned.value()->wait();
    forget(reference);
    const VoidResult reaped =
        runtime_->processes().reap(spawned.value()->id(), spawned.value()->generation());
    (void)reaped;
    if (!outcome) {
      report.status = outcome.code();
      report.detail = outcome.status().message();
      return report;
    }
    report.executed = true;
    report.process = outcome.value();
    report.status = report.process.status.code();
    report.detail = report.process.status.message();

    // Materialise the declared outputs into evidence. Registration records what
    // is on disk right now; it never asserts that the output is valid, and a
    // missing required output is reported honestly as absent.
    for (const OutputBinding& binding : invocation.expected_outputs) {
      OutputDescriptor descriptor;
      descriptor.logical_name = binding.logical_name;
      descriptor.path = binding.path;
      descriptor.format = binding.expected_format;
      std::error_code ec;
      if (std::filesystem::is_regular_file(binding.path, ec) && !ec) {
        descriptor.exists = true;
        descriptor.size_bytes = static_cast<std::uint64_t>(std::filesystem::file_size(binding.path, ec));
        Digest content;
        if (Digest::of_file(binding.path, content)) descriptor.content = content;
      }
      report.outputs.push_back(std::move(descriptor));
    }
    return report;
  }

  VoidResult cancel(Ref<InvocationId> invocation, std::string reason) override {
    const std::lock_guard<std::recursive_mutex> guard(mutex_);
    const auto found = active_.find(invocation.id.value());
    if (found == active_.end()) {
      return Status(StatusCode::not_found, "no local process matches the invocation");
    }
    if (!(found->second.invocation == invocation)) {
      return Status(StatusCode::stale_invocation,
                    "the active process belongs to a different invocation generation");
    }
    found->second.cancellation->store(true);
    if (found->second.handle != nullptr) {
      return found->second.handle->terminate(reason);
    }
    return VoidResult{};
  }

  std::string describe() const override { return "local in-process executor"; }
  bool remote() const noexcept override { return false; }

  void forget(Ref<InvocationId> invocation) {
    const std::lock_guard<std::recursive_mutex> guard(mutex_);
    active_.erase(invocation.id.value());
  }

 private:
  struct Entry {
    Ref<InvocationId> invocation;
    std::shared_ptr<ProcessHandle> handle;
    std::shared_ptr<std::atomic<bool>> cancellation;
  };
  Runtime* runtime_;
  std::recursive_mutex mutex_;
  std::unordered_map<std::uint64_t, Entry> active_;
};

}  // namespace

std::shared_ptr<PhaseExecutor> make_local_executor(Runtime& runtime) {
  return std::make_shared<LocalPhaseExecutor>(runtime);
}

namespace {

/// Everything captured when a phase execution is reserved. The reservation is
/// created under the runtime lock and then executed without holding it.
struct Reservation {
  CompilerSessionId session{};
  CompilerPhaseId phase{};
  CompilerPhaseGeneration phase_generation{};
  Ref<InvocationId> invocation{};
  AttemptId attempt{};
  AttemptGeneration attempt_generation{};
  Ref<LeaseId> lease{};
  PhaseKind kind = PhaseKind::unknown;
  PhaseAuthority authority{};
  Workspace workspace{};
  InvocationSpec invocation_spec{};
  ProcessSpec process_spec{};
  bool remote = false;
};

}  // namespace

// ---------------------------------------------------------------------------
// Runtime state.
// ---------------------------------------------------------------------------
struct Runtime::Impl {
  explicit Impl(RuntimeOptions value)
      : options(std::move(value)), workspaces(options.workspace) {}

  RuntimeOptions options;
  std::uint64_t epoch = 0;
  std::unique_ptr<PersistenceStore> persistence;
  ToolchainRegistry toolchains;
  TargetRegistry targets;
  EnvironmentRegistry environments;
  PolicyRegistry policies;
  SourceRegistry sources;
  ArtifactRegistry artifacts;
  DiagnosticStore diagnostics;
  ProvenanceLog provenance;
  LeaseTable leases;
  EvidenceLog evidence_log;
  AdapterRegistry adapter_registry;
  ProcessSupervisor processes;
  WorkspaceManager workspaces;

  mutable std::recursive_mutex mutex;
  std::unordered_map<std::uint64_t, CompilerSession> sessions;
  std::unordered_map<std::uint64_t, std::shared_ptr<std::atomic<bool>>> cancel_flags;
  /// Most recent physical execution evidence per phase. Bounded by the number of
  /// phases; cleared when a session retires. Never treated as authority.
  std::unordered_map<std::uint64_t, ProcessOutcome> last_outcomes;
  /// Most recent output validation result per phase, used to cite the checks
  /// that justified a final candidate.
  std::unordered_map<std::uint64_t, ValidationEvidence> last_validation;
  std::shared_ptr<PhaseExecutor> executor;

  IdAllocator<CompilerSessionId> session_ids;
  IdAllocator<InvocationId> invocation_ids;
  IdAllocator<CommitId> commit_ids;
  /// Phase identities are runtime-owned and globally unique. An adapter builds a
  /// plan with plan-local identities, and the runtime remaps them here so that
  /// two sessions never share a phase identity.
  IdAllocator<CompilerPhaseId> phase_ids;
  mutable IdAllocator<RecoveryId> recovery_ids;
  IdAllocator<FinalArtifactId> final_ids;
  IdAllocator<AttemptId> attempt_ids;

  std::atomic<bool> shutting_down{false};
  std::atomic<std::uint64_t> commit_total{0};
  std::atomic<std::uint64_t> stale_commit_total{0};
  std::size_t persisted_defects = 0;

  CRF_NODISCARD CompilerSession* find(CompilerSessionId id) {
    const auto found = sessions.find(id.value());
    return found == sessions.end() ? nullptr : &found->second;
  }
  CRF_NODISCARD const CompilerSession* find(CompilerSessionId id) const {
    const auto found = sessions.find(id.value());
    return found == sessions.end() ? nullptr : &found->second;
  }
  CRF_NODISCARD std::shared_ptr<std::atomic<bool>> cancel_flag(CompilerSessionId id) {
    const auto found = cancel_flags.find(id.value());
    if (found != cancel_flags.end()) return found->second;
    auto flag = std::make_shared<std::atomic<bool>>(false);
    cancel_flags.emplace(id.value(), flag);
    return flag;
  }

  CRF_NODISCARD AuthorityObservation observe(const CompilerSession& session) const {
    AuthorityObservation observation;
    observation.session_generation = session.generation;
    observation.compilation_generation = session.compilation_generation;
    observation.attempt_generation = session.attempt_generation;
    if (const ToolchainIdentity* toolchain = toolchains.find(session.toolchain.id)) {
      observation.toolchain = Ref<ToolchainId>{toolchain->id, toolchain->generation};
      observation.toolchain_current = true;
    } else {
      observation.toolchain = session.toolchain;
      observation.toolchain_current = false;
    }
    for (const Ref<ToolchainId>& reference : session.cooperating_toolchains) {
      const ToolchainIdentity* toolchain = toolchains.find(reference.id);
      observation.cooperating_toolchains.push_back(
          toolchain != nullptr ? Ref<ToolchainId>{toolchain->id, toolchain->generation} : reference);
    }
    if (const TargetIdentity* target = targets.find(session.target.id)) {
      observation.target = Ref<TargetId>{target->id, target->generation};
      observation.target_current = true;
    } else {
      observation.target = session.target;
      observation.target_current = false;
    }
    if (const EnvironmentIdentity* environment = environments.find(session.environment.id)) {
      observation.environment = Ref<EnvironmentId>{environment->id, environment->generation};
      observation.environment_current = true;
    } else {
      observation.environment = session.environment;
      observation.environment_current = false;
    }
    if (const PolicyIdentity* policy = policies.find(session.policy.id)) {
      observation.policy = Ref<PolicyId>{policy->id, policy->generation};
      observation.policy_current = true;
    } else {
      observation.policy = session.policy;
      observation.policy_current = false;
    }
    if (const SourceUnit* unit = sources.find(session.source.id)) {
      observation.source = Ref<SourceId>{unit->id, unit->generation};
      observation.source_current = true;
    } else {
      observation.source = session.source;
      observation.source_current = false;
    }
    observation.ir_generation = session.ir_generation;
    observation.session_active = session_state_admits_new_authority(session.state) ||
                                 session.state == SessionState::recovering;
    observation.component_current = true;
    observation.lease_held = true;
    return observation;
  }

  CRF_NODISCARD VoidResult persist(const CompilerSession& session) {
    if (persistence == nullptr) return VoidResult{};
    AuthorityBundle authority;
    authority.toolchains = &toolchains;
    authority.targets = &targets;
    authority.environments = &environments;
    authority.policies = &policies;
    authority.sources = &sources;
    authority.provenance = &provenance;
    const std::string payload = encode_session_bundle(session, artifacts, diagnostics, authority);
    const Result<std::uint64_t> appended =
        persistence->append(RecordKind::session_state_changed, payload);
    if (!appended) return appended.status();
    return VoidResult{};
  }

  void append_transition(PhaseRecord& phase, PhaseState next, std::string reason) {
    PhaseTransition transition;
    transition.from = phase.state;
    transition.to = next;
    transition.at_nanos = monotonic_nanos();
    transition.reason = std::move(reason);
    if (phase.history.size() >= kMaxPhaseTransitions) phase.history.erase(phase.history.begin());
    phase.history.push_back(std::move(transition));
    phase.state = next;
  }

  /// Record a lifecycle transition. When the direct edge is not legal the
  /// transition is routed through an intermediate state the lifecycle does
  /// allow, so the recorded history always matches the state and the auditor
  /// never sees an invented edge. A transition that has no legal route is
  /// refused outright rather than recorded.
  void record_transition(PhaseRecord& phase, PhaseState next, std::string reason) {
    if (phase.state == next) return;
    if (is_legal_phase_transition(phase.state, next)) {
      append_transition(phase, next, std::move(reason));
      return;
    }
    static constexpr PhaseState kRoutes[] = {PhaseState::ready, PhaseState::failed,
                                             PhaseState::fenced};
    for (const PhaseState intermediate : kRoutes) {
      if (!is_legal_phase_transition(phase.state, intermediate)) continue;
      if (!is_legal_phase_transition(intermediate, next)) continue;
      append_transition(phase, intermediate,
                        "phase passed through " + std::string(to_string(intermediate)) +
                            " before " + reason);
      append_transition(phase, next, std::move(reason));
      return;
    }
    // No legal route exists. Leave the state untouched rather than record an
    // illegal edge.
  }

  CRF_NODISCARD Result<std::vector<Ref<IntermediateArtifactId>>> resolve_inputs(
      const CompilerSession& session, const PhaseRecord& phase) const {
    const PhaseNode* node = session.plan.find(phase.id);
    if (node == nullptr) {
      return Status(StatusCode::not_found, "phase is not part of the session plan");
    }
    std::vector<Ref<IntermediateArtifactId>> inputs;
    for (const CompilerPhaseId dependency : node->depends_on) {
      const PhaseRecord* producer = session.find_phase(dependency);
      if (producer == nullptr || producer->state != PhaseState::committed) {
        return Status(StatusCode::fan_in_incomplete,
                      "a required producer phase is not committed: " + dependency.to_string());
      }
      for (const Ref<IntermediateArtifactId>& output : producer->outputs) {
        const IntermediateArtifact* artifact = artifacts.find(output.id);
        if (artifact == nullptr) {
          return Status(StatusCode::not_found,
                        "producer output is not registered: " + output.id.to_string());
        }
        if (artifact->authority != AuthorityState::authoritative ||
            !artifact_state_is_consumable(artifact->state)) {
          return Status(StatusCode::fan_in_inconsistent,
                        "producer output is not authoritative: " + output.id.to_string());
        }
        inputs.push_back(Ref<IntermediateArtifactId>{artifact->id, artifact->generation});
      }
    }
    // Deterministic canonical ordering: ordering is never semantically relevant
    // for a fan-in input set, so the runtime fixes it.
    std::sort(inputs.begin(), inputs.end(),
              [](const Ref<IntermediateArtifactId>& a, const Ref<IntermediateArtifactId>& b) {
                return a.id < b.id;
              });
    inputs.erase(std::unique(inputs.begin(), inputs.end(),
                             [](const Ref<IntermediateArtifactId>& a,
                                const Ref<IntermediateArtifactId>& b) { return a.id == b.id; }),
                 inputs.end());
    if (node->fan_in && inputs.size() < node->required_inputs) {
      return Status(StatusCode::fan_in_incomplete,
                    "fan-in phase received fewer authoritative inputs than it declared");
    }
    return inputs;
  }

  struct Reserved {
    Reservation reservation;
    std::size_t session_index = 0;
  };

  CRF_NODISCARD Result<Reservation> reserve(CompilerSessionId session_id, CompilerPhaseId phase_id,
                                            bool is_retry) {
    const std::lock_guard<std::recursive_mutex> guard(mutex);
    if (shutting_down.load()) {
      return Status(StatusCode::shutting_down, "runtime is shutting down");
    }
    CompilerSession* session = find(session_id);
    if (session == nullptr) {
      return Status(StatusCode::not_found, "session is not registered: " + session_id.to_string());
    }
    if (session->state == SessionState::recovering) {
      return Status(StatusCode::session_not_active,
                    "session requires recovery before new authority is granted");
    }
    if (!session_state_admits_new_authority(session->state)) {
      return Status(StatusCode::session_not_active,
                    std::string("session state ") + std::string(to_string(session->state)) +
                        " does not admit new authority");
    }
    PhaseRecord* phase = session->find_phase(phase_id);
    if (phase == nullptr) {
      return Status(StatusCode::not_found, "phase is not part of the session: " + phase_id.to_string());
    }
    switch (phase->state) {
      case PhaseState::committed:
        return Status(StatusCode::duplicate_completion,
                      "phase already committed an authoritative result");
      case PhaseState::retired:
      case PhaseState::fenced:
      case PhaseState::cancelled:
        return Status(StatusCode::phase_retired,
                      std::string("phase is ") + std::string(to_string(phase->state)) +
                          " and retains no execution authority");
      case PhaseState::running:
      case PhaseState::preparing:
      case PhaseState::produced:
      case PhaseState::validating:
      case PhaseState::commit_ready:
        return Status(StatusCode::phase_already_running, "phase is still in flight");
      default:
        break;
    }
    if (is_retry && phase->state != PhaseState::failed &&
        phase->state != PhaseState::recovery_required) {
      return Status(StatusCode::illegal_transition, "phase is not in a retryable state");
    }
    if (!is_retry && phase->state == PhaseState::failed) {
      return Status(StatusCode::illegal_transition,
                    "a failed phase may only be restarted through an explicit retry");
    }
    const std::vector<CompilerPhaseId> committed = session->committed_phases();
    if (!session->plan.is_ready(phase_id, committed)) {
      return Status(StatusCode::phase_not_ready,
                    "a dependency of this phase is not committed yet");
    }

    // Refuse to grant new authority when the session's binding has already moved.
    PhaseRecord probe = *phase;
    probe.lease = Ref<LeaseId>{};
    const PhaseAuthority bound_at_reserve = authority_from_session(*session, probe);
    AuthorityObservation observation = observe(*session);
    observation.phase_generation = probe.generation;
    observation.attempt_generation = probe.attempt_generation.present()
                                         ? probe.attempt_generation
                                         : session->attempt_generation;
    observation.session_generation = bound_at_reserve.session_generation;
    const AuthorityVerdict verdict = compare_authority(bound_at_reserve, observation);
    if (!authority_verdict_is_current(verdict)) {
      return Status(to_status_code(verdict),
                    std::string("session authority is not current: ") + std::string(to_string(verdict)));
    }

    const Result<std::vector<Ref<IntermediateArtifactId>>> inputs = resolve_inputs(*session, *phase);
    if (!inputs) return inputs.status();

    if (phase->attempts.size() >= kMaxPhaseAttempts) {
      return Status(StatusCode::capacity_exceeded, "phase attempt history is full");
    }

    Reservation reservation;
    reservation.session = session_id;
    reservation.phase = phase_id;
    reservation.kind = phase->kind;
    reservation.phase_generation = phase->generation.present() ? phase->generation.next()
                                                              : CompilerPhaseGeneration::initial();
    reservation.attempt_generation = is_retry || !phase->attempt_generation.present()
                                         ? (phase->attempt_generation.present()
                                                ? phase->attempt_generation.next()
                                                : AttemptGeneration::initial())
                                         : phase->attempt_generation;
    reservation.attempt = attempt_ids.next();
    reservation.invocation = Ref<InvocationId>{invocation_ids.next(), InvocationGeneration::initial()};

    const Result<Workspace> workspace =
        workspaces.create(session->id, session->generation, phase_id, reservation.phase_generation,
                          is_retry ? "retry" : "");
    if (!workspace) return workspace.status();
    reservation.workspace = workspace.value();

    const Result<Ref<LeaseId>> lease =
        leases.grant(Ref<CompilerSessionId>{session->id, session->generation},
                     Ref<CompilerPhaseId>{phase_id, reservation.phase_generation}, 0,
                     is_retry ? "retry of a failed phase" : "phase execution");
    if (!lease) return lease.status();
    reservation.lease = lease.value();

    // Bind the phase record to the authority it was reserved under, so that a
    // later audit can prove the binding rather than reconstruct it.
    phase->session_generation = session->generation;
    phase->compilation_generation = session->compilation_generation;
    phase->toolchain = session->toolchain;
    phase->target = session->target;
    phase->environment = session->environment;
    phase->policy = session->policy;
    phase->source = session->source;
    phase->ir_generation = session->ir_generation;
    phase->generation = reservation.phase_generation;
    phase->attempt_generation = reservation.attempt_generation;
    PhaseAttempt attempt;
    attempt.id = reservation.attempt;
    attempt.generation = reservation.attempt_generation;
    attempt.invocation = reservation.invocation;
    attempt.terminal_state = PhaseState::pending;
    attempt.started_at_nanos = monotonic_nanos();
    phase->attempts.push_back(std::move(attempt));
    phase->active_invocation = reservation.invocation;
    phase->active_process = ProcessId{};
    phase->active_process_generation = ProcessGeneration{};
    phase->lease = reservation.lease;
    phase->inputs = inputs.value();
    phase->outputs.clear();
    phase->diagnostics = Ref<DiagnosticSetId>{};
    phase->commit = CommitId{};
    phase->committed_output_digest = Digest{};
    phase->failure = FailureClass::none;
    phase->last_status = StatusCode::ok;
    phase->last_detail.clear();
    session->attempt_generation = reservation.attempt_generation;
    session->current_phase = phase_id;
    session->generation = session->generation.next();
    session->updated_at_nanos = monotonic_nanos();
    record_transition(*phase, PhaseState::ready, is_retry ? "retry authority reserved"
                                                          : "phase authority reserved");
    record_transition(*phase, PhaseState::preparing, "workspace and environment prepared");

    reservation.authority = authority_from_session(*session, *phase);
    const VoidResult persisted = persist(*session);
    if (!persisted) return persisted.status();
    return reservation;
  }

  /// Build the adapter request context for a reserved phase.
  CRF_NODISCARD Result<PhaseExecutionRequest> build_request(CompilerSession& session,
                                                            const PhaseRecord& phase,
                                                            const Reservation& reservation) {
    PhaseExecutionRequest request;
    request.session = Ref<CompilerSessionId>{session.id, session.generation};
    request.compilation_generation = session.compilation_generation;
    request.attempt_generation = phase.attempt_generation;
    request.phase = Ref<CompilerPhaseId>{phase.id, phase.generation};
    request.kind = phase.kind;
    request.adapter_phase = phase.adapter_phase;
    request.toolchain = toolchains.find(session.toolchain.id);
    request.target = targets.find(session.target.id);
    const EnvironmentIdentity* environment = environments.find(session.environment.id);
    request.environment = environment != nullptr ? &environment->spec : nullptr;
    const PolicyIdentity* policy = policies.find(session.policy.id);
    request.policy = policy != nullptr ? &policy->spec : nullptr;
    request.artifacts = &artifacts;
    for (const Ref<SourceId>& reference : session.sources) {
      const SourceUnit* unit = sources.find(reference.id);
      if (unit != nullptr) request.sources.push_back(unit);
    }
    request.resolved_inputs = phase.inputs;
    request.workspace = &reservation.workspace;
    request.output_directory = reservation.workspace.outputs_directory();
    request.final_artifact_name = session.final_artifact_name;
    request.adapter_options = session.adapter_options;
    if (request.toolchain == nullptr || request.target == nullptr || request.environment == nullptr ||
        request.policy == nullptr) {
      return Status(StatusCode::integrity_unproven,
                    "phase execution context is missing an authority component");
    }
    return request;
  }

  CRF_NODISCARD Result<ExecutionReport> execute_reserved(Reservation& reservation);
  CRF_NODISCARD VoidResult record_execution(Reservation& reservation, const ExecutionReport& report);
  CRF_NODISCARD Result<ValidationEvidence> validate_phase_outputs(Reservation& reservation);
  CRF_NODISCARD Result<PhaseRunReport> commit_reserved(Reservation& reservation,
                                                       const ExecutionReport& report);
  CRF_NODISCARD Result<PhaseRunReport> run_phase_impl(CompilerSessionId session,
                                                      CompilerPhaseId phase, bool is_retry);
  CRF_NODISCARD Result<bool> reproducibility_verify(Reservation& reservation,
                                                    const std::vector<OutputDescriptor>& primary);
  CRF_NODISCARD PhaseRunReport phase_status_report(CompilerSessionId session,
                                                   CompilerPhaseId phase);
  CRF_NODISCARD Result<CompileOutcome> run_session_impl(CompilerSessionId session);
  CRF_NODISCARD Result<RecoveryPlan> plan_recovery_impl(CompilerSessionId session) const;
  CRF_NODISCARD Result<Ref<CompilerSessionId>> create_session_impl(const CompileRequest& request);
  CRF_NODISCARD VoidResult fence_all_in_flight(CompilerSession& session, std::string_view reason);
  CRF_NODISCARD Result<Ref<SourceId>> sources_add_inline(const std::string& name,
                                                        const std::string& contents);
  /// Write an inline source into a runtime-owned staging directory and admit it
  /// by path. A compiler is given a real file, never an in-memory buffer with a
  /// synthetic name.
  CRF_NODISCARD Result<std::filesystem::path> stage_inline_source(CompilerSessionId session,
                                                                 const std::string& name,
                                                                 const std::string& contents);
  CRF_NODISCARD std::filesystem::path staged_sources_root() const;
  void remove_staged_sources(CompilerSessionId session);
};

// ---------------------------------------------------------------------------
// Phase orchestration.
// ---------------------------------------------------------------------------
PhaseRunReport Runtime::Impl::phase_status_report(CompilerSessionId session_id,
                                                  CompilerPhaseId phase_id) {
  const std::lock_guard<std::recursive_mutex> guard(mutex);
  PhaseRunReport report;
  const CompilerSession* session = find(session_id);
  if (session == nullptr) {
    report.status = StatusCode::not_found;
    report.detail = "session is not registered";
    return report;
  }
  const PhaseRecord* phase = session->find_phase(phase_id);
  if (phase == nullptr) {
    report.status = StatusCode::not_found;
    report.detail = "phase is not registered";
    return report;
  }
  report.phase = Ref<CompilerPhaseId>{phase->id, phase->generation};
  report.state = phase->state;
  report.status = phase->last_status;
  report.failure = phase->failure;
  report.diagnostics = phase->diagnostics;
  report.invocation = phase->active_invocation;
  report.process = phase->active_process;
  report.outputs = phase->outputs;
  report.detail = phase->last_detail;
  return report;
}

Result<bool> Runtime::Impl::reproducibility_verify(Reservation& reservation,
                                                   const std::vector<OutputDescriptor>& primary) {
  std::shared_ptr<const CompilerAdapter> adapter;
  CompilerSessionId session_id = reservation.session;
  {
    const std::lock_guard<std::recursive_mutex> guard(mutex);
    const CompilerSession* session = find(session_id);
    if (session == nullptr) return Status(StatusCode::not_found, "session disappeared");
    adapter = adapter_registry.find_by_name(session->adapter_name);
    if (adapter == nullptr) return Status(StatusCode::unsupported, "no adapter registered");
    if (!adapter->is_deterministic_phase(reservation.kind)) return true;
  }
  // A genuine second execution, in its own generation-bound workspace, under the
  // same authoritative inputs. The runtime never rewrites output after the fact.
  const Result<Workspace> repro = workspaces.create(reservation.session, CompilerSessionGeneration{},
                                                    reservation.phase, reservation.phase_generation,
                                                    "repro");
  if (!repro) return repro.status();
  Workspace workspace = repro.value();
  workspace.valid = true;

  InvocationSpec spec;
  ProcessSpec process;
  {
    const std::lock_guard<std::recursive_mutex> guard(mutex);
    CompilerSession* session = find(session_id);
    if (session == nullptr) return Status(StatusCode::not_found, "session disappeared");
    PhaseRecord* phase = session->find_phase(reservation.phase);
    if (phase == nullptr) return Status(StatusCode::not_found, "phase disappeared");
    const Result<PhaseExecutionRequest> request = build_request(*session, *phase, reservation);
    if (!request) return request.status();
    PhaseExecutionRequest repro_request = request.value();
    repro_request.workspace = &workspace;
    repro_request.output_directory = workspace.outputs_directory();
    repro_request.reproducibility_second_run = true;

    EnvironmentSpec environment = *repro_request.environment;
    environment.temp_directory = workspace.temp_directory();
    if (const VoidResult valid = environment.canonicalize(); !valid) return valid.status();
    const Result<std::vector<EnvironmentVariable>> block = build_process_environment(environment);
    if (!block) return block.status();

    const Result<InvocationSpec> built = adapter->build_invocation(repro_request);
    if (!built) return built.status();
    spec = built.value();
    spec.id = reservation.invocation.id;
    spec.generation = reservation.invocation.generation;
    spec.session = Ref<CompilerSessionId>{session->id, reservation.workspace.session_generation};
    spec.phase = Ref<CompilerPhaseId>{phase->id, phase->generation};
    spec.attempt_generation = phase->attempt_generation;
    spec.toolchain = session->toolchain;
    spec.target = session->target;
    spec.environment = session->environment;
    spec.policy = session->policy;
    spec.environment_variables = block.value();
    spec.working_directory = workspace.root;
    spec.adapter_name = session->adapter_name;
    const ToolchainIdentity* toolchain = toolchains.find(session->toolchain.id);
    if (toolchain != nullptr) {
      for (const ComponentIdentity& candidate : toolchain->components) {
        if (canonical_path_key(candidate.file.canonical_path) == canonical_path_key(spec.executable)) {
          spec.component = candidate.id;
          spec.component_generation = candidate.generation;
          spec.executable_identity = candidate.file;
          break;
        }
      }
    }
    const PolicyIdentity* policy = policies.find(session->policy.id);
    const TargetIdentity* target = targets.find(session->target.id);
    InvocationValidationContext context;
    context.workspace = &workspace;
    context.family = adapter->describe().family;
    context.target_architecture = target != nullptr ? target->spec.architecture : Architecture::unknown;
    if (policy != nullptr) context.forbidden_options = policy->spec.forbidden_options;
    const Result<InvocationSpec> validated = validate_invocation(std::move(spec), context);
    if (!validated) return validated.status();
    spec = validated.value();
    Result<ProcessSpec> built_process = spec.to_process_spec();
    if (!built_process) return built_process.status();
    process = built_process.value();
  }

  const std::shared_ptr<PhaseExecutor> current_executor = executor;
  if (current_executor == nullptr) return Status(StatusCode::internal_error, "no executor configured");
  const Result<ExecutionReport> second =
      current_executor->execute(spec, process, workspace, "reproducibility-verify");
  evidence_log.record(EvidenceClass::real, "reproducibility-second-run",
                      second ? "second execution completed" : second.status().message(),
                      second ? second.value().evidence_digest() : Digest{});
  if (!second) return second.status();
  if (!second.value().executed || !second.value().process.exited_zero()) {
    return Status(StatusCode::unknown_outcome,
                  "the reproducibility verification run did not complete successfully");
  }
  if (output_set_digest(second.value().outputs) != output_set_digest(primary)) {
    return Status(StatusCode::divergent_completion,
                  "reproducibility is REQUIRED but two executions of a deterministic phase produced "
                  "different output; the runtime refuses to choose a winner");
  }
  return true;
}

Result<PhaseRunReport> Runtime::Impl::run_phase_impl(CompilerSessionId session_id,
                                                     CompilerPhaseId phase_id, bool is_retry) {
  const std::uint64_t governance_start = monotonic_nanos();
  Result<Reservation> reserved = reserve(session_id, phase_id, is_retry);
  if (!reserved) {
    PhaseRunReport report = phase_status_report(session_id, phase_id);
    report.status = reserved.code();
    report.detail = reserved.status().message();
    return report;
  }
  Reservation& reservation = reserved.value();

  Result<ExecutionReport> executed = execute_reserved(reservation);
  ExecutionReport execution;
  if (executed) {
    execution = executed.value();
  } else {
    execution.status = executed.code();
    execution.detail = executed.status().message();
    execution.workspace_root = reservation.workspace.root;
    execution.workspace_marker = reservation.workspace.marker_digest;
    execution.process.invocation = reservation.invocation;
    execution.process.termination = ProcessTermination::launch_failed;
  }
  if (execution.diagnostics.empty()) {
    const std::shared_ptr<const CompilerAdapter> adapter = [&]() {
      const std::lock_guard<std::recursive_mutex> guard(mutex);
      const CompilerSession* session = find(session_id);
      return session != nullptr ? adapter_registry.find_by_name(session->adapter_name) : nullptr;
    }();
    if (adapter != nullptr && execution.executed) {
      const std::lock_guard<std::recursive_mutex> guard(mutex);
      CompilerSession* session = find(session_id);
      PhaseRecord* phase = session != nullptr ? session->find_phase(phase_id) : nullptr;
      if (session != nullptr && phase != nullptr) {
        const Result<PhaseExecutionRequest> request = build_request(*session, *phase, reservation);
        if (request) {
          const Result<std::vector<Diagnostic>> parsed =
              adapter->parse_diagnostics(execution.process, request.value());
          if (parsed) execution.diagnostics = parsed.value();
        }
      }
    }
  }

  const VoidResult recorded = record_execution(reservation, execution);
  if (!recorded) return recorded.status();

  {
    const std::lock_guard<std::recursive_mutex> guard(mutex);
    const CompilerSession* session = find(session_id);
    const PhaseRecord* phase = session != nullptr ? session->find_phase(phase_id) : nullptr;
    if (phase != nullptr && phase->state == PhaseState::failed) {
      PhaseRunReport report = phase_status_report(session_id, phase_id);
      report.retry = evaluate_retry(*phase, policies.find(session->policy.id) != nullptr
                                                 ? policies.find(session->policy.id)->spec
                                                 : PolicySpec{},
                                    session->session_retries_used);
      report.governance_nanos = monotonic_nanos() - governance_start;
      report.compiler_nanos = execution.process.duration_nanos();
      return report;
    }
  }

  // Reproducibility contract, evaluated before validation so that a divergent
  // pair never reaches the commit path.
  {
    bool required = false;
    {
      const std::lock_guard<std::recursive_mutex> guard(mutex);
      const CompilerSession* session = find(session_id);
      if (session != nullptr) {
        const PolicyIdentity* policy = policies.find(session->policy.id);
        required = policy != nullptr &&
                   policy->spec.reproducibility == ReproducibilityPolicy::required;
      }
    }
    if (required) {
      const Result<bool> consistent = reproducibility_verify(reservation, execution.outputs);
      if (!consistent) {
        const StatusCode code = consistent.code();
        const std::string detail = consistent.status().message();
        {
          const std::lock_guard<std::recursive_mutex> guard(mutex);
          CompilerSession* session = find(session_id);
          PhaseRecord* phase = session != nullptr ? session->find_phase(phase_id) : nullptr;
          if (session != nullptr && phase != nullptr) {
            phase->failure = FailureClass::output_invalid;
            phase->last_status = code;
            phase->last_detail = detail;
            record_transition(*phase, PhaseState::failed, detail);
            (void)artifacts.revoke_phase_outputs(phase->id, phase->generation, detail);
            session->generation = session->generation.next();
            const VoidResult persisted = persist(*session);
            if (!persisted) return persisted.status();
          }
        }
        PhaseRunReport report = phase_status_report(session_id, phase_id);
        report.status = code;
        report.detail = detail;
        report.governance_nanos = monotonic_nanos() - governance_start;
        return report;
      }
    }
  }

  const Result<ValidationEvidence> evidence = validate_phase_outputs(reservation);
  if (!evidence) return evidence.status();
  if (!evidence.value().accepted) {
    PhaseRunReport report = phase_status_report(session_id, phase_id);
    report.status = evidence.value().refusal;
    report.detail = evidence.value().detail;
    report.governance_nanos = monotonic_nanos() - governance_start;
    return report;
  }

  Result<PhaseRunReport> committed = commit_reserved(reservation, execution);
  if (!committed) return committed.status();
  committed.value().governance_nanos = monotonic_nanos() - governance_start;
  committed.value().compiler_nanos = execution.process.duration_nanos();
  return committed;
}

Result<CompileOutcome> Runtime::Impl::run_session_impl(CompilerSessionId session_id) {
  CompileOutcome outcome;
  outcome.session = Ref<CompilerSessionId>{session_id, CompilerSessionGeneration{}};
  std::size_t parallel_limit = 1;
  {
    const std::lock_guard<std::recursive_mutex> guard(mutex);
    CompilerSession* session = find(session_id);
    if (session == nullptr) {
      return Status(StatusCode::not_found, "session is not registered: " + session_id.to_string());
    }
    const PolicyIdentity* policy = policies.find(session->policy.id);
    if (policy != nullptr && policy->spec.allow_parallel_phases) {
      parallel_limit = std::max<std::size_t>(1, policy->spec.max_parallel_phases);
    }
  }

  // Progress guard: a session can never need more phase executions than its
  // plan size multiplied by the retry ceiling plus one. Exceeding that is a
  // defect in the runtime, and it is reported as one instead of looping.
  std::size_t iteration_ceiling = 0;
  {
    const std::lock_guard<std::recursive_mutex> guard(mutex);
    const CompilerSession* session = find(session_id);
    if (session == nullptr) {
      return Status(StatusCode::not_found, "session is not registered: " + session_id.to_string());
    }
    const PolicyIdentity* policy = policies.find(session->policy.id);
    const std::uint32_t retries = policy != nullptr ? policy->spec.max_retries_per_phase : 2;
    iteration_ceiling = session->plan.size() * (static_cast<std::size_t>(retries) + 2) + 16;
  }
  std::size_t iterations = 0;

  for (;;) {
    if (++iterations > iteration_ceiling) {
      const std::lock_guard<std::recursive_mutex> guard(mutex);
      CompilerSession* session = find(session_id);
      std::string detail = "session made no progress after " + std::to_string(iterations) +
                           " scheduling rounds";
      if (session != nullptr) {
        for (const CompilerPhaseId id : session->plan.topological_order()) {
          const PhaseRecord* phase = session->find_phase(id);
          if (phase == nullptr) continue;
          detail.append(" | ");
          detail.append(id.to_string());
          detail.push_back('=');
          detail.append(to_string(phase->state));
          detail.append("/");
          detail.append(to_string(phase->last_status));
        }
        session->state = SessionState::failed;
        session->failure_detail = detail;
        const VoidResult persisted = persist(*session);
        (void)persisted;
      }
      return Status(StatusCode::internal_error, detail);
    }
    std::vector<CompilerPhaseId> ready;
    {
      const std::lock_guard<std::recursive_mutex> guard(mutex);
      CompilerSession* session = find(session_id);
      if (session == nullptr) {
        return Status(StatusCode::not_found, "session disappeared during execution");
      }
      session->state = SessionState::active;
      const std::vector<CompilerPhaseId> committed = session->committed_phases();
      for (const CompilerPhaseId id : session->plan.topological_order()) {
        const PhaseRecord* phase = session->find_phase(id);
        if (phase == nullptr) continue;
        if (phase->state == PhaseState::committed) continue;
        if (phase->state == PhaseState::failed || phase->state == PhaseState::fenced ||
            phase->state == PhaseState::cancelled || phase->state == PhaseState::retired) {
          continue;
        }
        if (session->plan.is_ready(id, committed)) ready.push_back(id);
      }
      if (ready.empty()) {
        if (session->all_mandatory_committed()) break;
        const PhaseRecord* blocked = nullptr;
        for (const CompilerPhaseId id : session->plan.topological_order()) {
          const PhaseRecord* phase = session->find_phase(id);
          if (phase == nullptr) continue;
          if (phase->state != PhaseState::committed) {
            blocked = phase;
            break;
          }
        }
        outcome.status = blocked != nullptr ? blocked->last_status : StatusCode::phase_not_ready;
        outcome.detail = blocked != nullptr
                             ? std::string("session cannot progress: phase ") +
                                   blocked->id.to_string() + " is " + std::string(to_string(blocked->state))
                             : std::string("session cannot progress");
        session->state = SessionState::failed;
        session->failure_detail = outcome.detail;
        const VoidResult persisted = persist(*session);
        if (!persisted) return persisted.status();
        outcome.phases = std::vector<PhaseRunReport>{};
        return outcome;
      }
    }

    const std::size_t batch = std::min(parallel_limit, ready.size());
    if (batch <= 1) {
      const Result<PhaseRunReport> report = run_phase_impl(session_id, ready.front(), false);
      if (!report) return report.status();
      outcome.phases.push_back(report.value());
      if (!report.value().committed()) {
        // A phase that did not commit cannot advance the session. It either
        // failed (the session is failed) or was refused (the refusal is
        // surfaced). Either way the driver stops instead of rescheduling.
        outcome.status = report.value().status;
        outcome.detail = report.value().detail;
        const std::lock_guard<std::recursive_mutex> guard(mutex);
        CompilerSession* session = find(session_id);
        if (session != nullptr && session->state == SessionState::active) {
          session->state = SessionState::failed;
          session->failure_detail = outcome.detail;
          const VoidResult persisted = persist(*session);
          (void)persisted;
        }
        return outcome;
      }
      continue;
    }

    std::vector<Result<PhaseRunReport>> results(
        batch, Result<PhaseRunReport>(Status(StatusCode::internal_error, "phase did not run")));
    std::vector<std::thread> workers;
    workers.reserve(batch);
    for (std::size_t i = 0; i < batch; ++i) {
      const CompilerPhaseId phase = ready[i];
      workers.emplace_back([this, session_id, phase, &results, i]() {
        results[i] = run_phase_impl(session_id, phase, false);
      });
    }
    for (std::thread& worker : workers) {
      if (worker.joinable()) worker.join();
    }
    bool stalled = false;
    for (Result<PhaseRunReport>& result : results) {
      if (!result) return result.status();
      outcome.phases.push_back(result.value());
      if (!result.value().committed()) {
        outcome.status = result.value().status;
        outcome.detail = result.value().detail;
        stalled = true;
      }
    }
    if (stalled) {
      const std::lock_guard<std::recursive_mutex> guard(mutex);
      CompilerSession* session = find(session_id);
      if (session != nullptr && session->state == SessionState::active) {
        session->state = SessionState::failed;
        session->failure_detail = outcome.detail;
        const VoidResult persisted = persist(*session);
        (void)persisted;
      }
      return outcome;
    }
  }

  const std::lock_guard<std::recursive_mutex> guard(mutex);
  CompilerSession* session = find(session_id);
  if (session == nullptr) {
    return Status(StatusCode::not_found, "session disappeared at completion");
  }
  if (session->candidate_present) {
    outcome.candidate = session->candidate;
    outcome.intermediates = session->intermediates;
    outcome.lineage_digest = session->candidate.lineage_digest;
  }
  outcome.diagnostics = session->final_phase() != nullptr ? session->final_phase()->diagnostics
                                                          : Ref<DiagnosticSetId>{};
  for (const PhaseRunReport& report : outcome.phases) {
    outcome.compiler_nanos += report.compiler_nanos;
    outcome.governance_nanos += report.governance_nanos;
  }
  const std::shared_ptr<const CompilerAdapter> adapter =
      adapter_registry.find_by_name(session->adapter_name);
  outcome.evidence = adapter != nullptr ? adapter->describe().evidence_class : EvidenceClass::unknown;
  return outcome;
}

Result<RecoveryPlan> Runtime::Impl::plan_recovery_impl(CompilerSessionId session_id) const {
  RecoveryInputs inputs;
  RecoveryPlan plan;
  {
    const std::lock_guard<std::recursive_mutex> guard(mutex);
    const CompilerSession* session = find(session_id);
    if (session == nullptr) {
      return Status(StatusCode::not_found, "session is not registered: " + session_id.to_string());
    }
    std::vector<PhaseRecord> phases;
    for (const CompilerPhaseId id : session->plan.topological_order()) {
      const PhaseRecord* phase = session->find_phase(id);
      if (phase != nullptr) phases.push_back(*phase);
    }
    inputs.plan = &session->plan;
    inputs.phases = &phases;
    inputs.artifacts = &artifacts;
    inputs.authority = observe(*session);
    inputs.after_runtime_restart = session->state == SessionState::recovering ||
                                   session->recovery_state == RecoveryState::required;
    inputs.epoch_advanced = session->epoch.present() && session->epoch.value() != epoch;
    RecoveryPlanner planner;
    plan = planner.plan(inputs);
  }
  plan.id = RecoveryId::from_value(recovery_ids.next().value());
  plan.generation = RecoveryGeneration::initial();
  plan.session = Ref<CompilerSessionId>{session_id, CompilerSessionGeneration{}};
  return plan;
}

VoidResult Runtime::Impl::fence_all_in_flight(CompilerSession& session, std::string_view reason) {
  for (const CompilerPhaseId id : session.plan.topological_order()) {
    PhaseRecord* phase = session.find_phase(id);
    if (phase == nullptr) continue;
    if (!phase_state_retains_commit_authority(phase->state)) continue;
    if (phase->state == PhaseState::pending || phase->state == PhaseState::ready) continue;
    phase->failure = FailureClass::authority_invalidated;
    phase->last_status = StatusCode::stale_epoch;
    phase->last_detail = std::string(reason);
    record_transition(*phase, PhaseState::fenced, std::string(reason));
    if (phase->attempts.size() > 0) {
      phase->attempts.back().terminal_state = PhaseState::fenced;
      phase->attempts.back().failure = FailureClass::authority_invalidated;
    }
    (void)artifacts.revoke_phase_outputs(phase->id, phase->generation, std::string(reason));
    (void)leases.revoke(phase->lease.id, std::string(reason));
    phase->active_invocation = Ref<InvocationId>{};
    phase->active_process = ProcessId{};
    phase->active_process_generation = ProcessGeneration{};
  }
  return VoidResult{};
}

// ---------------------------------------------------------------------------
// Session creation.
// ---------------------------------------------------------------------------
Result<Ref<CompilerSessionId>> Runtime::Impl::create_session_impl(const CompileRequest& request) {
  const std::lock_guard<std::recursive_mutex> guard(mutex);
  if (shutting_down.load()) {
    return Status(StatusCode::shutting_down, "runtime is shutting down");
  }
  if (sessions.size() >= options.max_sessions) {
    return Status(StatusCode::capacity_exceeded, "session ceiling reached");
  }
  if (request.sources.empty() && request.inline_sources.empty()) {
    return Status(StatusCode::invalid_argument, "a compile request must carry at least one source");
  }

  // 1. Resolve the adapter for the requested family.
  std::shared_ptr<const CompilerAdapter> adapter =
      adapter_registry.find(request.toolchain_family);
  if (adapter == nullptr) {
    return Status(StatusCode::unsupported,
                  std::string("no adapter is registered for toolchain family ") +
                      std::string(to_string(request.toolchain_family)));
  }

  // 2. Resolve the toolchain generation.
  const ToolchainIdentity* toolchain = nullptr;
  if (request.toolchain.present()) {
    toolchain = toolchains.find(request.toolchain);
    if (toolchain == nullptr) {
      return Status(StatusCode::toolchain_not_found,
                    "requested toolchain is not registered: " + request.toolchain.to_string());
    }
  } else {
    toolchain = toolchains.find_latest(request.toolchain_family);
    if (toolchain == nullptr) {
      return Status(StatusCode::toolchain_not_found,
                    "no toolchain of the requested family has been discovered yet");
    }
  }

  // 3. Resolve the target.
  const Result<TargetSpec> resolved = adapter->resolve_target(*toolchain, request.target);
  if (!resolved) return resolved.status();
  const Result<Ref<TargetId>> target = targets.intern(resolved.value());
  if (!target) return target.status();

  // 4. Admit sources.
  std::vector<Ref<SourceId>> admitted_sources;
  for (const std::filesystem::path& path : request.sources) {
    const Result<Ref<SourceId>> added =
        sources.add(path, source_language_from_extension(path.extension().string()), "");
    if (!added) return added.status();
    admitted_sources.push_back(added.value());
  }
  for (const auto& [name, contents] : request.inline_sources) {
    const Result<Ref<SourceId>> added = sources_add_inline(name, contents);
    if (!added) return added.status();
    admitted_sources.push_back(added.value());
  }
  if (admitted_sources.empty()) {
    return Status(StatusCode::invalid_argument, "no source could be admitted");
  }

  // 5. Compose and intern the environment.
  const Result<EnvironmentSpec> composed =
      adapter->compose_environment(*toolchain, resolved.value(), request.environment);
  if (!composed) return composed.status();
  EnvironmentSpec environment = composed.value();
  if (request.policy.reproducibility != ReproducibilityPolicy::not_required &&
      environment.deterministic_controls) {
    if (environment.locale_policy == LocalePolicy::user_default) {
      environment.locale_policy = LocalePolicy::c_locale;
    }
  }
  const Result<Ref<EnvironmentId>> environment_id = environments.intern(environment);
  if (!environment_id) return environment_id.status();

  // 6. Intern the policy.
  const Result<Ref<PolicyId>> policy_id = policies.intern(request.policy);
  if (!policy_id) return policy_id.status();

  // 7. Build the phase plan.
  PhasePlanRequest plan_request;
  plan_request.family = request.toolchain_family;
  plan_request.toolchain = toolchain;
  plan_request.target = &resolved.value();
  plan_request.language = admitted_sources.empty()
                              ? SourceLanguage::unknown
                              : sources.find(admitted_sources.front().id)->language;
  plan_request.translation_unit_count = admitted_sources.size();
  plan_request.want_link = true;
  plan_request.want_smoke_test = request.run_smoke_test;
  plan_request.policy = request.policy;
  const Result<PhasePlan> local_plan = adapter->build_plan(plan_request);
  if (!local_plan) return local_plan.status();
  // Remap plan-local phase identities into the runtime's own domain. Without
  // this, every session would reuse the same phase identities and an operation
  // that names a phase would silently address another session's phase.
  std::unordered_map<std::uint64_t, CompilerPhaseId> remap;
  remap.reserve(local_plan.value().size());
  for (const PhaseNode& node : local_plan.value().nodes()) {
    remap.emplace(node.id.value(), phase_ids.next());
  }
  std::vector<PhaseNode> remapped_nodes = local_plan.value().nodes();
  for (PhaseNode& node : remapped_nodes) {
    node.id = remap.at(node.id.value());
    for (CompilerPhaseId& dependency : node.depends_on) {
      dependency = remap.at(dependency.value());
    }
  }
  const Result<PhasePlan> plan = PhasePlan::build(std::move(remapped_nodes));
  if (!plan) return plan.status();

  CompilerSession session;
  session.id = session_ids.next();
  session.generation = CompilerSessionGeneration::initial();
  session.state = SessionState::active;
  session.recovery_state = RecoveryState::none;
  session.request = request.request.present() ? request.request : RequestId::from_value(session.id.value());
  session.compilation = request.compilation.present() ? request.compilation
                                                     : CompilationId::from_value(session.id.value());
  session.compilation_generation = request.compilation_generation.present()
                                       ? request.compilation_generation
                                       : CompilationGeneration::initial();
  session.attempt = request.attempt.present() ? request.attempt
                                              : attempt_ids.next();
  session.attempt_generation = request.attempt_generation.present()
                                   ? request.attempt_generation
                                   : AttemptGeneration::initial();
  session.toolchain = Ref<ToolchainId>{toolchain->id, toolchain->generation};
  session.target = target.value();
  session.environment = environment_id.value();
  session.policy = policy_id.value();
  // Inline sources are materialised so that every admitted source has a real
  // file the compiler can read, staged under the runtime's own sources root and
  // removed with the session.
  for (std::size_t i = 0; i < request.inline_sources.size(); ++i) {
    const auto& [name, contents] = request.inline_sources[i];
    const Result<std::filesystem::path> staged =
        stage_inline_source(session.id, name, contents);
    if (!staged) return staged.status();
    const std::size_t index = request.sources.size() + i;
    if (index >= admitted_sources.size()) break;
    const Result<Ref<SourceId>> replaced =
        sources.add(staged.value(), source_language_from_extension(staged.value().extension().string()),
                    "");
    if (!replaced) return replaced.status();
    admitted_sources[index] = replaced.value();
  }
  session.source = admitted_sources.front();
  session.sources = admitted_sources;
  session.ir_generation = IRGeneration::initial();
  session.adapter_name = adapter->describe().name;
  session.final_artifact_name = request.final_artifact_name;
  session.adapter_options = request.adapter_options;
  session.plan = plan.value();
  session.epoch = EpochId::from_value(epoch);
  session.created_at_nanos = monotonic_nanos();
  session.updated_at_nanos = session.created_at_nanos;
  session.request_digest = request.canonical_digest();
  for (const PhaseNode& node : session.plan.nodes()) {
    PhaseRecord record;
    record.id = node.id;
    record.generation = CompilerPhaseGeneration::initial();
    record.attempt_generation = session.attempt_generation;
    record.kind = node.kind;
    record.adapter_phase = node.adapter_phase;
    record.mandatory = node.mandatory;
    record.depends_on = node.depends_on;
    record.state = PhaseState::pending;
    session.phases.emplace(node.id.value(), std::move(record));
  }
  session_ids.observe(session.id);
  const CompilerSessionId id = session.id;
  (void)cancel_flag(id);

  const VoidResult persisted = persist(session);
  if (!persisted) return persisted.status();
  sessions.emplace(id.value(), std::move(session));
  evidence_log.record(EvidenceClass::real, "session-created",
                      "session " + id.to_string() + " created for adapter " +
                          adapter->describe().name);
  return Ref<CompilerSessionId>{id, CompilerSessionGeneration::initial()};
}

std::filesystem::path Runtime::Impl::staged_sources_root() const {
  return normalize_path(options.workspace.base_directory / "_staged-sources");
}

Result<std::filesystem::path> Runtime::Impl::stage_inline_source(CompilerSessionId session,
                                                                const std::string& name,
                                                                const std::string& contents) {
  std::string leaf = std::filesystem::path(name).filename().string();
  if (leaf.empty()) leaf = "translation-unit.cpp";
  for (char& c : leaf) {
    if (c == '\\' || c == '/' || c == ':' || c == '\0') c = '_';
  }
  const std::filesystem::path directory = staged_sources_root() / session.to_string();
  std::error_code ec;
  std::filesystem::create_directories(directory, ec);
  if (ec) {
    return Status(StatusCode::permission_denied,
                  "staged source directory could not be created: " + ec.message());
  }
  const std::filesystem::path path = normalize_path(directory / leaf);
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) {
    return Status(StatusCode::permission_denied,
                  "staged source could not be written: " + path.string());
  }
  stream.write(contents.data(), static_cast<std::streamsize>(contents.size()));
  stream.flush();
  if (!stream) {
    return Status(StatusCode::persistence_io, "staged source write failed: " + path.string());
  }
  return path;
}

void Runtime::Impl::remove_staged_sources(CompilerSessionId session) {
  std::error_code ec;
  std::filesystem::remove_all(staged_sources_root() / session.to_string(), ec);
}

Result<Ref<SourceId>> Runtime::Impl::sources_add_inline(const std::string& name,
                                                       const std::string& contents) {
  return sources.add_from_bytes(name, contents, SourceLanguage::unknown, "");
}

namespace {

/// Remove the system-temporary scratch trees created for children whose
/// workspace path contained a space.
CRF_NODISCARD std::size_t remove_child_scratch() {
  std::error_code ec;
  const std::filesystem::path base = std::filesystem::temp_directory_path(ec);
  if (ec) return 0;
  const std::filesystem::path root = base / "compiler-runtime-fabric";
  if (!std::filesystem::exists(root, ec) || ec) return 0;
  std::size_t removed = 0;
  for (const std::filesystem::directory_entry& entry :
       std::filesystem::directory_iterator(root, ec)) {
    if (ec) break;
    std::error_code inner;
    std::filesystem::remove_all(entry.path(), inner);
    if (!inner) ++removed;
  }
  std::filesystem::remove(root, ec);
  return removed;
}

/// Digest of an already-registered output set, used to compare a late
/// completion with the one that committed.
CRF_NODISCARD Digest output_set_digest_from_artifacts(
    const ArtifactRegistry& artifacts, const std::vector<Ref<IntermediateArtifactId>>& outputs) {
  std::vector<std::string> entries;
  entries.reserve(outputs.size());
  for (const Ref<IntermediateArtifactId>& reference : outputs) {
    const IntermediateArtifact* artifact = artifacts.find(reference.id);
    if (artifact == nullptr) continue;
    entries.push_back(reference.id.to_string() + "|" + artifact->content.to_hex());
  }
  std::sort(entries.begin(), entries.end());
  CanonicalWriter writer;
  writer.u64(entries.size());
  for (const std::string& entry : entries) writer.text(entry);
  return Digest::of(writer.bytes());
}

CRF_NODISCARD FailureClass classify_execution_failure(const ExecutionReport& report) {
  if (report.executed) {
    switch (report.process.termination) {
      case ProcessTermination::crashed:
        return FailureClass::process_crash;
      case ProcessTermination::killed:
      case ProcessTermination::timed_out:
        return FailureClass::external_cancellation;
      case ProcessTermination::launch_failed:
        return FailureClass::transient_workspace_failure;
      case ProcessTermination::unknown:
        return FailureClass::unknown_outcome;
      case ProcessTermination::exited:
        break;
    }
  } else if (report.status == StatusCode::protocol_peer_closed ||
             report.status == StatusCode::protocol_io) {
    // The executor lost its worker. The physical outcome is not observable, so
    // the runtime treats it as an interruption rather than a compiler failure.
    return FailureClass::process_interrupted;
  } else if (report.status == StatusCode::unknown_outcome ||
             report.status == StatusCode::integrity_unproven) {
    return FailureClass::unknown_outcome;
  }
  return classify_status(report.status);
}

}  // namespace

Result<ExecutionReport> Runtime::Impl::execute_reserved(Reservation& reservation) {
  std::shared_ptr<const CompilerAdapter> adapter;
  {
    const std::lock_guard<std::recursive_mutex> guard(mutex);
    CompilerSession* session = find(reservation.session);
    if (session == nullptr) {
      return Status(StatusCode::not_found, "session disappeared during execution");
    }
    const PhaseRecord* phase = session->find_phase(reservation.phase);
    if (phase == nullptr) {
      return Status(StatusCode::not_found, "phase disappeared during execution");
    }
    if (phase->generation != reservation.phase_generation ||
        !(phase->active_invocation == reservation.invocation)) {
      return Status(StatusCode::stale_invocation,
                    "phase invocation is no longer the current one");
    }
    adapter = adapter_registry.find_by_name(session->adapter_name);
    if (adapter == nullptr) {
      return Status(StatusCode::unsupported,
                    "no adapter is registered for " + session->adapter_name);
    }
    const Result<PhaseExecutionRequest> request = build_request(*session, *phase, reservation);
    if (!request) return request.status();

    EnvironmentSpec environment = *request.value().environment;
    // Some compilers mishandle a temporary path that contains a space. The
    // workspace normally owns the phase's scratch directory; when that path has
    // a space and the system temporary directory does not, the child gets a
    // unique scratch directory under the system temporary directory instead.
    // The workspace still owns the phase's inputs and outputs either way.
    std::filesystem::path child_temp = reservation.workspace.temp_directory();
    if (child_temp.string().find(' ') != std::string::npos) {
      std::error_code ec;
      const std::filesystem::path system_temp = std::filesystem::temp_directory_path(ec);
      if (!ec && system_temp.string().find(' ') == std::string::npos) {
        const std::filesystem::path scratch =
            system_temp / "compiler-runtime-fabric" /
            (session->id.to_string() + "-" + reservation.phase.to_string() + "-g" +
             reservation.phase_generation.to_string());
        std::filesystem::create_directories(scratch, ec);
        if (!ec) child_temp = scratch;
      }
    }
    environment.temp_directory = child_temp;
    if (const VoidResult valid = environment.canonicalize(); !valid) return valid.status();

    const Result<std::vector<EnvironmentVariable>> block = build_process_environment(environment);
    if (!block) return block.status();

    const Result<InvocationSpec> built = adapter->build_invocation(request.value());
    if (!built) return built.status();
    InvocationSpec spec = built.value();
    spec.id = reservation.invocation.id;
    spec.generation = reservation.invocation.generation;
    spec.session = Ref<CompilerSessionId>{session->id, reservation.workspace.session_generation};
    spec.phase = Ref<CompilerPhaseId>{phase->id, phase->generation};
    spec.attempt_generation = phase->attempt_generation;
    spec.toolchain = session->toolchain;
    spec.target = session->target;
    spec.environment = session->environment;
    spec.policy = session->policy;
    spec.environment_variables = block.value();
    spec.working_directory = reservation.workspace.root;
    spec.adapter_name = session->adapter_name;

    // Bind the executable to a registered component identity. A launch whose
    // executable cannot be tied to a probed component is refused.
    const ToolchainIdentity* toolchain = toolchains.find(session->toolchain.id);
    const ComponentIdentity* component = nullptr;
    if (toolchain != nullptr) {
      for (const ComponentIdentity& candidate : toolchain->components) {
        if (canonical_path_key(candidate.file.canonical_path) == canonical_path_key(spec.executable)) {
          component = &candidate;
          break;
        }
      }
    }
    if (component == nullptr) {
      if (!spec.produced_executable) {
        return Status(StatusCode::component_not_found,
                      "invocation executable is not a probed toolchain component: " +
                          spec.executable.string());
      }
      // A produced executable is bound to an authoritative artifact of this
      // session, not to a toolchain component. The runtime proves both the
      // lineage binding and the bytes on disk.
      bool authoritative = false;
      for (const Ref<IntermediateArtifactId>& reference : phase->inputs) {
        const IntermediateArtifact* artifact = artifacts.find(reference.id);
        if (artifact == nullptr) continue;
        if (artifact->authority != AuthorityState::authoritative) continue;
        if (canonical_path_key(artifact->path) == canonical_path_key(spec.executable)) {
          authoritative = true;
          break;
        }
      }
      if (!authoritative) {
        return Status(StatusCode::not_authoritative,
                      "produced executable is not an authoritative artifact of this session: " +
                          spec.executable.string());
      }
      const Result<FileIdentity> observed = probe_file_identity(spec.executable, true);
      if (!observed) return observed.status();
      spec.executable_identity = observed.value();
    } else {
      spec.component = component->id;
      spec.component_generation = component->generation;
      spec.executable_identity = component->file;
    }

    const PolicyIdentity* policy = policies.find(session->policy.id);
    const TargetIdentity* target = targets.find(session->target.id);
    InvocationValidationContext context;
    context.workspace = &reservation.workspace;
    context.family = adapter->describe().family;
    context.target_architecture = target != nullptr ? target->spec.architecture : Architecture::unknown;
    if (policy != nullptr) context.forbidden_options = policy->spec.forbidden_options;
    context.require_component_identity = !spec.produced_executable;

    const Result<InvocationSpec> validated = validate_invocation(std::move(spec), context);
    if (!validated) {
      const StatusCode code = validated.code();
      const std::string detail = validated.status().message();
      PhaseRecord* mutable_phase = session->find_phase(reservation.phase);
      if (mutable_phase != nullptr) {
        mutable_phase->last_status = code;
        mutable_phase->failure = classify_status(code);
        mutable_phase->last_detail = detail;
      }
      return Status(code, detail);
    }
    reservation.invocation_spec = validated.value();

    Result<ProcessSpec> process = reservation.invocation_spec.to_process_spec();
    if (!process) return process.status();
    if (policy != nullptr) {
      process.value().timeout_millis = policy->spec.phase_timeout_millis;
      const std::size_t ceiling = std::max<std::size_t>(
          4096, std::min<std::size_t>(policy->spec.max_diagnostic_bytes_per_stream, kMaxCaptureBytes));
      process.value().max_capture_bytes = ceiling;
    }
    reservation.process_spec = process.value();

    PhaseRecord* mutable_phase = session->find_phase(reservation.phase);
    if (mutable_phase == nullptr) {
      return Status(StatusCode::not_found, "phase disappeared during preparation");
    }
    record_transition(*mutable_phase, PhaseState::running, "compiler process launched");
    session->updated_at_nanos = monotonic_nanos();
    const VoidResult persisted = persist(*session);
    if (!persisted) return persisted.status();
  }

  const std::shared_ptr<PhaseExecutor> current_executor = executor;
  if (current_executor == nullptr) {
    return Status(StatusCode::internal_error, "runtime has no executor configured");
  }
  const std::string phase_label = std::string(to_string(reservation.kind));
  Result<ExecutionReport> report = current_executor->execute(
      reservation.invocation_spec, reservation.process_spec, reservation.workspace, phase_label);
  if (!report) {
    ExecutionReport failure;
    failure.status = report.code();
    failure.detail = report.status().message();
    failure.workspace_root = reservation.workspace.root;
    failure.workspace_marker = reservation.workspace.marker_digest;
    return failure;
  }
  if (report.value().process.id.present()) {
    const std::lock_guard<std::recursive_mutex> guard(mutex);
    if (CompilerSession* session = find(reservation.session)) {
      if (PhaseRecord* phase = session->find_phase(reservation.phase)) {
        phase->active_process = report.value().process.id;
        phase->active_process_generation = report.value().process.generation;
      }
    }
  }
  return report;
}

VoidResult Runtime::Impl::record_execution(Reservation& reservation, const ExecutionReport& report) {
  const std::lock_guard<std::recursive_mutex> guard(mutex);
  CompilerSession* session = find(reservation.session);
  if (session == nullptr) {
    return Status(StatusCode::not_found, "session disappeared");
  }
  PhaseRecord* phase = session->find_phase(reservation.phase);
  if (phase == nullptr) {
    return Status(StatusCode::not_found, "phase disappeared");
  }
  if (phase->generation != reservation.phase_generation) {
    return Status(StatusCode::stale_phase_generation,
                  "phase generation moved while the execution was in flight");
  }
  if (!(phase->active_invocation == reservation.invocation)) {
    return Status(StatusCode::stale_invocation,
                  "invocation is no longer current for this phase generation");
  }

  PhaseAttempt* attempt = nullptr;
  for (PhaseAttempt& candidate : phase->attempts) {
    if (candidate.id == reservation.attempt) {
      attempt = &candidate;
      break;
    }
  }
  if (attempt == nullptr) {
    return Status(StatusCode::not_found, "attempt record is missing");
  }
  attempt->invocation = reservation.invocation;
  attempt->process_generation = report.process.generation;
  attempt->os_process_id = report.process.os_process_id;
  attempt->exit_code = static_cast<std::int32_t>(report.process.exit_code);
  attempt->started_at_nanos = report.process.started_at_nanos;
  attempt->finished_at_nanos = report.process.finished_at_nanos;
  attempt->status = report.status;
  attempt->detail = report.detail;

  const std::shared_ptr<const CompilerAdapter> adapter = adapter_registry.find_by_name(session->adapter_name);
  const std::string origin = adapter != nullptr ? adapter->describe().name : "compiler";
  DiagnosticSet set;
  set.invocation = reservation.invocation;
  set.phase = Ref<CompilerPhaseId>{phase->id, phase->generation};
  set.toolchain = session->toolchain;
  set.target = session->target;
  set.exit_code = static_cast<std::int32_t>(report.process.exit_code);
  set.process_crashed = report.process.termination == ProcessTermination::crashed;
  set.raw_stdout_bytes = report.process.capture.standard_output_bytes;
  set.raw_stderr_bytes = report.process.capture.standard_error_bytes;
  set.dropped_stdout_bytes = report.process.capture.dropped_standard_output_bytes;
  set.dropped_stderr_bytes = report.process.capture.dropped_standard_error_bytes;
  set.truncated = report.process.capture.truncated;
  set.raw_stdout_tail = report.process.capture.standard_output.size() > DiagnosticSet::kMaxRawTailBytes
                            ? report.process.capture.standard_output.substr(
                                  report.process.capture.standard_output.size() -
                                  DiagnosticSet::kMaxRawTailBytes)
                            : report.process.capture.standard_output;
  set.raw_stderr_tail = report.process.capture.standard_error.size() > DiagnosticSet::kMaxRawTailBytes
                            ? report.process.capture.standard_error.substr(
                                  report.process.capture.standard_error.size() -
                                  DiagnosticSet::kMaxRawTailBytes)
                            : report.process.capture.standard_error;
  set.entries = report.diagnostics;
  set.normalized = adapter != nullptr && has_capability(adapter->describe().capabilities,
                                                        AdapterCapability::structured_diagnostics);
  const std::size_t entry_ceiling = [&]() {
    const PolicyIdentity* policy = policies.find(session->policy.id);
    return policy != nullptr ? policy->spec.max_diagnostic_entries : DiagnosticSet::kMaxEntries;
  }();
  if (set.entries.size() > entry_ceiling) {
    set.entries.resize(entry_ceiling);
    set.truncated = true;
  }
  count_severities(set.entries, set.error_count, set.warning_count);

  const Result<Ref<DiagnosticSetId>> stored = diagnostics.add(std::move(set));
  if (!stored) return stored.status();
  phase->diagnostics = stored.value();
  last_outcomes[phase->id.value()] = report.process;
  (void)origin;

  const bool succeeded = report.executed && report.process.exited_zero();
  if (!succeeded) {
    phase->failure = classify_execution_failure(report);
    phase->last_status = report.status == StatusCode::ok ? StatusCode::process_exited_nonzero
                                                         : report.status;
    phase->last_detail = report.detail.empty() ? std::string("compiler execution did not succeed")
                                               : report.detail;
    attempt->terminal_state = PhaseState::failed;
    attempt->failure = phase->failure;
    record_transition(*phase, PhaseState::failed, phase->last_detail);
    session->updated_at_nanos = monotonic_nanos();
    const VoidResult persisted = persist(*session);
    if (!persisted) return persisted.status();
    return VoidResult{};
  }

  record_transition(*phase, PhaseState::produced, "compiler process exited 0; output is not yet authoritative");
  attempt->terminal_state = PhaseState::produced;

  // Register the reported outputs as candidates. Registration never grants
  // authority; only a commit can.
  for (const OutputDescriptor& output : report.outputs) {
    IntermediateArtifact artifact;
    artifact.format = output.format;
    artifact.path = output.path;
    artifact.content = output.content;
    artifact.size_bytes = output.size_bytes;
    artifact.producer_phase = Ref<CompilerPhaseId>{phase->id, phase->generation};
    artifact.producer_invocation = reservation.invocation;
    artifact.toolchain = session->toolchain;
    artifact.target = session->target;
    artifact.source = session->source;
    artifact.ir_generation = session->ir_generation;
    artifact.environment = session->environment;
    artifact.policy = session->policy;
    artifact.lineage_inputs = phase->inputs;
    artifact.state = output.exists ? ArtifactState::unknown : ArtifactState::stale;
    artifact.authority = AuthorityState::none;
    artifact.declared_digest = output.content;
    artifact.current = false;
    artifact.validation_detail = "registered as a candidate; not yet validated";
    const Result<Ref<IntermediateArtifactId>> registered = artifacts.register_artifact(std::move(artifact));
    if (!registered) return registered.status();
    phase->outputs.push_back(registered.value());
    session->intermediates.push_back(registered.value());
  }
  // The comparison key is the registered artifact set, not the reported
  // descriptor order, so a replayed equivalent completion is recognised.
  phase->committed_output_digest = output_set_digest_from_artifacts(artifacts, phase->outputs);
  record_transition(*phase, PhaseState::validating, "candidate outputs registered for validation");
  session->updated_at_nanos = monotonic_nanos();
  const VoidResult persisted = persist(*session);
  if (!persisted) return persisted.status();
  return VoidResult{};
}

Result<ValidationEvidence> Runtime::Impl::validate_phase_outputs(Reservation& reservation) {
  std::shared_ptr<const CompilerAdapter> adapter;
  PhaseExecutionRequest request;
  ProcessOutcome outcome;
  std::vector<OutputBinding> declared;
  {
    const std::lock_guard<std::recursive_mutex> guard(mutex);
    CompilerSession* session = find(reservation.session);
    if (session == nullptr) return Status(StatusCode::not_found, "session disappeared");
    PhaseRecord* phase = session->find_phase(reservation.phase);
    if (phase == nullptr) return Status(StatusCode::not_found, "phase disappeared");
    adapter = adapter_registry.find_by_name(session->adapter_name);
    if (adapter == nullptr) {
      return Status(StatusCode::unsupported, "no adapter is registered for this session");
    }
    const Result<PhaseExecutionRequest> built = build_request(*session, *phase, reservation);
    if (!built) return built.status();
    request = built.value();
    declared = reservation.invocation_spec.expected_outputs;
    const auto recorded = last_outcomes.find(phase->id.value());
    if (recorded != last_outcomes.end()) outcome = recorded->second;
    outcome.id = phase->active_process;
    outcome.generation = phase->active_process_generation;
    outcome.invocation = reservation.invocation;
  }
  OutputValidationRequest validation;
  validation.context = &request;
  validation.process = &outcome;
  validation.artifacts = &artifacts;
  validation.declared_outputs = declared;
  for (const Ref<IntermediateArtifactId>& reference : request.resolved_inputs) {
    (void)reference;
  }
  {
    const std::lock_guard<std::recursive_mutex> guard(mutex);
    CompilerSession* session = find(reservation.session);
    PhaseRecord* phase = session != nullptr ? session->find_phase(reservation.phase) : nullptr;
    if (phase != nullptr) validation.candidate_outputs = phase->outputs;
  }
  const Result<ValidationEvidence> evidence = adapter->validate_outputs(validation);
  if (!evidence) return evidence.status();

  const std::lock_guard<std::recursive_mutex> guard(mutex);
  CompilerSession* session = find(reservation.session);
  if (session == nullptr) return Status(StatusCode::not_found, "session disappeared");
  PhaseRecord* phase = session->find_phase(reservation.phase);
  if (phase == nullptr) return Status(StatusCode::not_found, "phase disappeared");
  for (const Ref<IntermediateArtifactId>& reference : phase->outputs) {
    const Result<VoidResult> applied = evidence.value().accepted
                                           ? artifacts.set_state(reference.id, ArtifactState::valid,
                                                                 evidence.value().detail)
                                           : artifacts.set_state(reference.id,
                                                                 evidence.value().state == ArtifactState::unknown
                                                                     ? ArtifactState::corrupt
                                                                     : evidence.value().state,
                                                                 evidence.value().detail);
    if (!applied) return applied.status();
  }
  if (!evidence.value().accepted) {
    phase->failure = classify_status(evidence.value().refusal);
    phase->last_status = evidence.value().refusal;
    phase->last_detail = evidence.value().detail;
    if (phase->attempts.size() > 0) {
      phase->attempts.back().terminal_state = PhaseState::failed;
      phase->attempts.back().failure = phase->failure;
    }
    record_transition(*phase, PhaseState::failed, evidence.value().detail);
    session->updated_at_nanos = monotonic_nanos();
    const VoidResult persisted = persist(*session);
    if (!persisted) return persisted.status();
    return evidence;
  }
  last_validation[phase->id.value()] = evidence.value();
  record_transition(*phase, PhaseState::commit_ready, "output validation accepted");
  session->updated_at_nanos = monotonic_nanos();
  const VoidResult persisted = persist(*session);
  if (!persisted) return persisted.status();
  return evidence;
}

Result<PhaseRunReport> Runtime::Impl::commit_reserved(Reservation& reservation,
                                                      const ExecutionReport& report) {
  const std::lock_guard<std::recursive_mutex> guard(mutex);
  CompilerSession* session = find(reservation.session);
  if (session == nullptr) {
    return Status(StatusCode::not_found, "session disappeared before commit");
  }
  PhaseRecord* phase = session->find_phase(reservation.phase);
  if (phase == nullptr) {
    return Status(StatusCode::not_found, "phase disappeared before commit");
  }
  if (phase->generation != reservation.phase_generation) {
    return Status(StatusCode::stale_phase_generation,
                  "phase generation moved before commit");
  }
  if (!(phase->active_invocation == reservation.invocation)) {
    return Status(StatusCode::stale_invocation, "invocation is no longer current");
  }
  if (phase->state != PhaseState::commit_ready) {
    return Status(StatusCode::illegal_transition,
                  std::string("phase is ") + std::string(to_string(phase->state)) +
                      ", not COMMIT_READY");
  }

  // Commit-time authority revalidation. The toolchain is re-probed from disk so
  // that a compiler replaced while the phase ran cannot commit.
  const std::shared_ptr<const CompilerAdapter> adapter =
      adapter_registry.find_by_name(session->adapter_name);
  Digest observed_toolchain_digest;
  if (adapter != nullptr) {
    const ToolchainIdentity* recorded = toolchains.find(session->toolchain.id);
    if (recorded != nullptr) {
      ToolchainProbeRequest probe;
      probe.family = recorded->family;
      probe.hash_components = true;
      // The re-probe repeats the probe inputs the session was created with.
      if (const TargetIdentity* target = targets.find(session->target.id)) {
        probe.target = target->spec;
      }
      const Result<ToolchainIdentity> observed = adapter->reprobe_toolchain(*recorded, probe);
      if (!observed) {
        stale_commit_total.fetch_add(1);
        phase->failure = FailureClass::invalid_toolchain;
        phase->last_status = StatusCode::integrity_unproven;
        phase->last_detail = "toolchain could not be re-probed at commit: " +
                             observed.status().message();
        record_transition(*phase, PhaseState::fenced, phase->last_detail);
        (void)artifacts.revoke_phase_outputs(phase->id, phase->generation, phase->last_detail);
        session->generation = session->generation.next();
        const VoidResult persisted = persist(*session);
        if (!persisted) return persisted.status();
        return Status(StatusCode::stale_toolchain_generation, phase->last_detail);
      }
      observed_toolchain_digest = observed.value().canonical_digest();
      const Result<ToolchainMutation> mutation = toolchains.refresh(observed.value());
      if (!mutation) return mutation.status();
      if (mutation.value().mutated) {
        evidence_log.record(EvidenceClass::real, "toolchain-mutation-at-commit",
                             mutation.value().detail, observed_toolchain_digest);
      }
    }
  }

  AuthorityObservation observation = observe(*session);
  observation.phase_generation = phase->generation;
  observation.attempt_generation = phase->attempt_generation;
  observation.lease = phase->lease;
  observation.lease_held = leases.is_held(phase->lease);
  // The session generation advances as a consequence of commits, including a
  // sibling phase's commit when phases run in parallel. It is bookkeeping rather
  // than an authority input, so it is not part of the commit test; the domains
  // that must still hold are the toolchain, target, environment, policy, source,
  // IR, compilation, attempt, phase, and lease generations.
  observation.session_generation = reservation.authority.session_generation;
  const AuthorityVerdict verdict = compare_authority(reservation.authority, observation);
  if (!authority_verdict_is_current(verdict)) {
    // The phase physically finished, but its output may not become current.
    stale_commit_total.fetch_add(1);
    const std::string detail = std::string("commit refused: ") + std::string(to_string(verdict));
    phase->failure = FailureClass::authority_invalidated;
    phase->last_status = to_status_code(verdict);
    phase->last_detail = detail;
    if (phase->attempts.size() > 0) {
      phase->attempts.back().terminal_state = PhaseState::fenced;
      phase->attempts.back().failure = phase->failure;
    }
    record_transition(*phase, PhaseState::fenced, detail);
    (void)artifacts.revoke_phase_outputs(phase->id, phase->generation, detail);
    (void)leases.revoke(phase->lease.id, detail);
    session->generation = session->generation.next();
    session->updated_at_nanos = monotonic_nanos();
    ProvenanceRecord record;
    record.kind = "phase-commit-refused";
    record.session = Ref<CompilerSessionId>{session->id, session->generation};
    record.phase = Ref<CompilerPhaseId>{phase->id, phase->generation};
    record.invocation = reservation.invocation;
    record.toolchain = session->toolchain;
    record.target = session->target;
    record.environment = session->environment;
    record.policy = session->policy;
    record.source = session->source;
    record.inputs = phase->inputs;
    record.outputs = phase->outputs;
    record.adapter = session->adapter_name;
    record.verdict = verdict;
    record.detail = detail;
    (void)provenance.append(record);
    const VoidResult persisted = persist(*session);
    if (!persisted) return persisted.status();
    PhaseRunReport outcome;
    outcome.phase = Ref<CompilerPhaseId>{phase->id, phase->generation};
    outcome.state = PhaseState::fenced;
    outcome.status = to_status_code(verdict);
    outcome.failure = FailureClass::authority_invalidated;
    outcome.authority = verdict;
    outcome.detail = detail;
    outcome.diagnostics = phase->diagnostics;
    outcome.invocation = reservation.invocation;
    outcome.outputs = phase->outputs;
    outcome.compiler_nanos = report.process.duration_nanos();
    return outcome;
  }

  // Provenance is written before the state that cites it. An authoritative
  // artifact whose provenance was not durable would be unexplainable after a
  // restart, so the record is appended and attached first, then persisted with
  // the session.
  ProvenanceRecord provenance_record;
  provenance_record.kind = "phase-committed";
  provenance_record.session = Ref<CompilerSessionId>{session->id, session->generation};
  provenance_record.phase = Ref<CompilerPhaseId>{phase->id, phase->generation};
  provenance_record.invocation = reservation.invocation;
  provenance_record.toolchain = session->toolchain;
  provenance_record.target = session->target;
  provenance_record.environment = session->environment;
  provenance_record.policy = session->policy;
  provenance_record.source = session->source;
  provenance_record.inputs = phase->inputs;
  provenance_record.outputs = phase->outputs;
  provenance_record.adapter = session->adapter_name;
  provenance_record.verdict = AuthorityVerdict::valid;
  provenance_record.detail = "phase committed with current authority";
  const ProvenanceRecord& stored_provenance = provenance.append(provenance_record);
  for (const Ref<IntermediateArtifactId>& reference : phase->outputs) {
    if (IntermediateArtifact* artifact = artifacts.find_mutable(reference.id)) {
      artifact->provenance = stored_provenance.id;
    }
  }

  // Publish: build the committed projection, persist it, and only then make it
  // visible. A failed persist leaves the previous state authoritative.
  CompilerSession committed = *session;
  PhaseRecord* committed_phase = committed.find_phase(phase->id);
  committed_phase->commit = CommitId::from_value(commit_ids.next().value());
  committed_phase->committed_at_nanos = monotonic_nanos();
  committed_phase->committed_output_digest = phase->committed_output_digest;
  if (committed_phase->attempts.size() > 0) {
    committed_phase->attempts.back().terminal_state = PhaseState::committed;
  }
  record_transition(*committed_phase, PhaseState::committed,
                    "authority revalidated and outputs committed");
  for (const Ref<IntermediateArtifactId>& reference : committed_phase->outputs) {
    const Result<VoidResult> applied =
        artifacts.set_authority(reference.id, AuthorityState::authoritative);
    if (!applied) {
      return Status(StatusCode::internal_error, "committed artifact could not be made authoritative");
    }
  }
  committed.generation = committed.generation.next();
  committed.updated_at_nanos = monotonic_nanos();
  // A session is complete only once every mandatory phase has committed and a
  // final candidate exists. The candidate may be registered by an earlier phase
  // than the last one in the plan, so this is re-evaluated on every commit.
  if (committed.candidate_present && committed.all_mandatory_committed()) {
    committed.state = SessionState::committed;
  }

  FinalCandidate candidate;
  bool candidate_ready = false;
  if (committed_phase->kind == PhaseKind::finalize || committed_phase->kind == PhaseKind::link ||
      committed_phase->id == committed.plan.topological_order().back()) {
    for (const Ref<IntermediateArtifactId>& reference : committed_phase->outputs) {
      const IntermediateArtifact* artifact = artifacts.find(reference.id);
      if (artifact == nullptr) continue;
      if (artifact->format != ObjectFormat::coff_image && artifact->format != ObjectFormat::elf) {
        continue;
      }
      candidate.id = FinalArtifactId::from_value(final_ids.next().value());
      candidate.generation = FinalArtifactGeneration::initial();
      candidate.compilation = committed.compilation;
      candidate.compilation_generation = committed.compilation_generation;
      candidate.attempt_generation = committed.attempt_generation;
      candidate.session = Ref<CompilerSessionId>{committed.id, committed.generation};
      candidate.toolchain = committed.toolchain;
      candidate.target = committed.target;
      candidate.environment = committed.environment;
      candidate.policy = committed.policy;
      candidate.source = committed.source;
      candidate.ir_generation = committed.ir_generation;
      candidate.format = artifact->format;
      candidate.path = artifact->path;
      candidate.content = artifact->content;
      candidate.size_bytes = artifact->size_bytes;
      candidate.lineage = committed.intermediates;
      std::sort(candidate.lineage.begin(), candidate.lineage.end(),
                [](const Ref<IntermediateArtifactId>& a, const Ref<IntermediateArtifactId>& b) {
                  return a.id < b.id;
                });
      candidate.complete_lineage = true;
      candidate.registered_at_nanos = monotonic_nanos();
      // Cite the checks that justified this candidate so that the artifact
      // carries the evidence, not just a claim.
      const auto validation = last_validation.find(committed_phase->id.value());
      if (validation != last_validation.end()) {
        for (const std::string& check : validation->second.checks) {
          candidate.validation_evidence.push_back(
              evidence_log
                  .record_ref(EvidenceClass::real, "candidate-validation-check", check,
                              Digest::of(check))
                  .id);
        }
        if (!validation->second.detail.empty()) {
          candidate.validation_evidence.push_back(
              evidence_log
                  .record_ref(EvidenceClass::real, "candidate-validation-detail",
                              validation->second.detail, Digest::of(validation->second.detail))
                  .id);
        }
      }
      candidate_ready = true;
      break;
    }
  }
  if (candidate_ready) {
    CanonicalWriter writer;
    for (const Ref<IntermediateArtifactId>& reference : candidate.lineage) {
      const IntermediateArtifact* artifact = artifacts.find(reference.id);
      if (artifact != nullptr) writer.text(artifact->canonical_digest().to_hex());
    }
    candidate.lineage_digest = Digest::of(writer.bytes());
    committed.candidate = candidate;
    committed.candidate_present = true;
    if (committed.all_mandatory_committed()) committed.state = SessionState::committed;
  }

  const VoidResult persisted = persist(committed);
  if (!persisted) return persisted.status();
  *session = committed;

  const ProvenanceRecord* live_provenance = provenance.find(stored_provenance.id);
  PhaseRecord* live_phase = session->find_phase(phase->id);
  live_phase->outputs = phase->outputs;
  for (const Ref<IntermediateArtifactId>& reference : live_phase->outputs) {
    if (IntermediateArtifact* artifact = artifacts.find_mutable(reference.id)) {
      if (live_provenance != nullptr) artifact->provenance = live_provenance->id;
      artifact->generation = artifact->generation.next();
    }
  }
  (void)leases.revoke(live_phase->lease.id, "phase committed");
  commit_total.fetch_add(1);

  PhaseRunReport outcome;
  outcome.phase = Ref<CompilerPhaseId>{live_phase->id, live_phase->generation};
  outcome.state = PhaseState::committed;
  outcome.status = StatusCode::ok;
  outcome.failure = FailureClass::none;
  outcome.authority = AuthorityVerdict::valid;
  outcome.diagnostics = live_phase->diagnostics;
  outcome.invocation = reservation.invocation;
  outcome.process = report.process.id;
  outcome.outputs = live_phase->outputs;
  outcome.compiler_nanos = report.process.duration_nanos();
  outcome.detail = candidate_ready ? "phase committed and final candidate registered"
                                   : "phase committed";
  return outcome;
}

// ---------------------------------------------------------------------------
// Public runtime surface.
// ---------------------------------------------------------------------------
Runtime::Runtime() = default;

Runtime::~Runtime() {
  if (impl_ != nullptr) {
    const VoidResult stopped = shutdown();
    (void)stopped;
  }
}

Result<std::unique_ptr<Runtime>> Runtime::create(RuntimeOptions options) {
  if (options.state_directory.empty()) {
    return Status(StatusCode::invalid_argument, "state directory is not configured");
  }
  if (options.workspace_root.empty()) {
    options.workspace_root = options.state_directory / "workspaces";
  }
  if (options.workspace.base_directory.empty()) {
    options.workspace.base_directory = options.workspace_root;
  }
  options.state_directory = normalize_path(options.state_directory);
  options.workspace_root = normalize_path(options.workspace_root);
  if (!options.workspace.base_directory.empty()) {
    options.workspace.base_directory = normalize_path(options.workspace.base_directory);
  }
  if (!options.persistence.directory.empty()) {
    options.persistence.directory = normalize_path(options.persistence.directory);
  }
  std::error_code ec;
  std::filesystem::create_directories(options.state_directory, ec);
  if (ec) {
    return Status(StatusCode::permission_denied,
                  "state directory could not be created: " + ec.message());
  }
  std::filesystem::create_directories(options.workspace.base_directory, ec);
  if (ec) {
    return Status(StatusCode::permission_denied,
                  "workspace root could not be created: " + ec.message());
  }

  auto runtime = std::unique_ptr<Runtime>(new Runtime());
  runtime->impl_ = std::make_unique<Runtime::Impl>(options);
  Runtime::Impl& impl = *runtime->impl_;

  if (options.enable_persistence) {
    PersistenceOptions persistence_options = options.persistence;
    if (persistence_options.directory.empty()) persistence_options.directory = options.state_directory;
    if (persistence_options.name.empty()) persistence_options.name = options.runtime_name;
    Result<std::unique_ptr<PersistenceStore>> store = PersistenceStore::open(persistence_options);
    if (!store) return store.status();
    impl.persistence = std::move(store.value());

    const Result<DurableState> previous = impl.persistence->load();
    if (!previous) return previous.status();
    if (!previous.value().trustworthy()) {
      return Status(StatusCode::persistence_corrupt,
                    "existing durable state is not trustworthy: " + previous.value().detail);
    }
    impl.epoch = previous.value().runtime_epoch + 1;
    const Result<std::uint64_t> epoch_sequence = impl.persistence->record_epoch(impl.epoch);
    if (!epoch_sequence) return epoch_sequence.status();

    if (options.recover_on_load) {
      // Replay: the last bundle written for a session identity wins.
      std::unordered_map<std::uint64_t, SessionBundle> latest;
      std::vector<std::uint64_t> order;
      for (const JournalRecord& record : previous.value().records) {
        // Only records that carry a session projection are decoded as one; every
        // other record kind is informational and is not a defect.
        if (record.kind != RecordKind::session_state_changed &&
            record.kind != RecordKind::session_created &&
            record.kind != RecordKind::phase_committed &&
            record.kind != RecordKind::session_retired) {
          continue;
        }
        const Result<SessionBundle> bundle = decode_session_bundle(record.payload);
        if (!bundle) {
          impl.persisted_defects += 1;
          continue;
        }
        const std::uint64_t key = bundle.value().session.id.value();
        if (latest.find(key) == latest.end()) order.push_back(key);
        latest[key] = bundle.value();
      }
      std::sort(order.begin(), order.end());
      for (const std::uint64_t key : order) {
        SessionBundle& bundle = latest[key];
        // Reload the authority the session was bound to before adopting it.
        if (!bundle.toolchain.empty()) {
          const Result<ToolchainIdentity> identity = decode_toolchain(bundle.toolchain);
          if (!identity) return identity.status();
          const Result<Ref<ToolchainId>> registered =
              impl.toolchains.register_toolchain_as(identity.value().id, identity.value());
          if (!registered) return registered.status();
        }
        if (!bundle.target.empty()) {
          const Result<TargetIdentity> identity = decode_target_identity(bundle.target);
          if (!identity) return identity.status();
          const Result<Ref<TargetId>> registered =
              impl.targets.intern_as(identity.value().id, identity.value().spec);
          if (!registered) return registered.status();
        }
        if (!bundle.environment.empty()) {
          const Result<EnvironmentIdentity> identity = decode_environment_identity(bundle.environment);
          if (!identity) return identity.status();
          const Result<Ref<EnvironmentId>> registered =
              impl.environments.intern_as(identity.value().id, identity.value().spec);
          if (!registered) return registered.status();
        }
        if (!bundle.policy.empty()) {
          const Result<PolicyIdentity> identity = decode_policy_identity(bundle.policy);
          if (!identity) return identity.status();
          const Result<Ref<PolicyId>> registered =
              impl.policies.intern_as(identity.value().id, identity.value().spec);
          if (!registered) return registered.status();
        }
        for (const std::string& encoded : bundle.sources) {
          if (encoded.empty()) continue;
          const Result<SourceUnit> unit = decode_source_unit(encoded);
          if (!unit) return unit.status();
          const Result<Ref<SourceId>> registered = impl.sources.add_as(unit.value().id, unit.value());
          if (!registered) return registered.status();
        }
        for (const IntermediateArtifact& artifact : bundle.artifacts) {
          const Result<Ref<IntermediateArtifactId>> registered =
              impl.artifacts.register_artifact_as(artifact.id, artifact);
          if (!registered) return registered.status();
        }
        for (const std::string& encoded : bundle.provenance) {
          if (encoded.empty()) continue;
          const Result<ProvenanceRecord> record = decode_provenance(encoded);
          if (!record) return record.status();
          (void)impl.provenance.append_as(record.value());
        }
        for (const DiagnosticSet& set : bundle.diagnostics) {
          const Result<Ref<DiagnosticSetId>> registered = impl.diagnostics.add_as(set.id, set);
          if (!registered) return registered.status();
        }
        CompilerSession session = bundle.session;
        impl.session_ids.observe(session.id);
        const VoidResult fenced =
            impl.fence_all_in_flight(session, "runtime restart fenced in-flight phase authority");
        if (!fenced) return fenced.status();
        session.epoch = EpochId::from_value(impl.epoch);
        if (session.state != SessionState::committed && session.state != SessionState::retired) {
          session.state = SessionState::recovering;
          session.recovery_state = RecoveryState::required;
        }
        session.generation = session.generation.next();
        session.updated_at_nanos = monotonic_nanos();
        (void)impl.cancel_flag(session.id);
        const VoidResult persisted = impl.persist(session);
        if (!persisted) return persisted.status();
        impl.sessions.emplace(session.id.value(), std::move(session));
      }
      if (!order.empty()) {
        impl.evidence_log.record(EvidenceClass::real, "durable-state-recovered",
                                 std::to_string(order.size()) + " session(s) recovered at epoch " +
                                     std::to_string(impl.epoch));
      }
    }
  } else {
    impl.epoch = 1;
  }

  if (options.register_builtin_adapters) {
    if (std::shared_ptr<const CompilerAdapter> msvc = make_msvc_adapter()) {
      impl.adapter_registry.add(std::move(msvc));
    }
    if (std::shared_ptr<const CompilerAdapter> cuda = make_cuda_adapter()) {
      impl.adapter_registry.add(std::move(cuda));
    }
    impl.adapter_registry.add(
        make_synthetic_adapter(ToolchainFamily::hipcc, "AMD ROCm hipcc (modelled)"));
    impl.adapter_registry.add(
        make_synthetic_adapter(ToolchainFamily::intel_icx, "Intel oneAPI icx (modelled)"));
    impl.adapter_registry.add(make_synthetic_adapter(ToolchainFamily::gcc, "GNU gcc (modelled)"));
    impl.adapter_registry.add(make_synthetic_adapter(ToolchainFamily::clang, "LLVM clang (modelled)"));
  }

  impl.executor = make_local_executor(*runtime);
  return runtime;
}

ToolchainRegistry& Runtime::toolchains() noexcept { return impl_->toolchains; }
const ToolchainRegistry& Runtime::toolchains() const noexcept { return impl_->toolchains; }
TargetRegistry& Runtime::targets() noexcept { return impl_->targets; }
const TargetRegistry& Runtime::targets() const noexcept { return impl_->targets; }
EnvironmentRegistry& Runtime::environments() noexcept { return impl_->environments; }
const EnvironmentRegistry& Runtime::environments() const noexcept { return impl_->environments; }
const PolicyRegistry& Runtime::policies() const noexcept { return impl_->policies; }
PolicyRegistry& Runtime::policies() noexcept { return impl_->policies; }
SourceRegistry& Runtime::sources() noexcept { return impl_->sources; }
ArtifactRegistry& Runtime::artifacts() noexcept { return impl_->artifacts; }
const ArtifactRegistry& Runtime::artifacts() const noexcept { return impl_->artifacts; }
DiagnosticStore& Runtime::diagnostics() noexcept { return impl_->diagnostics; }
const DiagnosticStore& Runtime::diagnostics() const noexcept { return impl_->diagnostics; }
ProvenanceLog& Runtime::provenance() noexcept { return impl_->provenance; }
const ProvenanceLog& Runtime::provenance() const noexcept { return impl_->provenance; }
LeaseTable& Runtime::leases() noexcept { return impl_->leases; }
const LeaseTable& Runtime::leases() const noexcept { return impl_->leases; }
ProcessSupervisor& Runtime::processes() noexcept { return impl_->processes; }
const ProcessSupervisor& Runtime::processes() const noexcept { return impl_->processes; }
AdapterRegistry& Runtime::adapters() noexcept { return impl_->adapter_registry; }
const AdapterRegistry& Runtime::adapters() const noexcept { return impl_->adapter_registry; }
EvidenceLog& Runtime::evidence() noexcept { return impl_->evidence_log; }
const EvidenceLog& Runtime::evidence() const noexcept { return impl_->evidence_log; }
PersistenceStore* Runtime::persistence() noexcept { return impl_->persistence.get(); }
const RuntimeOptions& Runtime::options() const noexcept { return impl_->options; }
std::uint64_t Runtime::epoch() const noexcept { return impl_->epoch; }
bool Runtime::is_shutting_down() const noexcept { return impl_->shutting_down.load(); }
std::uint64_t Runtime::commit_count() const noexcept { return impl_->commit_total.load(); }
std::uint64_t Runtime::stale_commit_count() const noexcept { return impl_->stale_commit_total.load(); }
std::shared_ptr<PhaseExecutor> Runtime::executor() const noexcept { return impl_->executor; }

void Runtime::set_executor(std::shared_ptr<PhaseExecutor> executor) {
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  impl_->executor = std::move(executor);
}

std::shared_ptr<std::atomic<bool>> Runtime::session_cancel_flag(CompilerSessionId session) const {
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  return impl_->cancel_flag(session);
}

Result<ToolchainIdentity> Runtime::probe_toolchain(ToolchainFamily family,
                                                   const ToolchainProbeRequest& request) const {
  const std::shared_ptr<const CompilerAdapter> adapter = impl_->adapter_registry.find(family);
  if (adapter == nullptr) {
    return Status(StatusCode::unsupported,
                  std::string("no adapter is registered for toolchain family ") +
                      std::string(to_string(family)));
  }
  ToolchainProbeRequest effective = request;
  if (effective.family == ToolchainFamily::unknown) effective.family = family;
  return adapter->probe_toolchain(effective);
}

Result<Ref<ToolchainId>> Runtime::discover_toolchain(ToolchainFamily family,
                                                     const ToolchainProbeRequest& request) {
  Result<ToolchainIdentity> probed = probe_toolchain(family, request);
  if (!probed) return probed.status();
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  const Result<Ref<ToolchainId>> registered = impl_->toolchains.register_toolchain(probed.value());
  if (!registered) return registered.status();
  impl_->evidence_log.record(probed.value().evidence_class, "toolchain-discovered",
                             probed.value().describe(), probed.value().evidence_digest);
  return registered;
}

Result<ToolchainMutation> Runtime::refresh_toolchain(ToolchainId id) {
  const ToolchainIdentity* recorded = impl_->toolchains.find(id);
  if (recorded == nullptr) {
    return Status(StatusCode::toolchain_not_found, "toolchain is not registered: " + id.to_string());
  }
  const std::shared_ptr<const CompilerAdapter> adapter =
      impl_->adapter_registry.find(recorded->family);
  if (adapter == nullptr) {
    return Status(StatusCode::unsupported, "no adapter is registered for this toolchain family");
  }
  ToolchainProbeRequest request;
  request.family = recorded->family;
  request.hash_components = true;
  const Result<ToolchainIdentity> observed = adapter->reprobe_toolchain(*recorded, request);
  if (!observed) return observed.status();
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  const Result<ToolchainMutation> mutation = impl_->toolchains.refresh(observed.value());
  if (!mutation) return mutation.status();
  if (mutation.value().mutated) {
    impl_->evidence_log.record(EvidenceClass::real, "toolchain-mutated", mutation.value().detail,
                               observed.value().evidence_digest);
  }
  return mutation;
}

Result<ToolchainMutation> Runtime::invalidate_toolchain(ToolchainId id, std::string reason) {
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  const Result<ToolchainMutation> mutation = impl_->toolchains.invalidate(id, std::move(reason));
  if (!mutation) return mutation.status();
  impl_->evidence_log.record(EvidenceClass::real, "toolchain-invalidated", mutation.value().detail);
  return mutation;
}

Result<ToolchainMutation> Runtime::apply_toolchain_observation(const ToolchainIdentity& observed) {
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  const Result<ToolchainMutation> mutation = impl_->toolchains.refresh(observed);
  if (!mutation) return mutation.status();
  if (mutation.value().mutated) {
    impl_->evidence_log.record(EvidenceClass::real, "toolchain-observed-changed",
                               mutation.value().detail, observed.evidence_digest);
  }
  return mutation;
}

Result<Ref<ToolchainId>> Runtime::register_synthetic_toolchain(ToolchainFamily family,
                                                              std::string display_name,
                                                              TargetSpec target) {
  std::shared_ptr<const CompilerAdapter> adapter = impl_->adapter_registry.find(family);
  if (adapter == nullptr) {
    impl_->adapter_registry.add(make_synthetic_adapter(family, display_name));
    adapter = impl_->adapter_registry.find(family);
  }
  if (adapter == nullptr) {
    return Status(StatusCode::unsupported, "no synthetic adapter could be constructed");
  }
  ToolchainProbeRequest request;
  request.family = family;
  request.target = target;
  const Result<ToolchainIdentity> probed = adapter->probe_toolchain(request);
  if (!probed) return probed.status();
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  return impl_->toolchains.register_toolchain(probed.value());
}

Result<Ref<CompilerSessionId>> Runtime::create_session(const CompileRequest& request) {
  return impl_->create_session_impl(request);
}

Result<Ref<CompilerSessionId>> Runtime::adopt_session(CompilerSession session) {
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  if (!session.id.present()) {
    return Status(StatusCode::invalid_identity, "adopted session has no identity");
  }
  if (impl_->find(session.id) != nullptr) {
    return Status(StatusCode::already_exists, "session identity is already registered");
  }
  impl_->session_ids.observe(session.id);
  const VoidResult fenced =
      impl_->fence_all_in_flight(session, "session adoption fenced in-flight authority");
  if (!fenced) return fenced.status();
  session.epoch = EpochId::from_value(impl_->epoch);
  session.generation = session.generation.next();
  session.updated_at_nanos = monotonic_nanos();
  if (session.state != SessionState::committed && session.state != SessionState::retired) {
    session.state = SessionState::recovering;
    session.recovery_state = RecoveryState::required;
  }
  (void)impl_->cancel_flag(session.id);
  const VoidResult persisted = impl_->persist(session);
  if (!persisted) return persisted.status();
  const CompilerSessionId id = session.id;
  impl_->sessions.emplace(id.value(), std::move(session));
  return Ref<CompilerSessionId>{id, CompilerSessionGeneration{}};
}

Result<PhaseRunReport> Runtime::run_phase(CompilerSessionId session, CompilerPhaseId phase) {
  return impl_->run_phase_impl(session, phase, false);
}

Result<PhaseRunReport> Runtime::retry_phase(CompilerSessionId session, CompilerPhaseId phase) {
  RetryDecision decision;
  {
    const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
    CompilerSession* found = impl_->find(session);
    if (found == nullptr) {
      return Status(StatusCode::not_found, "session is not registered");
    }
    PhaseRecord* record = found->find_phase(phase);
    if (record == nullptr) {
      return Status(StatusCode::not_found, "phase is not registered");
    }
    const PolicyIdentity* policy = impl_->policies.find(found->policy.id);
    decision = evaluate_retry(*record, policy != nullptr ? policy->spec : PolicySpec{},
                              found->session_retries_used);
    if (!decision.legal) {
      PhaseRunReport report = impl_->phase_status_report(session, phase);
      report.retry = decision;
      report.status = decision.refusal == StatusCode::ok ? StatusCode::retry_not_permitted
                                                         : decision.refusal;
      report.detail = decision.reason;
      return report;
    }
    found->session_retries_used += 1;
  }
  Result<PhaseRunReport> report = impl_->run_phase_impl(session, phase, true);
  if (report) report.value().retry = decision;
  return report;
}

Result<CompileOutcome> Runtime::run_session(CompilerSessionId session) {
  return impl_->run_session_impl(session);
}

VoidResult Runtime::cancel_phase(CompilerSessionId session, CompilerPhaseId phase,
                                 std::string reason) {
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  CompilerSession* found = impl_->find(session);
  if (found == nullptr) {
    return Status(StatusCode::not_found, "session is not registered");
  }
  PhaseRecord* record = found->find_phase(phase);
  if (record == nullptr) {
    return Status(StatusCode::not_found, "phase is not registered");
  }
  if (record->state == PhaseState::committed) {
    return Status(StatusCode::duplicate_completion,
                  "a committed phase cannot be cancelled; retire the session instead");
  }
  if (record->active_invocation.id.present() && impl_->executor != nullptr) {
    const VoidResult cancelled = impl_->executor->cancel(record->active_invocation, reason);
    (void)cancelled;
  }
  if (record->active_process.present()) {
    const VoidResult terminated =
        impl_->processes.terminate(record->active_process, record->active_process_generation, reason);
    (void)terminated;
  }
  (void)impl_->leases.revoke(record->lease.id, reason);
  (void)impl_->artifacts.revoke_phase_outputs(record->id, record->generation, reason);
  if (phase_state_retains_commit_authority(record->state)) {
    if (!record->attempts.empty()) {
      record->attempts.back().terminal_state = PhaseState::cancelled;
      record->attempts.back().failure = FailureClass::external_cancellation;
    }
    record->failure = FailureClass::external_cancellation;
    record->last_status = StatusCode::cancelled;
    record->last_detail = reason;
    impl_->record_transition(*record, PhaseState::cancelled, reason);
  }
  record->active_invocation = Ref<InvocationId>{};
  found->generation = found->generation.next();
  found->updated_at_nanos = monotonic_nanos();
  const VoidResult persisted = impl_->persist(*found);
  if (!persisted) return persisted.status();
  impl_->evidence_log.record(EvidenceClass::real, "phase-cancelled",
                             "phase " + phase.to_string() + " cancelled: " + reason);
  return VoidResult{};
}

VoidResult Runtime::cancel_session(CompilerSessionId session, std::string reason) {
  {
    const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
    const std::shared_ptr<std::atomic<bool>> flag = impl_->cancel_flag(session);
    flag->store(true);
  }
  std::vector<CompilerPhaseId> phases;
  {
    const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
    CompilerSession* found = impl_->find(session);
    if (found == nullptr) {
      return Status(StatusCode::not_found, "session is not registered");
    }
    phases = found->plan.topological_order();
  }
  for (const CompilerPhaseId phase : phases) {
    const VoidResult cancelled = cancel_phase(session, phase, reason);
    (void)cancelled;
  }
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  CompilerSession* found = impl_->find(session);
  if (found == nullptr) {
    return Status(StatusCode::not_found, "session is not registered");
  }
  found->state = SessionState::cancelled;
  found->failure_detail = reason;
  found->generation = found->generation.next();
  found->updated_at_nanos = monotonic_nanos();
  return impl_->persist(*found);
}

VoidResult Runtime::retire_session(CompilerSessionId session, std::string reason) {
  {
    const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
    CompilerSession* found = impl_->find(session);
    if (found == nullptr) {
      return Status(StatusCode::not_found, "session is not registered");
    }
    const std::shared_ptr<std::atomic<bool>> flag = impl_->cancel_flag(session);
    flag->store(true);
    for (const CompilerPhaseId id : found->plan.topological_order()) {
      PhaseRecord* record = found->find_phase(id);
      if (record == nullptr) continue;
      (void)impl_->leases.revoke(record->lease.id, reason);
      if (record->active_process.present()) {
        const VoidResult terminated = impl_->processes.terminate(
            record->active_process, record->active_process_generation, reason);
        (void)terminated;
      }
      if (record->state != PhaseState::retired) {
        impl_->record_transition(*record, PhaseState::retired, reason);
      }
    }
    found->state = SessionState::retired;
    found->failure_detail = reason;
    found->generation = found->generation.next();
    found->updated_at_nanos = monotonic_nanos();
    const VoidResult persisted = impl_->persist(*found);
    if (!persisted) return persisted.status();
  }
  (void)impl_->workspaces.cleanup_all();
  return VoidResult{};
}

Result<PhaseRunReport> Runtime::report_output(CompilerSessionId session, CompilerPhaseId phase,
                                              CompilerPhaseGeneration phase_generation,
                                              Ref<InvocationId> invocation,
                                              std::vector<OutputDescriptor> outputs,
                                              const ProcessOutcome& process) {
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  CompilerSession* found = impl_->find(session);
  if (found == nullptr) {
    return Status(StatusCode::not_found, "session is not registered");
  }
  PhaseRecord* record = found->find_phase(phase);
  if (record == nullptr) {
    return Status(StatusCode::not_found, "phase is not registered");
  }
  if (record->generation != phase_generation) {
    return Status(StatusCode::stale_phase_generation,
                  "reported phase generation is not the current one");
  }
  if (!(record->active_invocation == invocation)) {
    return Status(StatusCode::stale_invocation,
                  "reported invocation is not the current one for this phase generation");
  }
  Reservation reservation;
  reservation.session = session;
  reservation.phase = phase;
  reservation.phase_generation = phase_generation;
  reservation.invocation = invocation;
  reservation.attempt = record->attempts.empty() ? AttemptId{} : record->attempts.back().id;
  reservation.kind = record->kind;
  reservation.authority = authority_from_session(*found, *record);

  ExecutionReport report;
  report.executed = process.termination == ProcessTermination::exited ||
                    process.termination == ProcessTermination::crashed;
  report.process = process;
  report.process.invocation = invocation;
  report.outputs = std::move(outputs);
  report.status = process.status.code();
  report.detail = process.status.message();
  const VoidResult recorded = impl_->record_execution(reservation, report);
  if (!recorded) return recorded.status();
  return impl_->phase_status_report(session, phase);
}

Result<PhaseRunReport> Runtime::commit_phase(CompilerSessionId session, CompilerPhaseId phase,
                                             CompilerPhaseGeneration phase_generation,
                                             Ref<InvocationId> invocation) {
  Reservation reservation;
  ExecutionReport report;
  {
    const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
    CompilerSession* found = impl_->find(session);
    if (found == nullptr) {
      return Status(StatusCode::not_found, "session is not registered");
    }
    PhaseRecord* record = found->find_phase(phase);
    if (record == nullptr) {
      return Status(StatusCode::not_found, "phase is not registered");
    }
    // Staleness is decided before duplication: a completion that names a stale
    // generation or invocation is not a duplicate of the current one.
    if (record->generation != phase_generation) {
      return Status(StatusCode::stale_phase_generation,
                    "commit request names a phase generation that is not current");
    }
    if (!(record->active_invocation == invocation)) {
      return Status(StatusCode::stale_invocation,
                    "commit request names an invocation that is not current");
    }
    if (record->state == PhaseState::committed) {
      // Duplicate equivalent completion returns the existing authoritative
      // result; a divergent completion is refused.
      if (!record->committed_output_digest.zero() &&
          record->committed_output_digest ==
              output_set_digest_from_artifacts(impl_->artifacts, record->outputs)) {
        PhaseRunReport existing = impl_->phase_status_report(session, phase);
        existing.status = StatusCode::duplicate_completion;
        existing.detail =
            "an equivalent completion already committed this phase generation; the existing "
            "authoritative result is returned";
        return existing;
      }
      return Status(StatusCode::divergent_completion,
                    "a different completion already committed this phase generation");
    }
    if (record->state != PhaseState::validating && record->state != PhaseState::commit_ready) {
      return Status(StatusCode::illegal_transition,
                    std::string("phase is ") + std::string(to_string(record->state)) +
                        " and cannot commit");
    }
    reservation.session = session;
    reservation.phase = phase;
    reservation.phase_generation = phase_generation;
    reservation.invocation = invocation;
    reservation.attempt = record->attempts.empty() ? AttemptId{} : record->attempts.back().id;
    reservation.kind = record->kind;
    reservation.authority = authority_from_session(*found, *record);
    report.process.invocation = invocation;
    report.process.termination = ProcessTermination::exited;
    report.process.exit_code = 0;
  }
  const Result<ValidationEvidence> evidence = impl_->validate_phase_outputs(reservation);
  if (!evidence) return evidence.status();
  if (!evidence.value().accepted) {
    return impl_->phase_status_report(session, phase);
  }
  return impl_->commit_reserved(reservation, report);
}

Result<PhaseRunReport> Runtime::fail_phase(CompilerSessionId session, CompilerPhaseId phase,
                                           CompilerPhaseGeneration phase_generation,
                                           FailureClass failure, StatusCode status,
                                           std::string detail) {
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  CompilerSession* found = impl_->find(session);
  if (found == nullptr) {
    return Status(StatusCode::not_found, "session is not registered");
  }
  PhaseRecord* record = found->find_phase(phase);
  if (record == nullptr) {
    return Status(StatusCode::not_found, "phase is not registered");
  }
  if (record->generation != phase_generation) {
    return Status(StatusCode::stale_phase_generation, "failed outcome names a stale phase generation");
  }
  if (record->state == PhaseState::committed) {
    return Status(StatusCode::duplicate_completion, "a committed phase cannot be failed");
  }
  record->failure = failure;
  record->last_status = status;
  record->last_detail = detail;
  if (!record->attempts.empty()) {
    record->attempts.back().terminal_state = PhaseState::failed;
    record->attempts.back().failure = failure;
    record->attempts.back().status = status;
  }
  if (phase_state_retains_commit_authority(record->state)) {
    impl_->record_transition(*record, PhaseState::failed, detail);
  }
  (void)impl_->artifacts.revoke_phase_outputs(record->id, record->generation, detail);
  (void)impl_->leases.revoke(record->lease.id, detail);
  found->generation = found->generation.next();
  found->updated_at_nanos = monotonic_nanos();
  const VoidResult persisted = impl_->persist(*found);
  if (!persisted) return persisted.status();
  return impl_->phase_status_report(session, phase);
}

Result<AuthorityVerdict> Runtime::check_authority(CompilerSessionId session,
                                                  CompilerPhaseId phase) const {
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  const CompilerSession* found = impl_->find(session);
  if (found == nullptr) {
    return Status(StatusCode::not_found, "session is not registered");
  }
  const PhaseRecord* record = found->find_phase(phase);
  if (record == nullptr) {
    return Status(StatusCode::not_found, "phase is not registered");
  }
  const PhaseAuthority bound = authority_from_session(*found, *record);
  AuthorityObservation observation = impl_->observe(*found);
  observation.phase_generation = record->generation;
  observation.attempt_generation = record->attempt_generation;
  observation.lease = record->lease;
  observation.lease_held = impl_->leases.is_held(record->lease);
  return compare_authority(bound, observation);
}

std::optional<CompilerSession> Runtime::find_session(CompilerSessionId session) const {
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  const CompilerSession* found = impl_->find(session);
  if (found == nullptr) return std::nullopt;
  return *found;
}

Result<CompilerSession> Runtime::require_session(CompilerSessionId session) const {
  const std::optional<CompilerSession> found = find_session(session);
  if (!found.has_value()) {
    return Status(StatusCode::not_found, "session is not registered: " + session.to_string());
  }
  return found.value();
}

std::vector<CompilerSession> Runtime::list_sessions() const {
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  std::vector<CompilerSession> out;
  out.reserve(impl_->sessions.size());
  for (const auto& [key, entry] : impl_->sessions) {
    (void)key;
    out.push_back(entry);
  }
  std::sort(out.begin(), out.end(),
            [](const CompilerSession& a, const CompilerSession& b) { return a.id < b.id; });
  return out;
}

const FinalCandidate* Runtime::find_candidate(CompilerSessionId session) const {
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  const CompilerSession* found = impl_->find(session);
  if (found == nullptr || !found->candidate_present) return nullptr;
  return &found->candidate;
}

Result<RecoveryPlan> Runtime::plan_recovery(CompilerSessionId session) const {
  return impl_->plan_recovery_impl(session);
}

Result<RecoveryPlan> Runtime::apply_recovery(CompilerSessionId session) {
  Result<RecoveryPlan> plan = impl_->plan_recovery_impl(session);
  if (!plan) return plan.status();
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  CompilerSession* found = impl_->find(session);
  if (found == nullptr) {
    return Status(StatusCode::not_found, "session is not registered");
  }
  RecoveryPlanner planner;
  const Result<std::size_t> revalidated = planner.apply_revalidation(plan.value(), impl_->artifacts);
  if (!revalidated) return revalidated.status();
  found->recovery = plan.value().id;
  found->recovery_generation = plan.value().generation;
  found->recovery_state =
      plan.value().requires_operator ? RecoveryState::manual_required : RecoveryState::resolved;
  if (found->state == SessionState::recovering && !plan.value().requires_operator) {
    found->state = SessionState::active;
    const std::vector<CompilerPhaseId> phases = found->plan.topological_order();
    for (const CompilerPhaseId id : phases) {
      PhaseRecord* record = found->find_phase(id);
      if (record == nullptr) continue;
      if (record->state == PhaseState::committed || record->state == PhaseState::failed ||
          record->state == PhaseState::cancelled || record->state == PhaseState::retired) {
        continue;
      }
      if (phase_state_retains_commit_authority(record->state)) {
        impl_->record_transition(*record, PhaseState::ready,
                                 "recovery resumed from the last authoritative boundary");
      } else if (record->state == PhaseState::fenced) {
        impl_->record_transition(*record, PhaseState::retired,
                                 "recovery retired a fenced phase generation");
      }
      record->failure = FailureClass::none;
      record->last_status = StatusCode::ok;
      record->last_detail.clear();
    }
  } else if (plan.value().requires_operator) {
    found->state = SessionState::recovering;
  }
  found->generation = found->generation.next();
  found->updated_at_nanos = monotonic_nanos();
  const VoidResult persisted = impl_->persist(*found);
  if (!persisted) return persisted.status();
  impl_->evidence_log.record(EvidenceClass::real, "recovery-applied", plan.value().describe());
  return plan;
}

VoidResult Runtime::snapshot() {
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  if (impl_->persistence == nullptr) {
    return Status(StatusCode::unsupported, "persistence is disabled for this runtime");
  }
  StateSnapshot state;
  state.runtime_epoch = impl_->epoch;
  state.last_sequence = impl_->persistence->last_sequence();
  std::vector<std::uint64_t> keys;
  keys.reserve(impl_->sessions.size());
  for (const auto& [key, entry] : impl_->sessions) {
    (void)entry;
    keys.push_back(key);
  }
  std::sort(keys.begin(), keys.end());
  for (const std::uint64_t key : keys) {
    const CompilerSession& session = impl_->sessions.at(key);
    state.encoded_sessions.push_back(encode_session(session));
    for (const Ref<IntermediateArtifactId>& reference : session.intermediates) {
      const IntermediateArtifact* artifact = impl_->artifacts.find(reference.id);
      if (artifact != nullptr) state.encoded_artifacts.push_back(encode_artifact(*artifact));
    }
    for (const CompilerPhaseId id : session.plan.topological_order()) {
      const PhaseRecord* record = session.find_phase(id);
      if (record == nullptr || !record->diagnostics.id.present()) continue;
      const DiagnosticSet* set = impl_->diagnostics.find(record->diagnostics.id);
      if (set != nullptr) state.encoded_diagnostics.push_back(encode_diagnostic_set(*set));
    }
  }
  const std::string payload = state.encode();
  const VoidResult written = impl_->persistence->write_snapshot(payload, state.last_sequence);
  if (!written) return written.status();
  impl_->evidence_log.record(EvidenceClass::real, "snapshot-written",
                             std::to_string(state.encoded_sessions.size()) + " session(s)");
  return VoidResult{};
}

Result<DurableState> Runtime::durable_state() const {
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  if (impl_->persistence == nullptr) {
    DurableState state;
    state.outcome = LoadOutcome::empty;
    state.detail = "persistence is disabled for this runtime";
    return state;
  }
  return impl_->persistence->load();
}

Result<AuditReport> Runtime::audit() const {
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  AuditSubject subject;
  const std::vector<CompilerSession> sessions = list_sessions();
  subject.sessions = &sessions;
  subject.artifacts = &impl_->artifacts;
  subject.diagnostics = &impl_->diagnostics;
  subject.provenance = &impl_->provenance;
  subject.toolchains = &impl_->toolchains;
  subject.targets = &impl_->targets;
  subject.environments = &impl_->environments;
  subject.policies = &impl_->policies;
  subject.sources = &impl_->sources;
  subject.leases = &impl_->leases;
  subject.processes = &impl_->processes;
  subject.persisted_records_checked =
      impl_->persistence != nullptr ? impl_->persistence->append_count() : 0;
  subject.persisted_defects = impl_->persisted_defects;
  subject.runtime_epoch = impl_->epoch;
  InvariantAuditor auditor;
  return auditor.audit(subject);
}

VoidResult Runtime::shutdown() {
  if (impl_ == nullptr) return VoidResult{};
  {
    const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
    if (impl_->shutting_down.exchange(true)) {
      impl_->processes.close();
      return VoidResult{};
    }
    for (auto& [key, flag] : impl_->cancel_flags) {
      (void)key;
      flag->store(true);
    }
    for (auto& [key, session] : impl_->sessions) {
      (void)key;
      if (session.state == SessionState::retired || session.state == SessionState::committed) continue;
      const VoidResult fenced =
          impl_->fence_all_in_flight(session, "runtime shutdown fenced in-flight authority");
      (void)fenced;
    }
  }
  (void)impl_->processes.terminate_all("runtime shutdown");
  impl_->processes.close();
  {
    const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
    for (auto& [key, session] : impl_->sessions) {
      (void)key;
      if (session.state == SessionState::retired || session.state == SessionState::committed) continue;
      if (session.state == SessionState::active || session.state == SessionState::created) {
        session.state = SessionState::failed;
        session.failure_detail = "runtime shutdown while the session was in progress";
      }
      session.updated_at_nanos = monotonic_nanos();
      const VoidResult persisted = impl_->persist(session);
      (void)persisted;
    }
  }
  (void)impl_->workspaces.cleanup_all();
  (void)remove_child_scratch();
  if (impl_->persistence != nullptr && impl_->options.ephemeral_state) {
    const VoidResult reset = impl_->persistence->reset();
    (void)reset;
  }
  impl_->evidence_log.record(EvidenceClass::real, "runtime-shutdown",
                             "runtime stopped at epoch " + std::to_string(impl_->epoch));
  return VoidResult{};
}

void Runtime::reopen() { impl_->shutting_down.store(false); }

std::string Runtime::describe() const {
  const std::lock_guard<std::recursive_mutex> guard(impl_->mutex);
  std::string out;
  out.append("Compiler Runtime Fabric ");
  out.append(version_string);
  out.append(" runtime=\"");
  out.append(impl_->options.runtime_name);
  out.append("\" epoch=");
  out.append(std::to_string(impl_->epoch));
  out.append(" sessions=");
  out.append(std::to_string(impl_->sessions.size()));
  out.append(" toolchains=");
  out.append(std::to_string(impl_->toolchains.size()));
  out.append(" adapters=");
  out.append(std::to_string(impl_->adapter_registry.size()));
  out.append(" executor=");
  out.append(impl_->executor != nullptr ? impl_->executor->describe() : std::string("<none>"));
  return out;
}

}  // namespace crf

