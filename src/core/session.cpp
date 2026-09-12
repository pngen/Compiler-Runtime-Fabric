#include "crf/session.hpp"
#include "crf/canonical.hpp"

#include <algorithm>

namespace crf {

std::string_view to_string(SessionState value) noexcept {
  switch (value) {
    case SessionState::created: return "CREATED";
    case SessionState::active: return "ACTIVE";
    case SessionState::recovering: return "RECOVERING";
    case SessionState::committed: return "COMMITTED";
    case SessionState::failed: return "FAILED";
    case SessionState::cancelled: return "CANCELLED";
    case SessionState::retired: return "RETIRED";
  }
  return "UNKNOWN";
}

bool parse_session_state(std::string_view text, SessionState& out) noexcept {
  static constexpr SessionState kValues[] = {SessionState::created, SessionState::active,
                                             SessionState::recovering, SessionState::committed,
                                             SessionState::failed, SessionState::cancelled,
                                             SessionState::retired};
  for (SessionState value : kValues) {
    if (equals_ascii_ci(text, to_string(value))) {
      out = value;
      return true;
    }
  }
  return false;
}

bool session_state_admits_new_authority(SessionState value) noexcept {
  return value == SessionState::created || value == SessionState::active;
}

std::string_view to_string(RecoveryState value) noexcept {
  switch (value) {
    case RecoveryState::none: return "NONE";
    case RecoveryState::required: return "REQUIRED";
    case RecoveryState::planned: return "PLANNED";
    case RecoveryState::in_progress: return "IN_PROGRESS";
    case RecoveryState::resolved: return "RESOLVED";
    case RecoveryState::manual_required: return "MANUAL_REQUIRED";
    case RecoveryState::unsupported: return "UNSUPPORTED";
  }
  return "UNKNOWN";
}

Digest CompileRequest::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(request.to_string());
  writer.text(compilation.to_string());
  writer.u64(compilation_generation.value());
  writer.text(attempt.to_string());
  writer.u64(attempt_generation.value());
  writer.text(to_string(toolchain_family));
  writer.text(toolchain.to_string());
  writer.text(target.canonical_digest().to_hex());
  std::vector<std::string> source_keys;
  source_keys.reserve(sources.size());
  for (const std::filesystem::path& path : sources) source_keys.push_back(canonical_path_key(path));
  std::sort(source_keys.begin(), source_keys.end());
  for (const std::string& key : source_keys) writer.text(key);
  std::vector<std::string> inline_keys;
  inline_keys.reserve(inline_sources.size());
  for (const auto& [name, contents] : inline_sources) {
    inline_keys.push_back(name + "\u0000" + Digest::of(contents).to_hex());
  }
  std::sort(inline_keys.begin(), inline_keys.end());
  for (const std::string& key : inline_keys) writer.text(key);
  writer.text(canonical_path_key(output_directory));
  writer.text(final_artifact_name);
  writer.text(policy.canonical_digest().to_hex());
  writer.text(environment.canonical_digest().to_hex());
  writer.boolean(stage_inputs);
  writer.boolean(run_smoke_test);
  std::vector<EnvironmentVariable> options = adapter_options;
  std::sort(options.begin(), options.end(), [](const EnvironmentVariable& a, const EnvironmentVariable& b) {
    return less_ascii_ci(a.name, b.name);
  });
  for (const EnvironmentVariable& option : options) {
    writer.text(to_upper_ascii(option.name));
    writer.text(option.value);
  }
  return Digest::of(writer.bytes());
}

std::string CompileRequest::describe() const {
  std::string out;
  out.append("request=");
  out.append(request.to_string());
  out.append(" compilation=");
  out.append(compilation.to_string());
  out.append("@");
  out.append(compilation_generation.to_string());
  out.append(" attempt=");
  out.append(attempt.to_string());
  out.append("@");
  out.append(attempt_generation.to_string());
  out.append(" toolchain-family=");
  out.append(to_string(toolchain_family));
  out.append(" sources=");
  out.append(std::to_string(sources.size() + inline_sources.size()));
  out.append(" target=");
  out.append(target.triple);
  return out;
}

PhaseRecord* CompilerSession::find_phase(CompilerPhaseId phase_id) noexcept {
  const auto found = phases.find(phase_id.value());
  return found == phases.end() ? nullptr : &found->second;
}

const PhaseRecord* CompilerSession::find_phase(CompilerPhaseId phase_id) const noexcept {
  const auto found = phases.find(phase_id.value());
  return found == phases.end() ? nullptr : &found->second;
}

std::vector<CompilerPhaseId> CompilerSession::committed_phases() const {
  std::vector<CompilerPhaseId> out;
  for (const CompilerPhaseId phase_id : plan.topological_order()) {
    const PhaseRecord* phase = find_phase(phase_id);
    if (phase != nullptr && phase->state == PhaseState::committed) out.push_back(phase_id);
  }
  return out;
}

bool CompilerSession::has_committed(CompilerPhaseId phase_id) const noexcept {
  const PhaseRecord* phase = find_phase(phase_id);
  return phase != nullptr && phase->state == PhaseState::committed;
}

bool CompilerSession::all_mandatory_committed() const {
  for (const PhaseNode& node : plan.nodes()) {
    if (!node.mandatory) continue;
    if (!has_committed(node.id)) return false;
  }
  return true;
}

const PhaseRecord* CompilerSession::final_phase() const noexcept {
  if (plan.size() == 0) return nullptr;
  return find_phase(plan.topological_order().back());
}

Digest CompilerSession::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(id.to_string());
  writer.u64(generation.value());
  writer.text(to_string(state));
  writer.text(to_string(recovery_state));
  writer.text(request.to_string());
  writer.text(compilation.to_string());
  writer.u64(compilation_generation.value());
  writer.text(attempt.to_string());
  writer.u64(attempt_generation.value());
  writer.text(toolchain.to_string());
  std::vector<std::string> cooperating;
  cooperating.reserve(cooperating_toolchains.size());
  for (const Ref<ToolchainId>& entry : cooperating_toolchains) cooperating.push_back(entry.to_string());
  std::sort(cooperating.begin(), cooperating.end());
  for (const std::string& entry : cooperating) writer.text(entry);
  writer.text(target.to_string());
  writer.text(environment.to_string());
  writer.text(policy.to_string());
  writer.text(source.to_string());
  for (const Ref<SourceId>& entry : sources) writer.text(entry.to_string());
  writer.u64(ir_generation.value());
  writer.text(adapter_name);
  writer.text(plan.canonical_digest().to_hex());
  for (const CompilerPhaseId id_entry : plan.topological_order()) {
    const PhaseRecord* phase = find_phase(id_entry);
    if (phase == nullptr) continue;
    writer.text(phase->canonical_digest().to_hex());
  }
  for (const Ref<IntermediateArtifactId>& entry : intermediates) writer.text(entry.to_string());
  writer.boolean(candidate_present);
  if (candidate_present) writer.text(candidate.canonical_digest().to_hex());
  writer.u32(session_retries_used);
  writer.text(request_digest.to_hex());
  writer.text(epoch.to_string());
  return Digest::of(writer.bytes());
}

}  // namespace crf
