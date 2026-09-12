#include "crf/artifact.hpp"
#include "crf/canonical.hpp"
#include "crf/component.hpp"

#include <algorithm>

namespace crf {

std::string_view to_string(ArtifactState value) noexcept {
  switch (value) {
    case ArtifactState::unknown: return "UNKNOWN";
    case ArtifactState::valid: return "VALID";
    case ArtifactState::stale: return "STALE";
    case ArtifactState::incompatible: return "INCOMPATIBLE";
    case ArtifactState::corrupt: return "CORRUPT";
    case ArtifactState::superseded: return "SUPERSEDED";
    case ArtifactState::unsupported: return "UNSUPPORTED";
  }
  return "UNKNOWN";
}

bool parse_artifact_state(std::string_view text, ArtifactState& out) noexcept {
  static constexpr ArtifactState kValues[] = {
      ArtifactState::unknown, ArtifactState::valid,     ArtifactState::stale,
      ArtifactState::incompatible, ArtifactState::corrupt, ArtifactState::superseded,
      ArtifactState::unsupported};
  for (ArtifactState value : kValues) {
    if (equals_ascii_ci(text, to_string(value))) {
      out = value;
      return true;
    }
  }
  return false;
}

bool artifact_state_is_consumable(ArtifactState value) noexcept {
  return value == ArtifactState::valid;
}

std::string_view to_string(AuthorityState value) noexcept {
  switch (value) {
    case AuthorityState::candidate: return "CANDIDATE";
    case AuthorityState::authoritative: return "AUTHORITATIVE";
    case AuthorityState::revoked: return "REVOKED";
    case AuthorityState::none: return "NONE";
  }
  return "NONE";
}

Digest IntermediateArtifact::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(id.to_string());
  writer.u64(generation.value());
  writer.text(to_string(format));
  writer.text(canonical_path_key(path));
  writer.text(content.to_hex());
  writer.u64(size_bytes);
  writer.text(producer_phase.to_string());
  writer.text(producer_invocation.to_string());
  writer.text(toolchain.to_string());
  writer.text(target.to_string());
  writer.text(source.to_string());
  writer.u64(ir_generation.value());
  writer.text(environment.to_string());
  writer.text(policy.to_string());
  std::vector<std::string> lineage;
  lineage.reserve(lineage_inputs.size());
  for (const Ref<IntermediateArtifactId>& input : lineage_inputs) lineage.push_back(input.to_string());
  std::sort(lineage.begin(), lineage.end());
  for (const std::string& entry : lineage) writer.text(entry);
  writer.text(to_string(state));
  writer.text(to_string(authority));
  writer.text(provenance.to_string());
  writer.text(declared_digest.to_hex());
  return Digest::of(writer.bytes());
}

Result<Ref<IntermediateArtifactId>> ArtifactRegistry::register_artifact(IntermediateArtifact artifact) {
  if (entries_.size() >= kMaxArtifacts) {
    return Status(StatusCode::capacity_exceeded, "artifact registry is full");
  }
  artifact.id = allocator_.next();
  artifact.generation = IntermediateArtifactGeneration::initial();
  const IntermediateArtifactId id = artifact.id;
  by_phase_[artifact.producer_phase.id.value()].push_back(id);
  entries_.emplace(id.value(), std::move(artifact));
  return Ref<IntermediateArtifactId>{id, IntermediateArtifactGeneration::initial()};
}

Result<Ref<IntermediateArtifactId>> ArtifactRegistry::register_artifact_as(
    IntermediateArtifactId id, IntermediateArtifact artifact) {
  if (!id.present()) {
    return Status(StatusCode::invalid_identity, "artifact identity is absent");
  }
  allocator_.observe(id);
  artifact.id = id;
  if (!artifact.generation.present()) {
    artifact.generation = IntermediateArtifactGeneration::initial();
  }
  by_phase_[artifact.producer_phase.id.value()].push_back(id);
  entries_[id.value()] = std::move(artifact);
  return Ref<IntermediateArtifactId>{id, entries_[id.value()].generation};
}

const IntermediateArtifact* ArtifactRegistry::find(IntermediateArtifactId id) const noexcept {
  const auto found = entries_.find(id.value());
  if (found == entries_.end()) return nullptr;
  return &found->second;
}

IntermediateArtifact* ArtifactRegistry::find_mutable(IntermediateArtifactId id) noexcept {
  const auto found = entries_.find(id.value());
  if (found == entries_.end()) return nullptr;
  return &found->second;
}

std::vector<const IntermediateArtifact*> ArtifactRegistry::produced_by(
    CompilerPhaseId phase, CompilerPhaseGeneration generation) const {
  std::vector<const IntermediateArtifact*> out;
  const auto found = by_phase_.find(phase.value());
  if (found == by_phase_.end()) return out;
  for (const IntermediateArtifactId id : found->second) {
    const auto entry = entries_.find(id.value());
    if (entry == entries_.end()) continue;
    if (entry->second.producer_phase.generation != generation) continue;
    out.push_back(&entry->second);
  }
  std::sort(out.begin(), out.end(),
            [](const IntermediateArtifact* a, const IntermediateArtifact* b) { return a->id < b->id; });
  return out;
}

std::vector<const IntermediateArtifact*> ArtifactRegistry::all_produced_by(
    CompilerPhaseId phase) const {
  std::vector<const IntermediateArtifact*> out;
  const auto found = by_phase_.find(phase.value());
  if (found == by_phase_.end()) return out;
  for (const IntermediateArtifactId id : found->second) {
    const auto entry = entries_.find(id.value());
    if (entry == entries_.end()) continue;
    out.push_back(&entry->second);
  }
  std::sort(out.begin(), out.end(),
            [](const IntermediateArtifact* a, const IntermediateArtifact* b) { return a->id < b->id; });
  return out;
}

VoidResult ArtifactRegistry::set_state(IntermediateArtifactId id, ArtifactState state,
                                       std::string detail) {
  const auto found = entries_.find(id.value());
  if (found == entries_.end()) {
    return Status(StatusCode::not_found, "artifact is not registered: " + id.to_string());
  }
  found->second.state = state;
  found->second.validation_detail = std::move(detail);
  if (!artifact_state_is_consumable(state) && found->second.authority == AuthorityState::authoritative) {
    // A state that can no longer be consumed cannot retain authority.
    found->second.authority = AuthorityState::revoked;
    found->second.current = false;
  }
  return VoidResult{};
}

VoidResult ArtifactRegistry::set_authority(IntermediateArtifactId id, AuthorityState authority) {
  const auto found = entries_.find(id.value());
  if (found == entries_.end()) {
    return Status(StatusCode::not_found, "artifact is not registered: " + id.to_string());
  }
  if (authority == AuthorityState::authoritative && !artifact_state_is_consumable(found->second.state)) {
    return Status(StatusCode::not_authoritative,
                  "artifact cannot be authoritative while its state is " +
                      std::string(to_string(found->second.state)));
  }
  found->second.authority = authority;
  found->second.current = authority == AuthorityState::authoritative;
  return VoidResult{};
}

std::size_t ArtifactRegistry::revoke_phase_outputs(CompilerPhaseId phase,
                                                   CompilerPhaseGeneration generation,
                                                   std::string detail) {
  std::size_t revoked = 0;
  const auto found = by_phase_.find(phase.value());
  if (found == by_phase_.end()) return 0;
  for (const IntermediateArtifactId id : found->second) {
    const auto entry = entries_.find(id.value());
    if (entry == entries_.end()) continue;
    IntermediateArtifact& artifact = entry->second;
    if (artifact.producer_phase.generation != generation) continue;
    if (artifact.authority == AuthorityState::authoritative) ++revoked;
    artifact.authority = AuthorityState::revoked;
    artifact.current = false;
    if (artifact.state == ArtifactState::valid) artifact.state = ArtifactState::superseded;
    if (!detail.empty()) artifact.validation_detail = detail;
  }
  return revoked;
}

std::vector<IntermediateArtifact> ArtifactRegistry::list() const {
  std::vector<IntermediateArtifact> out;
  out.reserve(entries_.size());
  for (const auto& [key, entry] : entries_) {
    (void)key;
    out.push_back(entry);
  }
  std::sort(out.begin(), out.end(),
            [](const IntermediateArtifact& a, const IntermediateArtifact& b) { return a.id < b.id; });
  return out;
}

Result<ArtifactState> ArtifactRegistry::revalidate(IntermediateArtifactId id) {
  const auto found = entries_.find(id.value());
  if (found == entries_.end()) {
    return Status(StatusCode::not_found, "artifact is not registered: " + id.to_string());
  }
  IntermediateArtifact& artifact = found->second;
  if (artifact.path.empty()) {
    return Status(StatusCode::invalid_argument, "artifact has no path to revalidate");
  }
  std::error_code ec;
  if (!std::filesystem::exists(artifact.path, ec) || ec) {
    artifact.state = ArtifactState::stale;
    artifact.authority = AuthorityState::revoked;
    artifact.current = false;
    artifact.validation_detail = "artifact file is missing at its recorded path";
    return ArtifactState::stale;
  }
  Digest observed;
  if (!Digest::of_file(artifact.path, observed)) {
    artifact.state = ArtifactState::unknown;
    artifact.authority = AuthorityState::revoked;
    artifact.current = false;
    artifact.validation_detail = "artifact content could not be hashed";
    return ArtifactState::unknown;
  }
  if (observed != artifact.content) {
    artifact.state = ArtifactState::corrupt;
    artifact.authority = AuthorityState::revoked;
    artifact.current = false;
    artifact.validation_detail = "artifact content no longer matches its recorded digest";
    return ArtifactState::corrupt;
  }
  artifact.validation_detail = "artifact content matches its recorded digest";
  return artifact.state;
}

Digest FinalCandidate::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(id.to_string());
  writer.u64(generation.value());
  writer.text(compilation.to_string());
  writer.u64(compilation_generation.value());
  writer.u64(attempt_generation.value());
  writer.text(session.to_string());
  writer.text(toolchain.to_string());
  writer.text(target.to_string());
  writer.text(environment.to_string());
  writer.text(policy.to_string());
  writer.text(source.to_string());
  writer.u64(ir_generation.value());
  writer.text(to_string(format));
  writer.text(canonical_path_key(path));
  writer.text(content.to_hex());
  writer.u64(size_bytes);
  std::vector<std::string> lineage_text;
  lineage_text.reserve(lineage.size());
  for (const Ref<IntermediateArtifactId>& entry : lineage) lineage_text.push_back(entry.to_string());
  std::sort(lineage_text.begin(), lineage_text.end());
  for (const std::string& entry : lineage_text) writer.text(entry);
  writer.text(provenance.to_string());
  writer.text(lineage_digest.to_hex());
  writer.boolean(complete_lineage);
  return Digest::of(writer.bytes());
}

}  // namespace crf
