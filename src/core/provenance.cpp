#include "crf/provenance.hpp"
#include "crf/canonical.hpp"

#include <algorithm>
#include <deque>
#include <unordered_set>

namespace crf {

Digest ProvenanceRecord::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(id.to_string());
  writer.u64(generation.value());
  writer.text(kind);
  writer.text(session.to_string());
  writer.text(compilation.to_string());
  writer.text(phase.to_string());
  writer.text(invocation.to_string());
  writer.text(toolchain.to_string());
  writer.text(target.to_string());
  writer.text(environment.to_string());
  writer.text(policy.to_string());
  writer.text(source.to_string());
  std::vector<std::string> inputs_text;
  inputs_text.reserve(inputs.size());
  for (const Ref<IntermediateArtifactId>& entry : inputs) inputs_text.push_back(entry.to_string());
  std::sort(inputs_text.begin(), inputs_text.end());
  for (const std::string& entry : inputs_text) writer.text(entry);
  std::vector<std::string> outputs_text;
  outputs_text.reserve(outputs.size());
  for (const Ref<IntermediateArtifactId>& entry : outputs) outputs_text.push_back(entry.to_string());
  std::sort(outputs_text.begin(), outputs_text.end());
  for (const std::string& entry : outputs_text) writer.text(entry);
  writer.text(adapter);
  writer.text(to_string(verdict));
  writer.text(detail);
  return Digest::of(writer.bytes());
}

ProvenanceRecord& ProvenanceLog::append(ProvenanceRecord record) {
  record.id = allocator_.next();
  record.generation = EvidenceGeneration::from_value(record.id.value());
  if (record.detail.size() > kMaxDetailBytes) record.detail.resize(kMaxDetailBytes);
  if (record.at_nanos == 0) record.at_nanos = monotonic_nanos();
  if (records_.size() >= kMaxRecords) {
    truncated_ = true;
    records_.erase(records_.begin());
  }
  records_.push_back(std::move(record));
  return records_.back();
}

ProvenanceRecord& ProvenanceLog::append_as(ProvenanceRecord record) {
  if (record.detail.size() > kMaxDetailBytes) record.detail.resize(kMaxDetailBytes);
  allocator_.observe(record.id);
  if (records_.size() >= kMaxRecords) {
    truncated_ = true;
    records_.erase(records_.begin());
  }
  records_.push_back(std::move(record));
  return records_.back();
}

const ProvenanceRecord* ProvenanceLog::find(ProvenanceId id) const noexcept {
  for (const ProvenanceRecord& record : records_) {
    if (record.id == id) return &record;
  }
  return nullptr;
}

Result<std::vector<Ref<IntermediateArtifactId>>> ProvenanceLog::trace_lineage(
    const ArtifactRegistry& artifacts, IntermediateArtifactId root) const {
  std::vector<Ref<IntermediateArtifactId>> out;
  std::unordered_set<std::uint64_t> visited;
  std::deque<IntermediateArtifactId> pending;
  pending.push_back(root);
  while (!pending.empty()) {
    const IntermediateArtifactId current = pending.front();
    pending.pop_front();
    if (!visited.insert(current.value()).second) {
      return Status(StatusCode::invalid_argument,
                    "artifact lineage contains a cycle at " + current.to_string());
    }
    const IntermediateArtifact* artifact = artifacts.find(current);
    if (artifact == nullptr) {
      return Status(StatusCode::not_found,
                    "artifact lineage references an unregistered artifact: " + current.to_string());
    }
    out.push_back(Ref<IntermediateArtifactId>{artifact->id, artifact->generation});
    for (const Ref<IntermediateArtifactId>& input : artifact->lineage_inputs) {
      pending.push_back(input.id);
    }
  }
  std::sort(out.begin(), out.end(), [](const Ref<IntermediateArtifactId>& a,
                                       const Ref<IntermediateArtifactId>& b) { return a.id < b.id; });
  return out;
}

bool ProvenanceLog::lineage_is_authoritative(const ArtifactRegistry& artifacts,
                                             IntermediateArtifactId root) const {
  const Result<std::vector<Ref<IntermediateArtifactId>>> lineage = trace_lineage(artifacts, root);
  if (!lineage) return false;
  for (const Ref<IntermediateArtifactId>& reference : lineage.value()) {
    const IntermediateArtifact* artifact = artifacts.find(reference.id);
    if (artifact == nullptr) return false;
    if (artifact->authority != AuthorityState::authoritative) return false;
    if (!artifact_state_is_consumable(artifact->state)) return false;
  }
  return true;
}

}  // namespace crf
