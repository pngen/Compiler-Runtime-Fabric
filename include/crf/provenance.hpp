#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "crf/artifact.hpp"
#include "crf/authority.hpp"
#include "crf/digest.hpp"
#include "crf/evidence.hpp"
#include "crf/strong_id.hpp"

namespace crf {

/// A provenance record. One is written for every authoritative artifact and for
/// every refused commit, so that the decision remains explainable after the
/// process that made it has exited.
///
/// Provenance is local: it records which inputs, toolchain, target, environment,
/// and policy produced which outputs. Global/distributed provenance ownership
/// belongs to the distributed coordinator.
struct CRF_API ProvenanceRecord {
  ProvenanceId id{};
  EvidenceGeneration generation{};
  std::string kind;
  Ref<CompilerSessionId> session{};
  Ref<CompilationId> compilation{};
  Ref<CompilerPhaseId> phase{};
  Ref<InvocationId> invocation{};
  Ref<ToolchainId> toolchain{};
  Ref<TargetId> target{};
  Ref<EnvironmentId> environment{};
  Ref<PolicyId> policy{};
  Ref<SourceId> source{};
  std::vector<Ref<IntermediateArtifactId>> inputs;
  std::vector<Ref<IntermediateArtifactId>> outputs;
  std::string adapter;
  AuthorityVerdict verdict = AuthorityVerdict::valid;
  std::string detail;
  std::uint64_t at_nanos = 0;

  CRF_NODISCARD Digest canonical_digest() const;
};

class CRF_API ProvenanceLog {
 public:
  static constexpr std::size_t kMaxRecords = 65536;
  static constexpr std::size_t kMaxDetailBytes = 2048;

  CRF_NODISCARD ProvenanceRecord& append(ProvenanceRecord record);
  /// Restore a record with the identity it was persisted under, so a reloaded
  /// runtime can still resolve the provenance an artifact cites.
  CRF_NODISCARD ProvenanceRecord& append_as(ProvenanceRecord record);
  CRF_NODISCARD const ProvenanceRecord* find(ProvenanceId id) const noexcept;
  CRF_NODISCARD const std::vector<ProvenanceRecord>& records() const noexcept { return records_; }
  CRF_NODISCARD std::size_t size() const noexcept { return records_.size(); }
  CRF_NODISCARD bool truncated() const noexcept { return truncated_; }

  /// Walk lineage back from a stored artifact to its authoritative roots.
  /// Returns identities in deterministic order. A cycle is reported as a defect
  /// rather than followed.
  CRF_NODISCARD Result<std::vector<Ref<IntermediateArtifactId>>> trace_lineage(
      const ArtifactRegistry& artifacts, IntermediateArtifactId root) const;

  /// True when every artifact in the lineage is authoritative and valid.
  CRF_NODISCARD bool lineage_is_authoritative(const ArtifactRegistry& artifacts,
                                              IntermediateArtifactId root) const;

 private:
  std::vector<ProvenanceRecord> records_;
  IdAllocator<ProvenanceId> allocator_;
  bool truncated_ = false;
};

}  // namespace crf
