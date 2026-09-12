#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "crf/digest.hpp"
#include "crf/evidence.hpp"
#include "crf/phase.hpp"
#include "crf/status.hpp"
#include "crf/strong_id.hpp"
#include "crf/target.hpp"

namespace crf {

/// Validity of an intermediate artifact at a point in time.
///
/// UNKNOWN fails closed: a consumer may not take an UNKNOWN intermediate.
enum class ArtifactState : std::uint8_t {
  unknown = 0,
  valid = 1,
  stale = 2,
  incompatible = 3,
  corrupt = 4,
  superseded = 5,
  unsupported = 6,
};

CRF_NODISCARD CRF_API std::string_view to_string(ArtifactState value) noexcept;
CRF_NODISCARD CRF_API bool parse_artifact_state(std::string_view text, ArtifactState& out) noexcept;
/// Only VALID permits consumption by a dependent phase.
CRF_NODISCARD CRF_API bool artifact_state_is_consumable(ArtifactState value) noexcept;

/// Whether an artifact currently confers compilation authority.
enum class AuthorityState : std::uint8_t {
  /// The artifact exists and is registered but carries no authority yet.
  candidate = 0,
  /// The artifact is the current authoritative output of its phase generation.
  authoritative = 1,
  /// Authority was withdrawn because a generation moved, a phase was fenced, or
  /// a newer artifact superseded it.
  revoked = 2,
  /// Never granted.
  none = 3,
};

CRF_NODISCARD CRF_API std::string_view to_string(AuthorityState value) noexcept;

/// A governed intermediate.
struct CRF_API IntermediateArtifact {
  IntermediateArtifactId id{};
  IntermediateArtifactGeneration generation{};
  ObjectFormat format = ObjectFormat::unknown;
  std::filesystem::path path;
  Digest content{};
  std::uint64_t size_bytes = 0;

  Ref<CompilerPhaseId> producer_phase{};
  Ref<InvocationId> producer_invocation{};
  Ref<ToolchainId> toolchain{};
  Ref<TargetId> target{};
  Ref<SourceId> source{};
  IRGeneration ir_generation{};
  Ref<EnvironmentId> environment{};
  Ref<PolicyId> policy{};

  /// Direct lineage inputs. Each edge is explicit; no implicit edges exist.
  std::vector<Ref<IntermediateArtifactId>> lineage_inputs;

  ArtifactState state = ArtifactState::unknown;
  AuthorityState authority = AuthorityState::none;
  ProvenanceId provenance{};
  std::string validation_detail;
  /// Digest of the producer's declared output set, used for divergence
  /// detection across retries.
  Digest declared_digest{};
  bool current = false;

  CRF_NODISCARD Digest canonical_digest() const;
  CRF_NODISCARD bool consumable() const noexcept {
    return artifact_state_is_consumable(state) && authority == AuthorityState::authoritative;
  }
};

/// Registry of intermediates with O(1) lookup by identity and by producer phase.
class CRF_API ArtifactRegistry {
 public:
  static constexpr std::size_t kMaxArtifacts = 65536;

  CRF_NODISCARD Result<Ref<IntermediateArtifactId>> register_artifact(IntermediateArtifact artifact);
  CRF_NODISCARD Result<Ref<IntermediateArtifactId>> register_artifact_as(
      IntermediateArtifactId id, IntermediateArtifact artifact);

  CRF_NODISCARD const IntermediateArtifact* find(IntermediateArtifactId id) const noexcept;
  CRF_NODISCARD IntermediateArtifact* find_mutable(IntermediateArtifactId id) noexcept;

  /// O(1) producer lookup through an index keyed by phase identity.
  CRF_NODISCARD std::vector<const IntermediateArtifact*> produced_by(
      CompilerPhaseId phase, CompilerPhaseGeneration generation) const;
  CRF_NODISCARD std::vector<const IntermediateArtifact*> all_produced_by(
      CompilerPhaseId phase) const;

  CRF_NODISCARD VoidResult set_state(IntermediateArtifactId id, ArtifactState state,
                                     std::string detail);
  CRF_NODISCARD VoidResult set_authority(IntermediateArtifactId id, AuthorityState authority);
  /// Revoke authority on every artifact produced by a phase generation.
  CRF_NODISCARD std::size_t revoke_phase_outputs(CompilerPhaseId phase,
                                                 CompilerPhaseGeneration generation,
                                                 std::string detail);

  CRF_NODISCARD std::vector<IntermediateArtifact> list() const;
  CRF_NODISCARD std::size_t size() const noexcept { return entries_.size(); }

  /// Re-hash the on-disk content and compare. A missing or changed file moves
  /// the artifact to STALE or CORRUPT; UNKNOWN is never returned as valid.
  CRF_NODISCARD Result<ArtifactState> revalidate(IntermediateArtifactId id);

 private:
  std::unordered_map<std::uint64_t, IntermediateArtifact> entries_;
  std::unordered_map<std::uint64_t, std::vector<IntermediateArtifactId>> by_phase_;
  IdAllocator<IntermediateArtifactId> allocator_;
};

/// The candidate final artifact produced by the runtime.
///
/// The candidate carries complete local provenance. It is explicitly *not* a
/// global/distributed artifact commit: promotion beyond the compiler-runtime
/// boundary belongs to Distributed Compilation.
struct CRF_API FinalCandidate {
  FinalArtifactId id{};
  FinalArtifactGeneration generation{};
  CompilationId compilation{};
  CompilationGeneration compilation_generation{};
  AttemptGeneration attempt_generation{};
  Ref<CompilerSessionId> session{};
  Ref<ToolchainId> toolchain{};
  Ref<TargetId> target{};
  Ref<EnvironmentId> environment{};
  Ref<PolicyId> policy{};
  Ref<SourceId> source{};
  IRGeneration ir_generation{};

  ObjectFormat format = ObjectFormat::unknown;
  std::filesystem::path path;
  Digest content{};
  std::uint64_t size_bytes = 0;

  std::vector<Ref<IntermediateArtifactId>> lineage;
  std::vector<EvidenceId> validation_evidence;
  ProvenanceId provenance{};
  Digest lineage_digest{};
  bool complete_lineage = false;
  std::uint64_t registered_at_nanos = 0;
  bool handed_off = false;

  CRF_NODISCARD Digest canonical_digest() const;
};

}  // namespace crf
