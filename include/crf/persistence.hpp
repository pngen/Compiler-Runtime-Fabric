#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "crf/digest.hpp"
#include "crf/session.hpp"
#include "crf/status.hpp"

namespace crf {

/// Durable record kinds. Values are part of the persisted schema.
enum class RecordKind : std::uint16_t {
  unknown = 0,
  epoch_advanced = 1,
  toolchain_registered = 2,
  target_registered = 3,
  environment_registered = 4,
  policy_registered = 5,
  source_registered = 6,
  session_created = 7,
  session_state_changed = 8,
  phase_reserved = 9,
  phase_state_changed = 10,
  phase_committed = 11,
  phase_refused = 12,
  artifact_registered = 13,
  artifact_authority_changed = 14,
  diagnostics_recorded = 15,
  candidate_registered = 16,
  recovery_decided = 17,
  provenance_appended = 18,
  session_retired = 19,
  lease_granted = 20,
  lease_revoked = 21,
};

CRF_NODISCARD CRF_API std::string_view to_string(RecordKind value) noexcept;
CRF_NODISCARD CRF_API bool parse_record_kind(std::uint16_t raw, RecordKind& out) noexcept;

inline constexpr std::uint16_t kPersistenceSchemaVersion = 1;

/// One journal record as loaded from disk.
struct CRF_API JournalRecord {
  RecordKind kind = RecordKind::unknown;
  std::uint64_t sequence = 0;
  std::uint64_t at_nanos = 0;
  std::string payload;
  std::uint32_t stored_crc = 0;

  CRF_NODISCARD Digest payload_digest() const;
};

enum class LoadOutcome : std::uint8_t {
  ok = 0,
  empty = 1,
  /// The final record was incomplete. It was discarded; every earlier record is
  /// intact and trustworthy.
  torn_tail_repaired = 2,
  /// A record in the middle of the journal failed its integrity check. The
  /// journal is refused rather than partially trusted.
  corrupt = 3,
  schema_mismatch = 4,
  io_error = 5,
  bounds_exceeded = 6,
};

CRF_NODISCARD CRF_API std::string_view to_string(LoadOutcome value) noexcept;

struct CRF_API DurableState {
  LoadOutcome outcome = LoadOutcome::empty;
  std::uint64_t runtime_epoch = 0;
  std::uint64_t last_sequence = 0;
  std::uint64_t created_at_nanos = 0;
  std::vector<JournalRecord> records;
  std::uint64_t repaired_bytes = 0;
  std::uint64_t bytes_read = 0;
  std::string detail;

  CRF_NODISCARD bool trustworthy() const noexcept {
    return outcome == LoadOutcome::ok || outcome == LoadOutcome::empty ||
           outcome == LoadOutcome::torn_tail_repaired;
  }
};

struct CRF_API PersistenceOptions {
  std::filesystem::path directory;
  /// Base name of the journal and snapshot files. Empty means "use the runtime
  /// name", which is what a caller normally wants.
  std::string name;
  /// Flush the journal to stable storage before returning from append. A caller
  /// that observed a successful durable phase commit can then recover it after
  /// a restart.
  bool durable_appends = true;
  std::size_t max_record_bytes = 4u << 20;
  std::size_t max_records_per_load = 1u << 20;
  std::size_t max_journal_bytes = 1u << 30;
};

/// Append-only journal with an atomically replaced snapshot.
///
/// Every record carries its own CRC-32C and length, so truncation and bit rot
/// are both detectable. Decoding is bounded: no persisted length is trusted
/// before it is compared against a configured ceiling.
class CRF_API PersistenceStore {
 public:
  PersistenceStore();
  ~PersistenceStore();
  PersistenceStore(const PersistenceStore&) = delete;
  PersistenceStore& operator=(const PersistenceStore&) = delete;

  CRF_NODISCARD static Result<std::unique_ptr<PersistenceStore>> open(PersistenceOptions options);

  CRF_NODISCARD const PersistenceOptions& options() const noexcept;
  CRF_NODISCARD const std::filesystem::path& journal_path() const noexcept;
  CRF_NODISCARD const std::filesystem::path& snapshot_path() const noexcept;

  /// Append one record and make it durable. Returns the assigned sequence.
  CRF_NODISCARD Result<std::uint64_t> append(RecordKind kind, std::string payload);
  /// Durably record the runtime epoch. Written once per runtime start.
  CRF_NODISCARD Result<std::uint64_t> record_epoch(std::uint64_t epoch);
  /// Rotate the journal into a snapshot and start a fresh journal. The snapshot
  /// is written to a temporary file and atomically renamed.
  CRF_NODISCARD VoidResult write_snapshot(std::string payload, std::uint64_t sequence);
  CRF_NODISCARD Result<std::optional<std::string>> read_snapshot() const;
  CRF_NODISCARD Result<DurableState> load() const;

  CRF_NODISCARD std::uint64_t last_sequence() const noexcept;
  CRF_NODISCARD std::uint64_t journal_bytes() const noexcept;
  CRF_NODISCARD std::size_t append_count() const noexcept;

  /// Remove the journal and the snapshot. Used by tests and by clean shutdown of
  /// an ephemeral runtime.
  CRF_NODISCARD VoidResult reset();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Session codec.
//
// Deterministic, bounded, versioned encoding of a CompilerSession plus its
// dependent phase, artifact, and diagnostic state. Used for journal payloads
// and for the snapshot. Decoding never trusts a persisted length.
// ---------------------------------------------------------------------------
CRF_NODISCARD CRF_API std::string encode_session(const CompilerSession& session);
CRF_NODISCARD CRF_API Result<CompilerSession> decode_session(std::string_view bytes);

CRF_NODISCARD CRF_API std::string encode_phase(const PhaseRecord& phase);
CRF_NODISCARD CRF_API Result<PhaseRecord> decode_phase(std::string_view bytes);

CRF_NODISCARD CRF_API std::string encode_artifact(const IntermediateArtifact& artifact);
CRF_NODISCARD CRF_API Result<IntermediateArtifact> decode_artifact(std::string_view bytes);

CRF_NODISCARD CRF_API std::string encode_diagnostic_set(const DiagnosticSet& set);
CRF_NODISCARD CRF_API Result<DiagnosticSet> decode_diagnostic_set(std::string_view bytes);

CRF_NODISCARD CRF_API std::string encode_candidate(const FinalCandidate& candidate);
CRF_NODISCARD CRF_API Result<FinalCandidate> decode_candidate(std::string_view bytes);

CRF_NODISCARD CRF_API std::string encode_plan(const PhasePlan& plan);
CRF_NODISCARD CRF_API Result<PhasePlan> decode_plan(std::string_view bytes);

// Authority registry entries. A restarted runtime reloads these so that the
// generations committed phases were bound to can be revalidated.
CRF_NODISCARD CRF_API std::string encode_toolchain(const ToolchainIdentity& identity);
CRF_NODISCARD CRF_API Result<ToolchainIdentity> decode_toolchain(std::string_view bytes);
CRF_NODISCARD CRF_API std::string encode_target_identity(const TargetIdentity& identity);
CRF_NODISCARD CRF_API Result<TargetIdentity> decode_target_identity(std::string_view bytes);
CRF_NODISCARD CRF_API std::string encode_environment_identity(const EnvironmentIdentity& identity);
CRF_NODISCARD CRF_API Result<EnvironmentIdentity> decode_environment_identity(std::string_view bytes);
CRF_NODISCARD CRF_API std::string encode_policy_identity(const PolicyIdentity& identity);
CRF_NODISCARD CRF_API Result<PolicyIdentity> decode_policy_identity(std::string_view bytes);
CRF_NODISCARD CRF_API std::string encode_source_unit(const SourceUnit& unit);
CRF_NODISCARD CRF_API Result<SourceUnit> decode_source_unit(std::string_view bytes);
CRF_NODISCARD CRF_API std::string encode_provenance(const ProvenanceRecord& record);
CRF_NODISCARD CRF_API Result<ProvenanceRecord> decode_provenance(std::string_view bytes);

/// Snapshot envelope: sessions plus the registries needed to reconstruct
/// authority. Decoding refuses a mismatched schema or a bad checksum.
struct CRF_API StateSnapshot {
  std::uint16_t schema_version = kPersistenceSchemaVersion;
  std::uint64_t runtime_epoch = 0;
  std::uint64_t last_sequence = 0;
  std::vector<std::string> encoded_sessions;
  std::vector<std::string> encoded_artifacts;
  std::vector<std::string> encoded_diagnostics;

  CRF_NODISCARD std::string encode() const;
  CRF_NODISCARD static Result<StateSnapshot> decode(std::string_view bytes);
};

}  // namespace crf
