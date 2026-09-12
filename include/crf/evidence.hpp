#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "crf/digest.hpp"
#include "crf/status.hpp"
#include "crf/strong_id.hpp"

namespace crf {

/// Evidence classification. The runtime labels every observable claim so that a
/// report can never overstate what was actually executed.
enum class EvidenceClass : std::uint8_t {
  unknown = 0,
  /// Produced by executing real tooling or real operating-system facilities on
  /// this machine in this run.
  real = 1,
  /// Modelled by the runtime to exercise governance paths where real tooling is
  /// unavailable. Never presented as real execution.
  synthetic = 2,
  /// The capability is not implemented. Refusals carry this label.
  unsupported = 3,
};

CRF_NODISCARD CRF_API std::string_view to_string(EvidenceClass value) noexcept;
CRF_NODISCARD CRF_API bool parse_evidence_class(std::string_view text, EvidenceClass& out) noexcept;

/// An individually attributable observation.
struct CRF_API EvidenceRecord {
  EvidenceId id{};
  EvidenceGeneration generation{};
  EvidenceClass evidence_class = EvidenceClass::unknown;
  /// Short machine-readable kind: "toolchain-probe", "process-exit", ...
  std::string kind;
  /// Human-readable detail. Bounded.
  std::string detail;
  /// Digest of the raw evidence payload where one exists.
  Digest payload{};
  std::uint64_t observed_at_nanos = 0;

  CRF_NODISCARD Digest canonical_digest() const;
};

/// Bounded collection of evidence with deterministic ordering by identity.
class CRF_API EvidenceLog {
 public:
  static constexpr std::size_t kMaxRecords = 4096;
  static constexpr std::size_t kMaxDetailBytes = 4096;

  /// Append one observation. The log owns the record; callers that need the
  /// stored identity use record_ref().
  void record(EvidenceClass evidence_class, std::string kind, std::string detail,
              Digest payload = {});
  /// Append one observation and return the stored record so the caller can cite
  /// its identity (for example from a final candidate).
  EvidenceRecord& record_ref(EvidenceClass evidence_class, std::string kind, std::string detail,
                             Digest payload = {});
  void observe(const EvidenceRecord& record);

  CRF_NODISCARD const std::vector<EvidenceRecord>& records() const noexcept { return records_; }
  CRF_NODISCARD std::size_t size() const noexcept { return records_.size(); }
  CRF_NODISCARD bool truncated() const noexcept { return truncated_; }
  CRF_NODISCARD const EvidenceRecord* find(EvidenceId id) const noexcept;

 private:
  EvidenceRecord& append_entry(EvidenceRecord entry);

  std::vector<EvidenceRecord> records_;
  IdAllocator<EvidenceId> allocator_;
  bool truncated_ = false;
};

}  // namespace crf
