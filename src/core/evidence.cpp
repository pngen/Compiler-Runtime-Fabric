#include "crf/evidence.hpp"
#include "crf/canonical.hpp"

#include <algorithm>

namespace crf {

std::string_view to_string(EvidenceClass value) noexcept {
  switch (value) {
    case EvidenceClass::unknown: return "UNKNOWN";
    case EvidenceClass::real: return "REAL";
    case EvidenceClass::synthetic: return "SYNTHETIC";
    case EvidenceClass::unsupported: return "UNSUPPORTED";
  }
  return "UNKNOWN";
}

bool parse_evidence_class(std::string_view text, EvidenceClass& out) noexcept {
  if (equals_ascii_ci(text, "REAL")) { out = EvidenceClass::real; return true; }
  if (equals_ascii_ci(text, "SYNTHETIC")) { out = EvidenceClass::synthetic; return true; }
  if (equals_ascii_ci(text, "UNSUPPORTED")) { out = EvidenceClass::unsupported; return true; }
  if (equals_ascii_ci(text, "UNKNOWN")) { out = EvidenceClass::unknown; return true; }
  return false;
}

Digest EvidenceRecord::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(id.to_string());
  writer.u64(generation.value());
  writer.u8(static_cast<std::uint8_t>(evidence_class));
  writer.text(kind);
  writer.text(detail);
  writer.text(payload.to_hex());
  return Digest::of(writer.bytes());
}

EvidenceRecord& EvidenceLog::record_ref(EvidenceClass evidence_class, std::string kind,
                                        std::string detail, Digest payload) {
  EvidenceRecord entry;
  entry.id = allocator_.next();
  entry.generation = EvidenceGeneration::from_value(entry.id.value());
  entry.evidence_class = evidence_class;
  entry.kind = std::move(kind);
  if (detail.size() > kMaxDetailBytes) {
    detail.resize(kMaxDetailBytes);
    detail.append("...[truncated]");
  }
  entry.detail = std::move(detail);
  entry.payload = payload;
  entry.observed_at_nanos = monotonic_nanos();
  return append_entry(std::move(entry));
}

void EvidenceLog::record(EvidenceClass evidence_class, std::string kind, std::string detail,
                         Digest payload) {
  (void)record_ref(evidence_class, std::move(kind), std::move(detail), payload);
}

void EvidenceLog::observe(const EvidenceRecord& record) {
  EvidenceRecord copy = record;
  if (!copy.id.present()) {
    copy.id = allocator_.next();
  } else {
    allocator_.observe(copy.id);
  }
  if (!copy.generation.present()) {
    copy.generation = EvidenceGeneration::from_value(copy.id.value());
  }
  if (copy.detail.size() > kMaxDetailBytes) copy.detail.resize(kMaxDetailBytes);
  append_entry(std::move(copy));
}

const EvidenceRecord* EvidenceLog::find(EvidenceId id) const noexcept {
  for (const EvidenceRecord& entry : records_) {
    if (entry.id == id) return &entry;
  }
  return nullptr;
}

EvidenceRecord& EvidenceLog::append_entry(EvidenceRecord entry) {
  if (records_.size() >= kMaxRecords) {
    truncated_ = true;
    records_.erase(records_.begin());
  }
  records_.push_back(std::move(entry));
  return records_.back();
}

}  // namespace crf
