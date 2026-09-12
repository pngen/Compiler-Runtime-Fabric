#include "crf/persistence.hpp"
#include "crf/canonical.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <mutex>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#  include <windows.h>
#endif

namespace crf {
namespace {

constexpr char kJournalMagic[8] = {'C', 'R', 'F', 'J', 'R', 'N', 'L', '1'};
constexpr std::size_t kJournalHeaderBytes = 48;
constexpr std::uint32_t kRecordMagic = 0x43524652u;   // "CRFR"
constexpr std::size_t kRecordHeaderBytes = 40;
constexpr char kSnapshotMagic[8] = {'C', 'R', 'F', 'S', 'N', 'P', '0', '1'};
constexpr std::size_t kSnapshotHeaderBytes = 32;

constexpr std::size_t kMaxStringBytes = 8192;
constexpr std::size_t kMaxPathBytes = 32768;
constexpr std::size_t kMaxBlobBytes = 4u << 20;
constexpr std::size_t kMaxCollection = 1u << 16;

void put_u16(char* target, std::uint16_t value) {
  for (int i = 0; i < 2; ++i) target[i] = static_cast<char>((value >> (i * 8)) & 0xFFu);
}

void put_u32(char* target, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) target[i] = static_cast<char>((value >> (i * 8)) & 0xFFu);
}

void put_u64(char* target, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) target[i] = static_cast<char>((value >> (i * 8)) & 0xFFu);
}

CRF_NODISCARD std::uint16_t get_u16(const char* source) {
  std::uint16_t value = 0;
  for (int i = 0; i < 2; ++i) {
    value |= static_cast<std::uint16_t>(static_cast<unsigned char>(source[i])) << (i * 8);
  }
  return value;
}

CRF_NODISCARD std::uint32_t get_u32(const char* source) {
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(static_cast<unsigned char>(source[i])) << (i * 8);
  }
  return value;
}

CRF_NODISCARD std::uint64_t get_u64(const char* source) {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(static_cast<unsigned char>(source[i])) << (i * 8);
  }
  return value;
}

// ---------------------------------------------------------------------------
// Bounded encoder / decoder helpers. No persisted length is trusted before it
// is compared against a configured ceiling.
// ---------------------------------------------------------------------------
struct Encoder {
  CanonicalWriter writer;

  void u8(std::uint8_t value) { writer.u8(value); }
  void u16(std::uint16_t value) { writer.u16(value); }
  void u32(std::uint32_t value) { writer.u32(value); }
  void u64(std::uint64_t value) { writer.u64(value); }
  void i32(std::int32_t value) { writer.i32(value); }
  void b(bool value) { writer.boolean(value); }
  void str(std::string_view value) { writer.text(value); }
  void path(const std::filesystem::path& value) { writer.text(value.string()); }
  /// Digests are length-prefixed like every other variable-width field so that
  /// the decoder can validate the length before it reads the value.
  void digest(const Digest& value) { writer.text(value.to_hex()); }
  std::string take() { return writer.take(); }
};

struct RawRef {
  std::uint64_t id = 0;
  std::uint64_t generation = 0;
};

template <class IdType>
CRF_NODISCARD Referenced<IdType> make_reference(const RawRef& raw) {
  Referenced<IdType> out;
  out.id = IdType::from_value(raw.id);
  out.generation = Generation<typename IdType::tag_type>::from_value(raw.generation);
  return out;
}

struct Decoder {
  CanonicalReader reader;
  bool ok = true;

  explicit Decoder(std::string_view bytes) : reader(bytes) {}

  void fail() { ok = false; }
  CRF_NODISCARD bool good() const { return ok; }

  std::uint8_t u8() {
    std::uint8_t value = 0;
    if (!reader.u8(value)) fail();
    return value;
  }
  std::uint16_t u16() {
    std::uint16_t value = 0;
    if (!reader.u16(value)) fail();
    return value;
  }
  std::uint32_t u32() {
    std::uint32_t value = 0;
    if (!reader.u32(value)) fail();
    return value;
  }
  std::uint64_t u64() {
    std::uint64_t value = 0;
    if (!reader.u64(value)) fail();
    return value;
  }
  std::int32_t i32() {
    std::int32_t value = 0;
    if (!reader.i32(value)) fail();
    return value;
  }
  bool b() {
    bool value = false;
    if (!reader.boolean(value)) fail();
    return value;
  }
  std::string str(std::size_t bound = kMaxStringBytes) {
    std::string value;
    if (!reader.text(value, bound)) fail();
    return value;
  }
  std::string path() {
    std::string value;
    if (!reader.text(value, kMaxPathBytes)) fail();
    return value;
  }
  Digest digest() {
    std::string hex;
    if (!reader.text(hex, 64) || hex.size() != 64) {
      fail();
      return {};
    }
    Digest value;
    if (!Digest::from_hex(hex, value)) {
      fail();
      return {};
    }
    return value;
  }
  RawRef reference() {
    RawRef out;
    out.id = u64();
    out.generation = u64();
    return out;
  }
  CRF_NODISCARD std::size_t collection(std::size_t bound = kMaxCollection) {
    const std::uint64_t count = u64();
    if (count > bound) {
      fail();
      return 0;
    }
    return static_cast<std::size_t>(count);
  }
  CRF_NODISCARD bool exhausted() const { return reader.exhausted(); }

  template <class Enum>
  Enum enumeration(std::uint32_t raw, std::uint32_t maximum) {
    if (raw > maximum) {
      fail();
      return static_cast<Enum>(0);
    }
    return static_cast<Enum>(raw);
  }
};

CRF_NODISCARD Status malformed(const char* what) {
  return Status(StatusCode::persistence_corrupt,
                std::string("persisted state is malformed: ") + what);
}

// ---------------------------------------------------------------------------
// Record codecs.
// ---------------------------------------------------------------------------
void encode_attempt(Encoder& enc, const PhaseAttempt& attempt) {
  enc.u64(attempt.id.value());
  enc.u64(attempt.generation.value());
  enc.u64(attempt.invocation.id.value());
  enc.u64(attempt.invocation.generation.value());
  enc.u64(attempt.process_generation.value());
  enc.u32(attempt.os_process_id);
  enc.u8(static_cast<std::uint8_t>(attempt.terminal_state));
  enc.u8(static_cast<std::uint8_t>(attempt.failure));
  enc.u16(static_cast<std::uint16_t>(attempt.status));
  enc.i32(attempt.exit_code);
  enc.u64(attempt.started_at_nanos);
  enc.u64(attempt.finished_at_nanos);
  enc.digest(attempt.observed_output_digest);
  enc.str(attempt.detail);
}

void decode_attempt(Decoder& dec, PhaseAttempt& attempt) {
  attempt.id = AttemptId::from_value(dec.u64());
  attempt.generation = AttemptGeneration::from_value(dec.u64());
  attempt.invocation = make_reference<InvocationId>(RawRef{dec.u64(), dec.u64()});
  attempt.process_generation = ProcessGeneration::from_value(dec.u64());
  attempt.os_process_id = dec.u32();
  attempt.terminal_state = dec.enumeration<PhaseState>(dec.u8(), 12);
  attempt.failure = dec.enumeration<FailureClass>(dec.u8(), 15);
  attempt.status = dec.enumeration<StatusCode>(dec.u16(), 200);
  attempt.exit_code = dec.i32();
  attempt.started_at_nanos = dec.u64();
  attempt.finished_at_nanos = dec.u64();
  attempt.observed_output_digest = dec.digest();
  attempt.detail = dec.str();
}

void encode_diagnostic(Encoder& enc, const Diagnostic& entry) {
  enc.u8(static_cast<std::uint8_t>(entry.severity));
  enc.str(entry.code);
  enc.str(entry.message);
  enc.str(entry.file);
  enc.u32(entry.line);
  enc.u32(entry.column);
  enc.str(entry.origin);
  enc.str(entry.raw);
}

void decode_diagnostic(Decoder& dec, Diagnostic& entry) {
  entry.severity = dec.enumeration<DiagnosticSeverity>(dec.u8(), 5);
  entry.code = dec.str();
  entry.message = dec.str();
  entry.file = dec.str();
  entry.line = dec.u32();
  entry.column = dec.u32();
  entry.origin = dec.str();
  entry.raw = dec.str(kMaxBlobBytes);
}

}  // namespace

// ---------------------------------------------------------------------------
// Public record-kind and outcome helpers.
// ---------------------------------------------------------------------------
std::string_view to_string(RecordKind value) noexcept {
  switch (value) {
    case RecordKind::unknown: return "unknown";
    case RecordKind::epoch_advanced: return "epoch-advanced";
    case RecordKind::toolchain_registered: return "toolchain-registered";
    case RecordKind::target_registered: return "target-registered";
    case RecordKind::environment_registered: return "environment-registered";
    case RecordKind::policy_registered: return "policy-registered";
    case RecordKind::source_registered: return "source-registered";
    case RecordKind::session_created: return "session-created";
    case RecordKind::session_state_changed: return "session-state-changed";
    case RecordKind::phase_reserved: return "phase-reserved";
    case RecordKind::phase_state_changed: return "phase-state-changed";
    case RecordKind::phase_committed: return "phase-committed";
    case RecordKind::phase_refused: return "phase-refused";
    case RecordKind::artifact_registered: return "artifact-registered";
    case RecordKind::artifact_authority_changed: return "artifact-authority-changed";
    case RecordKind::diagnostics_recorded: return "diagnostics-recorded";
    case RecordKind::candidate_registered: return "candidate-registered";
    case RecordKind::recovery_decided: return "recovery-decided";
    case RecordKind::provenance_appended: return "provenance-appended";
    case RecordKind::session_retired: return "session-retired";
    case RecordKind::lease_granted: return "lease-granted";
    case RecordKind::lease_revoked: return "lease-revoked";
  }
  return "unknown";
}

bool parse_record_kind(std::uint16_t raw, RecordKind& out) noexcept {
  if (raw > static_cast<std::uint16_t>(RecordKind::lease_revoked)) return false;
  out = static_cast<RecordKind>(raw);
  return true;
}

std::string_view to_string(LoadOutcome value) noexcept {
  switch (value) {
    case LoadOutcome::ok: return "ok";
    case LoadOutcome::empty: return "empty";
    case LoadOutcome::torn_tail_repaired: return "torn-tail-repaired";
    case LoadOutcome::corrupt: return "corrupt";
    case LoadOutcome::schema_mismatch: return "schema-mismatch";
    case LoadOutcome::io_error: return "io-error";
    case LoadOutcome::bounds_exceeded: return "bounds-exceeded";
  }
  return "unknown";
}

Digest JournalRecord::payload_digest() const { return Digest::of(payload); }

// ---------------------------------------------------------------------------
// Phase codec.
// ---------------------------------------------------------------------------
std::string encode_phase(const PhaseRecord& phase) {
  Encoder enc;
  enc.u16(kPersistenceSchemaVersion);
  enc.u64(phase.id.value());
  enc.u64(phase.generation.value());
  enc.u8(static_cast<std::uint8_t>(phase.kind));
  enc.str(phase.adapter_phase);
  enc.u8(static_cast<std::uint8_t>(phase.state));
  enc.b(phase.mandatory);
  enc.u64(phase.session_generation.value());
  enc.u64(phase.compilation_generation.value());
  enc.u64(phase.attempt_generation.value());
  enc.u64(phase.toolchain.id.value());
  enc.u64(phase.toolchain.generation.value());
  enc.u64(phase.target.id.value());
  enc.u64(phase.target.generation.value());
  enc.u64(phase.environment.id.value());
  enc.u64(phase.environment.generation.value());
  enc.u64(phase.policy.id.value());
  enc.u64(phase.policy.generation.value());
  enc.u64(phase.source.id.value());
  enc.u64(phase.source.generation.value());
  enc.u64(phase.ir_generation.value());
  enc.u64(phase.lease.id.value());
  enc.u64(phase.lease.generation.value());
  enc.u64(phase.active_invocation.id.value());
  enc.u64(phase.active_invocation.generation.value());
  enc.u64(phase.active_process.value());
  enc.u64(phase.active_process_generation.value());
  enc.u64(phase.diagnostics.id.value());
  enc.u64(phase.diagnostics.generation.value());
  enc.u64(phase.commit.value());
  enc.digest(phase.committed_output_digest);
  enc.u64(phase.committed_at_nanos);
  enc.u8(static_cast<std::uint8_t>(phase.failure));
  enc.u16(static_cast<std::uint16_t>(phase.last_status));
  enc.str(phase.last_detail);
  enc.u64(phase.recovery.value());
  enc.u64(phase.recovery_generation.value());
  enc.u64(phase.depends_on.size());
  for (const CompilerPhaseId dependency : phase.depends_on) enc.u64(dependency.value());
  enc.u64(phase.inputs.size());
  for (const Ref<IntermediateArtifactId>& input : phase.inputs) {
    enc.u64(input.id.value());
    enc.u64(input.generation.value());
  }
  enc.u64(phase.outputs.size());
  for (const Ref<IntermediateArtifactId>& output : phase.outputs) {
    enc.u64(output.id.value());
    enc.u64(output.generation.value());
  }
  enc.u64(phase.attempts.size());
  for (const PhaseAttempt& attempt : phase.attempts) encode_attempt(enc, attempt);
  enc.u64(phase.history.size());
  for (const PhaseTransition& transition : phase.history) {
    enc.u8(static_cast<std::uint8_t>(transition.from));
    enc.u8(static_cast<std::uint8_t>(transition.to));
    enc.u64(transition.at_nanos);
    enc.str(transition.reason);
  }
  return enc.take();
}

Result<PhaseRecord> decode_phase(std::string_view bytes) {
  Decoder dec(bytes);
  const std::uint16_t schema = dec.u16();
  if (!dec.good()) return malformed("phase header");
  if (schema != kPersistenceSchemaVersion) {
    return Status(StatusCode::persistence_schema_mismatch, "phase schema version mismatch");
  }
  PhaseRecord phase;
  phase.id = CompilerPhaseId::from_value(dec.u64());
  phase.generation = CompilerPhaseGeneration::from_value(dec.u64());
  phase.kind = dec.enumeration<PhaseKind>(dec.u8(), 16);
  phase.adapter_phase = dec.str();
  phase.state = dec.enumeration<PhaseState>(dec.u8(), 12);
  phase.mandatory = dec.b();
  phase.session_generation = CompilerSessionGeneration::from_value(dec.u64());
  phase.compilation_generation = CompilationGeneration::from_value(dec.u64());
  phase.attempt_generation = AttemptGeneration::from_value(dec.u64());
  phase.toolchain = make_reference<ToolchainId>(RawRef{dec.u64(), dec.u64()});
  phase.target = make_reference<TargetId>(RawRef{dec.u64(), dec.u64()});
  phase.environment = make_reference<EnvironmentId>(RawRef{dec.u64(), dec.u64()});
  phase.policy = make_reference<PolicyId>(RawRef{dec.u64(), dec.u64()});
  phase.source = make_reference<SourceId>(RawRef{dec.u64(), dec.u64()});
  phase.ir_generation = IRGeneration::from_value(dec.u64());
  phase.lease = make_reference<LeaseId>(RawRef{dec.u64(), dec.u64()});
  phase.active_invocation = make_reference<InvocationId>(RawRef{dec.u64(), dec.u64()});
  phase.active_process = ProcessId::from_value(dec.u64());
  phase.active_process_generation = ProcessGeneration::from_value(dec.u64());
  phase.diagnostics = make_reference<DiagnosticSetId>(RawRef{dec.u64(), dec.u64()});
  phase.commit = CommitId::from_value(dec.u64());
  phase.committed_output_digest = dec.digest();
  phase.committed_at_nanos = dec.u64();
  phase.failure = dec.enumeration<FailureClass>(dec.u8(), 15);
  phase.last_status = dec.enumeration<StatusCode>(dec.u16(), 200);
  phase.last_detail = dec.str();
  phase.recovery = RecoveryId::from_value(dec.u64());
  phase.recovery_generation = RecoveryGeneration::from_value(dec.u64());
  if (!dec.good()) return malformed("phase body");

  const std::size_t dependency_count = dec.collection();
  for (std::size_t i = 0; i < dependency_count && dec.good(); ++i) {
    phase.depends_on.push_back(CompilerPhaseId::from_value(dec.u64()));
  }
  const std::size_t input_count = dec.collection();
  for (std::size_t i = 0; i < input_count && dec.good(); ++i) {
    phase.inputs.push_back(make_reference<IntermediateArtifactId>(RawRef{dec.u64(), dec.u64()}));
  }
  const std::size_t output_count = dec.collection();
  for (std::size_t i = 0; i < output_count && dec.good(); ++i) {
    phase.outputs.push_back(make_reference<IntermediateArtifactId>(RawRef{dec.u64(), dec.u64()}));
  }
  const std::size_t attempt_count = dec.collection(kMaxPhaseAttempts);
  for (std::size_t i = 0; i < attempt_count && dec.good(); ++i) {
    PhaseAttempt attempt;
    decode_attempt(dec, attempt);
    phase.attempts.push_back(std::move(attempt));
  }
  const std::size_t transition_count = dec.collection(kMaxPhaseTransitions);
  for (std::size_t i = 0; i < transition_count && dec.good(); ++i) {
    PhaseTransition transition;
    transition.from = dec.enumeration<PhaseState>(dec.u8(), 12);
    transition.to = dec.enumeration<PhaseState>(dec.u8(), 12);
    transition.at_nanos = dec.u64();
    transition.reason = dec.str();
    phase.history.push_back(std::move(transition));
  }
  if (!dec.good()) return malformed("phase collections");
  if (!dec.exhausted()) return malformed("phase has trailing bytes");
  return phase;
}

// ---------------------------------------------------------------------------
// Artifact codec.
// ---------------------------------------------------------------------------
std::string encode_artifact(const IntermediateArtifact& artifact) {
  Encoder enc;
  enc.u16(kPersistenceSchemaVersion);
  enc.u64(artifact.id.value());
  enc.u64(artifact.generation.value());
  enc.u8(static_cast<std::uint8_t>(artifact.format));
  enc.path(artifact.path);
  enc.digest(artifact.content);
  enc.u64(artifact.size_bytes);
  enc.u64(artifact.producer_phase.id.value());
  enc.u64(artifact.producer_phase.generation.value());
  enc.u64(artifact.producer_invocation.id.value());
  enc.u64(artifact.producer_invocation.generation.value());
  enc.u64(artifact.toolchain.id.value());
  enc.u64(artifact.toolchain.generation.value());
  enc.u64(artifact.target.id.value());
  enc.u64(artifact.target.generation.value());
  enc.u64(artifact.source.id.value());
  enc.u64(artifact.source.generation.value());
  enc.u64(artifact.ir_generation.value());
  enc.u64(artifact.environment.id.value());
  enc.u64(artifact.environment.generation.value());
  enc.u64(artifact.policy.id.value());
  enc.u64(artifact.policy.generation.value());
  enc.u64(artifact.provenance.value());
  enc.u8(static_cast<std::uint8_t>(artifact.state));
  enc.u8(static_cast<std::uint8_t>(artifact.authority));
  enc.b(artifact.current);
  enc.digest(artifact.declared_digest);
  enc.str(artifact.validation_detail);
  enc.u64(artifact.lineage_inputs.size());
  for (const Ref<IntermediateArtifactId>& input : artifact.lineage_inputs) {
    enc.u64(input.id.value());
    enc.u64(input.generation.value());
  }
  return enc.take();
}

Result<IntermediateArtifact> decode_artifact(std::string_view bytes) {
  Decoder dec(bytes);
  const std::uint16_t schema = dec.u16();
  if (!dec.good()) return malformed("artifact header");
  if (schema != kPersistenceSchemaVersion) {
    return Status(StatusCode::persistence_schema_mismatch, "artifact schema version mismatch");
  }
  IntermediateArtifact artifact;
  artifact.id = IntermediateArtifactId::from_value(dec.u64());
  artifact.generation = IntermediateArtifactGeneration::from_value(dec.u64());
  artifact.format = dec.enumeration<ObjectFormat>(dec.u8(), 12);
  artifact.path = dec.path();
  artifact.content = dec.digest();
  artifact.size_bytes = dec.u64();
  artifact.producer_phase = make_reference<CompilerPhaseId>(RawRef{dec.u64(), dec.u64()});
  artifact.producer_invocation = make_reference<InvocationId>(RawRef{dec.u64(), dec.u64()});
  artifact.toolchain = make_reference<ToolchainId>(RawRef{dec.u64(), dec.u64()});
  artifact.target = make_reference<TargetId>(RawRef{dec.u64(), dec.u64()});
  artifact.source = make_reference<SourceId>(RawRef{dec.u64(), dec.u64()});
  artifact.ir_generation = IRGeneration::from_value(dec.u64());
  artifact.environment = make_reference<EnvironmentId>(RawRef{dec.u64(), dec.u64()});
  artifact.policy = make_reference<PolicyId>(RawRef{dec.u64(), dec.u64()});
  artifact.provenance = ProvenanceId::from_value(dec.u64());
  artifact.state = dec.enumeration<ArtifactState>(dec.u8(), 6);
  artifact.authority = dec.enumeration<AuthorityState>(dec.u8(), 3);
  artifact.current = dec.b();
  artifact.declared_digest = dec.digest();
  artifact.validation_detail = dec.str();
  const std::size_t lineage_count = dec.collection();
  for (std::size_t i = 0; i < lineage_count && dec.good(); ++i) {
    artifact.lineage_inputs.push_back(
        make_reference<IntermediateArtifactId>(RawRef{dec.u64(), dec.u64()}));
  }
  if (!dec.good()) return malformed("artifact body");
  if (!dec.exhausted()) return malformed("artifact has trailing bytes");
  return artifact;
}

// ---------------------------------------------------------------------------
// Diagnostic set codec.
// ---------------------------------------------------------------------------
std::string encode_diagnostic_set(const DiagnosticSet& set) {
  Encoder enc;
  enc.u16(kPersistenceSchemaVersion);
  enc.u64(set.id.value());
  enc.u64(set.generation.value());
  enc.u64(set.invocation.id.value());
  enc.u64(set.invocation.generation.value());
  enc.u64(set.phase.id.value());
  enc.u64(set.phase.generation.value());
  enc.u64(set.toolchain.id.value());
  enc.u64(set.toolchain.generation.value());
  enc.u64(set.target.id.value());
  enc.u64(set.target.generation.value());
  enc.b(set.normalized);
  enc.b(set.truncated);
  enc.u64(set.raw_stdout_bytes);
  enc.u64(set.raw_stderr_bytes);
  enc.u64(set.dropped_stdout_bytes);
  enc.u64(set.dropped_stderr_bytes);
  enc.i32(set.exit_code);
  enc.b(set.process_crashed);
  enc.u32(set.error_count);
  enc.u32(set.warning_count);
  enc.str(set.raw_stdout_tail);
  enc.str(set.raw_stderr_tail);
  enc.u64(set.entries.size());
  for (const Diagnostic& entry : set.entries) encode_diagnostic(enc, entry);
  return enc.take();
}

Result<DiagnosticSet> decode_diagnostic_set(std::string_view bytes) {
  Decoder dec(bytes);
  const std::uint16_t schema = dec.u16();
  if (!dec.good()) return malformed("diagnostic set header");
  if (schema != kPersistenceSchemaVersion) {
    return Status(StatusCode::persistence_schema_mismatch, "diagnostic schema version mismatch");
  }
  DiagnosticSet set;
  set.id = DiagnosticSetId::from_value(dec.u64());
  set.generation = DiagnosticGeneration::from_value(dec.u64());
  set.invocation = make_reference<InvocationId>(RawRef{dec.u64(), dec.u64()});
  set.phase = make_reference<CompilerPhaseId>(RawRef{dec.u64(), dec.u64()});
  set.toolchain = make_reference<ToolchainId>(RawRef{dec.u64(), dec.u64()});
  set.target = make_reference<TargetId>(RawRef{dec.u64(), dec.u64()});
  set.normalized = dec.b();
  set.truncated = dec.b();
  set.raw_stdout_bytes = dec.u64();
  set.raw_stderr_bytes = dec.u64();
  set.dropped_stdout_bytes = dec.u64();
  set.dropped_stderr_bytes = dec.u64();
  set.exit_code = dec.i32();
  set.process_crashed = dec.b();
  set.error_count = dec.u32();
  set.warning_count = dec.u32();
  set.raw_stdout_tail = dec.str(DiagnosticSet::kMaxRawTailBytes);
  set.raw_stderr_tail = dec.str(DiagnosticSet::kMaxRawTailBytes);
  const std::size_t entry_count = dec.collection(DiagnosticSet::kMaxEntries);
  for (std::size_t i = 0; i < entry_count && dec.good(); ++i) {
    Diagnostic entry;
    decode_diagnostic(dec, entry);
    set.entries.push_back(std::move(entry));
  }
  if (!dec.good()) return malformed("diagnostic set body");
  if (!dec.exhausted()) return malformed("diagnostic set has trailing bytes");
  return set;
}

// ---------------------------------------------------------------------------
// Candidate codec.
// ---------------------------------------------------------------------------
std::string encode_candidate(const FinalCandidate& candidate) {
  Encoder enc;
  enc.u16(kPersistenceSchemaVersion);
  enc.u64(candidate.id.value());
  enc.u64(candidate.generation.value());
  enc.u64(candidate.compilation.value());
  enc.u64(candidate.compilation_generation.value());
  enc.u64(candidate.attempt_generation.value());
  enc.u64(candidate.session.id.value());
  enc.u64(candidate.session.generation.value());
  enc.u64(candidate.toolchain.id.value());
  enc.u64(candidate.toolchain.generation.value());
  enc.u64(candidate.target.id.value());
  enc.u64(candidate.target.generation.value());
  enc.u64(candidate.environment.id.value());
  enc.u64(candidate.environment.generation.value());
  enc.u64(candidate.policy.id.value());
  enc.u64(candidate.policy.generation.value());
  enc.u64(candidate.source.id.value());
  enc.u64(candidate.source.generation.value());
  enc.u64(candidate.ir_generation.value());
  enc.u8(static_cast<std::uint8_t>(candidate.format));
  enc.path(candidate.path);
  enc.digest(candidate.content);
  enc.u64(candidate.size_bytes);
  enc.u64(candidate.provenance.value());
  enc.digest(candidate.lineage_digest);
  enc.b(candidate.complete_lineage);
  enc.b(candidate.handed_off);
  enc.u64(candidate.registered_at_nanos);
  enc.u64(candidate.lineage.size());
  for (const Ref<IntermediateArtifactId>& entry : candidate.lineage) {
    enc.u64(entry.id.value());
    enc.u64(entry.generation.value());
  }
  enc.u64(candidate.validation_evidence.size());
  for (const EvidenceId evidence : candidate.validation_evidence) enc.u64(evidence.value());
  return enc.take();
}

Result<FinalCandidate> decode_candidate(std::string_view bytes) {
  Decoder dec(bytes);
  const std::uint16_t schema = dec.u16();
  if (!dec.good()) return malformed("candidate header");
  if (schema != kPersistenceSchemaVersion) {
    return Status(StatusCode::persistence_schema_mismatch, "candidate schema version mismatch");
  }
  FinalCandidate candidate;
  candidate.id = FinalArtifactId::from_value(dec.u64());
  candidate.generation = FinalArtifactGeneration::from_value(dec.u64());
  candidate.compilation = CompilationId::from_value(dec.u64());
  candidate.compilation_generation = CompilationGeneration::from_value(dec.u64());
  candidate.attempt_generation = AttemptGeneration::from_value(dec.u64());
  candidate.session = make_reference<CompilerSessionId>(RawRef{dec.u64(), dec.u64()});
  candidate.toolchain = make_reference<ToolchainId>(RawRef{dec.u64(), dec.u64()});
  candidate.target = make_reference<TargetId>(RawRef{dec.u64(), dec.u64()});
  candidate.environment = make_reference<EnvironmentId>(RawRef{dec.u64(), dec.u64()});
  candidate.policy = make_reference<PolicyId>(RawRef{dec.u64(), dec.u64()});
  candidate.source = make_reference<SourceId>(RawRef{dec.u64(), dec.u64()});
  candidate.ir_generation = IRGeneration::from_value(dec.u64());
  candidate.format = dec.enumeration<ObjectFormat>(dec.u8(), 12);
  candidate.path = dec.path();
  candidate.content = dec.digest();
  candidate.size_bytes = dec.u64();
  candidate.provenance = ProvenanceId::from_value(dec.u64());
  candidate.lineage_digest = dec.digest();
  candidate.complete_lineage = dec.b();
  candidate.handed_off = dec.b();
  candidate.registered_at_nanos = dec.u64();
  const std::size_t lineage_count = dec.collection();
  for (std::size_t i = 0; i < lineage_count && dec.good(); ++i) {
    candidate.lineage.push_back(
        make_reference<IntermediateArtifactId>(RawRef{dec.u64(), dec.u64()}));
  }
  const std::size_t evidence_count = dec.collection();
  for (std::size_t i = 0; i < evidence_count && dec.good(); ++i) {
    candidate.validation_evidence.push_back(EvidenceId::from_value(dec.u64()));
  }
  if (!dec.good()) return malformed("candidate body");
  if (!dec.exhausted()) return malformed("candidate has trailing bytes");
  return candidate;
}

// ---------------------------------------------------------------------------
// Plan codec.
// ---------------------------------------------------------------------------
std::string encode_plan(const PhasePlan& plan) {
  Encoder enc;
  enc.u16(kPersistenceSchemaVersion);
  enc.u64(plan.nodes().size());
  for (const PhaseNode& node : plan.nodes()) {
    enc.u64(node.id.value());
    enc.u8(static_cast<std::uint8_t>(node.kind));
    enc.str(node.adapter_phase);
    enc.b(node.mandatory);
    enc.b(node.fan_in);
    enc.u64(node.required_inputs);
    enc.u64(node.depends_on.size());
    for (const CompilerPhaseId dependency : node.depends_on) enc.u64(dependency.value());
    enc.u64(node.expected_outputs.size());
    for (const ObjectFormat format : node.expected_outputs) enc.u8(static_cast<std::uint8_t>(format));
  }
  return enc.take();
}

Result<PhasePlan> decode_plan(std::string_view bytes) {
  Decoder dec(bytes);
  const std::uint16_t schema = dec.u16();
  if (!dec.good()) return malformed("plan header");
  if (schema != kPersistenceSchemaVersion) {
    return Status(StatusCode::persistence_schema_mismatch, "plan schema version mismatch");
  }
  const std::size_t node_count = dec.collection(PhasePlan::kMaxPhases);
  std::vector<PhaseNode> nodes;
  nodes.reserve(node_count);
  for (std::size_t i = 0; i < node_count && dec.good(); ++i) {
    PhaseNode node;
    node.id = CompilerPhaseId::from_value(dec.u64());
    node.kind = dec.enumeration<PhaseKind>(dec.u8(), 16);
    node.adapter_phase = dec.str();
    node.mandatory = dec.b();
    node.fan_in = dec.b();
    node.required_inputs = dec.collection();
    const std::size_t dependency_count = dec.collection();
    for (std::size_t d = 0; d < dependency_count && dec.good(); ++d) {
      node.depends_on.push_back(CompilerPhaseId::from_value(dec.u64()));
    }
    const std::size_t format_count = dec.collection();
    for (std::size_t f = 0; f < format_count && dec.good(); ++f) {
      node.expected_outputs.push_back(dec.enumeration<ObjectFormat>(dec.u8(), 12));
    }
    nodes.push_back(std::move(node));
  }
  if (!dec.good()) return malformed("plan body");
  if (!dec.exhausted()) return malformed("plan has trailing bytes");
  return PhasePlan::build(std::move(nodes));
}

// ---------------------------------------------------------------------------
// Session codec.
// ---------------------------------------------------------------------------
std::string encode_session(const CompilerSession& session) {
  Encoder enc;
  enc.u16(kPersistenceSchemaVersion);
  enc.u64(session.id.value());
  enc.u64(session.generation.value());
  enc.u8(static_cast<std::uint8_t>(session.state));
  enc.u8(static_cast<std::uint8_t>(session.recovery_state));
  enc.u64(session.request.value());
  enc.u64(session.compilation.value());
  enc.u64(session.compilation_generation.value());
  enc.u64(session.attempt.value());
  enc.u64(session.attempt_generation.value());
  enc.u64(session.toolchain.id.value());
  enc.u64(session.toolchain.generation.value());
  enc.u64(session.target.id.value());
  enc.u64(session.target.generation.value());
  enc.u64(session.environment.id.value());
  enc.u64(session.environment.generation.value());
  enc.u64(session.policy.id.value());
  enc.u64(session.policy.generation.value());
  enc.u64(session.source.id.value());
  enc.u64(session.source.generation.value());
  enc.u64(session.ir_generation.value());
  enc.str(session.adapter_name);
  enc.str(session.final_artifact_name);
  enc.u64(session.adapter_options.size());
  for (const EnvironmentVariable& option : session.adapter_options) {
    enc.str(option.name);
    enc.str(option.value);
  }
  enc.u64(session.cooperating_toolchains.size());
  for (const Ref<ToolchainId>& entry : session.cooperating_toolchains) {
    enc.u64(entry.id.value());
    enc.u64(entry.generation.value());
  }
  enc.u64(session.sources.size());
  for (const Ref<SourceId>& entry : session.sources) {
    enc.u64(entry.id.value());
    enc.u64(entry.generation.value());
  }
  const std::string plan_bytes = encode_plan(session.plan);
  enc.str(plan_bytes);
  enc.u64(session.phases.size());
  std::vector<const PhaseRecord*> ordered;
  ordered.reserve(session.phases.size());
  for (const auto& [key, phase] : session.phases) {
    (void)key;
    ordered.push_back(&phase);
  }
  std::sort(ordered.begin(), ordered.end(),
            [](const PhaseRecord* a, const PhaseRecord* b) { return a->id < b->id; });
  for (const PhaseRecord* phase : ordered) enc.str(encode_phase(*phase));
  enc.u64(session.current_phase.value());
  enc.u64(session.intermediates.size());
  for (const Ref<IntermediateArtifactId>& entry : session.intermediates) {
    enc.u64(entry.id.value());
    enc.u64(entry.generation.value());
  }
  enc.b(session.candidate_present);
  enc.str(encode_candidate(session.candidate));
  enc.u64(session.recovery.value());
  enc.u64(session.recovery_generation.value());
  enc.u64(session.evidence_generation.value());
  enc.u64(session.epoch.value());
  enc.str(session.failure_detail);
  enc.u64(session.created_at_nanos);
  enc.u64(session.updated_at_nanos);
  enc.u32(session.session_retries_used);
  enc.digest(session.request_digest);
  return enc.take();
}

Result<CompilerSession> decode_session(std::string_view bytes) {
  Decoder dec(bytes);
  const std::uint16_t schema = dec.u16();
  if (!dec.good()) return malformed("session header");
  if (schema != kPersistenceSchemaVersion) {
    return Status(StatusCode::persistence_schema_mismatch, "session schema version mismatch");
  }
  CompilerSession session;
  session.id = CompilerSessionId::from_value(dec.u64());
  session.generation = CompilerSessionGeneration::from_value(dec.u64());
  session.state = dec.enumeration<SessionState>(dec.u8(), 6);
  session.recovery_state = dec.enumeration<RecoveryState>(dec.u8(), 6);
  session.request = RequestId::from_value(dec.u64());
  session.compilation = CompilationId::from_value(dec.u64());
  session.compilation_generation = CompilationGeneration::from_value(dec.u64());
  session.attempt = AttemptId::from_value(dec.u64());
  session.attempt_generation = AttemptGeneration::from_value(dec.u64());
  session.toolchain = make_reference<ToolchainId>(RawRef{dec.u64(), dec.u64()});
  session.target = make_reference<TargetId>(RawRef{dec.u64(), dec.u64()});
  session.environment = make_reference<EnvironmentId>(RawRef{dec.u64(), dec.u64()});
  session.policy = make_reference<PolicyId>(RawRef{dec.u64(), dec.u64()});
  session.source = make_reference<SourceId>(RawRef{dec.u64(), dec.u64()});
  session.ir_generation = IRGeneration::from_value(dec.u64());
  session.adapter_name = dec.str();
  session.final_artifact_name = dec.str();
  const std::size_t option_count = dec.collection(1024);
  for (std::size_t i = 0; i < option_count && dec.good(); ++i) {
    EnvironmentVariable option;
    option.name = dec.str();
    option.value = dec.str();
    session.adapter_options.push_back(std::move(option));
  }
  const std::size_t cooperating_count = dec.collection();
  for (std::size_t i = 0; i < cooperating_count && dec.good(); ++i) {
    session.cooperating_toolchains.push_back(
        make_reference<ToolchainId>(RawRef{dec.u64(), dec.u64()}));
  }
  const std::size_t source_count = dec.collection(SourceRegistry::kMaxSources);
  for (std::size_t i = 0; i < source_count && dec.good(); ++i) {
    session.sources.push_back(make_reference<SourceId>(RawRef{dec.u64(), dec.u64()}));
  }
  const std::string plan_bytes = dec.str(kMaxBlobBytes);
  if (!dec.good()) return malformed("session body");
  const Result<PhasePlan> plan = decode_plan(plan_bytes);
  if (!plan) return plan.status();
  session.plan = plan.value();

  const std::size_t phase_count = dec.collection(PhasePlan::kMaxPhases);
  for (std::size_t i = 0; i < phase_count && dec.good(); ++i) {
    const std::string phase_bytes = dec.str(kMaxBlobBytes);
    if (!dec.good()) break;
    const Result<PhaseRecord> phase = decode_phase(phase_bytes);
    if (!phase) return phase.status();
    session.phases.emplace(phase.value().id.value(), phase.value());
  }
  session.current_phase = CompilerPhaseId::from_value(dec.u64());
  const std::size_t intermediate_count = dec.collection(ArtifactRegistry::kMaxArtifacts);
  for (std::size_t i = 0; i < intermediate_count && dec.good(); ++i) {
    session.intermediates.push_back(
        make_reference<IntermediateArtifactId>(RawRef{dec.u64(), dec.u64()}));
  }
  session.candidate_present = dec.b();
  const std::string candidate_bytes = dec.str(kMaxBlobBytes);
  if (!dec.good()) return malformed("session candidate");
  const Result<FinalCandidate> candidate = decode_candidate(candidate_bytes);
  if (!candidate) return candidate.status();
  session.candidate = candidate.value();
  session.recovery = RecoveryId::from_value(dec.u64());
  session.recovery_generation = RecoveryGeneration::from_value(dec.u64());
  session.evidence_generation = EvidenceGeneration::from_value(dec.u64());
  session.epoch = EpochId::from_value(dec.u64());
  session.failure_detail = dec.str();
  session.created_at_nanos = dec.u64();
  session.updated_at_nanos = dec.u64();
  session.session_retries_used = dec.u32();
  session.request_digest = dec.digest();
  if (!dec.good()) return malformed("session tail");
  if (!dec.exhausted()) return malformed("session has trailing bytes");
  return session;
}

// ---------------------------------------------------------------------------
// Snapshot envelope.
// ---------------------------------------------------------------------------
std::string StateSnapshot::encode() const {
  Encoder enc;
  enc.u16(schema_version);
  enc.u64(runtime_epoch);
  enc.u64(last_sequence);
  enc.u64(encoded_sessions.size());
  for (const std::string& entry : encoded_sessions) enc.str(entry);
  enc.u64(encoded_artifacts.size());
  for (const std::string& entry : encoded_artifacts) enc.str(entry);
  enc.u64(encoded_diagnostics.size());
  for (const std::string& entry : encoded_diagnostics) enc.str(entry);
  return enc.take();
}

Result<StateSnapshot> StateSnapshot::decode(std::string_view bytes) {
  Decoder dec(bytes);
  StateSnapshot snapshot;
  snapshot.schema_version = dec.u16();
  if (!dec.good()) return malformed("snapshot header");
  if (snapshot.schema_version != kPersistenceSchemaVersion) {
    return Status(StatusCode::persistence_schema_mismatch, "snapshot schema version mismatch");
  }
  snapshot.runtime_epoch = dec.u64();
  snapshot.last_sequence = dec.u64();
  const std::size_t session_count = dec.collection();
  for (std::size_t i = 0; i < session_count && dec.good(); ++i) {
    snapshot.encoded_sessions.push_back(dec.str(kMaxBlobBytes));
  }
  const std::size_t artifact_count = dec.collection(ArtifactRegistry::kMaxArtifacts);
  for (std::size_t i = 0; i < artifact_count && dec.good(); ++i) {
    snapshot.encoded_artifacts.push_back(dec.str(kMaxBlobBytes));
  }
  const std::size_t diagnostic_count = dec.collection(DiagnosticStore::kMaxSets);
  for (std::size_t i = 0; i < diagnostic_count && dec.good(); ++i) {
    snapshot.encoded_diagnostics.push_back(dec.str(kMaxBlobBytes));
  }
  if (!dec.good()) return malformed("snapshot body");
  if (!dec.exhausted()) return malformed("snapshot has trailing bytes");
  return snapshot;
}

// ---------------------------------------------------------------------------
// Journal and snapshot storage.
// ---------------------------------------------------------------------------
namespace {

struct JournalScan {
  LoadOutcome outcome = LoadOutcome::empty;
  std::uint64_t last_sequence = 0;
  std::uint64_t valid_bytes = 0;
  std::uint64_t repaired_bytes = 0;
  std::uint64_t bytes_read = 0;
  std::vector<JournalRecord> records;
  std::string detail;
};

CRF_NODISCARD std::vector<char> read_whole_file(const std::filesystem::path& path, std::size_t bound,
                                                bool& too_large, bool& missing) {
  too_large = false;
  missing = false;
  std::error_code ec;
  if (!std::filesystem::exists(path, ec) || ec) {
    missing = true;
    return {};
  }
  const std::uintmax_t size = std::filesystem::file_size(path, ec);
  if (ec) {
    missing = true;
    return {};
  }
  if (size > bound) {
    too_large = true;
    return {};
  }
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    missing = true;
    return {};
  }
  std::vector<char> bytes(static_cast<std::size_t>(size));
  if (size != 0) {
    stream.read(bytes.data(), static_cast<std::streamsize>(size));
    bytes.resize(static_cast<std::size_t>(stream.gcount()));
  }
  return bytes;
}

CRF_NODISCARD std::string journal_header_bytes(std::uint64_t epoch, std::uint64_t created_nanos) {
  std::string header(kJournalHeaderBytes, '\0');
  std::memcpy(header.data(), kJournalMagic, sizeof(kJournalMagic));
  put_u16(header.data() + 8, kPersistenceSchemaVersion);
  put_u16(header.data() + 10, 0);
  put_u32(header.data() + 12, 0);
  put_u64(header.data() + 16, epoch);
  put_u64(header.data() + 24, created_nanos);
  put_u32(header.data() + 32,
          crc32c(std::string_view(header.data(), 32)));
  put_u32(header.data() + 36, 0);
  put_u32(header.data() + 40, 0);
  put_u32(header.data() + 44, 0);
  return header;
}

CRF_NODISCARD bool valid_journal_header(std::string_view header, std::uint64_t& epoch,
                                        std::uint64_t& created_nanos) {
  if (header.size() < kJournalHeaderBytes) return false;
  if (std::memcmp(header.data(), kJournalMagic, sizeof(kJournalMagic)) != 0) return false;
  if (get_u16(header.data() + 8) != kPersistenceSchemaVersion) return false;
  const std::uint32_t expected = get_u32(header.data() + 32);
  if (expected != crc32c(header.substr(0, 32))) return false;
  epoch = get_u64(header.data() + 16);
  created_nanos = get_u64(header.data() + 24);
  return true;
}

CRF_NODISCARD JournalScan scan_journal(std::string_view bytes, const PersistenceOptions& options,
                                       bool repair_tail) {
  JournalScan scan;
  scan.bytes_read = bytes.size();
  if (bytes.size() < kJournalHeaderBytes) {
    scan.outcome = LoadOutcome::empty;
    scan.detail = "journal header is absent";
    return scan;
  }
  std::uint64_t epoch = 0;
  std::uint64_t created = 0;
  if (!valid_journal_header(bytes.substr(0, kJournalHeaderBytes), epoch, created)) {
    scan.outcome = LoadOutcome::corrupt;
    scan.detail = "journal header failed integrity validation";
    return scan;
  }
  std::size_t cursor = kJournalHeaderBytes;
  std::uint64_t expected_sequence = 1;
  while (cursor < bytes.size()) {
    const std::size_t remaining = bytes.size() - cursor;
    if (remaining < kRecordHeaderBytes) {
      scan.outcome = LoadOutcome::torn_tail_repaired;
      scan.repaired_bytes = remaining;
      scan.valid_bytes = cursor;
      scan.detail = "journal ends with a partial record header";
      return scan;
    }
    const char* header = bytes.data() + cursor;
    if (get_u32(header) != kRecordMagic) {
      scan.outcome = LoadOutcome::corrupt;
      scan.detail = "journal record magic is invalid at offset " + std::to_string(cursor);
      scan.valid_bytes = cursor;
      return scan;
    }
    if (get_u16(header + 4) != kPersistenceSchemaVersion) {
      scan.outcome = LoadOutcome::schema_mismatch;
      scan.detail = "journal record schema version mismatch";
      scan.valid_bytes = cursor;
      return scan;
    }
    const std::uint32_t header_crc = get_u32(header + 32);
    if (header_crc != crc32c(std::string_view(header, 32))) {
      scan.outcome = LoadOutcome::corrupt;
      scan.detail = "journal record header checksum failed at offset " + std::to_string(cursor);
      scan.valid_bytes = cursor;
      return scan;
    }
    const std::uint32_t payload_length = get_u32(header + 24);
    if (payload_length > options.max_record_bytes) {
      scan.outcome = LoadOutcome::bounds_exceeded;
      scan.detail = "journal record declares a payload beyond the configured ceiling";
      scan.valid_bytes = cursor;
      return scan;
    }
    const std::size_t payload_at = cursor + kRecordHeaderBytes;
    if (payload_length > bytes.size() - payload_at) {
      scan.outcome = LoadOutcome::torn_tail_repaired;
      scan.repaired_bytes = bytes.size() - cursor;
      scan.valid_bytes = cursor;
      scan.detail = "journal ends with a partially written record";
      return scan;
    }
    const std::string_view payload = bytes.substr(payload_at, payload_length);
    if (get_u32(header + 28) != crc32c(payload)) {
      scan.outcome = LoadOutcome::corrupt;
      scan.detail = "journal record payload checksum failed at offset " + std::to_string(cursor);
      scan.valid_bytes = cursor;
      return scan;
    }
    JournalRecord record;
    if (!parse_record_kind(get_u16(header + 6), record.kind)) {
      scan.outcome = LoadOutcome::corrupt;
      scan.detail = "journal record kind is unknown";
      scan.valid_bytes = cursor;
      return scan;
    }
    record.sequence = get_u64(header + 8);
    record.at_nanos = get_u64(header + 16);
    record.payload.assign(payload.data(), payload.size());
    record.stored_crc = get_u32(header + 28);
    if (record.sequence < expected_sequence) {
      scan.outcome = LoadOutcome::corrupt;
      scan.detail = "journal sequence is not monotonic at offset " + std::to_string(cursor);
      scan.valid_bytes = cursor;
      return scan;
    }
    expected_sequence = record.sequence + 1;
    scan.last_sequence = record.sequence;
    scan.records.push_back(std::move(record));
    cursor = payload_at + payload_length;
    if (scan.records.size() > options.max_records_per_load) {
      scan.outcome = LoadOutcome::bounds_exceeded;
      scan.detail = "journal holds more records than the configured ceiling";
      return scan;
    }
  }
  scan.valid_bytes = cursor;
  scan.outcome = scan.records.empty() ? LoadOutcome::empty : LoadOutcome::ok;
  if (repair_tail) {
    // Nothing to repair when the whole file parsed.
  }
  return scan;
}

}  // namespace

struct PersistenceStore::Impl {
  PersistenceOptions options;
  std::filesystem::path journal;
  std::filesystem::path snapshot;
  std::filesystem::path snapshot_temp;
  HANDLE handle = INVALID_HANDLE_VALUE;
  std::uint64_t last_sequence = 0;
  std::uint64_t bytes = 0;
  std::uint64_t created_nanos = 0;
  std::uint64_t epoch = 0;
  std::size_t appends = 0;
  mutable std::mutex mutex;

  ~Impl() {
    if (handle != INVALID_HANDLE_VALUE) {
      ::CloseHandle(handle);
      handle = INVALID_HANDLE_VALUE;
    }
  }

  CRF_NODISCARD VoidResult write_at(std::uint64_t offset, std::string_view bytes_to_write) {
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (::SetFilePointerEx(handle, position, nullptr, FILE_BEGIN) == 0) {
      return Status(StatusCode::persistence_io, "journal seek failed");
    }
    std::size_t written = 0;
    while (written < bytes_to_write.size()) {
      const DWORD chunk = static_cast<DWORD>(
          std::min<std::size_t>(bytes_to_write.size() - written, 1u << 20));
      DWORD done = 0;
      if (::WriteFile(handle, bytes_to_write.data() + written, chunk, &done, nullptr) == 0 ||
          done == 0) {
        return Status(StatusCode::persistence_io, "journal write failed");
      }
      written += done;
    }
    return VoidResult{};
  }

  CRF_NODISCARD VoidResult flush() {
    if (::FlushFileBuffers(handle) == 0) {
      return Status(StatusCode::persistence_io, "journal flush failed");
    }
    return VoidResult{};
  }

  CRF_NODISCARD std::uint64_t file_size() const {
    LARGE_INTEGER size{};
    if (::GetFileSizeEx(handle, &size) == 0) return 0;
    return static_cast<std::uint64_t>(size.QuadPart);
  }

  /// Rewrite the journal header so that the recorded runtime epoch survives a
  /// restart. The header carries its own checksum, so the whole header is
  /// rewritten rather than patched in place.
  CRF_NODISCARD VoidResult update_header_epoch(std::uint64_t new_epoch) {
    const std::string header = journal_header_bytes(new_epoch, created_nanos);
    const VoidResult written = write_at(0, header);
    if (!written) return written.status();
    return flush();
  }

  CRF_NODISCARD VoidResult truncate_to(std::uint64_t offset) {
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (::SetFilePointerEx(handle, position, nullptr, FILE_BEGIN) == 0) {
      return Status(StatusCode::persistence_io, "journal seek failed during truncation");
    }
    if (::SetEndOfFile(handle) == 0) {
      return Status(StatusCode::persistence_io, "journal truncation failed");
    }
    return VoidResult{};
  }
};

PersistenceStore::PersistenceStore() : impl_(std::make_unique<Impl>()) {}
PersistenceStore::~PersistenceStore() = default;

Result<std::unique_ptr<PersistenceStore>> PersistenceStore::open(PersistenceOptions options) {
  if (options.directory.empty()) {
    return Status(StatusCode::invalid_argument, "persistence directory is not configured");
  }
  if (options.name.empty()) {
    return Status(StatusCode::invalid_argument, "persistence name is not configured");
  }
  if (options.name.find_first_of("\\/:*?\"<>|") != std::string::npos) {
    return Status(StatusCode::invalid_argument,
                  "persistence name contains a character that is not valid in a file name");
  }
  if (options.max_record_bytes == 0 || options.max_record_bytes > kMaxBlobBytes) {
    return Status(StatusCode::invalid_argument, "maximum record size is out of range");
  }

  std::error_code ec;
  std::filesystem::create_directories(options.directory, ec);
  if (ec) {
    return Status(StatusCode::persistence_io,
                  "persistence directory could not be created: " + ec.message());
  }

  auto store = std::unique_ptr<PersistenceStore>(new PersistenceStore());
  store->impl_->options = std::move(options);
  // Durable paths are canonicalised before they reach the operating system, so
  // that a configured root with mixed separators cannot produce a path the
  // loader rejects.
  store->impl_->options.directory = normalize_path(store->impl_->options.directory);
  store->impl_->options.name = normalize_path_string(std::filesystem::path(store->impl_->options.name));
  store->impl_->journal =
      normalize_path(store->impl_->options.directory / (store->impl_->options.name + ".crfjournal"));
  store->impl_->snapshot =
      normalize_path(store->impl_->options.directory / (store->impl_->options.name + ".crfsnapshot"));
  store->impl_->snapshot_temp = normalize_path(store->impl_->options.directory /
                                               (store->impl_->options.name + ".crfsnapshot.tmp"));

  const HANDLE handle = ::CreateFileW(store->impl_->journal.c_str(), GENERIC_READ | GENERIC_WRITE,
                                      FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                                      FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return Status(StatusCode::persistence_io,
                  "journal could not be opened: " + store->impl_->journal.string() +
                      " (Win32 error " + std::to_string(::GetLastError()) + ")");
  }
  store->impl_->handle = handle;

  const std::uint64_t size = store->impl_->file_size();
  if (size == 0) {
    const std::string header = journal_header_bytes(0, wall_nanos());
    const VoidResult written = store->impl_->write_at(0, header);
    if (!written) return written.status();
    const VoidResult flushed = store->impl_->flush();
    if (!flushed) return flushed.status();
    store->impl_->last_sequence = 0;
    store->impl_->bytes = kJournalHeaderBytes;
    return store;
  }

  // Recover whatever is already on disk before accepting appends. A corrupt
  // journal is refused outright; only a torn tail is repaired.
  const Result<DurableState> existing = store->load();
  if (!existing) return existing.status();
  if (!existing.value().trustworthy()) {
    return Status(StatusCode::persistence_corrupt,
                  "existing journal is not trustworthy: " + existing.value().detail);
  }
  const std::uint64_t valid = static_cast<std::uint64_t>(kJournalHeaderBytes) +
                              (existing.value().bytes_read - existing.value().repaired_bytes -
                               kJournalHeaderBytes);
  if (existing.value().outcome == LoadOutcome::torn_tail_repaired) {
    const VoidResult truncated = store->impl_->truncate_to(valid);
    if (!truncated) return truncated.status();
    const VoidResult flushed = store->impl_->flush();
    if (!flushed) return flushed.status();
  }
  store->impl_->last_sequence = existing.value().last_sequence;
  store->impl_->epoch = existing.value().runtime_epoch;
  store->impl_->created_nanos = existing.value().created_at_nanos;
  store->impl_->bytes = valid;
  return store;
}

const PersistenceOptions& PersistenceStore::options() const noexcept { return impl_->options; }
const std::filesystem::path& PersistenceStore::journal_path() const noexcept { return impl_->journal; }
const std::filesystem::path& PersistenceStore::snapshot_path() const noexcept { return impl_->snapshot; }
std::uint64_t PersistenceStore::last_sequence() const noexcept { return impl_->last_sequence; }
std::uint64_t PersistenceStore::journal_bytes() const noexcept { return impl_->bytes; }
std::size_t PersistenceStore::append_count() const noexcept { return impl_->appends; }

Result<std::uint64_t> PersistenceStore::append(RecordKind kind, std::string payload) {
  if (payload.size() > impl_->options.max_record_bytes) {
    return Status(StatusCode::persistence_bounds_exceeded,
                  "record payload exceeds the configured ceiling");
  }
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  if (impl_->handle == INVALID_HANDLE_VALUE) {
    return Status(StatusCode::persistence_io, "journal is not open");
  }
  if (impl_->bytes + payload.size() + kRecordHeaderBytes > impl_->options.max_journal_bytes) {
    return Status(StatusCode::persistence_bounds_exceeded,
                  "journal size ceiling reached; rotate the snapshot before appending");
  }

  const std::uint64_t sequence = impl_->last_sequence + 1;
  const std::uint64_t at = wall_nanos();
  std::string record(kRecordHeaderBytes, '\0');
  put_u32(record.data(), kRecordMagic);
  put_u16(record.data() + 4, kPersistenceSchemaVersion);
  put_u16(record.data() + 6, static_cast<std::uint16_t>(kind));
  put_u64(record.data() + 8, sequence);
  put_u64(record.data() + 16, at);
  put_u32(record.data() + 24, static_cast<std::uint32_t>(payload.size()));
  put_u32(record.data() + 28, crc32c(std::string_view(payload)));
  put_u32(record.data() + 32, crc32c(std::string_view(record.data(), 32)));
  put_u32(record.data() + 36, 0);
  record.append(payload);

  // One write call per record: a crash can only ever leave a prefix of the
  // record on disk, which the loader recognises as a torn tail.
  const VoidResult written = impl_->write_at(impl_->bytes, record);
  if (!written) return written.status();
  if (impl_->options.durable_appends) {
    const VoidResult flushed = impl_->flush();
    if (!flushed) return flushed.status();
  }
  impl_->bytes += record.size();
  impl_->last_sequence = sequence;
  ++impl_->appends;
  return sequence;
}

Result<std::uint64_t> PersistenceStore::record_epoch(std::uint64_t epoch) {
  std::string payload(8, '\0');
  put_u64(payload.data(), epoch);
  const Result<std::uint64_t> sequence = append(RecordKind::epoch_advanced, std::move(payload));
  if (!sequence) return sequence.status();
  const VoidResult updated = impl_->update_header_epoch(epoch);
  if (!updated) return updated.status();
  impl_->epoch = epoch;
  return sequence;
}

VoidResult PersistenceStore::write_snapshot(std::string payload, std::uint64_t sequence) {
  if (payload.size() > impl_->options.max_record_bytes) {
    return Status(StatusCode::persistence_bounds_exceeded, "snapshot exceeds the configured ceiling");
  }
  std::string file(kSnapshotHeaderBytes, '\0');
  std::memcpy(file.data(), kSnapshotMagic, sizeof(kSnapshotMagic));
  put_u16(file.data() + 8, kPersistenceSchemaVersion);
  put_u16(file.data() + 10, 0);
  put_u32(file.data() + 12, static_cast<std::uint32_t>(payload.size()));
  put_u64(file.data() + 16, sequence);
  put_u32(file.data() + 24, crc32c(std::string_view(payload)));
  put_u32(file.data() + 28, 0);
  put_u32(file.data() + 28, crc32c(std::string_view(file.data(), 28)));
  file.append(payload);

  {
    std::ofstream stream(impl_->snapshot_temp, std::ios::binary | std::ios::trunc);
    if (!stream) {
      return Status(StatusCode::persistence_io, "snapshot temporary file could not be created");
    }
    stream.write(file.data(), static_cast<std::streamsize>(file.size()));
    stream.flush();
    if (!stream) {
      return Status(StatusCode::persistence_io, "snapshot write failed");
    }
  }
  // Atomic replacement: a reader either sees the previous snapshot or the new
  // one, never a partially written file.
  if (::MoveFileExW(impl_->snapshot_temp.c_str(), impl_->snapshot.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    std::error_code ec;
    std::filesystem::remove(impl_->snapshot_temp, ec);
    return Status(StatusCode::persistence_io, "snapshot replacement failed");
  }
  return VoidResult{};
}

Result<std::optional<std::string>> PersistenceStore::read_snapshot() const {
  bool too_large = false;
  bool missing = false;
  const std::vector<char> bytes =
      read_whole_file(impl_->snapshot, impl_->options.max_record_bytes + kSnapshotHeaderBytes,
                      too_large, missing);
  if (missing) return std::optional<std::string>{};
  if (too_large) {
    return Status(StatusCode::persistence_bounds_exceeded, "snapshot exceeds the configured ceiling");
  }
  if (bytes.size() < kSnapshotHeaderBytes) {
    return Status(StatusCode::persistence_truncated, "snapshot header is incomplete");
  }
  const std::string_view view(bytes.data(), bytes.size());
  if (std::memcmp(view.data(), kSnapshotMagic, sizeof(kSnapshotMagic)) != 0) {
    return Status(StatusCode::persistence_corrupt, "snapshot magic is invalid");
  }
  if (get_u16(view.data() + 8) != kPersistenceSchemaVersion) {
    return Status(StatusCode::persistence_schema_mismatch, "snapshot schema version mismatch");
  }
  if (get_u32(view.data() + 28) != crc32c(view.substr(0, 28))) {
    return Status(StatusCode::persistence_corrupt, "snapshot header checksum failed");
  }
  const std::uint32_t payload_length = get_u32(view.data() + 12);
  if (payload_length > impl_->options.max_record_bytes) {
    return Status(StatusCode::persistence_bounds_exceeded, "snapshot payload is too large");
  }
  if (view.size() - kSnapshotHeaderBytes < payload_length) {
    return Status(StatusCode::persistence_truncated, "snapshot payload is incomplete");
  }
  const std::string_view payload = view.substr(kSnapshotHeaderBytes, payload_length);
  if (get_u32(view.data() + 24) != crc32c(payload)) {
    return Status(StatusCode::persistence_corrupt, "snapshot payload checksum failed");
  }
  return std::optional<std::string>(std::string(payload));
}

Result<DurableState> PersistenceStore::load() const {
  bool too_large = false;
  bool missing = false;
  const std::vector<char> bytes =
      read_whole_file(impl_->journal, impl_->options.max_journal_bytes, too_large, missing);

  DurableState state;
  if (missing) {
    state.outcome = LoadOutcome::empty;
    state.detail = "journal does not exist";
    return state;
  }
  if (too_large) {
    state.outcome = LoadOutcome::bounds_exceeded;
    state.detail = "journal exceeds the configured byte ceiling";
    return state;
  }
  const std::string_view view(bytes.data(), bytes.size());
  JournalScan scan = scan_journal(view, impl_->options, false);
  state.outcome = scan.outcome;
  state.last_sequence = scan.last_sequence;
  state.repaired_bytes = scan.repaired_bytes;
  state.bytes_read = scan.bytes_read;
  state.records = std::move(scan.records);
  state.detail = scan.detail;
  if (view.size() >= kJournalHeaderBytes) {
    std::uint64_t epoch = 0;
    std::uint64_t created = 0;
    if (valid_journal_header(view.substr(0, kJournalHeaderBytes), epoch, created)) {
      state.runtime_epoch = epoch;
      state.created_at_nanos = created;
    }
  }
  return state;
}

VoidResult PersistenceStore::reset() {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  if (impl_->handle != INVALID_HANDLE_VALUE) {
    ::CloseHandle(impl_->handle);
    impl_->handle = INVALID_HANDLE_VALUE;
  }
  std::error_code ec;
  std::filesystem::remove(impl_->journal, ec);
  std::filesystem::remove(impl_->snapshot, ec);
  std::filesystem::remove(impl_->snapshot_temp, ec);

  const HANDLE handle = ::CreateFileW(impl_->journal.c_str(), GENERIC_READ | GENERIC_WRITE,
                                      FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                                      FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return Status(StatusCode::persistence_io, "journal could not be recreated");
  }
  impl_->handle = handle;
  const std::string header = journal_header_bytes(0, wall_nanos());
  const VoidResult written = impl_->write_at(0, header);
  if (!written) return written.status();
  const VoidResult flushed = impl_->flush();
  if (!flushed) return flushed.status();
  impl_->last_sequence = 0;
  impl_->bytes = kJournalHeaderBytes;
  impl_->appends = 0;
  return VoidResult{};
}

// ---------------------------------------------------------------------------
// Authority registry codecs.
//
// A restarted runtime must be able to revalidate the authority that committed
// phases were bound to, so the toolchain, target, environment, policy, and
// source entries a session depends on are persisted with it.
// ---------------------------------------------------------------------------
namespace {

void encode_file_identity(Encoder& enc, const FileIdentity& file) {
  enc.path(file.canonical_path);
  enc.str(file.volume_serial_hex);
  enc.str(file.file_index_hex);
  enc.u64(file.size_bytes);
  enc.u64(file.last_write_nanos);
  enc.digest(file.content);
  enc.b(file.content_hashed);
}

FileIdentity decode_file_identity(Decoder& dec) {
  FileIdentity file;
  file.canonical_path = dec.path();
  file.volume_serial_hex = dec.str(64);
  file.file_index_hex = dec.str(64);
  file.size_bytes = dec.u64();
  file.last_write_nanos = dec.u64();
  file.content = dec.digest();
  file.content_hashed = dec.b();
  return file;
}

void encode_environment_variables(Encoder& enc, const std::vector<EnvironmentVariable>& variables) {
  enc.u64(variables.size());
  for (const EnvironmentVariable& variable : variables) {
    enc.str(variable.name);
    enc.str(variable.value);
  }
}

std::vector<EnvironmentVariable> decode_environment_variables(Decoder& dec) {
  std::vector<EnvironmentVariable> variables;
  const std::size_t count = dec.collection(4096);
  for (std::size_t i = 0; i < count && dec.good(); ++i) {
    EnvironmentVariable variable;
    variable.name = dec.str(4096);
    variable.value = dec.str(1u << 20);
    variables.push_back(std::move(variable));
  }
  return variables;
}

void encode_environment_spec(Encoder& enc, const EnvironmentSpec& spec) {
  enc.path(spec.working_directory);
  enc.path(spec.temp_directory);
  encode_environment_variables(enc, spec.variables);
  const auto encode_paths = [&enc](const std::vector<std::filesystem::path>& paths) {
    enc.u64(paths.size());
    for (const std::filesystem::path& path : paths) enc.path(path);
  };
  encode_paths(spec.include_paths);
  encode_paths(spec.library_paths);
  encode_paths(spec.sdk_roots);
  encode_paths(spec.toolkit_roots);
  enc.u64(spec.inherited_variables.size());
  for (const std::string& name : spec.inherited_variables) enc.str(name);
  enc.u8(static_cast<std::uint8_t>(spec.locale_policy));
  enc.str(spec.locale_name);
  enc.b(spec.deterministic_controls);
}

EnvironmentSpec decode_environment_spec(Decoder& dec) {
  EnvironmentSpec spec;
  spec.working_directory = dec.path();
  spec.temp_directory = dec.path();
  spec.variables = decode_environment_variables(dec);
  const auto decode_paths = [&dec](std::vector<std::filesystem::path>& paths) {
    const std::size_t count = dec.collection(4096);
    for (std::size_t i = 0; i < count && dec.good(); ++i) paths.push_back(dec.path());
  };
  decode_paths(spec.include_paths);
  decode_paths(spec.library_paths);
  decode_paths(spec.sdk_roots);
  decode_paths(spec.toolkit_roots);
  const std::size_t inherited = dec.collection(4096);
  for (std::size_t i = 0; i < inherited && dec.good(); ++i) {
    spec.inherited_variables.push_back(dec.str(1024));
  }
  spec.locale_policy = static_cast<LocalePolicy>(dec.u8());
  spec.locale_name = dec.str(256);
  spec.deterministic_controls = dec.b();
  return spec;
}

void encode_policy_spec(Encoder& enc, const PolicySpec& spec) {
  enc.u8(static_cast<std::uint8_t>(spec.reproducibility));
  enc.u32(spec.max_retries_per_phase);
  enc.u32(spec.max_retries_per_session);
  enc.u64(spec.retryable_classes.size());
  for (const FailureClass value : spec.retryable_classes) enc.u8(static_cast<std::uint8_t>(value));
  enc.u64(spec.forbidden_options.size());
  for (const std::string& option : spec.forbidden_options) enc.str(option);
  enc.b(spec.allow_parallel_phases);
  enc.u64(spec.max_parallel_phases);
  enc.u32(spec.phase_timeout_millis);
  enc.u32(spec.validation_timeout_millis);
  enc.b(spec.run_smoke_test);
  enc.b(spec.require_content_digest);
  enc.u64(spec.max_diagnostic_entries);
  enc.u64(spec.max_diagnostic_bytes_per_stream);
  enc.b(spec.allow_local_cache);
}

PolicySpec decode_policy_spec(Decoder& dec) {
  PolicySpec spec;
  spec.reproducibility = static_cast<ReproducibilityPolicy>(dec.u8());
  spec.max_retries_per_phase = dec.u32();
  spec.max_retries_per_session = dec.u32();
  const std::size_t classes = dec.collection(64);
  for (std::size_t i = 0; i < classes && dec.good(); ++i) {
    spec.retryable_classes.push_back(static_cast<FailureClass>(dec.u8()));
  }
  const std::size_t options = dec.collection(PolicySpec::kMaxForbiddenOptions);
  for (std::size_t i = 0; i < options && dec.good(); ++i) {
    spec.forbidden_options.push_back(dec.str(4096));
  }
  spec.allow_parallel_phases = dec.b();
  spec.max_parallel_phases = dec.collection(4096);
  spec.phase_timeout_millis = dec.u32();
  spec.validation_timeout_millis = dec.u32();
  spec.run_smoke_test = dec.b();
  spec.require_content_digest = dec.b();
  spec.max_diagnostic_entries = dec.collection(1u << 20);
  spec.max_diagnostic_bytes_per_stream = dec.collection(1u << 30);
  spec.allow_local_cache = dec.b();
  return spec;
}

void encode_target_spec(Encoder& enc, const TargetSpec& spec) {
  enc.u8(static_cast<std::uint8_t>(spec.architecture));
  enc.u8(static_cast<std::uint8_t>(spec.os));
  enc.str(spec.triple);
  enc.str(spec.cpu);
  enc.str(spec.device_arch);
  enc.str(spec.device_virtual_arch);
  enc.str(spec.abi);
  enc.u32(spec.pointer_width_bits);
}

TargetSpec decode_target_spec(Decoder& dec) {
  TargetSpec spec;
  spec.architecture = static_cast<Architecture>(dec.u8());
  spec.os = static_cast<OperatingSystem>(dec.u8());
  spec.triple = dec.str(256);
  spec.cpu = dec.str(256);
  spec.device_arch = dec.str(256);
  spec.device_virtual_arch = dec.str(256);
  spec.abi = dec.str(256);
  spec.pointer_width_bits = dec.u32();
  return spec;
}

template <class Enum>
CRF_NODISCARD std::vector<Enum> decode_enum_list(Decoder& dec, std::size_t bound, std::uint32_t max) {
  std::vector<Enum> values;
  const std::size_t count = dec.collection(bound);
  for (std::size_t i = 0; i < count && dec.good(); ++i) {
    values.push_back(dec.enumeration<Enum>(dec.u8(), max));
  }
  return values;
}

}  // namespace

std::string encode_toolchain(const ToolchainIdentity& identity) {
  Encoder enc;
  enc.u16(kPersistenceSchemaVersion);
  enc.u64(identity.id.value());
  enc.u64(identity.generation.value());
  enc.u8(static_cast<std::uint8_t>(identity.family));
  enc.str(identity.display_name);
  enc.str(identity.version);
  enc.u64(identity.components.size());
  for (const ComponentIdentity& component : identity.components) {
    enc.u64(component.id.value());
    enc.u64(component.generation.value());
    enc.u8(static_cast<std::uint8_t>(component.kind));
    enc.str(component.name);
    enc.str(component.version);
    encode_file_identity(enc, component.file);
    enc.u64(component.command_capabilities.size());
    for (const std::string& capability : component.command_capabilities) enc.str(capability);
    enc.u64(component.target_support.size());
    for (const Architecture architecture : component.target_support) {
      enc.u8(static_cast<std::uint8_t>(architecture));
    }
    enc.u64(component.object_formats.size());
    for (const ObjectFormat format : component.object_formats) {
      enc.u8(static_cast<std::uint8_t>(format));
    }
    encode_environment_variables(enc, component.environment_requirements);
    enc.u8(static_cast<std::uint8_t>(component.evidence_class));
  }
  enc.u64(identity.target_support.size());
  for (const Architecture architecture : identity.target_support) {
    enc.u8(static_cast<std::uint8_t>(architecture));
  }
  enc.u64(identity.object_formats.size());
  for (const ObjectFormat format : identity.object_formats) enc.u8(static_cast<std::uint8_t>(format));
  encode_environment_variables(enc, identity.environment_contract);
  enc.path(identity.toolkit_root);
  enc.path(identity.sdk_root);
  encode_environment_variables(enc, identity.attributes);
  enc.str(identity.standard_library_identity);
  enc.u8(static_cast<std::uint8_t>(identity.evidence_class));
  enc.digest(identity.evidence_digest);
  return enc.take();
}

Result<ToolchainIdentity> decode_toolchain(std::string_view bytes) {
  Decoder dec(bytes);
  const std::uint16_t schema = dec.u16();
  if (!dec.good()) return malformed("toolchain header");
  if (schema != kPersistenceSchemaVersion) {
    return Status(StatusCode::persistence_schema_mismatch, "toolchain schema version mismatch");
  }
  ToolchainIdentity identity;
  identity.id = ToolchainId::from_value(dec.u64());
  identity.generation = ToolchainGeneration::from_value(dec.u64());
  identity.family = static_cast<ToolchainFamily>(dec.u8());
  identity.display_name = dec.str();
  identity.version = dec.str();
  const std::size_t components = dec.collection(256);
  for (std::size_t i = 0; i < components && dec.good(); ++i) {
    ComponentIdentity component;
    component.id = CompilerComponentId::from_value(dec.u64());
    component.generation = CompilerComponentGeneration::from_value(dec.u64());
    component.kind = static_cast<ComponentKind>(dec.u8());
    component.name = dec.str();
    component.version = dec.str();
    component.file = decode_file_identity(dec);
    const std::size_t capabilities = dec.collection(256);
    for (std::size_t c = 0; c < capabilities && dec.good(); ++c) {
      component.command_capabilities.push_back(dec.str(4096));
    }
    component.target_support = decode_enum_list<Architecture>(dec, 32, 4);
    component.object_formats = decode_enum_list<ObjectFormat>(dec, 32, 12);
    component.environment_requirements = decode_environment_variables(dec);
    component.evidence_class = static_cast<EvidenceClass>(dec.u8());
    identity.components.push_back(std::move(component));
  }
  identity.target_support = decode_enum_list<Architecture>(dec, 32, 4);
  identity.object_formats = decode_enum_list<ObjectFormat>(dec, 32, 12);
  identity.environment_contract = decode_environment_variables(dec);
  identity.toolkit_root = dec.path();
  identity.sdk_root = dec.path();
  identity.attributes = decode_environment_variables(dec);
  identity.standard_library_identity = dec.str();
  identity.evidence_class = static_cast<EvidenceClass>(dec.u8());
  identity.evidence_digest = dec.digest();
  if (!dec.good()) return malformed("toolchain body");
  if (!dec.exhausted()) return malformed("toolchain has trailing bytes");
  return identity;
}

std::string encode_target_identity(const TargetIdentity& identity) {
  Encoder enc;
  enc.u16(kPersistenceSchemaVersion);
  enc.u64(identity.id.value());
  enc.u64(identity.generation.value());
  enc.digest(identity.digest);
  encode_target_spec(enc, identity.spec);
  return enc.take();
}

Result<TargetIdentity> decode_target_identity(std::string_view bytes) {
  Decoder dec(bytes);
  const std::uint16_t schema = dec.u16();
  if (!dec.good() || schema != kPersistenceSchemaVersion) {
    return malformed("target identity header");
  }
  TargetIdentity identity;
  identity.id = TargetId::from_value(dec.u64());
  identity.generation = TargetGeneration::from_value(dec.u64());
  identity.digest = dec.digest();
  identity.spec = decode_target_spec(dec);
  if (!dec.good()) return malformed("target identity body");
  if (!dec.exhausted()) return malformed("target identity has trailing bytes");
  return identity;
}

std::string encode_environment_identity(const EnvironmentIdentity& identity) {
  Encoder enc;
  enc.u16(kPersistenceSchemaVersion);
  enc.u64(identity.id.value());
  enc.u64(identity.generation.value());
  enc.digest(identity.digest);
  encode_environment_spec(enc, identity.spec);
  return enc.take();
}

Result<EnvironmentIdentity> decode_environment_identity(std::string_view bytes) {
  Decoder dec(bytes);
  const std::uint16_t schema = dec.u16();
  if (!dec.good() || schema != kPersistenceSchemaVersion) {
    return malformed("environment identity header");
  }
  EnvironmentIdentity identity;
  identity.id = EnvironmentId::from_value(dec.u64());
  identity.generation = EnvironmentGeneration::from_value(dec.u64());
  identity.digest = dec.digest();
  identity.spec = decode_environment_spec(dec);
  if (!dec.good()) return malformed("environment identity body");
  if (!dec.exhausted()) return malformed("environment identity has trailing bytes");
  return identity;
}

std::string encode_policy_identity(const PolicyIdentity& identity) {
  Encoder enc;
  enc.u16(kPersistenceSchemaVersion);
  enc.u64(identity.id.value());
  enc.u64(identity.generation.value());
  enc.digest(identity.digest);
  encode_policy_spec(enc, identity.spec);
  return enc.take();
}

Result<PolicyIdentity> decode_policy_identity(std::string_view bytes) {
  Decoder dec(bytes);
  const std::uint16_t schema = dec.u16();
  if (!dec.good() || schema != kPersistenceSchemaVersion) {
    return malformed("policy identity header");
  }
  PolicyIdentity identity;
  identity.id = PolicyId::from_value(dec.u64());
  identity.generation = PolicyGeneration::from_value(dec.u64());
  identity.digest = dec.digest();
  identity.spec = decode_policy_spec(dec);
  if (!dec.good()) return malformed("policy identity body");
  if (!dec.exhausted()) return malformed("policy identity has trailing bytes");
  return identity;
}

std::string encode_source_unit(const SourceUnit& unit) {
  Encoder enc;
  enc.u16(kPersistenceSchemaVersion);
  enc.u64(unit.id.value());
  enc.u64(unit.generation.value());
  enc.path(unit.path);
  enc.u8(static_cast<std::uint8_t>(unit.language));
  enc.str(unit.dialect);
  enc.digest(unit.content);
  enc.u64(unit.size_bytes);
  enc.b(unit.redact_diagnostics);
  return enc.take();
}

Result<SourceUnit> decode_source_unit(std::string_view bytes) {
  Decoder dec(bytes);
  const std::uint16_t schema = dec.u16();
  if (!dec.good() || schema != kPersistenceSchemaVersion) {
    return malformed("source unit header");
  }
  SourceUnit unit;
  unit.id = SourceId::from_value(dec.u64());
  unit.generation = SourceGeneration::from_value(dec.u64());
  unit.path = dec.path();
  unit.language = static_cast<SourceLanguage>(dec.u8());
  unit.dialect = dec.str(256);
  unit.content = dec.digest();
  unit.size_bytes = dec.u64();
  unit.redact_diagnostics = dec.b();
  if (!dec.good()) return malformed("source unit body");
  if (!dec.exhausted()) return malformed("source unit has trailing bytes");
  return unit;
}

std::string encode_provenance(const ProvenanceRecord& record) {
  Encoder enc;
  enc.u16(kPersistenceSchemaVersion);
  enc.u64(record.id.value());
  enc.u64(record.generation.value());
  enc.str(record.kind);
  enc.u64(record.session.id.value());
  enc.u64(record.session.generation.value());
  enc.u64(record.compilation.id.value());
  enc.u64(record.compilation.generation.value());
  enc.u64(record.phase.id.value());
  enc.u64(record.phase.generation.value());
  enc.u64(record.invocation.id.value());
  enc.u64(record.invocation.generation.value());
  enc.u64(record.toolchain.id.value());
  enc.u64(record.toolchain.generation.value());
  enc.u64(record.target.id.value());
  enc.u64(record.target.generation.value());
  enc.u64(record.environment.id.value());
  enc.u64(record.environment.generation.value());
  enc.u64(record.policy.id.value());
  enc.u64(record.policy.generation.value());
  enc.u64(record.source.id.value());
  enc.u64(record.source.generation.value());
  enc.u64(record.inputs.size());
  for (const Ref<IntermediateArtifactId>& entry : record.inputs) {
    enc.u64(entry.id.value());
    enc.u64(entry.generation.value());
  }
  enc.u64(record.outputs.size());
  for (const Ref<IntermediateArtifactId>& entry : record.outputs) {
    enc.u64(entry.id.value());
    enc.u64(entry.generation.value());
  }
  enc.str(record.adapter);
  enc.u8(static_cast<std::uint8_t>(record.verdict));
  enc.str(record.detail);
  enc.u64(record.at_nanos);
  return enc.take();
}

Result<ProvenanceRecord> decode_provenance(std::string_view bytes) {
  Decoder dec(bytes);
  const std::uint16_t schema = dec.u16();
  if (!dec.good() || schema != kPersistenceSchemaVersion) {
    return malformed("provenance header");
  }
  ProvenanceRecord record;
  const auto reference = [&dec]() { return RawRef{dec.u64(), dec.u64()}; };
  record.id = ProvenanceId::from_value(dec.u64());
  record.generation = EvidenceGeneration::from_value(dec.u64());
  record.kind = dec.str(256);
  record.session = make_reference<CompilerSessionId>(reference());
  record.compilation = make_reference<CompilationId>(reference());
  record.phase = make_reference<CompilerPhaseId>(reference());
  record.invocation = make_reference<InvocationId>(reference());
  record.toolchain = make_reference<ToolchainId>(reference());
  record.target = make_reference<TargetId>(reference());
  record.environment = make_reference<EnvironmentId>(reference());
  record.policy = make_reference<PolicyId>(reference());
  record.source = make_reference<SourceId>(reference());
  const std::size_t input_count = dec.collection(4096);
  for (std::size_t i = 0; i < input_count && dec.good(); ++i) {
    record.inputs.push_back(make_reference<IntermediateArtifactId>(reference()));
  }
  const std::size_t output_count = dec.collection(4096);
  for (std::size_t i = 0; i < output_count && dec.good(); ++i) {
    record.outputs.push_back(make_reference<IntermediateArtifactId>(reference()));
  }
  record.adapter = dec.str(256);
  record.verdict = static_cast<AuthorityVerdict>(dec.u8());
  record.detail = dec.str(ProvenanceLog::kMaxDetailBytes);
  record.at_nanos = dec.u64();
  if (!dec.good()) return malformed("provenance body");
  if (!dec.exhausted()) return malformed("provenance has trailing bytes");
  return record;
}

}  // namespace crf
