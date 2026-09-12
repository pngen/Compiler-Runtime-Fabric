#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <type_traits>

#include "crf/export.hpp"

namespace crf {

/// Tag types. Each authority domain owns a distinct tag so that ids from
/// different domains are not interchangeable at compile time. A raw integer or
/// string must never be passed where one of these identities is required.
///
/// Every tag declares a stable lowercase name used for deterministic rendering
/// and for diagnostics. The name is part of the persisted schema.
#define CRF_DEFINE_ID_TAG(TypeName, TextName)          \
  struct TypeName {                                    \
    static constexpr std::string_view id_name = TextName; \
  }

CRF_DEFINE_ID_TAG(CompilerSessionTag, "session");
CRF_DEFINE_ID_TAG(CompilationTag, "compilation");
CRF_DEFINE_ID_TAG(AttemptTag, "attempt");
CRF_DEFINE_ID_TAG(CompilerPhaseTag, "phase");
CRF_DEFINE_ID_TAG(ToolchainTag, "toolchain");
CRF_DEFINE_ID_TAG(CompilerComponentTag, "component");
CRF_DEFINE_ID_TAG(TargetTag, "target");
CRF_DEFINE_ID_TAG(SourceTag, "source");
CRF_DEFINE_ID_TAG(IRTag, "ir");
CRF_DEFINE_ID_TAG(IntermediateArtifactTag, "intermediate");
CRF_DEFINE_ID_TAG(FinalArtifactTag, "artifact");
CRF_DEFINE_ID_TAG(EnvironmentTag, "environment");
CRF_DEFINE_ID_TAG(DiagnosticSetTag, "diagnostics");
CRF_DEFINE_ID_TAG(InvocationTag, "invocation");
CRF_DEFINE_ID_TAG(ProcessTag, "process");
CRF_DEFINE_ID_TAG(LeaseTag, "lease");
CRF_DEFINE_ID_TAG(PolicyTag, "policy");
CRF_DEFINE_ID_TAG(RequestTag, "request");
CRF_DEFINE_ID_TAG(CommitTag, "commit");
CRF_DEFINE_ID_TAG(EvidenceTag, "evidence");
CRF_DEFINE_ID_TAG(ProvenanceTag, "provenance");
CRF_DEFINE_ID_TAG(RecoveryTag, "recovery");
CRF_DEFINE_ID_TAG(WorkerTag, "worker");
CRF_DEFINE_ID_TAG(EpochTag, "epoch");

#undef CRF_DEFINE_ID_TAG

/// A strongly typed 64-bit identity.
///
/// Value 0 is reserved for "absent". Identities are assigned by the runtime from
/// deterministic counters seeded from canonical session material, so equivalent
/// canonical inputs yield equivalent governance decisions.
template <class Tag>
class StrongId {
 public:
  using tag_type = Tag;
  using rep = std::uint64_t;

  constexpr StrongId() noexcept = default;
  explicit constexpr StrongId(rep value) noexcept : value_(value) {}

  CRF_NODISCARD static constexpr StrongId from_value(rep value) noexcept {
    return StrongId(value);
  }
  CRF_NODISCARD static constexpr StrongId absent() noexcept { return StrongId(0); }

  CRF_NODISCARD constexpr rep value() const noexcept { return value_; }
  CRF_NODISCARD constexpr bool present() const noexcept { return value_ != 0; }

  friend constexpr bool operator==(StrongId a, StrongId b) noexcept = default;
  friend constexpr auto operator<=>(StrongId a, StrongId b) noexcept = default;

  /// Deterministic rendering: "<name>-<16 lowercase hex digits>".
  CRF_NODISCARD std::string to_string() const;

  /// Parse the rendering produced by to_string(). Returns absent() when the
  /// text is malformed; callers that must distinguish must use try_parse.
  CRF_NODISCARD static StrongId parse(std::string_view text) noexcept;
  CRF_NODISCARD static bool try_parse(std::string_view text, StrongId& out) noexcept;

 private:
  rep value_ = 0;
};

template <class Tag>
std::string StrongId<Tag>::to_string() const {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(Tag::id_name.size() + 17);
  out.append(Tag::id_name.data(), Tag::id_name.size());
  out.push_back('-');
  for (int shift = 60; shift >= 0; shift -= 4) {
    out.push_back(kHex[(value_ >> shift) & 0xFULL]);
  }
  return out;
}

template <class Tag>
bool StrongId<Tag>::try_parse(std::string_view text, StrongId& out) noexcept {
  if (text.size() != Tag::id_name.size() + 1 + 16) return false;
  if (text.substr(0, Tag::id_name.size()) != Tag::id_name) return false;
  if (text[Tag::id_name.size()] != '-') return false;
  rep value = 0;
  for (std::size_t i = Tag::id_name.size() + 1; i < text.size(); ++i) {
    const char c = text[i];
    rep digit = 0;
    if (c >= '0' && c <= '9') {
      digit = static_cast<rep>(c - '0');
    } else if (c >= 'a' && c <= 'f') {
      digit = static_cast<rep>(c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
      digit = static_cast<rep>(c - 'A' + 10);
    } else {
      return false;
    }
    value = (value << 4) | digit;
  }
  out = StrongId(value);
  return true;
}

template <class Tag>
StrongId<Tag> StrongId<Tag>::parse(std::string_view text) noexcept {
  StrongId out;
  if (!try_parse(text, out)) return StrongId(0);
  return out;
}

/// A monotonic generation counter for one authority domain.
///
/// Generations advance whenever authority-relevant state changes. A generation
/// is compared for exact equality on commit: a newer generation invalidates
/// older work even when the older work physically completed.
template <class Tag>
class Generation {
 public:
  using rep = std::uint64_t;

  constexpr Generation() noexcept = default;
  explicit constexpr Generation(rep value) noexcept : value_(value) {}

  CRF_NODISCARD static constexpr Generation initial() noexcept { return Generation(1); }
  CRF_NODISCARD static constexpr Generation from_value(rep value) noexcept {
    return Generation(value);
  }

  CRF_NODISCARD constexpr rep value() const noexcept { return value_; }
  CRF_NODISCARD constexpr bool present() const noexcept { return value_ != 0; }

  /// Advance to the next generation. Saturating: an exhausted counter is a
  /// defect rather than a wrap-around, so it pins at the maximum value.
  CRF_NODISCARD constexpr Generation next() const noexcept {
    return value_ == kMax ? *this : Generation(value_ + 1);
  }
  CRF_NODISCARD constexpr Generation advance(rep delta) const noexcept {
    if (delta == 0) return *this;
    return value_ > kMax - delta ? Generation(kMax) : Generation(value_ + delta);
  }

  friend constexpr bool operator==(Generation a, Generation b) noexcept = default;
  friend constexpr auto operator<=>(Generation a, Generation b) noexcept = default;

  CRF_NODISCARD std::string to_string() const;

  static constexpr rep kMax = 0xFFFFFFFFFFFFFFFFULL;

 private:
  rep value_ = 0;
};

template <class Tag>
std::string Generation<Tag>::to_string() const {
  return std::to_string(value_);
}

// ---------------------------------------------------------------------------
// Concrete identity aliases. These are the authority domains named by the
// Compiler Runtime Fabric specification. Semantically distinct domains never
// share a type.
// ---------------------------------------------------------------------------
using CompilerSessionId = StrongId<CompilerSessionTag>;
using CompilationId = StrongId<CompilationTag>;
using AttemptId = StrongId<AttemptTag>;
using CompilerPhaseId = StrongId<CompilerPhaseTag>;
using ToolchainId = StrongId<ToolchainTag>;
using CompilerComponentId = StrongId<CompilerComponentTag>;
using TargetId = StrongId<TargetTag>;
using SourceId = StrongId<SourceTag>;
using IRId = StrongId<IRTag>;
using IntermediateArtifactId = StrongId<IntermediateArtifactTag>;
using FinalArtifactId = StrongId<FinalArtifactTag>;
using EnvironmentId = StrongId<EnvironmentTag>;
using DiagnosticSetId = StrongId<DiagnosticSetTag>;
using InvocationId = StrongId<InvocationTag>;
using ProcessId = StrongId<ProcessTag>;
using LeaseId = StrongId<LeaseTag>;
using PolicyId = StrongId<PolicyTag>;
using RequestId = StrongId<RequestTag>;
using CommitId = StrongId<CommitTag>;
using EvidenceId = StrongId<EvidenceTag>;
using ProvenanceId = StrongId<ProvenanceTag>;
using RecoveryId = StrongId<RecoveryTag>;
using WorkerId = StrongId<WorkerTag>;
using EpochId = StrongId<EpochTag>;

using CompilerSessionGeneration = Generation<CompilerSessionTag>;
using CompilationGeneration = Generation<CompilationTag>;
using AttemptGeneration = Generation<AttemptTag>;
using CompilerPhaseGeneration = Generation<CompilerPhaseTag>;
using ToolchainGeneration = Generation<ToolchainTag>;
using CompilerComponentGeneration = Generation<CompilerComponentTag>;
using TargetGeneration = Generation<TargetTag>;
using SourceGeneration = Generation<SourceTag>;
using IRGeneration = Generation<IRTag>;
using IntermediateArtifactGeneration = Generation<IntermediateArtifactTag>;
using FinalArtifactGeneration = Generation<FinalArtifactTag>;
using EnvironmentGeneration = Generation<EnvironmentTag>;
using DiagnosticGeneration = Generation<DiagnosticSetTag>;
using InvocationGeneration = Generation<InvocationTag>;
using ProcessGeneration = Generation<ProcessTag>;
using LeaseGeneration = Generation<LeaseTag>;
using PolicyGeneration = Generation<PolicyTag>;
using EvidenceGeneration = Generation<EvidenceTag>;
using RecoveryGeneration = Generation<RecoveryTag>;

/// Immutable pairing of an identity with the generation it was observed at.
template <class IdType>
struct Referenced {
  IdType id{};
  Generation<typename IdType::tag_type> generation{};

  friend constexpr bool operator==(const Referenced&, const Referenced&) noexcept = default;

  CRF_NODISCARD constexpr bool present() const noexcept { return id.present(); }
  CRF_NODISCARD std::string to_string() const {
    return id.to_string() + "@" + generation.to_string();
  }
};

template <class IdType>
using Ref = Referenced<IdType>;

/// Monotonic id allocator for one authority domain.
///
/// Allocators are per-runtime (never global) so that two runtimes in one process
/// cannot interleave identity assignment and so that identity assignment is
/// reproducible from canonical state.
template <class IdType>
class IdAllocator {
 public:
  using rep = typename IdType::rep;

  CRF_NODISCARD IdType next() noexcept {
    if (counter_ == rep{0}) counter_ = rep{1};
    const IdType value = IdType::from_value(counter_);
    if (counter_ != kMax) ++counter_;
    return value;
  }

  /// Reserve an identity without advancing the counter; used when replaying a
  /// durable journal so that identities observed after restart do not collide.
  void observe(IdType id) noexcept {
    if (id.value() >= counter_) counter_ = id.value() == kMax ? kMax : id.value() + 1;
  }

  CRF_NODISCARD rep peek_next() const noexcept { return counter_; }

 private:
  static constexpr rep kMax = 0xFFFFFFFFFFFFFFFFULL;
  rep counter_ = 1;
};

}  // namespace crf

namespace std {
template <class Tag>
struct hash<crf::StrongId<Tag>> {
  std::size_t operator()(const crf::StrongId<Tag>& id) const noexcept {
    // The identity value is already a well-distributed counter; mixing keeps
    // unordered_map bucket selection stable across platforms.
    std::uint64_t v = id.value();
    v ^= v >> 33;
    v *= 0xFF51AFD7ED558CCDULL;
    v ^= v >> 33;
    return static_cast<std::size_t>(v);
  }
};

template <class Tag>
struct hash<crf::Generation<Tag>> {
  std::size_t operator()(const crf::Generation<Tag>& g) const noexcept {
    std::uint64_t v = g.value();
    v ^= v >> 33;
    v *= 0xC4CEB9FE1A85EC53ULL;
    v ^= v >> 33;
    return static_cast<std::size_t>(v);
  }
};
}  // namespace std
