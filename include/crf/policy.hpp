#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "crf/digest.hpp"
#include "crf/phase.hpp"
#include "crf/status.hpp"
#include "crf/strong_id.hpp"

namespace crf {

/// Reproducibility contract declared by the caller.
enum class ReproducibilityPolicy : std::uint8_t {
  /// Equivalent authoritative inputs must produce equivalent validated output.
  /// The runtime executes the deterministic phase a second time and compares
  /// digests; divergence is surfaced, never silently resolved.
  required = 0,
  /// Deterministic environment controls are applied, but the runtime does not
  /// pay for a second execution unless the operator asks for verification.
  preferred = 1,
  not_required = 2,
};

CRF_NODISCARD CRF_API std::string_view to_string(ReproducibilityPolicy value) noexcept;
CRF_NODISCARD CRF_API bool parse_reproducibility_policy(std::string_view text,
                                                        ReproducibilityPolicy& out) noexcept;

/// The compile policy that governs a session. Every field is authority-relevant
/// and participates in PolicyGeneration.
struct CRF_API PolicySpec {
  static constexpr std::size_t kMaxForbiddenOptions = 256;
  static constexpr std::uint32_t kMaxRetriesCeiling = 32;

  ReproducibilityPolicy reproducibility = ReproducibilityPolicy::preferred;

  /// Per-phase retry ceiling and per-session retry ceiling. Both are enforced;
  /// whichever is reached first stops retry.
  std::uint32_t max_retries_per_phase = 2;
  std::uint32_t max_retries_per_session = 8;

  /// Failure classes the policy permits retrying. Empty means "use the runtime's
  /// default classification".
  std::vector<FailureClass> retryable_classes;

  /// Option strings the policy forbids in any invocation, e.g. "/fallback".
  std::vector<std::string> forbidden_options;

  bool allow_parallel_phases = true;
  std::size_t max_parallel_phases = 4;

  /// 0 disables the corresponding timeout.
  std::uint32_t phase_timeout_millis = 0;
  std::uint32_t validation_timeout_millis = 0;

  bool run_smoke_test = true;
  /// Require a content digest for every authoritative artifact. Turning this off
  /// is only meaningful for adapters that cannot hash their outputs; those
  /// artifacts then remain UNKNOWN and cannot be consumed.
  bool require_content_digest = true;

  std::size_t max_diagnostic_entries = 4096;
  std::size_t max_diagnostic_bytes_per_stream = 1u << 20;

  /// Permit reusing a locally cached intermediate. Cached data is always a
  /// candidate: it must still pass identity, generation, and digest checks.
  bool allow_local_cache = false;

  CRF_NODISCARD VoidResult validate() const;
  CRF_NODISCARD Digest canonical_digest() const;
  CRF_NODISCARD bool permits_retry(FailureClass failure) const noexcept;
  CRF_NODISCARD bool forbids_option(std::string_view argument) const noexcept;
};

struct CRF_API PolicyIdentity {
  PolicyId id{};
  PolicyGeneration generation{};
  Digest digest{};
  PolicySpec spec;
};

class CRF_API PolicyRegistry {
 public:
  CRF_NODISCARD Result<Ref<PolicyId>> intern(const PolicySpec& spec);
  CRF_NODISCARD Result<Ref<PolicyId>> intern_as(PolicyId id, const PolicySpec& spec);
  CRF_NODISCARD Result<Ref<PolicyId>> revise(PolicyId id, const PolicySpec& spec);
  CRF_NODISCARD const PolicyIdentity* find(PolicyId id) const noexcept;
  CRF_NODISCARD std::vector<PolicyIdentity> list() const;
  CRF_NODISCARD std::size_t size() const noexcept { return entries_.size(); }

 private:
  struct Entry {
    PolicyIdentity identity;
    bool current = true;
  };
  std::unordered_map<std::uint64_t, Entry> entries_;
  IdAllocator<PolicyId> allocator_;
};

}  // namespace crf
