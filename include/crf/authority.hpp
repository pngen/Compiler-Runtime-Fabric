#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "crf/digest.hpp"
#include "crf/status.hpp"
#include "crf/strong_id.hpp"
#include "crf/toolchain.hpp"
#include "crf/target.hpp"

namespace crf {

/// The complete generation binding under which a phase executes.
///
/// A phase output may become current only if every one of these still matches at
/// commit time. The binding is captured when the phase is reserved and is never
/// silently refreshed.
struct CRF_API PhaseAuthority {
  CompilerSessionGeneration session_generation{};
  CompilationGeneration compilation_generation{};
  AttemptGeneration attempt_generation{};
  CompilerPhaseGeneration phase_generation{};
  Ref<ToolchainId> toolchain{};
  std::vector<Ref<ToolchainId>> cooperating_toolchains{};
  Ref<TargetId> target{};
  Ref<EnvironmentId> environment{};
  Ref<PolicyId> policy{};
  Ref<SourceId> source{};
  IRGeneration ir_generation{};
  Ref<LeaseId> lease{};

  CRF_NODISCARD Digest canonical_digest() const;
  CRF_NODISCARD std::string describe() const;
};

enum class AuthorityVerdict : std::uint8_t {
  valid = 0,
  stale_session = 1,
  stale_compilation = 2,
  stale_attempt = 3,
  stale_phase = 4,
  stale_toolchain = 5,
  stale_target = 6,
  stale_environment = 7,
  stale_policy = 8,
  stale_source = 9,
  stale_ir = 10,
  stale_lease = 11,
  stale_component = 12,
  toolchain_retired = 13,
  target_retired = 14,
  environment_retired = 15,
  policy_retired = 16,
  /// The runtime cannot prove the binding is current. Fails closed.
  unknown = 17,
};

CRF_NODISCARD CRF_API std::string_view to_string(AuthorityVerdict value) noexcept;
CRF_NODISCARD CRF_API bool authority_verdict_is_current(AuthorityVerdict value) noexcept;
CRF_NODISCARD CRF_API StatusCode to_status_code(AuthorityVerdict value) noexcept;

/// What the runtime currently believes about the generations a session binds.
struct CRF_API AuthorityObservation {
  CompilerSessionGeneration session_generation{};
  CompilationGeneration compilation_generation{};
  AttemptGeneration attempt_generation{};
  /// Generation of the phase execution being evaluated. A retry advances this,
  /// which invalidates the previous attempt's binding.
  CompilerPhaseGeneration phase_generation{};
  Ref<ToolchainId> toolchain{};
  std::vector<Ref<ToolchainId>> cooperating_toolchains{};
  Ref<TargetId> target{};
  Ref<EnvironmentId> environment{};
  Ref<PolicyId> policy{};
  Ref<SourceId> source{};
  IRGeneration ir_generation{};
  Ref<LeaseId> lease{};

  /// Per-domain liveness. A registered identity that has been retired or whose
  /// generation advanced makes the corresponding comparison fail even when the
  /// numeric generation happens to match.
  bool session_active = true;
  bool toolchain_current = true;
  bool target_current = true;
  bool environment_current = true;
  bool policy_current = true;
  bool source_current = true;
  bool lease_held = true;
  bool component_current = true;
};

/// Compare a bound authority against the runtime's current observation.
///
/// The check order is fixed so that a refusal always names the same reason for
/// the same state, independent of hash iteration or thread timing.
CRF_NODISCARD CRF_API AuthorityVerdict compare_authority(const PhaseAuthority& bound,
                                                         const AuthorityObservation& current) noexcept;

/// A lease is a bounded grant of phase execution authority. Revoking a lease
/// fences every invocation that was authorised under it.
struct CRF_API Lease {
  LeaseId id{};
  LeaseGeneration generation{};
  Ref<CompilerSessionId> session{};
  Ref<CompilerPhaseId> phase{};
  std::uint64_t granted_at_nanos = 0;
  std::uint64_t expires_at_nanos = 0;   // 0 = no expiry
  bool held = true;
  std::string reason;

  CRF_NODISCARD bool held_at(std::uint64_t now_nanos) const noexcept {
    if (!held) return false;
    return expires_at_nanos == 0 || now_nanos <= expires_at_nanos;
  }
};

class CRF_API LeaseTable {
 public:
  CRF_NODISCARD Result<Ref<LeaseId>> grant(Ref<CompilerSessionId> session, Ref<CompilerPhaseId> phase,
                                           std::uint64_t ttl_nanos, std::string reason);
  CRF_NODISCARD VoidResult revoke(LeaseId id, std::string reason);
  CRF_NODISCARD std::size_t revoke_phase(CompilerPhaseId phase, std::string reason);
  CRF_NODISCARD const Lease* find(LeaseId id) const noexcept;
  CRF_NODISCARD bool is_held(Ref<LeaseId> reference) const noexcept;
  CRF_NODISCARD std::vector<Lease> list() const;
  CRF_NODISCARD std::size_t size() const noexcept { return entries_.size(); }

 private:
  struct Entry {
    Lease lease;
  };
  std::unordered_map<std::uint64_t, Entry> entries_;
  IdAllocator<LeaseId> allocator_;
};

}  // namespace crf
