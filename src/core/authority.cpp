#include "crf/authority.hpp"
#include "crf/canonical.hpp"

#include <algorithm>

namespace crf {

Digest PhaseAuthority::canonical_digest() const {
  CanonicalWriter writer;
  writer.u64(session_generation.value());
  writer.u64(compilation_generation.value());
  writer.u64(attempt_generation.value());
  writer.u64(phase_generation.value());
  writer.text(toolchain.to_string());
  std::vector<std::string> cooperating;
  cooperating.reserve(cooperating_toolchains.size());
  for (const Ref<ToolchainId>& entry : cooperating_toolchains) cooperating.push_back(entry.to_string());
  std::sort(cooperating.begin(), cooperating.end());
  for (const std::string& entry : cooperating) writer.text(entry);
  writer.text(target.to_string());
  writer.text(environment.to_string());
  writer.text(policy.to_string());
  writer.text(source.to_string());
  writer.u64(ir_generation.value());
  writer.text(lease.to_string());
  return Digest::of(writer.bytes());
}

std::string PhaseAuthority::describe() const {
  std::string out;
  out.append("session=");
  out.append(session_generation.to_string());
  out.append(" compilation=");
  out.append(compilation_generation.to_string());
  out.append(" attempt=");
  out.append(attempt_generation.to_string());
  out.append(" phase=");
  out.append(phase_generation.to_string());
  out.append(" toolchain=");
  out.append(toolchain.to_string());
  out.append(" target=");
  out.append(target.to_string());
  out.append(" environment=");
  out.append(environment.to_string());
  out.append(" policy=");
  out.append(policy.to_string());
  out.append(" source=");
  out.append(source.to_string());
  out.append(" ir=");
  out.append(ir_generation.to_string());
  out.append(" lease=");
  out.append(lease.to_string());
  return out;
}

std::string_view to_string(AuthorityVerdict value) noexcept {
  switch (value) {
    case AuthorityVerdict::valid: return "VALID";
    case AuthorityVerdict::stale_session: return "STALE_SESSION";
    case AuthorityVerdict::stale_compilation: return "STALE_COMPILATION";
    case AuthorityVerdict::stale_attempt: return "STALE_ATTEMPT";
    case AuthorityVerdict::stale_phase: return "STALE_PHASE";
    case AuthorityVerdict::stale_toolchain: return "STALE_TOOLCHAIN";
    case AuthorityVerdict::stale_target: return "STALE_TARGET";
    case AuthorityVerdict::stale_environment: return "STALE_ENVIRONMENT";
    case AuthorityVerdict::stale_policy: return "STALE_POLICY";
    case AuthorityVerdict::stale_source: return "STALE_SOURCE";
    case AuthorityVerdict::stale_ir: return "STALE_IR";
    case AuthorityVerdict::stale_lease: return "STALE_LEASE";
    case AuthorityVerdict::stale_component: return "STALE_COMPONENT";
    case AuthorityVerdict::toolchain_retired: return "TOOLCHAIN_RETIRED";
    case AuthorityVerdict::target_retired: return "TARGET_RETIRED";
    case AuthorityVerdict::environment_retired: return "ENVIRONMENT_RETIRED";
    case AuthorityVerdict::policy_retired: return "POLICY_RETIRED";
    case AuthorityVerdict::unknown: return "UNKNOWN";
  }
  return "UNKNOWN";
}

bool authority_verdict_is_current(AuthorityVerdict value) noexcept {
  return value == AuthorityVerdict::valid;
}

StatusCode to_status_code(AuthorityVerdict value) noexcept {
  switch (value) {
    case AuthorityVerdict::valid: return StatusCode::ok;
    case AuthorityVerdict::stale_session: return StatusCode::stale_session_generation;
    case AuthorityVerdict::stale_compilation: return StatusCode::stale_compilation_generation;
    case AuthorityVerdict::stale_attempt: return StatusCode::stale_attempt_generation;
    case AuthorityVerdict::stale_phase: return StatusCode::stale_phase_generation;
    case AuthorityVerdict::stale_toolchain: return StatusCode::stale_toolchain_generation;
    case AuthorityVerdict::stale_target: return StatusCode::stale_target_generation;
    case AuthorityVerdict::stale_environment: return StatusCode::stale_environment_generation;
    case AuthorityVerdict::stale_policy: return StatusCode::stale_policy_generation;
    case AuthorityVerdict::stale_source: return StatusCode::stale_source_generation;
    case AuthorityVerdict::stale_ir: return StatusCode::stale_ir_generation;
    case AuthorityVerdict::stale_lease: return StatusCode::stale_lease_generation;
    case AuthorityVerdict::stale_component: return StatusCode::stale_component_generation;
    case AuthorityVerdict::toolchain_retired: return StatusCode::toolchain_not_found;
    case AuthorityVerdict::target_retired: return StatusCode::target_unsupported;
    case AuthorityVerdict::environment_retired: return StatusCode::stale_environment_generation;
    case AuthorityVerdict::policy_retired: return StatusCode::stale_policy_generation;
    case AuthorityVerdict::unknown: return StatusCode::integrity_unproven;
  }
  return StatusCode::integrity_unproven;
}

AuthorityVerdict compare_authority(const PhaseAuthority& bound,
                                   const AuthorityObservation& current) noexcept {
  // Fixed evaluation order: the first mismatch names the refusal so that the
  // same state always produces the same explained reason.
  if (!current.session_active) return AuthorityVerdict::stale_session;
  if (bound.session_generation != current.session_generation) {
    return AuthorityVerdict::stale_session;
  }
  if (bound.compilation_generation != current.compilation_generation) {
    return AuthorityVerdict::stale_compilation;
  }
  if (bound.attempt_generation != current.attempt_generation) {
    return AuthorityVerdict::stale_attempt;
  }
  if (bound.phase_generation != current.phase_generation) {
    return AuthorityVerdict::stale_phase;
  }
  if (!current.toolchain_current) return AuthorityVerdict::toolchain_retired;
  if (bound.toolchain.present() &&
      (bound.toolchain.id != current.toolchain.id ||
       bound.toolchain.generation != current.toolchain.generation)) {
    return AuthorityVerdict::stale_toolchain;
  }
  if (bound.cooperating_toolchains.size() != current.cooperating_toolchains.size()) {
    return AuthorityVerdict::stale_toolchain;
  }
  for (std::size_t i = 0; i < bound.cooperating_toolchains.size(); ++i) {
    if (!(bound.cooperating_toolchains[i] == current.cooperating_toolchains[i])) {
      return AuthorityVerdict::stale_toolchain;
    }
  }
  if (!current.component_current) return AuthorityVerdict::stale_component;
  if (!current.target_current) return AuthorityVerdict::target_retired;
  if (bound.target.present() &&
      (bound.target.id != current.target.id || bound.target.generation != current.target.generation)) {
    return AuthorityVerdict::stale_target;
  }
  if (!current.environment_current) return AuthorityVerdict::environment_retired;
  if (bound.environment.present() && (bound.environment.id != current.environment.id ||
                                      bound.environment.generation != current.environment.generation)) {
    return AuthorityVerdict::stale_environment;
  }
  if (!current.policy_current) return AuthorityVerdict::policy_retired;
  if (bound.policy.present() &&
      (bound.policy.id != current.policy.id || bound.policy.generation != current.policy.generation)) {
    return AuthorityVerdict::stale_policy;
  }
  if (!current.source_current) return AuthorityVerdict::stale_source;
  if (bound.source.present() &&
      (bound.source.id != current.source.id || bound.source.generation != current.source.generation)) {
    return AuthorityVerdict::stale_source;
  }
  if (bound.ir_generation.present() && bound.ir_generation != current.ir_generation) {
    return AuthorityVerdict::stale_ir;
  }
  if (bound.lease.present()) {
    if (!current.lease_held) return AuthorityVerdict::stale_lease;
    if (bound.lease.id != current.lease.id || bound.lease.generation != current.lease.generation) {
      return AuthorityVerdict::stale_lease;
    }
  }
  return AuthorityVerdict::valid;
}

Result<Ref<LeaseId>> LeaseTable::grant(Ref<CompilerSessionId> session, Ref<CompilerPhaseId> phase,
                                       std::uint64_t ttl_nanos, std::string reason) {
  Entry entry;
  entry.lease.id = allocator_.next();
  entry.lease.generation = LeaseGeneration::initial();
  entry.lease.session = session;
  entry.lease.phase = phase;
  entry.lease.granted_at_nanos = monotonic_nanos();
  entry.lease.expires_at_nanos = ttl_nanos == 0 ? 0 : entry.lease.granted_at_nanos + ttl_nanos;
  entry.lease.held = true;
  entry.lease.reason = std::move(reason);
  const LeaseId id = entry.lease.id;
  entries_.emplace(id.value(), std::move(entry));
  return Ref<LeaseId>{id, LeaseGeneration::initial()};
}

VoidResult LeaseTable::revoke(LeaseId id, std::string reason) {
  const auto found = entries_.find(id.value());
  if (found == entries_.end()) {
    return Status(StatusCode::not_found, "lease is not registered: " + id.to_string());
  }
  if (!found->second.lease.held) return VoidResult{};
  found->second.lease.held = false;
  found->second.lease.generation = found->second.lease.generation.next();
  found->second.lease.reason = std::move(reason);
  return VoidResult{};
}

std::size_t LeaseTable::revoke_phase(CompilerPhaseId phase, std::string reason) {
  std::size_t count = 0;
  for (auto& [key, entry] : entries_) {
    (void)key;
    if (entry.lease.phase.id != phase) continue;
    if (!entry.lease.held) continue;
    entry.lease.held = false;
    entry.lease.generation = entry.lease.generation.next();
    entry.lease.reason = reason;
    ++count;
  }
  return count;
}

const Lease* LeaseTable::find(LeaseId id) const noexcept {
  const auto found = entries_.find(id.value());
  if (found == entries_.end()) return nullptr;
  return &found->second.lease;
}

bool LeaseTable::is_held(Ref<LeaseId> reference) const noexcept {
  const Lease* lease = find(reference.id);
  if (lease == nullptr) return false;
  if (lease->generation != reference.generation) return false;
  return lease->held_at(monotonic_nanos());
}

std::vector<Lease> LeaseTable::list() const {
  std::vector<Lease> out;
  out.reserve(entries_.size());
  for (const auto& [key, entry] : entries_) {
    (void)key;
    out.push_back(entry.lease);
  }
  std::sort(out.begin(), out.end(), [](const Lease& a, const Lease& b) { return a.id < b.id; });
  return out;
}

}  // namespace crf
