#include "crf/policy.hpp"
#include "crf/canonical.hpp"

#include <algorithm>

namespace crf {

std::string_view to_string(ReproducibilityPolicy value) noexcept {
  switch (value) {
    case ReproducibilityPolicy::required: return "REQUIRED";
    case ReproducibilityPolicy::preferred: return "PREFERRED";
    case ReproducibilityPolicy::not_required: return "NOT_REQUIRED";
  }
  return "UNKNOWN";
}

bool parse_reproducibility_policy(std::string_view text, ReproducibilityPolicy& out) noexcept {
  if (equals_ascii_ci(text, "REQUIRED")) { out = ReproducibilityPolicy::required; return true; }
  if (equals_ascii_ci(text, "PREFERRED")) { out = ReproducibilityPolicy::preferred; return true; }
  if (equals_ascii_ci(text, "NOT_REQUIRED") || equals_ascii_ci(text, "NOT-REQUIRED")) {
    out = ReproducibilityPolicy::not_required;
    return true;
  }
  return false;
}

VoidResult PolicySpec::validate() const {
  if (max_retries_per_phase > kMaxRetriesCeiling) {
    return Status(StatusCode::invalid_argument, "per-phase retry ceiling is out of range");
  }
  if (max_retries_per_session > kMaxRetriesCeiling * 4) {
    return Status(StatusCode::invalid_argument, "per-session retry ceiling is out of range");
  }
  if (forbidden_options.size() > kMaxForbiddenOptions) {
    return Status(StatusCode::capacity_exceeded, "forbidden option list is too large");
  }
  for (const std::string& option : forbidden_options) {
    if (option.empty() || option.size() > 4096) {
      return Status(StatusCode::invalid_argument, "forbidden option entry has an invalid length");
    }
  }
  if (max_parallel_phases == 0 && allow_parallel_phases) {
    return Status(StatusCode::invalid_argument,
                  "parallel phases are enabled with a zero concurrency ceiling");
  }
  if (max_parallel_phases > 256) {
    return Status(StatusCode::invalid_argument, "parallel phase ceiling is out of range");
  }
  return VoidResult{};
}

Digest PolicySpec::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(to_string(reproducibility));
  writer.u32(max_retries_per_phase);
  writer.u32(max_retries_per_session);
  std::vector<std::string> classes;
  classes.reserve(retryable_classes.size());
  for (FailureClass value : retryable_classes) classes.emplace_back(to_string(value));
  std::sort(classes.begin(), classes.end());
  for (const std::string& value : classes) writer.text(value);
  std::vector<std::string> options = forbidden_options;
  std::sort(options.begin(), options.end());
  for (const std::string& option : options) writer.text(to_lower_ascii(option));
  writer.boolean(allow_parallel_phases);
  writer.u64(max_parallel_phases);
  writer.u32(phase_timeout_millis);
  writer.u32(validation_timeout_millis);
  writer.boolean(run_smoke_test);
  writer.boolean(require_content_digest);
  writer.u64(max_diagnostic_entries);
  writer.u64(max_diagnostic_bytes_per_stream);
  writer.boolean(allow_local_cache);
  return Digest::of(writer.bytes());
}

bool PolicySpec::permits_retry(FailureClass failure) const noexcept {
  if (retryable_classes.empty()) return is_retryable(failure);
  return std::find(retryable_classes.begin(), retryable_classes.end(), failure) !=
         retryable_classes.end();
}

bool PolicySpec::forbids_option(std::string_view argument) const noexcept {
  for (const std::string& option : forbidden_options) {
    if (equals_ascii_ci(argument, option)) return true;
    if (argument.size() > option.size() && starts_with_ci(argument, option)) {
      const char separator = argument[option.size()];
      if (separator == ':' || separator == '=') return true;
    }
  }
  return false;
}

Result<Ref<PolicyId>> PolicyRegistry::intern(const PolicySpec& spec) {
  if (const VoidResult valid = spec.validate(); !valid) return valid.status();
  const Digest digest = spec.canonical_digest();
  for (auto& [key, entry] : entries_) {
    (void)key;
    if (entry.current && entry.identity.digest == digest) {
      return Ref<PolicyId>{entry.identity.id, entry.identity.generation};
    }
  }
  Entry entry;
  entry.identity.id = allocator_.next();
  entry.identity.generation = PolicyGeneration::initial();
  entry.identity.digest = digest;
  entry.identity.spec = spec;
  const PolicyId id = entry.identity.id;
  entries_.emplace(id.value(), std::move(entry));
  return Ref<PolicyId>{id, PolicyGeneration::initial()};
}

Result<Ref<PolicyId>> PolicyRegistry::intern_as(PolicyId id, const PolicySpec& spec) {
  if (!id.present()) {
    return Status(StatusCode::invalid_identity, "policy identity is absent");
  }
  if (const VoidResult valid = spec.validate(); !valid) return valid.status();
  allocator_.observe(id);
  Entry entry;
  entry.identity.id = id;
  entry.identity.generation = PolicyGeneration::initial();
  entry.identity.digest = spec.canonical_digest();
  entry.identity.spec = spec;
  entries_[id.value()] = std::move(entry);
  return Ref<PolicyId>{id, PolicyGeneration::initial()};
}

Result<Ref<PolicyId>> PolicyRegistry::revise(PolicyId id, const PolicySpec& spec) {
  const auto found = entries_.find(id.value());
  if (found == entries_.end()) {
    return Status(StatusCode::not_found, "policy identity is not registered: " + id.to_string());
  }
  if (const VoidResult valid = spec.validate(); !valid) return valid.status();
  const Digest digest = spec.canonical_digest();
  if (found->second.identity.digest == digest && found->second.current) {
    return Ref<PolicyId>{id, found->second.identity.generation};
  }
  found->second.identity.generation = found->second.identity.generation.next();
  found->second.identity.digest = digest;
  found->second.identity.spec = spec;
  found->second.current = true;
  return Ref<PolicyId>{id, found->second.identity.generation};
}

const PolicyIdentity* PolicyRegistry::find(PolicyId id) const noexcept {
  const auto found = entries_.find(id.value());
  if (found == entries_.end()) return nullptr;
  return &found->second.identity;
}

std::vector<PolicyIdentity> PolicyRegistry::list() const {
  std::vector<PolicyIdentity> out;
  out.reserve(entries_.size());
  for (const auto& [key, entry] : entries_) {
    (void)key;
    out.push_back(entry.identity);
  }
  std::sort(out.begin(), out.end(), [](const PolicyIdentity& a, const PolicyIdentity& b) {
    return a.id < b.id;
  });
  return out;
}

}  // namespace crf
