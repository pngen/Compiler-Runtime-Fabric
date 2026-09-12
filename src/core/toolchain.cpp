#include "crf/toolchain.hpp"
#include "crf/canonical.hpp"

#include <algorithm>
#include <set>

namespace crf {

std::string_view to_string(ToolchainFamily value) noexcept {
  switch (value) {
    case ToolchainFamily::unknown: return "unknown";
    case ToolchainFamily::msvc: return "msvc";
    case ToolchainFamily::clang_cl: return "clang-cl";
    case ToolchainFamily::clang: return "clang";
    case ToolchainFamily::gcc: return "gcc";
    case ToolchainFamily::nvcc: return "nvcc";
    case ToolchainFamily::hipcc: return "hipcc";
    case ToolchainFamily::intel_icx: return "intel-icx";
    case ToolchainFamily::synthetic: return "synthetic";
  }
  return "unknown";
}

bool parse_toolchain_family(std::string_view text, ToolchainFamily& out) noexcept {
  static constexpr ToolchainFamily kValues[] = {
      ToolchainFamily::unknown,  ToolchainFamily::msvc,     ToolchainFamily::clang_cl,
      ToolchainFamily::clang,    ToolchainFamily::gcc,      ToolchainFamily::nvcc,
      ToolchainFamily::hipcc,    ToolchainFamily::intel_icx, ToolchainFamily::synthetic};
  for (ToolchainFamily value : kValues) {
    if (equals_ascii_ci(text, to_string(value))) {
      out = value;
      return true;
    }
  }
  return false;
}

Digest ToolchainIdentity::canonical_digest() const {
  // The digest identifies the *evidence*, not the registry bookkeeping. The
  // identity and the generation are deliberately excluded: a re-probe compares
  // evidence, and a generation that advanced is a consequence of changed
  // evidence rather than a change in it.
  CanonicalWriter writer;
  writer.text(to_string(family));
  writer.text(display_name);
  writer.text(version);
  std::vector<std::string> component_digests;
  component_digests.reserve(components.size());
  for (const ComponentIdentity& component : components) {
    component_digests.push_back(component.name + "=" + component.canonical_digest().to_hex());
  }
  writer.u64(components.size());
  std::sort(component_digests.begin(), component_digests.end());
  for (const std::string& entry : component_digests) writer.text(entry);
  std::vector<std::string> architectures;
  architectures.reserve(target_support.size());
  for (Architecture architecture : target_support) architectures.emplace_back(to_string(architecture));
  std::sort(architectures.begin(), architectures.end());
  for (const std::string& architecture : architectures) writer.text(architecture);
  std::vector<std::string> formats;
  formats.reserve(object_formats.size());
  for (ObjectFormat format : object_formats) formats.emplace_back(to_string(format));
  std::sort(formats.begin(), formats.end());
  for (const std::string& format : formats) writer.text(format);
  std::vector<EnvironmentVariable> contract = environment_contract;
  std::sort(contract.begin(), contract.end(), [](const EnvironmentVariable& a, const EnvironmentVariable& b) {
    return less_ascii_ci(a.name, b.name);
  });
  for (const EnvironmentVariable& entry : contract) {
    writer.text(to_upper_ascii(entry.name));
    writer.text(entry.value);
  }
  writer.text(canonical_path_key(toolkit_root));
  writer.text(canonical_path_key(sdk_root));
  std::vector<EnvironmentVariable> attributes_copy = attributes;
  std::sort(attributes_copy.begin(), attributes_copy.end(),
            [](const EnvironmentVariable& a, const EnvironmentVariable& b) {
              return less_ascii_ci(a.name, b.name);
            });
  for (const EnvironmentVariable& attribute : attributes_copy) {
    writer.text(to_upper_ascii(attribute.name));
    writer.text(attribute.value);
  }
  writer.text(standard_library_identity);
  writer.text(to_string(evidence_class));
  writer.text(evidence_digest.to_hex());
  return Digest::of(writer.bytes());
}

const ComponentIdentity* ToolchainIdentity::find_component(ComponentKind kind) const noexcept {
  for (const ComponentIdentity& component : components) {
    if (component.kind == kind) return &component;
  }
  return nullptr;
}

const ComponentIdentity* ToolchainIdentity::find_component(std::string_view name) const noexcept {
  for (const ComponentIdentity& component : components) {
    if (equals_ascii_ci(component.name, name)) return &component;
  }
  return nullptr;
}

bool ToolchainIdentity::supports(Architecture architecture) const noexcept {
  return std::find(target_support.begin(), target_support.end(), architecture) !=
         target_support.end();
}

std::string ToolchainIdentity::describe() const {
  std::string out;
  out.append(display_name.empty() ? std::string(to_string(family)) : display_name);
  out.append(" ");
  out.append(version.empty() ? std::string("<unknown-version>") : version);
  out.append(" gen=");
  out.append(generation.to_string());
  out.append(" evidence=");
  out.append(to_string(evidence_class));
  return out;
}

ToolchainMutation diff_toolchains(const ToolchainIdentity& previous,
                                  const ToolchainIdentity& observed) {
  ToolchainMutation mutation;
  mutation.previous_generation = previous.generation;
  mutation.current_generation = previous.generation;
  if (!previous.id.present() || previous.id != observed.id) {
    mutation.detail = "toolchain identity changed";
    mutation.mutated = true;
    return mutation;
  }
  if (previous.canonical_digest() == observed.canonical_digest()) {
    mutation.detail = "toolchain evidence is unchanged";
    return mutation;
  }

  const auto describe_component = [](const ComponentIdentity& component) {
    return component.name + " (" + component.file.describe() + ")";
  };

  for (const ComponentIdentity& component : previous.components) {
    const ComponentIdentity* match = observed.find_component(component.name);
    if (match == nullptr) {
      mutation.removed_components.push_back(describe_component(component));
      continue;
    }
    if (component.file.same_binary_as(match->file)) continue;
    std::string detail = describe_component(*match);
    if (!component.file.same_file_as(match->file)) detail.append(" [replaced at same path]");
    else if (!component.file.content_hashed || !match->file.content_hashed) {
      detail.append(" [identity unprovable without content digest]");
    } else {
      detail.append(" [content changed in place]");
    }
    mutation.changed_components.push_back(std::move(detail));
  }
  for (const ComponentIdentity& component : observed.components) {
    if (previous.find_component(component.name) == nullptr) {
      mutation.added_components.push_back(describe_component(component));
    }
  }

  const bool attributes_changed = previous.attributes.size() != observed.attributes.size() ||
                                  !std::equal(previous.attributes.begin(), previous.attributes.end(),
                                              observed.attributes.begin());
  const bool metadata_changed = attributes_changed || previous.version != observed.version ||
                                previous.standard_library_identity != observed.standard_library_identity ||
                                canonical_path_key(previous.toolkit_root) !=
                                    canonical_path_key(observed.toolkit_root) ||
                                previous.evidence_digest != observed.evidence_digest ||
                                previous.environment_contract.size() != observed.environment_contract.size();
  mutation.mutated = !mutation.changed_components.empty() || !mutation.removed_components.empty() ||
                     !mutation.added_components.empty() || metadata_changed;
  if (!mutation.mutated) {
    mutation.detail = "no authority-relevant toolchain change detected";
    return mutation;
  }
  mutation.current_generation = previous.generation.next();
  mutation.detail = "toolchain generation advanced: " + std::to_string(mutation.changed_components.size()) +
                    " changed, " + std::to_string(mutation.removed_components.size()) + " removed, " +
                    std::to_string(mutation.added_components.size()) + " added";
  return mutation;
}

Result<Ref<ToolchainId>> ToolchainRegistry::register_toolchain(ToolchainIdentity identity) {
  if (identity.family == ToolchainFamily::unknown) {
    return Status(StatusCode::invalid_argument, "toolchain family is unknown");
  }
  if (identity.components.empty() && identity.evidence_class != EvidenceClass::synthetic) {
    return Status(StatusCode::invalid_argument,
                  "toolchain has no probed components and is not declared synthetic");
  }
  identity.id = allocator_.next();
  identity.generation = ToolchainGeneration::initial();
  Entry entry;
  entry.identity = std::move(identity);
  const ToolchainId id = entry.identity.id;
  entries_.emplace(id.value(), std::move(entry));
  return Ref<ToolchainId>{id, ToolchainGeneration::initial()};
}

Result<Ref<ToolchainId>> ToolchainRegistry::register_toolchain_as(ToolchainId id,
                                                                 ToolchainIdentity identity) {
  if (!id.present()) {
    return Status(StatusCode::invalid_identity, "toolchain identity is absent");
  }
  allocator_.observe(id);
  identity.id = id;
  if (!identity.generation.present()) identity.generation = ToolchainGeneration::initial();
  Entry entry;
  entry.identity = std::move(identity);
  entries_[id.value()] = std::move(entry);
  return Ref<ToolchainId>{id, entries_[id.value()].identity.generation};
}

Result<ToolchainMutation> ToolchainRegistry::apply_observed(const ToolchainIdentity& observed,
                                                            bool allow_generation_advance) {
  const auto found = entries_.find(observed.id.value());
  if (found == entries_.end()) {
    return Status(StatusCode::not_found,
                  "toolchain identity is not registered: " + observed.id.to_string());
  }
  ToolchainMutation mutation = diff_toolchains(found->second.identity, observed);
  if (!mutation.mutated) {
    return mutation;
  }
  if (!allow_generation_advance) {
    return mutation;
  }
  const ToolchainGeneration previous = found->second.identity.generation;
  const ToolchainGeneration next = previous.next();
  found->second.identity = observed;
  found->second.identity.generation = next;
  found->second.current = true;
  mutation.previous_generation = previous;
  mutation.current_generation = next;
  return mutation;
}

Result<ToolchainMutation> ToolchainRegistry::refresh(const ToolchainIdentity& observed) {
  return apply_observed(observed, true);
}

Result<ToolchainMutation> ToolchainRegistry::invalidate(ToolchainId id, std::string reason) {
  const auto found = entries_.find(id.value());
  if (found == entries_.end()) {
    return Status(StatusCode::not_found, "toolchain identity is not registered: " + id.to_string());
  }
  ToolchainMutation mutation;
  mutation.mutated = true;
  mutation.previous_generation = found->second.identity.generation;
  mutation.current_generation = found->second.identity.generation.next();
  mutation.detail = std::move(reason);
  found->second.identity.generation = mutation.current_generation;
  found->second.current = true;
  return mutation;
}

const ToolchainIdentity* ToolchainRegistry::find(ToolchainId id) const noexcept {
  const auto found = entries_.find(id.value());
  if (found == entries_.end()) return nullptr;
  return &found->second.identity;
}

const ToolchainIdentity* ToolchainRegistry::find_latest(ToolchainFamily family) const noexcept {
  const ToolchainIdentity* best = nullptr;
  for (const auto& [key, entry] : entries_) {
    (void)key;
    if (entry.identity.family != family) continue;
    if (best == nullptr || entry.identity.id > best->id) best = &entry.identity;
  }
  return best;
}

std::vector<ToolchainIdentity> ToolchainRegistry::list() const {
  std::vector<ToolchainIdentity> out;
  out.reserve(entries_.size());
  for (const auto& [key, entry] : entries_) {
    (void)key;
    out.push_back(entry.identity);
  }
  std::sort(out.begin(), out.end(), [](const ToolchainIdentity& a, const ToolchainIdentity& b) {
    return a.id < b.id;
  });
  return out;
}

std::vector<ToolchainIdentity> ToolchainRegistry::history(ToolchainFamily family) const {
  std::vector<ToolchainIdentity> out;
  for (const auto& [key, entry] : entries_) {
    (void)key;
    if (entry.identity.family == family) out.push_back(entry.identity);
  }
  std::sort(out.begin(), out.end(), [](const ToolchainIdentity& a, const ToolchainIdentity& b) {
    return a.id > b.id;
  });
  return out;
}

bool ToolchainRegistry::is_current(const Ref<ToolchainId>& reference) const noexcept {
  const auto found = entries_.find(reference.id.value());
  if (found == entries_.end()) return false;
  if (!found->second.current) return false;
  return found->second.identity.generation == reference.generation;
}

}  // namespace crf
