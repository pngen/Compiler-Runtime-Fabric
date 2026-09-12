#include "crf/target.hpp"
#include "crf/canonical.hpp"

#include <algorithm>

namespace crf {

std::string_view to_string(Architecture value) noexcept {
  switch (value) {
    case Architecture::unknown: return "unknown";
    case Architecture::x86: return "x86";
    case Architecture::x64: return "x64";
    case Architecture::arm: return "arm";
    case Architecture::arm64: return "arm64";
  }
  return "unknown";
}

bool parse_architecture(std::string_view text, Architecture& out) noexcept {
  struct Pair {
    std::string_view text;
    Architecture value;
  };
  static constexpr Pair kPairs[] = {{"unknown", Architecture::unknown},
                                    {"x86", Architecture::x86},
                                    {"i386", Architecture::x86},
                                    {"x64", Architecture::x64},
                                    {"amd64", Architecture::x64},
                                    {"x86_64", Architecture::x64},
                                    {"arm", Architecture::arm},
                                    {"arm64", Architecture::arm64},
                                    {"aarch64", Architecture::arm64}};
  for (const Pair& pair : kPairs) {
    if (equals_ascii_ci(text, pair.text)) {
      out = pair.value;
      return true;
    }
  }
  return false;
}

std::uint32_t pointer_bits(Architecture value) noexcept {
  switch (value) {
    case Architecture::x86:
    case Architecture::arm:
      return 32;
    case Architecture::x64:
    case Architecture::arm64:
      return 64;
    default:
      return 0;
  }
}

std::string_view to_string(OperatingSystem value) noexcept {
  switch (value) {
    case OperatingSystem::unknown: return "unknown";
    case OperatingSystem::windows: return "windows";
    case OperatingSystem::linux_kernel: return "linux";
    case OperatingSystem::macos: return "macos";
    case OperatingSystem::bare_metal: return "bare-metal";
  }
  return "unknown";
}

std::string_view to_string(ObjectFormat value) noexcept {
  switch (value) {
    case ObjectFormat::unknown: return "unknown";
    case ObjectFormat::coff_object: return "coff-object";
    case ObjectFormat::coff_image: return "coff-image";
    case ObjectFormat::ptx: return "ptx";
    case ObjectFormat::cubin: return "cubin";
    case ObjectFormat::fatbin: return "fatbin";
    case ObjectFormat::elf: return "elf";
    case ObjectFormat::archive: return "archive";
    case ObjectFormat::preprocessed_source: return "preprocessed-source";
    case ObjectFormat::assembly_source: return "assembly-source";
    case ObjectFormat::linker_map: return "linker-map";
    case ObjectFormat::debug_info: return "debug-info";
    case ObjectFormat::metadata: return "metadata";
  }
  return "unknown";
}

bool parse_object_format(std::string_view text, ObjectFormat& out) noexcept {
  static constexpr ObjectFormat kValues[] = {
      ObjectFormat::unknown,      ObjectFormat::coff_object,  ObjectFormat::coff_image,
      ObjectFormat::ptx,          ObjectFormat::cubin,        ObjectFormat::fatbin,
      ObjectFormat::elf,          ObjectFormat::archive,      ObjectFormat::preprocessed_source,
      ObjectFormat::assembly_source, ObjectFormat::linker_map, ObjectFormat::debug_info,
      ObjectFormat::metadata};
  for (ObjectFormat value : kValues) {
    if (equals_ascii_ci(text, to_string(value))) {
      out = value;
      return true;
    }
  }
  return false;
}

VoidResult TargetSpec::validate() const {
  if (architecture == Architecture::unknown) {
    return Status(StatusCode::invalid_argument, "target architecture is unknown");
  }
  if (os == OperatingSystem::unknown) {
    return Status(StatusCode::invalid_argument, "target operating system is unknown");
  }
  if (triple.empty()) {
    return Status(StatusCode::invalid_argument, "target triple is empty");
  }
  if (triple.size() > 256) {
    return Status(StatusCode::invalid_argument, "target triple is unreasonably long");
  }
  if (pointer_width_bits != 0 && pointer_width_bits != pointer_bits(architecture)) {
    return Status(StatusCode::invalid_argument,
                  "target pointer width disagrees with the declared architecture");
  }
  return VoidResult{};
}

Digest TargetSpec::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(to_string(architecture));
  writer.text(to_string(os));
  writer.text(triple);
  writer.text(cpu);
  writer.text(device_arch);
  writer.text(device_virtual_arch);
  writer.text(abi);
  writer.u32(pointer_width_bits);
  return Digest::of(writer.bytes());
}

Result<Ref<TargetId>> TargetRegistry::intern(const TargetSpec& spec) {
  if (const VoidResult valid = spec.validate(); !valid) return valid.status();
  const Digest digest = spec.canonical_digest();
  // Canonical intern: an identical spec already present is reused rather than
  // duplicated, so equivalent requests share one target generation.
  for (auto& [key, entry] : entries_) {
    (void)key;
    if (entry.current && entry.identity.digest == digest) {
      return Ref<TargetId>{entry.identity.id, entry.identity.generation};
    }
  }
  Entry entry;
  entry.identity.id = allocator_.next();
  entry.identity.generation = TargetGeneration::initial();
  entry.identity.digest = digest;
  entry.identity.spec = spec;
  const TargetId id = entry.identity.id;
  entries_.emplace(id.value(), std::move(entry));
  return Ref<TargetId>{id, TargetGeneration::initial()};
}

Result<Ref<TargetId>> TargetRegistry::intern_as(TargetId id, const TargetSpec& spec) {
  if (!id.present()) {
    return Status(StatusCode::invalid_identity, "target identity is absent");
  }
  if (const VoidResult valid = spec.validate(); !valid) return valid.status();
  allocator_.observe(id);
  Entry entry;
  entry.identity.id = id;
  entry.identity.generation = TargetGeneration::initial();
  entry.identity.digest = spec.canonical_digest();
  entry.identity.spec = spec;
  entries_[id.value()] = std::move(entry);
  return Ref<TargetId>{id, TargetGeneration::initial()};
}

Result<Ref<TargetId>> TargetRegistry::revise(TargetId id, const TargetSpec& spec) {
  const auto found = entries_.find(id.value());
  if (found == entries_.end()) {
    return Status(StatusCode::not_found, "target identity is not registered: " + id.to_string());
  }
  if (const VoidResult valid = spec.validate(); !valid) return valid.status();
  const Digest digest = spec.canonical_digest();
  if (found->second.identity.digest == digest && found->second.current) {
    return Ref<TargetId>{id, found->second.identity.generation};
  }
  found->second.identity.generation = found->second.identity.generation.next();
  found->second.identity.digest = digest;
  found->second.identity.spec = spec;
  found->second.current = true;
  return Ref<TargetId>{id, found->second.identity.generation};
}

const TargetIdentity* TargetRegistry::find(TargetId id) const noexcept {
  const auto found = entries_.find(id.value());
  if (found == entries_.end()) return nullptr;
  return &found->second.identity;
}

std::vector<TargetIdentity> TargetRegistry::list() const {
  std::vector<TargetIdentity> out;
  out.reserve(entries_.size());
  for (const auto& [key, entry] : entries_) {
    (void)key;
    out.push_back(entry.identity);
  }
  std::sort(out.begin(), out.end(), [](const TargetIdentity& a, const TargetIdentity& b) {
    return a.id < b.id;
  });
  return out;
}

std::uint16_t coff_machine_for(Architecture value) noexcept {
  switch (value) {
    case Architecture::x86: return 0x014Cu;    // IMAGE_FILE_MACHINE_I386
    case Architecture::x64: return 0x8664u;    // IMAGE_FILE_MACHINE_AMD64
    case Architecture::arm: return 0x01C0u;    // IMAGE_FILE_MACHINE_ARM
    case Architecture::arm64: return 0xAA64u;  // IMAGE_FILE_MACHINE_ARM64
    default: return 0;
  }
}

}  // namespace crf
