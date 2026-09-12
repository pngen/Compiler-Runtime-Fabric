#include "crf/source.hpp"
#include "crf/canonical.hpp"

#include <algorithm>
#include <fstream>

namespace crf {

std::string_view to_string(SourceLanguage value) noexcept {
  switch (value) {
    case SourceLanguage::unknown: return "unknown";
    case SourceLanguage::c: return "c";
    case SourceLanguage::cxx: return "c++";
    case SourceLanguage::cuda: return "cuda";
    case SourceLanguage::assembly: return "assembly";
    case SourceLanguage::ptx: return "ptx";
    case SourceLanguage::other: return "other";
  }
  return "unknown";
}

bool parse_source_language(std::string_view text, SourceLanguage& out) noexcept {
  if (equals_ascii_ci(text, "c")) { out = SourceLanguage::c; return true; }
  if (equals_ascii_ci(text, "c++") || equals_ascii_ci(text, "cpp") || equals_ascii_ci(text, "cxx")) {
    out = SourceLanguage::cxx;
    return true;
  }
  if (equals_ascii_ci(text, "cuda") || equals_ascii_ci(text, "cu")) {
    out = SourceLanguage::cuda;
    return true;
  }
  if (equals_ascii_ci(text, "assembly") || equals_ascii_ci(text, "asm")) {
    out = SourceLanguage::assembly;
    return true;
  }
  if (equals_ascii_ci(text, "ptx")) { out = SourceLanguage::ptx; return true; }
  if (equals_ascii_ci(text, "other")) { out = SourceLanguage::other; return true; }
  return false;
}

SourceLanguage source_language_from_extension(std::string_view extension) noexcept {
  const std::string lowered = to_lower_ascii(extension);
  if (lowered == ".c") return SourceLanguage::c;
  if (lowered == ".cc" || lowered == ".cpp" || lowered == ".cxx" || lowered == ".c++" ||
      lowered == ".hpp" || lowered == ".hxx" || lowered == ".ixx") {
    return SourceLanguage::cxx;
  }
  if (lowered == ".cu") return SourceLanguage::cuda;
  if (lowered == ".asm" || lowered == ".s") return SourceLanguage::assembly;
  if (lowered == ".ptx") return SourceLanguage::ptx;
  return SourceLanguage::unknown;
}

Digest SourceUnit::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(id.to_string());
  writer.u64(generation.value());
  writer.text(canonical_path_key(path));
  writer.text(to_string(language));
  writer.text(dialect);
  writer.text(content.to_hex());
  writer.u64(size_bytes);
  writer.boolean(redact_diagnostics);
  return Digest::of(writer.bytes());
}

Digest IRDescriptor::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(id.to_string());
  writer.u64(generation.value());
  writer.text(format);
  writer.text(content.to_hex());
  writer.text(source.to_string());
  return Digest::of(writer.bytes());
}

Result<Ref<SourceId>> SourceRegistry::add(const std::filesystem::path& path,
                                          SourceLanguage language, std::string dialect) {
  if (entries_.size() >= kMaxSources) {
    return Status(StatusCode::capacity_exceeded, "source registry is full");
  }
  Digest content;
  if (!Digest::of_file(path, content)) {
    return Status(StatusCode::not_found, "source file could not be hashed: " + path.string());
  }
  std::error_code ec;
  const std::uintmax_t size = std::filesystem::file_size(path, ec);
  if (ec) {
    return Status(StatusCode::not_found, "source file size is unavailable: " + path.string());
  }

  SourceUnit unit;
  unit.id = allocator_.next();
  unit.generation = SourceGeneration::initial();
  unit.path = normalize_path(path);
  unit.language = language == SourceLanguage::unknown
                      ? source_language_from_extension(path.extension().string())
                      : language;
  unit.dialect = std::move(dialect);
  unit.content = content;
  unit.size_bytes = static_cast<std::uint64_t>(size);

  const SourceId id = unit.id;
  entries_.emplace(id.value(), std::move(unit));
  return Ref<SourceId>{id, SourceGeneration::initial()};
}

Result<Ref<SourceId>> SourceRegistry::add_from_bytes(std::string name, std::string_view bytes,
                                                     SourceLanguage language,
                                                     std::string dialect) {
  if (entries_.size() >= kMaxSources) {
    return Status(StatusCode::capacity_exceeded, "source registry is full");
  }
  SourceUnit unit;
  unit.id = allocator_.next();
  unit.generation = SourceGeneration::initial();
  unit.path = std::filesystem::path(name);
  unit.language = language == SourceLanguage::unknown
                      ? source_language_from_extension(std::filesystem::path(name).extension().string())
                      : language;
  unit.dialect = std::move(dialect);
  unit.content = Digest::of(bytes);
  unit.size_bytes = bytes.size();

  const SourceId id = unit.id;
  entries_.emplace(id.value(), std::move(unit));
  return Ref<SourceId>{id, SourceGeneration::initial()};
}

Result<Ref<SourceId>> SourceRegistry::add_as(SourceId id, const SourceUnit& unit) {
  if (!id.present()) {
    return Status(StatusCode::invalid_identity, "source identity is absent");
  }
  allocator_.observe(id);
  SourceUnit copy = unit;
  copy.id = id;
  if (!copy.generation.present()) copy.generation = SourceGeneration::initial();
  entries_[id.value()] = std::move(copy);
  return Ref<SourceId>{id, unit.generation.present() ? unit.generation : SourceGeneration::initial()};
}

const SourceUnit* SourceRegistry::find(SourceId id) const noexcept {
  const auto found = entries_.find(id.value());
  if (found == entries_.end()) return nullptr;
  return &found->second;
}

std::vector<SourceUnit> SourceRegistry::list() const {
  std::vector<SourceUnit> out;
  out.reserve(entries_.size());
  for (const auto& [key, entry] : entries_) {
    (void)key;
    out.push_back(entry);
  }
  std::sort(out.begin(), out.end(), [](const SourceUnit& a, const SourceUnit& b) {
    return a.id < b.id;
  });
  return out;
}

bool SourceRegistry::verify_unchanged(const SourceUnit& unit) const {
  if (unit.path.empty()) return false;
  Digest observed;
  if (!Digest::of_file(unit.path, observed)) return false;
  return observed == unit.content;
}

}  // namespace crf
