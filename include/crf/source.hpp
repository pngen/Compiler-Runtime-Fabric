#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "crf/digest.hpp"
#include "crf/status.hpp"
#include "crf/strong_id.hpp"

namespace crf {

enum class SourceLanguage : std::uint8_t {
  unknown = 0,
  c = 1,
  cxx = 2,
  cuda = 3,
  assembly = 4,
  ptx = 5,
  other = 6,
};

CRF_NODISCARD CRF_API std::string_view to_string(SourceLanguage value) noexcept;
CRF_NODISCARD CRF_API bool parse_source_language(std::string_view text, SourceLanguage& out) noexcept;
CRF_NODISCARD CRF_API SourceLanguage source_language_from_extension(std::string_view extension) noexcept;

/// One translation unit input. Content is digested at admission; a later edit
/// produces a different SourceGeneration and invalidates dependent phases.
struct CRF_API SourceUnit {
  SourceId id{};
  SourceGeneration generation{};
  std::filesystem::path path;
  SourceLanguage language = SourceLanguage::unknown;
  /// Dialect selection, e.g. "c++20", "c++17", "cuda-12.9".
  std::string dialect;
  Digest content{};
  std::uint64_t size_bytes = 0;
  /// When true, the source must not be embedded verbatim in diagnostics.
  bool redact_diagnostics = false;

  CRF_NODISCARD Digest canonical_digest() const;
};

/// A generated intermediate representation that is not a file artifact, for
/// example an in-memory module interface or a device fat binary descriptor.
struct CRF_API IRDescriptor {
  IRId id{};
  IRGeneration generation{};
  std::string format;
  Digest content{};
  Ref<SourceId> source{};

  CRF_NODISCARD Digest canonical_digest() const;
};

class CRF_API SourceRegistry {
 public:
  static constexpr std::size_t kMaxSources = 4096;

  CRF_NODISCARD Result<Ref<SourceId>> add(const std::filesystem::path& path,
                                          SourceLanguage language, std::string dialect = {});
  CRF_NODISCARD Result<Ref<SourceId>> add_from_bytes(std::string name, std::string_view bytes,
                                                     SourceLanguage language,
                                                     std::string dialect = {});
  /// Register a source with a known identity; used when replaying durable state.
  CRF_NODISCARD Result<Ref<SourceId>> add_as(SourceId id, const SourceUnit& unit);

  CRF_NODISCARD const SourceUnit* find(SourceId id) const noexcept;
  CRF_NODISCARD std::vector<SourceUnit> list() const;
  CRF_NODISCARD std::size_t size() const noexcept { return entries_.size(); }

  /// Recompute the on-disk digest and compare to the admitted value.
  CRF_NODISCARD bool verify_unchanged(const SourceUnit& unit) const;

 private:
  std::unordered_map<std::uint64_t, SourceUnit> entries_;
  IdAllocator<SourceId> allocator_;
};

}  // namespace crf
