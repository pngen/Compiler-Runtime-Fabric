#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "crf/digest.hpp"
#include "crf/environment.hpp"
#include "crf/evidence.hpp"
#include "crf/status.hpp"
#include "crf/strong_id.hpp"
#include "crf/target.hpp"

namespace crf {

enum class ComponentKind : std::uint8_t {
  unknown = 0,
  host_c_compiler = 1,
  host_cxx_compiler = 2,
  device_compiler = 3,
  device_assembler = 4,
  assembler = 5,
  linker = 6,
  librarian = 7,
  optimizer = 8,
  plugin = 9,
  sdk_header_set = 10,
  runtime_library = 11,
  standard_library = 12,
  target_library = 13,
  other = 14,
};

CRF_NODISCARD CRF_API std::string_view to_string(ComponentKind value) noexcept;
CRF_NODISCARD CRF_API bool parse_component_kind(std::string_view text, ComponentKind& out) noexcept;

/// Identity of one file on disk.
///
/// A path is not identity. This record captures the NTFS file id (volume serial
/// plus file index) and the content digest, so replacing an executable while
/// keeping its path produces a different identity. A probe that cannot hash the
/// content leaves content zero and sets content_hashed=false; such an identity
/// is UNKNOWN and cannot satisfy a component binding that requires content
/// proof.
struct CRF_API FileIdentity {
  std::filesystem::path canonical_path;
  std::string volume_serial_hex;
  std::string file_index_hex;
  std::uint64_t size_bytes = 0;
  std::uint64_t last_write_nanos = 0;
  Digest content{};
  bool content_hashed = false;

  friend bool operator==(const FileIdentity&, const FileIdentity&) = default;

  /// Same physical file (volume + index), regardless of content.
  CRF_NODISCARD bool same_file_as(const FileIdentity& other) const noexcept;
  /// Same physical file and same bytes.
  CRF_NODISCARD bool same_binary_as(const FileIdentity& other) const noexcept;

  CRF_NODISCARD Digest canonical_digest() const;
  CRF_NODISCARD std::string describe() const;
};

/// Probe a file's identity. When hash_content is true the content digest is
/// computed; hashing is bounded by Digest::kDefaultFileBound.
CRF_NODISCARD CRF_API Result<FileIdentity> probe_file_identity(
    const std::filesystem::path& path, bool hash_content = true);

/// One executable or library that participates in a compile path.
struct CRF_API ComponentIdentity {
  CompilerComponentId id{};
  CompilerComponentGeneration generation{};
  ComponentKind kind = ComponentKind::unknown;
  /// Stable logical name within the toolchain, e.g. "cl", "link", "ptxas".
  std::string name;
  /// Version string as reported by the component itself (probe output).
  std::string version;
  FileIdentity file;
  /// Command capabilities this component is known to accept, e.g. "/std:c++20".
  std::vector<std::string> command_capabilities;
  std::vector<Architecture> target_support;
  std::vector<ObjectFormat> object_formats;
  /// Variables this component requires in the child environment.
  std::vector<EnvironmentVariable> environment_requirements;
  EvidenceClass evidence_class = EvidenceClass::unknown;

  CRF_NODISCARD Digest canonical_digest() const;
  CRF_NODISCARD const EnvironmentVariable* requirement(std::string_view name) const noexcept;
};

/// Result of re-probing a component against its recorded identity.
struct CRF_API ComponentRevalidation {
  bool current = false;
  bool path_missing = false;
  bool content_changed = false;
  bool replaced_at_same_path = false;
  FileIdentity observed;
  std::string detail;
};

CRF_NODISCARD CRF_API ComponentRevalidation revalidate_component(
    const ComponentIdentity& recorded, bool hash_content = true);

}  // namespace crf
