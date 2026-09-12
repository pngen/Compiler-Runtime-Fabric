#pragma once

// PE/COFF inspection used by the adapters for output validation. Vendor-neutral
// container parsing lives here because validation must not trust a compiler's
// exit code.

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "crf/status.hpp"
#include "crf/target.hpp"

namespace crf::adapters {

struct PeImageInfo {
  bool valid = false;
  std::uint16_t machine = 0;
  std::uint16_t subsystem = 0;
  std::uint16_t characteristics = 0;
  std::uint16_t section_count = 0;
  std::uint32_t timestamp = 0;
  std::uint32_t size_of_image = 0;
  std::uint32_t entry_point_rva = 0;
  bool is_executable = false;
  bool is_dll = false;
  bool large_address_aware = false;
  bool has_imports = false;
  std::string detail;
};

struct CoffObjectInfo {
  bool valid = false;
  std::uint16_t machine = 0;
  std::uint16_t section_count = 0;
  std::uint16_t characteristics = 0;
  std::uint32_t symbol_count = 0;
  std::uint32_t timestamp = 0;
  std::uint64_t file_size = 0;
  std::vector<std::string> section_names;
  /// True when the object embeds device code (nvcc-produced objects carry an
  /// nv_fatbin section).
  bool has_device_code = false;
  std::string detail;
};

/// Parse a PE image header. Refuses a truncated or inconsistent header.
CRF_NODISCARD Result<PeImageInfo> inspect_pe_image(const std::filesystem::path& path);

/// Parse a COFF object header and the section-name table.
CRF_NODISCARD Result<CoffObjectInfo> inspect_coff_object(const std::filesystem::path& path);

/// True when the file begins like a PTX module.
CRF_NODISCARD bool looks_like_ptx(const std::filesystem::path& path);

/// True when the file is an ELF image (a cubin is an ELF with e_machine 190).
CRF_NODISCARD Result<bool> looks_like_cubin(const std::filesystem::path& path);

/// Read at most max_bytes from the head of a file.
CRF_NODISCARD Result<std::string> read_file_head(const std::filesystem::path& path,
                                                 std::size_t max_bytes);

}  // namespace crf::adapters
