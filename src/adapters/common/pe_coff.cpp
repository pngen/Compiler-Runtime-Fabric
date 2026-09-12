#include "pe_coff.hpp"

#include "crf/canonical.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>

namespace crf::adapters {
namespace {

CRF_NODISCARD std::uint16_t read_u16(const std::string& bytes, std::size_t offset) {
  if (offset + 2 > bytes.size()) return 0;
  return static_cast<std::uint16_t>(static_cast<unsigned char>(bytes[offset]) |
                                    (static_cast<std::uint16_t>(
                                         static_cast<unsigned char>(bytes[offset + 1]))
                                     << 8));
}

CRF_NODISCARD std::uint32_t read_u32(const std::string& bytes, std::size_t offset) {
  if (offset + 4 > bytes.size()) return 0;
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset + static_cast<std::size_t>(i)]))
             << (i * 8);
  }
  return value;
}

CRF_NODISCARD std::string read_section_name(const std::string& bytes, std::size_t offset) {
  std::string name;
  for (std::size_t i = 0; i < 8 && offset + i < bytes.size(); ++i) {
    const char c = bytes[offset + i];
    if (c == '\0') break;
    name.push_back(c);
  }
  return name;
}

}  // namespace

Result<std::string> read_file_head(const std::filesystem::path& path, std::size_t max_bytes) {
  std::error_code ec;
  if (!std::filesystem::exists(path, ec) || ec) {
    return Status(StatusCode::output_missing, "file does not exist: " + path.string());
  }
  const std::uintmax_t size = std::filesystem::file_size(path, ec);
  if (ec) {
    return Status(StatusCode::output_validation_failed, "file size is unavailable: " + path.string());
  }
  const std::size_t wanted =
      static_cast<std::size_t>(std::min<std::uintmax_t>(size, max_bytes));
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return Status(StatusCode::permission_denied, "file could not be opened: " + path.string());
  }
  std::string bytes(wanted, '\0');
  if (wanted != 0) {
    stream.read(bytes.data(), static_cast<std::streamsize>(wanted));
    bytes.resize(static_cast<std::size_t>(stream.gcount()));
  }
  return bytes;
}

Result<PeImageInfo> inspect_pe_image(const std::filesystem::path& path) {
  const Result<std::string> head = read_file_head(path, 1u << 20);
  if (!head) return head.status();
  const std::string& bytes = head.value();
  PeImageInfo info;
  if (bytes.size() < 64) {
    return Status(StatusCode::output_corrupt, "file is too small to be a PE image");
  }
  if (bytes[0] != 'M' || bytes[1] != 'Z') {
    return Status(StatusCode::output_unexpected_format, "file has no MZ signature");
  }
  const std::uint32_t pe_offset = read_u32(bytes, 0x3C);
  if (pe_offset == 0 || pe_offset + 24 > bytes.size()) {
    return Status(StatusCode::output_corrupt, "PE header offset is out of range");
  }
  if (bytes.compare(pe_offset, 4, "PE\0\0", 4) != 0) {
    return Status(StatusCode::output_corrupt, "PE signature is absent");
  }
  const std::size_t coff = pe_offset + 4;
  info.machine = read_u16(bytes, coff);
  info.section_count = read_u16(bytes, coff + 2);
  info.timestamp = read_u32(bytes, coff + 4);
  const std::uint16_t optional_size = read_u16(bytes, coff + 16);
  info.characteristics = read_u16(bytes, coff + 18);
  const std::size_t optional = coff + 20;
  if (optional_size < 2 || optional + optional_size > bytes.size()) {
    return Status(StatusCode::output_corrupt, "PE optional header is truncated");
  }
  const std::uint16_t magic = read_u16(bytes, optional);
  if (magic != 0x010Bu && magic != 0x020Bu) {
    return Status(StatusCode::output_unexpected_format, "PE optional header magic is not PE32/PE32+");
  }
  const std::size_t is_pe32_plus = magic == 0x020Bu ? 1u : 0u;
  info.entry_point_rva = read_u32(bytes, optional + 16);
  info.subsystem = read_u16(bytes, optional + 68);
  info.size_of_image = read_u32(bytes, optional + 56);
  const std::uint16_t dll_characteristics =
      read_u16(bytes, optional + (is_pe32_plus != 0 ? 70u : 70u));
  info.large_address_aware = (dll_characteristics & 0x0020u) != 0;
  info.is_dll = (info.characteristics & 0x2000u) != 0;
  info.is_executable = !info.is_dll && info.entry_point_rva != 0;
  if (info.section_count == 0) {
    return Status(StatusCode::output_corrupt, "PE image declares no sections");
  }
  info.valid = true;
  info.detail = "PE image machine=0x" + std::to_string(info.machine) + " subsystem=" +
                std::to_string(info.subsystem) + " sections=" + std::to_string(info.section_count) +
                (info.is_dll ? " dll" : " exe");
  return info;
}

Result<CoffObjectInfo> inspect_coff_object(const std::filesystem::path& path) {
  std::error_code ec;
  const std::uintmax_t file_size = std::filesystem::file_size(path, ec);
  if (ec) {
    return Status(StatusCode::output_missing, "object file is unavailable: " + path.string());
  }
  // Section names longer than eight characters live in the COFF string table,
  // which follows the symbol table, so the whole object is read (bounded).
  constexpr std::uintmax_t kObjectCeiling = 256ull * 1024ull * 1024ull;
  if (file_size > kObjectCeiling) {
    return Status(StatusCode::capacity_exceeded, "object file exceeds the inspection ceiling");
  }
  const Result<std::string> head = read_file_head(path, static_cast<std::size_t>(file_size));
  if (!head) return head.status();
  const std::string& bytes = head.value();
  CoffObjectInfo info;
  info.file_size = static_cast<std::uint64_t>(file_size);
  if (bytes.size() < 20) {
    return Status(StatusCode::output_corrupt, "file is too small to be a COFF object");
  }
  if (bytes[0] == 'M' && bytes[1] == 'Z') {
    return Status(StatusCode::output_unexpected_format,
                  "file is a PE image, not a COFF object");
  }
  info.machine = read_u16(bytes, 0);
  info.section_count = read_u16(bytes, 2);
  info.timestamp = read_u32(bytes, 4);
  info.symbol_count = read_u32(bytes, 12);
  const std::uint16_t optional_size = read_u16(bytes, 16);
  info.characteristics = read_u16(bytes, 18);
  if (optional_size != 0) {
    return Status(StatusCode::output_unexpected_format,
                  "file has an optional header and is therefore not a COFF object");
  }
  if (info.section_count == 0) {
    return Status(StatusCode::output_corrupt, "COFF object declares no sections");
  }
  // The string table starts after the symbol table: the first four bytes hold
  // its total size, and a name such as "/5317" is an offset into it.
  const std::size_t symbol_table = read_u32(bytes, 8);
  const std::size_t symbol_count = read_u32(bytes, 12);
  const std::size_t string_table = symbol_table + symbol_count * 18;
  const auto resolve_name = [&bytes, string_table](const std::string& raw) {
    if (raw.size() < 2 || raw[0] != '/') return raw;
    const std::string digits = raw.substr(1);
    if (digits.empty() ||
        !std::all_of(digits.begin(), digits.end(),
                     [](char c) { return c >= '0' && c <= '9'; })) {
      return raw;
    }
    const std::size_t offset = string_table + static_cast<std::size_t>(std::strtoul(digits.c_str(), nullptr, 10));
    if (offset >= bytes.size()) return raw;
    std::string name;
    for (std::size_t i = offset; i < bytes.size(); ++i) {
      if (bytes[i] == '\0') break;
      name.push_back(bytes[i]);
    }
    return name.empty() ? raw : name;
  };

  const std::size_t sections = 20;
  const std::size_t available = (bytes.size() - sections) / 40;
  const std::size_t count = std::min<std::size_t>(info.section_count, available);
  for (std::size_t i = 0; i < count; ++i) {
    const std::string name = resolve_name(read_section_name(bytes, sections + i * 40));
    if (!name.empty()) info.section_names.push_back(name);
    if (name == ".nv.info" || name == ".nv_fatbin" || name == "nv_fatbin" ||
        name == ".nvFatBinSegment") {
      info.has_device_code = true;
    }
  }
  info.valid = true;
  info.detail = "COFF object machine=0x" + std::to_string(info.machine) + " sections=" +
                std::to_string(info.section_count) + " symbols=" +
                std::to_string(info.symbol_count) +
                (info.has_device_code ? " with device code" : "");
  return info;
}

bool looks_like_ptx(const std::filesystem::path& path) {
  const Result<std::string> head = read_file_head(path, 4096);
  if (!head) return false;
  const std::string trimmed = std::string(trim_ascii(head.value()));
  return trimmed.rfind(".version", 0) == 0 || trimmed.rfind("//", 0) == 0 ||
         trimmed.find(".target") != std::string::npos;
}

Result<bool> looks_like_cubin(const std::filesystem::path& path) {
  const Result<std::string> head = read_file_head(path, 64);
  if (!head) return head.status();
  const std::string& bytes = head.value();
  if (bytes.size() < 20) return false;
  if (static_cast<unsigned char>(bytes[0]) != 0x7Fu || bytes[1] != 'E' || bytes[2] != 'L' ||
      bytes[3] != 'F') {
    return false;
  }
  const std::uint16_t machine = read_u16(bytes, 18);
  return machine == 190;   // EM_CUDA
}

}  // namespace crf::adapters
