#include "crf/component.hpp"
#include "crf/canonical.hpp"

#include <algorithm>
#include <cstdio>
#include <system_error>

#if defined(_WIN32)
#  include <windows.h>
#endif

namespace crf {
namespace {

CRF_NODISCARD std::string hex_u64(std::uint64_t value) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out(16, '0');
  for (int i = 15; i >= 0; --i) {
    out[static_cast<std::size_t>(i)] = kHex[value & 0xFull];
    value >>= 4;
  }
  return out;
}

CRF_NODISCARD std::string hex_u32(std::uint32_t value) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out(8, '0');
  for (int i = 7; i >= 0; --i) {
    out[static_cast<std::size_t>(i)] = kHex[value & 0xFull];
    value >>= 4;
  }
  return out;
}

#if defined(_WIN32)
/// 100-nanosecond intervals between the Windows epoch (1601-01-01) and the
/// Unix epoch (1970-01-01).
constexpr std::uint64_t kFiletimeEpochDelta = 116444736000000000ull;

CRF_NODISCARD std::uint64_t filetime_to_unix_nanos(const FILETIME& time) noexcept {
  const std::uint64_t ticks =
      (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
  if (ticks < kFiletimeEpochDelta) return 0;
  return (ticks - kFiletimeEpochDelta) * 100ull;
}
#endif

}  // namespace

std::string_view to_string(ComponentKind value) noexcept {
  switch (value) {
    case ComponentKind::unknown: return "unknown";
    case ComponentKind::host_c_compiler: return "host-c-compiler";
    case ComponentKind::host_cxx_compiler: return "host-cxx-compiler";
    case ComponentKind::device_compiler: return "device-compiler";
    case ComponentKind::device_assembler: return "device-assembler";
    case ComponentKind::assembler: return "assembler";
    case ComponentKind::linker: return "linker";
    case ComponentKind::librarian: return "librarian";
    case ComponentKind::optimizer: return "optimizer";
    case ComponentKind::plugin: return "plugin";
    case ComponentKind::sdk_header_set: return "sdk-header-set";
    case ComponentKind::runtime_library: return "runtime-library";
    case ComponentKind::standard_library: return "standard-library";
    case ComponentKind::target_library: return "target-library";
    case ComponentKind::other: return "other";
  }
  return "unknown";
}

bool parse_component_kind(std::string_view text, ComponentKind& out) noexcept {
  static constexpr ComponentKind kValues[] = {
      ComponentKind::unknown,          ComponentKind::host_c_compiler,
      ComponentKind::host_cxx_compiler, ComponentKind::device_compiler,
      ComponentKind::device_assembler,  ComponentKind::assembler,
      ComponentKind::linker,            ComponentKind::librarian,
      ComponentKind::optimizer,         ComponentKind::plugin,
      ComponentKind::sdk_header_set,    ComponentKind::runtime_library,
      ComponentKind::standard_library,  ComponentKind::target_library,
      ComponentKind::other};
  for (ComponentKind value : kValues) {
    if (equals_ascii_ci(text, to_string(value))) {
      out = value;
      return true;
    }
  }
  return false;
}

bool FileIdentity::same_file_as(const FileIdentity& other) const noexcept {
  if (volume_serial_hex.empty() || other.volume_serial_hex.empty()) {
    return canonical_path_key(canonical_path) == canonical_path_key(other.canonical_path);
  }
  return volume_serial_hex == other.volume_serial_hex && file_index_hex == other.file_index_hex;
}

bool FileIdentity::same_binary_as(const FileIdentity& other) const noexcept {
  if (!same_file_as(other)) return false;
  if (content_hashed && other.content_hashed) return content == other.content;
  // Without a content digest the runtime cannot prove byte identity. Size and
  // timestamp disagreement is enough to prove difference; agreement is not
  // enough to prove sameness.
  return size_bytes == other.size_bytes && last_write_nanos == other.last_write_nanos &&
         content_hashed == other.content_hashed;
}

Digest FileIdentity::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(canonical_path_key(canonical_path));
  writer.text(volume_serial_hex);
  writer.text(file_index_hex);
  writer.u64(size_bytes);
  writer.u64(last_write_nanos);
  writer.text(content.to_hex());
  writer.boolean(content_hashed);
  return Digest::of(writer.bytes());
}

std::string FileIdentity::describe() const {
  std::string out = canonical_path.empty() ? std::string("<none>") : canonical_path.string();
  out.append(" size=");
  out.append(std::to_string(size_bytes));
  if (content_hashed) {
    out.append(" sha256=");
    out.append(content.to_short_hex());
  } else {
    out.append(" sha256=<unhashed>");
  }
  if (!volume_serial_hex.empty()) {
    out.append(" fileid=");
    out.append(volume_serial_hex);
    out.append(":");
    out.append(file_index_hex);
  }
  return out;
}

Result<FileIdentity> probe_file_identity(const std::filesystem::path& path, bool hash_content) {
  std::error_code ec;
  if (!std::filesystem::exists(path, ec) || ec) {
    return Status(StatusCode::not_found, "file does not exist: " + path.string());
  }
  if (std::filesystem::is_directory(path, ec) || ec) {
    return Status(StatusCode::invalid_argument, "path is a directory, not a file: " + path.string());
  }

  FileIdentity identity;
  identity.canonical_path = normalize_path(path);
  identity.size_bytes = static_cast<std::uint64_t>(std::filesystem::file_size(path, ec));
  if (ec) {
    return Status(StatusCode::not_found, "file size is unavailable: " + path.string());
  }
  const auto write_time = std::filesystem::last_write_time(path, ec);
  if (!ec) {
    identity.last_write_nanos = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(write_time.time_since_epoch()).count());
  }

#if defined(_WIN32)
  const HANDLE handle = ::CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return Status(StatusCode::permission_denied, "file attributes are unavailable: " + path.string());
  }
  BY_HANDLE_FILE_INFORMATION info{};
  if (::GetFileInformationByHandle(handle, &info) == 0) {
    ::CloseHandle(handle);
    return Status(StatusCode::probe_failed, "GetFileInformationByHandle failed: " + path.string());
  }
  ::CloseHandle(handle);
  identity.volume_serial_hex = hex_u32(info.dwVolumeSerialNumber);
  identity.file_index_hex = hex_u64((static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) |
                                    info.nFileIndexLow);
  identity.size_bytes = (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
  identity.last_write_nanos = filetime_to_unix_nanos(info.ftLastWriteTime);
#endif

  if (hash_content) {
    Digest content;
    if (!Digest::of_file(identity.canonical_path, content)) {
      return Status(StatusCode::probe_failed,
                    "file content could not be hashed: " + path.string());
    }
    identity.content = content;
    identity.content_hashed = true;
  }
  return identity;
}

Digest ComponentIdentity::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(id.to_string());
  writer.u64(generation.value());
  writer.text(to_string(kind));
  writer.text(name);
  writer.text(version);
  writer.text(file.canonical_digest().to_hex());
  std::vector<std::string> capabilities = command_capabilities;
  std::sort(capabilities.begin(), capabilities.end());
  for (const std::string& capability : capabilities) writer.text(capability);
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
  std::vector<EnvironmentVariable> requirements = environment_requirements;
  std::sort(requirements.begin(), requirements.end(),
            [](const EnvironmentVariable& a, const EnvironmentVariable& b) {
              return less_ascii_ci(a.name, b.name);
            });
  for (const EnvironmentVariable& requirement : requirements) {
    writer.text(to_upper_ascii(requirement.name));
    writer.text(requirement.value);
  }
  writer.text(to_string(evidence_class));
  return Digest::of(writer.bytes());
}

const EnvironmentVariable* ComponentIdentity::requirement(std::string_view variable) const noexcept {
  for (const EnvironmentVariable& entry : environment_requirements) {
    if (equals_ascii_ci(entry.name, variable)) return &entry;
  }
  return nullptr;
}

ComponentRevalidation revalidate_component(const ComponentIdentity& recorded, bool hash_content) {
  ComponentRevalidation result;
  Digest probe_digest;
  std::error_code ec;
  if (!std::filesystem::exists(recorded.file.canonical_path, ec) || ec) {
    result.current = false;
    result.path_missing = true;
    result.detail = "component is missing at its recorded path: " +
                    recorded.file.canonical_path.string();
    return result;
  }
  const Result<FileIdentity> observed = probe_file_identity(recorded.file.canonical_path, hash_content);
  if (!observed) {
    result.current = false;
    result.detail = "component re-probe failed: " + observed.status().to_string();
    return result;
  }
  result.observed = observed.value();
  result.replaced_at_same_path = !recorded.file.same_file_as(result.observed);
  result.content_changed = !recorded.file.same_binary_as(result.observed);
  result.current = !result.content_changed;
  if (result.content_changed) {
    result.detail = result.replaced_at_same_path
                        ? "component was replaced by a different file at the same path"
                        : "component content changed in place";
  } else {
    result.detail = "component identity is current";
  }
  return result;
}

}  // namespace crf
