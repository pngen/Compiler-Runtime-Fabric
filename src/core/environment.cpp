#include "crf/environment.hpp"

#include <algorithm>
#include <cstdlib>
#include <unordered_set>

#if defined(_WIN32)
#  include <windows.h>
#endif

#include <cstring>

namespace crf {
namespace {

/// Ambient variables copied into the child purely because the Windows loader
/// requires them. They do not participate in environment identity: they
/// describe where the operating system lives, not how the compiler behaves.
constexpr const char* kLoaderVariables[] = {"SystemRoot", "windir", "SystemDrive"};

CRF_NODISCARD std::string ambient_value(std::string_view name) {
#if defined(_WIN32)
  const std::string key(name);
  char buffer[32768];
  const DWORD written = ::GetEnvironmentVariableA(key.c_str(), buffer, sizeof(buffer));
  if (written == 0 || written >= sizeof(buffer)) return {};
  return std::string(buffer, written);
#else
  const std::string key(name);
  const char* value = std::getenv(key.c_str());
  return value != nullptr ? std::string(value) : std::string{};
#endif
}

CRF_NODISCARD bool path_list_less(const std::filesystem::path& a, const std::filesystem::path& b) {
  return canonical_path_key(a) < canonical_path_key(b);
}

}  // namespace

std::string_view to_string(LocalePolicy value) noexcept {
  switch (value) {
    case LocalePolicy::c_locale: return "c-locale";
    case LocalePolicy::explicit_name: return "explicit-name";
    case LocalePolicy::user_default: return "user-default";
  }
  return "unknown";
}

bool parse_locale_policy(std::string_view text, LocalePolicy& out) noexcept {
  if (equals_ascii_ci(text, "c-locale") || equals_ascii_ci(text, "c")) {
    out = LocalePolicy::c_locale;
    return true;
  }
  if (equals_ascii_ci(text, "explicit-name") || equals_ascii_ci(text, "explicit")) {
    out = LocalePolicy::explicit_name;
    return true;
  }
  if (equals_ascii_ci(text, "user-default") || equals_ascii_ci(text, "user")) {
    out = LocalePolicy::user_default;
    return true;
  }
  return false;
}

VoidResult EnvironmentSpec::canonicalize() {
  if (variables.size() > kMaxVariables) {
    return Status(StatusCode::capacity_exceeded, "environment variable count exceeds the ceiling");
  }
  if (include_paths.size() > kMaxSearchPaths || library_paths.size() > kMaxSearchPaths ||
      sdk_roots.size() > kMaxSearchPaths || toolkit_roots.size() > kMaxSearchPaths) {
    return Status(StatusCode::capacity_exceeded, "environment search path count exceeds the ceiling");
  }
  if (inherited_variables.size() > 256) {
    return Status(StatusCode::capacity_exceeded, "inherited variable allowlist is too large");
  }

  std::uint64_t total_value_bytes = 0;
  for (EnvironmentVariable& variable : variables) {
    if (variable.name.empty()) {
      return Status(StatusCode::invalid_argument, "environment variable name is empty");
    }
    if (variable.name.size() > kMaxVariableNameBytes) {
      return Status(StatusCode::invalid_argument, "environment variable name is too long");
    }
    if (variable.value.size() > kMaxVariableValueBytes) {
      return Status(StatusCode::invalid_argument,
                    "environment variable value is too long: " + variable.name);
    }
    if (variable.name.find('=') != std::string::npos ||
        variable.name.find('\0') != std::string::npos) {
      return Status(StatusCode::invalid_argument,
                    "environment variable name contains an illegal character: " + variable.name);
    }
    total_value_bytes += variable.value.size();
  }
  if (total_value_bytes > kMaxTotalValueBytes) {
    return Status(StatusCode::capacity_exceeded, "environment variable bytes exceed the ceiling");
  }

  // Canonical order: ASCII-uppercased name, then exact name for stability.
  std::sort(variables.begin(), variables.end(),
            [](const EnvironmentVariable& a, const EnvironmentVariable& b) {
              const std::string left = to_upper_ascii(a.name);
              const std::string right = to_upper_ascii(b.name);
              if (left != right) return left < right;
              return a.name < b.name;
            });

  for (std::size_t i = 1; i < variables.size(); ++i) {
    if (equals_ascii_ci(variables[i - 1].name, variables[i].name)) {
      return Status(StatusCode::invalid_argument,
                    "duplicate environment variable name: " + variables[i].name);
    }
  }

  std::sort(inherited_variables.begin(), inherited_variables.end());
  inherited_variables.erase(
      std::unique(inherited_variables.begin(), inherited_variables.end()),
      inherited_variables.end());
  for (const std::string& name : inherited_variables) {
    if (name.empty() || name.find('=') != std::string::npos) {
      return Status(StatusCode::invalid_argument, "invalid inherited variable name");
    }
  }

  if (!working_directory.empty()) working_directory = normalize_path(working_directory);
  if (!temp_directory.empty()) temp_directory = normalize_path(temp_directory);

  const auto normalize_list = [](std::vector<std::filesystem::path>& paths) {
    for (std::filesystem::path& path : paths) path = normalize_path(path);
    std::sort(paths.begin(), paths.end(), path_list_less);
    paths.erase(std::unique(paths.begin(), paths.end()), paths.end());
  };
  normalize_list(include_paths);
  normalize_list(library_paths);
  normalize_list(sdk_roots);
  normalize_list(toolkit_roots);

  if (locale_policy == LocalePolicy::explicit_name && locale_name.empty()) {
    return Status(StatusCode::invalid_argument,
                  "explicit locale policy requires a locale name");
  }
  return VoidResult{};
}

Digest EnvironmentSpec::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(canonical_path_key(working_directory));
  writer.text(canonical_path_key(temp_directory));
  for (const EnvironmentVariable& variable : variables) {
    writer.text(to_upper_ascii(variable.name));
    writer.text(variable.value);
  }
  for (const std::filesystem::path& path : include_paths) writer.text(canonical_path_key(path));
  for (const std::filesystem::path& path : library_paths) writer.text(canonical_path_key(path));
  for (const std::filesystem::path& path : sdk_roots) writer.text(canonical_path_key(path));
  for (const std::filesystem::path& path : toolkit_roots) writer.text(canonical_path_key(path));
  for (const std::string& name : inherited_variables) writer.text(to_upper_ascii(name));
  writer.text(to_string(locale_policy));
  writer.text(locale_name);
  writer.boolean(deterministic_controls);
  return Digest::of(writer.bytes());
}

const std::string* EnvironmentSpec::find_variable(std::string_view name) const noexcept {
  for (const EnvironmentVariable& variable : variables) {
    if (equals_ascii_ci(variable.name, name)) return &variable.value;
  }
  return nullptr;
}

void EnvironmentSpec::set_variable(std::string name, std::string value) {
  for (EnvironmentVariable& variable : variables) {
    if (equals_ascii_ci(variable.name, name)) {
      variable.name = std::move(name);
      variable.value = std::move(value);
      return;
    }
  }
  variables.push_back(EnvironmentVariable{std::move(name), std::move(value)});
}

bool EnvironmentSpec::erase_variable(std::string_view name) {
  const auto found = std::find_if(variables.begin(), variables.end(),
                                  [name](const EnvironmentVariable& variable) {
                                    return equals_ascii_ci(variable.name, name);
                                  });
  if (found == variables.end()) return false;
  variables.erase(found);
  return true;
}

std::string EnvironmentSpec::join_paths(const std::vector<std::filesystem::path>& paths) const {
  std::string out;
  for (const std::filesystem::path& path : paths) {
    if (!out.empty()) out.push_back(';');
    out.append(path.string());
  }
  return out;
}

Result<Ref<EnvironmentId>> EnvironmentRegistry::intern(EnvironmentSpec spec) {
  if (const VoidResult valid = spec.canonicalize(); !valid) return valid.status();
  const Digest digest = spec.canonical_digest();
  for (auto& [key, entry] : entries_) {
    (void)key;
    if (entry.current && entry.identity.digest == digest) {
      return Ref<EnvironmentId>{entry.identity.id, entry.identity.generation};
    }
  }
  Entry entry;
  entry.identity.id = allocator_.next();
  entry.identity.generation = EnvironmentGeneration::initial();
  entry.identity.digest = digest;
  entry.identity.spec = std::move(spec);
  const EnvironmentId id = entry.identity.id;
  entries_.emplace(id.value(), std::move(entry));
  return Ref<EnvironmentId>{id, EnvironmentGeneration::initial()};
}

Result<Ref<EnvironmentId>> EnvironmentRegistry::intern_as(EnvironmentId id, EnvironmentSpec spec) {
  if (!id.present()) {
    return Status(StatusCode::invalid_identity, "environment identity is absent");
  }
  if (const VoidResult valid = spec.canonicalize(); !valid) return valid.status();
  allocator_.observe(id);
  Entry entry;
  entry.identity.id = id;
  entry.identity.generation = EnvironmentGeneration::initial();
  entry.identity.digest = spec.canonical_digest();
  entry.identity.spec = std::move(spec);
  entries_[id.value()] = std::move(entry);
  return Ref<EnvironmentId>{id, EnvironmentGeneration::initial()};
}

Result<Ref<EnvironmentId>> EnvironmentRegistry::revise(EnvironmentId id, EnvironmentSpec spec) {
  const auto found = entries_.find(id.value());
  if (found == entries_.end()) {
    return Status(StatusCode::not_found,
                  "environment identity is not registered: " + id.to_string());
  }
  if (const VoidResult valid = spec.canonicalize(); !valid) return valid.status();
  const Digest digest = spec.canonical_digest();
  if (found->second.identity.digest == digest && found->second.current) {
    return Ref<EnvironmentId>{id, found->second.identity.generation};
  }
  found->second.identity.generation = found->second.identity.generation.next();
  found->second.identity.digest = digest;
  found->second.identity.spec = std::move(spec);
  found->second.current = true;
  return Ref<EnvironmentId>{id, found->second.identity.generation};
}

const EnvironmentIdentity* EnvironmentRegistry::find(EnvironmentId id) const noexcept {
  const auto found = entries_.find(id.value());
  if (found == entries_.end()) return nullptr;
  return &found->second.identity;
}

std::vector<EnvironmentIdentity> EnvironmentRegistry::list() const {
  std::vector<EnvironmentIdentity> out;
  out.reserve(entries_.size());
  for (const auto& [key, entry] : entries_) {
    (void)key;
    out.push_back(entry.identity);
  }
  std::sort(out.begin(), out.end(), [](const EnvironmentIdentity& a, const EnvironmentIdentity& b) {
    return a.id < b.id;
  });
  return out;
}

std::vector<EnvironmentVariable> ambient_environment() {
  std::vector<EnvironmentVariable> out;
#if defined(_WIN32)
  LPWCH block = ::GetEnvironmentStringsW();
  if (block == nullptr) return out;
  for (const wchar_t* entry = block; *entry != L'\0'; entry += std::wcslen(entry) + 1) {
    const std::wstring line(entry);
    const std::size_t separator = line.find(L'=');
    if (separator == std::wstring::npos || separator == 0) continue;
    // Windows exposes pseudo-variables such as "=C:" that are not name/value
    // pairs and must not be re-emitted.
    if (separator == 0 || line[0] == L'=') continue;
    const std::wstring name = line.substr(0, separator);
    const std::wstring value = line.substr(separator + 1);
    const auto narrow = [](const std::wstring& text) {
      if (text.empty()) return std::string{};
      const int needed = ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                               nullptr, 0, nullptr, nullptr);
      if (needed <= 0) return std::string{};
      std::string out_text(static_cast<std::size_t>(needed), '\0');
      ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out_text.data(),
                            needed, nullptr, nullptr);
      return out_text;
    };
    out.push_back(EnvironmentVariable{narrow(name), narrow(value)});
  }
  ::FreeEnvironmentStringsW(block);
#endif
  std::sort(out.begin(), out.end(), [](const EnvironmentVariable& a, const EnvironmentVariable& b) {
    return less_ascii_ci(a.name, b.name);
  });
  return out;
}

Result<std::vector<EnvironmentVariable>> build_process_environment(const EnvironmentSpec& spec,
                                                                  bool include_loader_variables) {
  std::vector<EnvironmentVariable> out = spec.variables;

  if (include_loader_variables) {
    for (const char* name : kLoaderVariables) {
      const bool present = std::any_of(out.begin(), out.end(),
                                       [name](const EnvironmentVariable& variable) {
                                         return equals_ascii_ci(variable.name, name);
                                       });
      if (present) continue;
      const std::string value = ambient_value(name);
      if (value.empty()) continue;
      out.push_back(EnvironmentVariable{name, value});
    }
  }

  // A real tool needs a usable PATH and a temporary directory even when the
  // caller specifies neither. These defaults are loader-level conveniences for
  // probing and for tools the runtime launches outside a governed phase; a
  // governed phase environment always carries an explicit workspace temporary
  // directory and an explicit toolchain PATH.
  const auto has_variable = [&out](const char* name) {
    return std::any_of(out.begin(), out.end(), [name](const EnvironmentVariable& variable) {
      return equals_ascii_ci(variable.name, name);
    });
  };
  // The system directories must always be reachable. A toolchain PATH that
  // omitted them would leave real tools unable to load system components or to
  // start their own subprocesses, so they are appended when missing rather than
  // assumed. Toolchain entries keep their precedence.
  {
    const std::string system_root = ambient_value("SystemRoot");
    if (!system_root.empty()) {
      const std::string system32 = system_root + "\\System32";
      std::string* path_value = nullptr;
      for (EnvironmentVariable& variable : out) {
        if (equals_ascii_ci(variable.name, "PATH")) {
          path_value = &variable.value;
          break;
        }
      }
      if (path_value == nullptr) {
        out.push_back(EnvironmentVariable{"PATH", system32 + ";" + system_root});
      } else {
        if (!starts_with_ci(*path_value, system32) &&
            path_value->find(system32) == std::string::npos) {
          path_value->append(";").append(system32);
        }
        if (path_value->find(system_root) == std::string::npos) {
          path_value->append(";").append(system_root);
        }
      }
    }
  }
  if (spec.temp_directory.empty() && !has_variable("TEMP")) {
    std::string temporary = ambient_value("TEMP");
    if (temporary.empty()) temporary = ambient_value("SystemRoot");
    if (!temporary.empty()) {
      out.push_back(EnvironmentVariable{"TEMP", temporary});
    }
  }

  // The temporary directory is always redirected into the workspace so that two
  // concurrent sessions cannot observe each other's scratch files.
  if (!spec.temp_directory.empty()) {
    const std::string temp = spec.temp_directory.string();
    const auto set_or_add = [&out](const char* name, const std::string& value) {
      for (EnvironmentVariable& variable : out) {
        if (equals_ascii_ci(variable.name, name)) {
          variable.value = value;
          return;
        }
      }
      out.push_back(EnvironmentVariable{name, value});
    };
    set_or_add("TEMP", temp);
    set_or_add("TMP", temp);
  }

  std::sort(out.begin(), out.end(), [](const EnvironmentVariable& a, const EnvironmentVariable& b) {
    return less_ascii_ci(a.name, b.name);
  });
  std::vector<EnvironmentVariable> unique;
  unique.reserve(out.size());
  for (EnvironmentVariable& variable : out) {
    if (!unique.empty() && equals_ascii_ci(unique.back().name, variable.name)) {
      unique.back() = std::move(variable);
      continue;
    }
    unique.push_back(std::move(variable));
  }
  return unique;
}

bool environment_is_hermetic(const EnvironmentSpec& spec) noexcept {
  if (!spec.deterministic_controls) return false;
  if (spec.locale_policy == LocalePolicy::user_default) return false;
  if (spec.locale_policy == LocalePolicy::explicit_name && spec.locale_name.empty()) return false;
  return true;
}

}  // namespace crf
