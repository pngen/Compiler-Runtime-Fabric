#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "crf/canonical.hpp"
#include "crf/digest.hpp"
#include "crf/status.hpp"
#include "crf/strong_id.hpp"

namespace crf {

struct CRF_API EnvironmentVariable {
  std::string name;
  std::string value;

  friend bool operator==(const EnvironmentVariable&, const EnvironmentVariable&) = default;
  friend auto operator<=>(const EnvironmentVariable&, const EnvironmentVariable&) = default;
};

enum class LocalePolicy : std::uint8_t {
  /// Force the "C" locale. Diagnostics become stable across machines.
  c_locale = 0,
  /// Use an explicitly named locale; the name is part of environment identity.
  explicit_name = 1,
  /// Inherit the ambient user locale. Diagnostic text may then vary by machine,
  /// so the environment identity records that it is not stabilised.
  user_default = 2,
};

CRF_NODISCARD CRF_API std::string_view to_string(LocalePolicy value) noexcept;
CRF_NODISCARD CRF_API bool parse_locale_policy(std::string_view text, LocalePolicy& out) noexcept;

/// The complete, explicit description of the environment a compiler phase runs
/// in. Nothing is inherited from the runtime process by default.
///
/// Fields that participate in environment identity (all of them, by design):
///   working_directory, temp_directory, variables, include_paths, library_paths,
///   sdk_roots, toolkit_roots, inherited_variables, locale_policy, locale_name,
///   deterministic_controls.
///
/// The variable list is stored in canonical order: sorted by ASCII-uppercased
/// name, duplicates rejected. Two specs that differ only in insertion order have
/// the same identity.
struct CRF_API EnvironmentSpec {
  static constexpr std::size_t kMaxVariables = 4096;
  static constexpr std::size_t kMaxVariableNameBytes = 1024;
  static constexpr std::size_t kMaxVariableValueBytes = 32768;
  static constexpr std::size_t kMaxSearchPaths = 1024;
  static constexpr std::size_t kMaxTotalValueBytes = 1u << 20;

  std::filesystem::path working_directory;
  std::filesystem::path temp_directory;

  std::vector<EnvironmentVariable> variables;
  std::vector<std::filesystem::path> include_paths;
  std::vector<std::filesystem::path> library_paths;
  std::vector<std::filesystem::path> sdk_roots;
  std::vector<std::filesystem::path> toolkit_roots;

  /// Names of ambient variables that may be copied into the child environment.
  /// Empty by default: the runtime does not silently inherit the ambient
  /// environment.
  std::vector<std::string> inherited_variables;

  LocalePolicy locale_policy = LocalePolicy::c_locale;
  std::string locale_name;

  /// When set, the runtime sets the compiler's deterministic-build controls
  /// (/Brepro, /DSOURCE_DATE_EPOCH, ...) through the adapter's environment
  /// contract. The runtime never rewrites compiler output after the fact.
  bool deterministic_controls = true;

  /// Sort, reject duplicate names, normalise every path, enforce the bounds.
  CRF_NODISCARD VoidResult canonicalize();

  /// Digest over the canonical encoding of every identity-bearing field.
  CRF_NODISCARD Digest canonical_digest() const;

  CRF_NODISCARD const std::string* find_variable(std::string_view name) const noexcept;
  /// Insert or replace one variable. Replacement is case-insensitive on the
  /// name, matching how the Windows loader resolves variables.
  void set_variable(std::string name, std::string value);
  CRF_NODISCARD bool erase_variable(std::string_view name);
  CRF_NODISCARD std::string join_paths(const std::vector<std::filesystem::path>& paths) const;
};

/// Canonicalised environment plus its assigned identity and generation.
struct CRF_API EnvironmentIdentity {
  EnvironmentId id{};
  EnvironmentGeneration generation{};
  Digest digest{};
  EnvironmentSpec spec;

  CRF_NODISCARD std::string canonical_digest_hex() const { return digest.to_hex(); }
};

/// Canonical environment registry. Interning the same canonical spec returns the
/// same identity; interning a different spec yields a distinct identity, and
/// revising an existing identity advances its generation.
class CRF_API EnvironmentRegistry {
 public:
  /// Intern an exact canonical spec under a fresh identity.
  CRF_NODISCARD Result<Ref<EnvironmentId>> intern(EnvironmentSpec spec);

  /// Intern under a fixed identity so that durable state reloaded after restart
  /// keeps referring to the same environment.
  CRF_NODISCARD Result<Ref<EnvironmentId>> intern_as(EnvironmentId id, EnvironmentSpec spec);

  /// Advance the generation of an existing environment because an
  /// authority-relevant field changed. In-flight phases bound to the previous
  /// generation must fail to commit.
  CRF_NODISCARD Result<Ref<EnvironmentId>> revise(EnvironmentId id, EnvironmentSpec spec);

  CRF_NODISCARD const EnvironmentIdentity* find(EnvironmentId id) const noexcept;
  CRF_NODISCARD std::vector<EnvironmentIdentity> list() const;
  CRF_NODISCARD std::size_t size() const noexcept { return entries_.size(); }

 private:
  struct Entry {
    EnvironmentIdentity identity;
    bool current = true;
  };
  std::unordered_map<std::uint64_t, Entry> entries_;
  IdAllocator<EnvironmentId> allocator_;
};

/// Concrete variable block handed to the operating system when a compiler
/// process is created.
///
/// Only the explicit spec variables, the mandatory loader variables (SystemRoot
/// and windir), and an explicitly derived PATH are emitted. PATH is rebuilt from
/// the tool directories recorded by the adapter, never copied from the runtime
/// process environment.
CRF_NODISCARD CRF_API Result<std::vector<EnvironmentVariable>> build_process_environment(
    const EnvironmentSpec& spec, bool include_loader_variables = true);

/// True when the environment's compiler-relevant identity is fully determined
/// (deterministic controls on and a concrete locale).
CRF_NODISCARD CRF_API bool environment_is_hermetic(const EnvironmentSpec& spec) noexcept;

/// The runtime process's own environment, read once as an explicit list.
///
/// Governed phase environments never use this. It exists so that a toolchain
/// probe can run a vendor tool in the context that tool expects; the probe
/// records what the tool reported as evidence, and the resulting spec is what a
/// phase actually runs under.
CRF_NODISCARD CRF_API std::vector<EnvironmentVariable> ambient_environment();

}  // namespace crf
