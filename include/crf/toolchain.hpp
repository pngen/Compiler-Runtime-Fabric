#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "crf/component.hpp"
#include "crf/digest.hpp"
#include "crf/status.hpp"
#include "crf/strong_id.hpp"
#include "crf/target.hpp"

namespace crf {

enum class ToolchainFamily : std::uint8_t {
  unknown = 0,
  msvc = 1,
  clang_cl = 2,
  clang = 3,
  gcc = 4,
  nvcc = 5,
  hipcc = 6,
  intel_icx = 7,
  /// A toolchain the runtime models without real tooling present. Outputs from
  /// this family are labelled SYNTHETIC everywhere they appear.
  synthetic = 8,
};

CRF_NODISCARD CRF_API std::string_view to_string(ToolchainFamily value) noexcept;
CRF_NODISCARD CRF_API bool parse_toolchain_family(std::string_view text, ToolchainFamily& out) noexcept;

/// A compiler phase pipeline can require several cooperating toolchains (for
/// example, nvcc driving an MSVC host compiler). Each is registered separately
/// and the session records the primary toolchain plus any cooperating ones.
struct CRF_API ToolchainIdentity {
  ToolchainId id{};
  ToolchainGeneration generation{};
  ToolchainFamily family = ToolchainFamily::unknown;
  std::string display_name;
  std::string version;
  std::vector<ComponentIdentity> components;
  std::vector<Architecture> target_support;
  std::vector<ObjectFormat> object_formats;
  /// Environment contribution of this toolchain: INCLUDE, LIB, PATH members,
  /// toolkit-specific variables. Merged into the phase environment spec.
  std::vector<EnvironmentVariable> environment_contract;
  std::filesystem::path toolkit_root;
  std::filesystem::path sdk_root;
  /// Adapter-specific facts that participate in toolchain identity, for example
  /// "cuda.detected_device_arch". Deterministically ordered by name.
  std::vector<EnvironmentVariable> attributes;
  /// Identity of the C++ standard library this toolchain links against.
  std::string standard_library_identity;
  EvidenceClass evidence_class = EvidenceClass::unknown;
  /// Digest over all probed evidence that produced this identity.
  Digest evidence_digest{};

  CRF_NODISCARD Digest canonical_digest() const;
  CRF_NODISCARD const ComponentIdentity* find_component(ComponentKind kind) const noexcept;
  CRF_NODISCARD const ComponentIdentity* find_component(std::string_view name) const noexcept;
  CRF_NODISCARD bool supports(Architecture architecture) const noexcept;
  CRF_NODISCARD std::string describe() const;
};

/// Describes how a re-probe changed a registered toolchain.
struct CRF_API ToolchainMutation {
  bool mutated = false;
  ToolchainGeneration previous_generation{};
  ToolchainGeneration current_generation{};
  std::vector<std::string> changed_components;
  std::vector<std::string> removed_components;
  std::vector<std::string> added_components;
  std::string detail;

  CRF_NODISCARD bool generation_advanced() const noexcept {
    return current_generation.value() > previous_generation.value();
  }
};

/// Registry of toolchain identities with generation tracking.
///
/// Refreshing a toolchain with freshly probed evidence compares the evidence to
/// what was registered. Any authority-relevant change advances the generation,
/// which causes in-flight phases bound to the previous generation to fail
/// commit. Path stability alone never preserves identity.
class CRF_API ToolchainRegistry {
 public:
  CRF_NODISCARD Result<Ref<ToolchainId>> register_toolchain(ToolchainIdentity identity);
  /// Register under a fixed identity; used when replaying durable state.
  CRF_NODISCARD Result<Ref<ToolchainId>> register_toolchain_as(ToolchainId id,
                                                              ToolchainIdentity identity);

  /// Install freshly probed evidence for an existing toolchain. Returns the
  /// mutation report; the identity becomes stale for every phase bound to the
  /// previous generation.
  CRF_NODISCARD Result<ToolchainMutation> refresh(const ToolchainIdentity& observed);

  /// Force a generation advance with an explicit reason (used when a component
  /// is replaced by a byte-identical file, which is authority-neutral, versus a
  /// byte-different file, which is not).
  CRF_NODISCARD Result<ToolchainMutation> invalidate(ToolchainId id, std::string reason);

  CRF_NODISCARD const ToolchainIdentity* find(ToolchainId id) const noexcept;
  CRF_NODISCARD const ToolchainIdentity* find_latest(ToolchainFamily family) const noexcept;
  CRF_NODISCARD std::vector<ToolchainIdentity> list() const;
  /// All toolchains of a family, including superseded generations, newest first.
  CRF_NODISCARD std::vector<ToolchainIdentity> history(ToolchainFamily family) const;
  CRF_NODISCARD std::size_t size() const noexcept { return entries_.size(); }

  /// Verify that a recorded toolchain reference is still the current generation.
  CRF_NODISCARD bool is_current(const Ref<ToolchainId>& reference) const noexcept;

 private:
  CRF_NODISCARD Result<ToolchainMutation> apply_observed(const ToolchainIdentity& observed,
                                                         bool allow_generation_advance);

  struct Entry {
    ToolchainIdentity identity;
    bool current = true;
  };
  std::unordered_map<std::uint64_t, Entry> entries_;
  IdAllocator<ToolchainId> allocator_;
};

/// Compute the difference between two toolchain identities component by
/// component. Deterministic: output ordering follows component name.
CRF_NODISCARD CRF_API ToolchainMutation diff_toolchains(const ToolchainIdentity& previous,
                                                        const ToolchainIdentity& observed);

}  // namespace crf
