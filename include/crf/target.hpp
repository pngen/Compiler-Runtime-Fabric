#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "crf/digest.hpp"
#include "crf/status.hpp"
#include "crf/strong_id.hpp"

namespace crf {

enum class Architecture : std::uint8_t {
  unknown = 0,
  x86 = 1,
  x64 = 2,
  arm = 3,
  arm64 = 4,
};

CRF_NODISCARD CRF_API std::string_view to_string(Architecture value) noexcept;
CRF_NODISCARD CRF_API bool parse_architecture(std::string_view text, Architecture& out) noexcept;
CRF_NODISCARD CRF_API std::uint32_t pointer_bits(Architecture value) noexcept;

enum class OperatingSystem : std::uint8_t {
  unknown = 0,
  windows = 1,
  linux_kernel = 2,
  macos = 3,
  bare_metal = 4,
};

CRF_NODISCARD CRF_API std::string_view to_string(OperatingSystem value) noexcept;

/// Binary container formats the runtime can recognise and validate.
enum class ObjectFormat : std::uint8_t {
  unknown = 0,
  coff_object = 1,
  coff_image = 2,
  ptx = 3,
  cubin = 4,
  fatbin = 5,
  elf = 6,
  archive = 7,
  preprocessed_source = 8,
  assembly_source = 9,
  linker_map = 10,
  debug_info = 11,
  metadata = 12,
};

CRF_NODISCARD CRF_API std::string_view to_string(ObjectFormat value) noexcept;
CRF_NODISCARD CRF_API bool parse_object_format(std::string_view text, ObjectFormat& out) noexcept;

/// A complete compilation target. The device architecture participates in
/// identity because sm_90 and sm_120 artifacts are not interchangeable.
struct CRF_API TargetSpec {
  Architecture architecture = Architecture::unknown;
  OperatingSystem os = OperatingSystem::unknown;
  /// Canonical target triple, e.g. "x86_64-pc-windows-msvc".
  std::string triple;
  /// Host CPU model where the toolchain cares (e.g. "x86-64-v3"); empty = default.
  std::string cpu;
  /// Device architecture where applicable (e.g. "sm_120").
  std::string device_arch;
  /// Virtual device architecture used for forward compatibility (e.g. "compute_120").
  std::string device_virtual_arch;
  std::string abi;
  std::uint32_t pointer_width_bits = 0;

  CRF_NODISCARD VoidResult validate() const;
  CRF_NODISCARD Digest canonical_digest() const;
};

struct CRF_API TargetIdentity {
  TargetId id{};
  TargetGeneration generation{};
  Digest digest{};
  TargetSpec spec;
};

/// Target registry with generation tracking. Registering a target that differs
/// from a previously registered value under the same identity advances the
/// generation, which invalidates in-flight phases bound to the older value.
class CRF_API TargetRegistry {
 public:
  CRF_NODISCARD Result<Ref<TargetId>> intern(const TargetSpec& spec);
  CRF_NODISCARD Result<Ref<TargetId>> intern_as(TargetId id, const TargetSpec& spec);
  CRF_NODISCARD Result<Ref<TargetId>> revise(TargetId id, const TargetSpec& spec);

  CRF_NODISCARD const TargetIdentity* find(TargetId id) const noexcept;
  CRF_NODISCARD std::vector<TargetIdentity> list() const;
  CRF_NODISCARD std::size_t size() const noexcept { return entries_.size(); }

 private:
  struct Entry {
    TargetIdentity identity;
    bool current = true;
  };
  std::unordered_map<std::uint64_t, Entry> entries_;
  IdAllocator<TargetId> allocator_;
};

/// Map an architecture to the machine code a PE/COFF image must declare.
CRF_NODISCARD CRF_API std::uint16_t coff_machine_for(Architecture value) noexcept;

}  // namespace crf
