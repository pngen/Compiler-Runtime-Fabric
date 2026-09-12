#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>

#include "crf/export.hpp"

namespace crf {

/// A 256-bit content digest (SHA-256).
///
/// Content identity of toolchain executables, intermediate artifacts, and final
/// candidate artifacts is expressed as a digest. A path is never content
/// identity: the same path may hold different bytes at different generations.
class CRF_API Digest {
 public:
  static constexpr std::size_t kBytes = 32;

  constexpr Digest() noexcept = default;

  CRF_NODISCARD static Digest of(std::span<const std::byte> bytes) noexcept;
  CRF_NODISCARD static Digest of(std::string_view text) noexcept;

  /// Digest of a file's contents. Reads in bounded chunks; a file larger than
  /// the configured bound fails closed rather than allocating without limit.
  CRF_NODISCARD static bool of_file(const std::filesystem::path& path, Digest& out,
                                    std::uint64_t max_bytes = kDefaultFileBound) noexcept;

  CRF_NODISCARD static Digest from_bytes(const std::array<std::uint8_t, kBytes>& raw) noexcept;
  CRF_NODISCARD static bool from_hex(std::string_view hex, Digest& out) noexcept;

  CRF_NODISCARD const std::array<std::uint8_t, kBytes>& bytes() const noexcept { return raw_; }
  CRF_NODISCARD std::string to_hex() const;
  /// Short form used in human-facing CLI output; never used for equality.
  CRF_NODISCARD std::string to_short_hex() const;
  CRF_NODISCARD bool zero() const noexcept;

  friend constexpr bool operator==(const Digest&, const Digest&) noexcept = default;
  friend constexpr auto operator<=>(const Digest&, const Digest&) noexcept = default;

  static constexpr std::uint64_t kDefaultFileBound = 512ull * 1024ull * 1024ull;

 private:
  friend class Hasher;
  std::array<std::uint8_t, kBytes> raw_{};
};

/// Streaming SHA-256 hasher used for canonical state hashing.
class CRF_API Hasher {
 public:
  Hasher() noexcept;
  ~Hasher();

  Hasher(const Hasher&) = delete;
  Hasher& operator=(const Hasher&) = delete;

  void update(std::span<const std::byte> bytes) noexcept;
  void update(std::string_view text) noexcept;
  void update_byte(std::uint8_t value) noexcept;
  void update_u32(std::uint32_t value) noexcept;
  void update_u64(std::uint64_t value) noexcept;

  /// Length-prefixed text hashing. Makes concatenation unambiguous so that
  /// ("ab","c") and ("a","bc") cannot collide.
  void update_length_prefixed(std::string_view text) noexcept;

  CRF_NODISCARD Digest finish() noexcept;

 private:
  struct Impl;
  Impl* impl_;
};

/// CRC-32C (Castagnoli). Used for journal record and protocol frame integrity,
/// not for content identity.
CRF_API std::uint32_t crc32c(std::span<const std::byte> bytes) noexcept;
CRF_API std::uint32_t crc32c(std::string_view text) noexcept;

}  // namespace crf
