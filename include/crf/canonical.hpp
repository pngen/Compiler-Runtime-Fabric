#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "crf/export.hpp"

namespace crf {

// ---------------------------------------------------------------------------
// ASCII string primitives. The runtime never uses locale-sensitive comparison
// for identity-bearing state.
// ---------------------------------------------------------------------------
CRF_NODISCARD CRF_API std::string to_lower_ascii(std::string_view text);
CRF_NODISCARD CRF_API std::string to_upper_ascii(std::string_view text);
CRF_NODISCARD CRF_API std::string_view trim_ascii(std::string_view text);
CRF_NODISCARD CRF_API bool equals_ascii_ci(std::string_view a, std::string_view b) noexcept;
CRF_NODISCARD CRF_API bool less_ascii_ci(std::string_view a, std::string_view b) noexcept;
CRF_NODISCARD CRF_API bool starts_with_ci(std::string_view text, std::string_view prefix) noexcept;
CRF_NODISCARD CRF_API std::vector<std::string> split_ascii(std::string_view text, char separator);
CRF_NODISCARD CRF_API std::string join_ascii(const std::vector<std::string>& parts,
                                             std::string_view separator);

// ---------------------------------------------------------------------------
// Path canonicalisation.
//
// Canonicalisation is purely lexical so that it never touches the filesystem
// during identity computation and never follows a reparse point. Filesystem
// authorisation is a separate, explicit check performed by the workspace guard.
// ---------------------------------------------------------------------------
CRF_NODISCARD CRF_API std::string normalize_path_string(const std::filesystem::path& path);
CRF_NODISCARD CRF_API std::filesystem::path normalize_path(const std::filesystem::path& path);
CRF_NODISCARD CRF_API std::string canonical_path_key(const std::filesystem::path& path);

/// True when \p candidate is the same as, or lexically inside, \p root.
/// Both paths are normalised before comparison. Comparison is case-insensitive
/// on Windows.
CRF_NODISCARD CRF_API bool path_is_within(const std::filesystem::path& candidate,
                                          const std::filesystem::path& root);

/// Reject "..", drive-relative roots, and embedded NUL characters in a path that
/// arrives from an untrusted peer.
CRF_NODISCARD CRF_API bool path_has_traversal(const std::filesystem::path& path);

// ---------------------------------------------------------------------------
// Canonical encoding primitives.
//
// All identity-bearing structures serialise through these helpers so that the
// digest of equivalent canonical state is equivalent regardless of container
// iteration order, insertion order, or platform.
// ---------------------------------------------------------------------------
class CRF_API CanonicalWriter {
 public:
  void u8(std::uint8_t value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void i32(std::int32_t value);
  void boolean(bool value);
  void raw_text(std::string_view value);
  /// Length-prefixed text: unambiguous concatenation.
  void text(std::string_view value);
  void digest_bytes(std::string_view hex);

  CRF_NODISCARD const std::string& bytes() const noexcept { return buffer_; }
  CRF_NODISCARD std::string take() { return std::move(buffer_); }

 private:
  std::string buffer_;
};

class CRF_API CanonicalReader {
 public:
  explicit CanonicalReader(std::string_view bytes) noexcept : bytes_(bytes) {}

  CRF_NODISCARD bool u8(std::uint8_t& out) noexcept;
  CRF_NODISCARD bool u16(std::uint16_t& out) noexcept;
  CRF_NODISCARD bool u32(std::uint32_t& out) noexcept;
  CRF_NODISCARD bool u64(std::uint64_t& out) noexcept;
  CRF_NODISCARD bool i32(std::int32_t& out) noexcept;
  CRF_NODISCARD bool boolean(bool& out) noexcept;
  CRF_NODISCARD bool text(std::string& out, std::size_t max_length) noexcept;

  CRF_NODISCARD bool exhausted() const noexcept { return cursor_ == bytes_.size(); }
  CRF_NODISCARD std::size_t remaining() const noexcept { return bytes_.size() - cursor_; }

 private:
  CRF_NODISCARD bool take(std::size_t count, std::string_view& out) noexcept;

  std::string_view bytes_;
  std::size_t cursor_ = 0;
};

/// Deterministic monotonic clock reading in nanoseconds. Used for ordering and
/// duration reporting; never used as identity or as authority.
CRF_NODISCARD CRF_API std::uint64_t monotonic_nanos() noexcept;

/// Wall-clock reading in nanoseconds since the Unix epoch. Diagnostic only.
CRF_NODISCARD CRF_API std::uint64_t wall_nanos() noexcept;

/// Deterministic pseudo-random source. Randomised tests record the seed they
/// used so a failure can be replayed exactly.
class CRF_API DeterministicRng {
 public:
  explicit DeterministicRng(std::uint64_t seed) noexcept;
  CRF_NODISCARD std::uint64_t next_u64() noexcept;
  CRF_NODISCARD std::uint32_t next_u32() noexcept;
  /// Uniform value in [0, bound). Returns 0 when bound == 0.
  CRF_NODISCARD std::uint64_t next_below(std::uint64_t bound) noexcept;
  CRF_NODISCARD bool next_bool() noexcept;
  CRF_NODISCARD std::uint64_t seed() const noexcept { return seed_; }

 private:
  std::uint64_t seed_;
  std::uint64_t state_;
};

}  // namespace crf
