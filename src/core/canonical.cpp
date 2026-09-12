#include "crf/canonical.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

#if defined(_WIN32)
#  include <windows.h>
#endif

namespace crf {
namespace {

CRF_NODISCARD bool ascii_is_space(char c) noexcept {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

CRF_NODISCARD char ascii_lower(char c) noexcept {
  return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

}  // namespace

std::string to_lower_ascii(std::string_view text) {
  std::string out;
  out.resize(text.size());
  for (std::size_t i = 0; i < text.size(); ++i) out[i] = ascii_lower(text[i]);
  return out;
}

std::string to_upper_ascii(std::string_view text) {
  std::string out;
  out.resize(text.size());
  for (std::size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    out[i] = (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
  }
  return out;
}

std::string_view trim_ascii(std::string_view text) {
  std::size_t begin = 0;
  std::size_t end = text.size();
  while (begin < end && ascii_is_space(text[begin])) ++begin;
  while (end > begin && ascii_is_space(text[end - 1])) --end;
  return text.substr(begin, end - begin);
}

bool equals_ascii_ci(std::string_view a, std::string_view b) noexcept {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (ascii_lower(a[i]) != ascii_lower(b[i])) return false;
  }
  return true;
}

bool less_ascii_ci(std::string_view a, std::string_view b) noexcept {
  const std::size_t common = a.size() < b.size() ? a.size() : b.size();
  for (std::size_t i = 0; i < common; ++i) {
    const char ca = ascii_lower(a[i]);
    const char cb = ascii_lower(b[i]);
    if (ca != cb) return ca < cb;
  }
  return a.size() < b.size();
}

bool starts_with_ci(std::string_view text, std::string_view prefix) noexcept {
  if (text.size() < prefix.size()) return false;
  return equals_ascii_ci(text.substr(0, prefix.size()), prefix);
}

std::vector<std::string> split_ascii(std::string_view text, char separator) {
  std::vector<std::string> parts;
  std::size_t start = 0;
  while (start <= text.size()) {
    const std::size_t position = text.find(separator, start);
    if (position == std::string_view::npos) {
      parts.emplace_back(text.substr(start));
      break;
    }
    parts.emplace_back(text.substr(start, position - start));
    start = position + 1;
  }
  return parts;
}

std::string join_ascii(const std::vector<std::string>& parts, std::string_view separator) {
  std::string out;
  for (std::size_t i = 0; i < parts.size(); ++i) {
    if (i != 0) out.append(separator.data(), separator.size());
    out.append(parts[i]);
  }
  return out;
}

std::filesystem::path normalize_path(const std::filesystem::path& path) {
  std::filesystem::path result = path.lexically_normal();
  // lexically_normal leaves a trailing separator on directory-like inputs;
  // strip it so that "a/b/" and "a/b" have the same identity.
  std::string text = result.string();
  while (text.size() > 3 && (text.back() == '\\' || text.back() == '/')) {
    // Keep a root such as "C:\\" or "\\\\server\\share\\" intact.
    const std::string prefix = text.substr(0, text.size() - 1);
    if (prefix.size() == 2 && prefix[1] == ':') break;
    text.pop_back();
  }
  return std::filesystem::path(text);
}

std::string normalize_path_string(const std::filesystem::path& path) {
  return normalize_path(path).string();
}

std::string canonical_path_key(const std::filesystem::path& path) {
  std::string text = normalize_path_string(path);
  for (char& c : text) {
    if (c == '/') {
      c = '\\';
    } else {
      c = ascii_lower(c);
    }
  }
  return text;
}

bool path_is_within(const std::filesystem::path& candidate, const std::filesystem::path& root) {
  std::string child = canonical_path_key(candidate);
  std::string parent = canonical_path_key(root);
  if (child.empty() || parent.empty()) return false;
  if (child == parent) return true;
  if (parent.back() != '\\') parent.push_back('\\');
  return child.size() > parent.size() && child.compare(0, parent.size(), parent) == 0;
}

bool path_has_traversal(const std::filesystem::path& path) {
  const std::string text = path.string();
  if (text.find('\0') != std::string::npos) return true;
  for (const auto& component : path) {
    const std::string part = component.string();
    if (part == "..") return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------
void CanonicalWriter::u8(std::uint8_t value) {
  buffer_.push_back(static_cast<char>(value));
}

void CanonicalWriter::u16(std::uint16_t value) {
  buffer_.push_back(static_cast<char>(value & 0xFFu));
  buffer_.push_back(static_cast<char>((value >> 8) & 0xFFu));
}

void CanonicalWriter::u32(std::uint32_t value) {
  for (int shift = 0; shift < 32; shift += 8) {
    buffer_.push_back(static_cast<char>((value >> shift) & 0xFFu));
  }
}

void CanonicalWriter::u64(std::uint64_t value) {
  for (int shift = 0; shift < 64; shift += 8) {
    buffer_.push_back(static_cast<char>((value >> shift) & 0xFFu));
  }
}

void CanonicalWriter::i32(std::int32_t value) {
  u32(static_cast<std::uint32_t>(value));
}

void CanonicalWriter::boolean(bool value) {
  u8(value ? 1u : 0u);
}

void CanonicalWriter::raw_text(std::string_view value) {
  buffer_.append(value.data(), value.size());
}

void CanonicalWriter::text(std::string_view value) {
  u32(static_cast<std::uint32_t>(value.size()));
  buffer_.append(value.data(), value.size());
}

void CanonicalWriter::digest_bytes(std::string_view hex) {
  text(hex);
}

bool CanonicalReader::take(std::size_t count, std::string_view& out) noexcept {
  if (count > bytes_.size() - cursor_) return false;
  out = bytes_.substr(cursor_, count);
  cursor_ += count;
  return true;
}

bool CanonicalReader::u8(std::uint8_t& out) noexcept {
  std::string_view slice;
  if (!take(1, slice)) return false;
  out = static_cast<std::uint8_t>(static_cast<unsigned char>(slice[0]));
  return true;
}

bool CanonicalReader::u16(std::uint16_t& out) noexcept {
  std::string_view slice;
  if (!take(2, slice)) return false;
  out = static_cast<std::uint16_t>(static_cast<unsigned char>(slice[0]) |
                                   (static_cast<std::uint16_t>(static_cast<unsigned char>(slice[1])) << 8));
  return true;
}

bool CanonicalReader::u32(std::uint32_t& out) noexcept {
  std::string_view slice;
  if (!take(4, slice)) return false;
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(static_cast<unsigned char>(slice[static_cast<std::size_t>(i)]))
             << (i * 8);
  }
  out = value;
  return true;
}

bool CanonicalReader::u64(std::uint64_t& out) noexcept {
  std::string_view slice;
  if (!take(8, slice)) return false;
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(static_cast<unsigned char>(slice[static_cast<std::size_t>(i)]))
             << (i * 8);
  }
  out = value;
  return true;
}

bool CanonicalReader::i32(std::int32_t& out) noexcept {
  std::uint32_t raw = 0;
  if (!u32(raw)) return false;
  out = static_cast<std::int32_t>(raw);
  return true;
}

bool CanonicalReader::boolean(bool& out) noexcept {
  std::uint8_t raw = 0;
  if (!u8(raw)) return false;
  out = raw != 0;
  return true;
}

bool CanonicalReader::text(std::string& out, std::size_t max_length) noexcept {
  std::uint32_t length = 0;
  if (!u32(length)) return false;
  if (length > max_length) return false;
  std::string_view slice;
  if (!take(length, slice)) return false;
  out.assign(slice.data(), slice.size());
  return true;
}

std::uint64_t monotonic_nanos() noexcept {
#if defined(_WIN32)
  static const std::uint64_t frequency = []() noexcept -> std::uint64_t {
    LARGE_INTEGER value{};
    if (::QueryPerformanceFrequency(&value) == 0) return 1000000000ull;
    return static_cast<std::uint64_t>(value.QuadPart);
  }();
  LARGE_INTEGER counter{};
  if (::QueryPerformanceCounter(&counter) == 0) return 0;
  const std::uint64_t ticks = static_cast<std::uint64_t>(counter.QuadPart);
  if (frequency == 0) return 0;
  if (frequency == 1000000000ull) return ticks;
  return (ticks / frequency) * 1000000000ull + ((ticks % frequency) * 1000000000ull) / frequency;
#else
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
#endif
}

std::uint64_t wall_nanos() noexcept {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

DeterministicRng::DeterministicRng(std::uint64_t seed) noexcept : seed_(seed), state_(seed) {
  if (state_ == 0) state_ = 0x9E3779B97F4A7C15ull;
}

std::uint64_t DeterministicRng::next_u64() noexcept {
  // SplitMix64: full-period, well distributed, and identical everywhere.
  state_ += 0x9E3779B97F4A7C15ull;
  std::uint64_t z = state_;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

std::uint32_t DeterministicRng::next_u32() noexcept {
  return static_cast<std::uint32_t>(next_u64() >> 32);
}

std::uint64_t DeterministicRng::next_below(std::uint64_t bound) noexcept {
  if (bound == 0) return 0;
  return next_u64() % bound;
}

bool DeterministicRng::next_bool() noexcept {
  return (next_u64() & 1u) != 0;
}

}  // namespace crf
