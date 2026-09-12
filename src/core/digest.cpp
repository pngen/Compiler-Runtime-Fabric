#include "crf/digest.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>

namespace crf {
namespace {

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4). Implemented here so the runtime has no third-party or
// platform crypto dependency; content identity must work identically on every
// supported platform.
// ---------------------------------------------------------------------------
constexpr std::uint32_t kRoundConstants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

constexpr std::uint32_t kInitialState[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

constexpr std::uint32_t rotr(std::uint32_t value, unsigned count) noexcept {
  return (value >> count) | (value << (32u - count));
}

struct Sha256State {
  std::uint32_t h[8];
  std::uint64_t total_bytes = 0;
  unsigned char block[64];
  std::size_t block_bytes = 0;

  Sha256State() noexcept {
    for (std::size_t i = 0; i < 8; ++i) h[i] = kInitialState[i];
  }

  void compress(const unsigned char* data) noexcept {
    std::uint32_t w[64];
    for (std::size_t i = 0; i < 16; ++i) {
      w[i] = (static_cast<std::uint32_t>(data[i * 4]) << 24) |
             (static_cast<std::uint32_t>(data[i * 4 + 1]) << 16) |
             (static_cast<std::uint32_t>(data[i * 4 + 2]) << 8) |
             static_cast<std::uint32_t>(data[i * 4 + 3]);
    }
    for (std::size_t i = 16; i < 64; ++i) {
      const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    std::uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (std::size_t i = 0; i < 64; ++i) {
      const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const std::uint32_t ch = (e & f) ^ ((~e) & g);
      const std::uint32_t temp1 = hh + s1 + ch + kRoundConstants[i] + w[i];
      const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      const std::uint32_t temp2 = s0 + maj;
      hh = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }

  void update(const unsigned char* data, std::size_t size) noexcept {
    total_bytes += size;
    if (block_bytes != 0) {
      const std::size_t need = 64 - block_bytes;
      const std::size_t take = size < need ? size : need;
      std::memcpy(block + block_bytes, data, take);
      block_bytes += take;
      data += take;
      size -= take;
      if (block_bytes == 64) {
        compress(block);
        block_bytes = 0;
      }
    }
    while (size >= 64) {
      compress(data);
      data += 64;
      size -= 64;
    }
    if (size != 0) {
      std::memcpy(block, data, size);
      block_bytes = size;
    }
  }

  void finish(unsigned char out[32]) noexcept {
    const std::uint64_t bit_length = total_bytes * 8u;
    unsigned char pad[72];
    std::size_t pad_bytes = 0;
    pad[pad_bytes++] = 0x80u;
    const std::size_t rem = static_cast<std::size_t>((total_bytes + 1) % 64);
    const std::size_t zeros = rem <= 56 ? 56 - rem : 120 - rem;
    for (std::size_t i = 0; i < zeros; ++i) pad[pad_bytes++] = 0;
    for (int i = 7; i >= 0; --i) pad[pad_bytes++] = static_cast<unsigned char>((bit_length >> (i * 8)) & 0xFFu);
    update(pad, pad_bytes);
    for (std::size_t i = 0; i < 8; ++i) {
      out[i * 4] = static_cast<unsigned char>((h[i] >> 24) & 0xFFu);
      out[i * 4 + 1] = static_cast<unsigned char>((h[i] >> 16) & 0xFFu);
      out[i * 4 + 2] = static_cast<unsigned char>((h[i] >> 8) & 0xFFu);
      out[i * 4 + 3] = static_cast<unsigned char>(h[i] & 0xFFu);
    }
  }
};

constexpr char kHexDigits[] = "0123456789abcdef";

CRF_NODISCARD int hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// CRC-32C (Castagnoli), reflected, polynomial 0x1EDC6F41.
struct Crc32cTable {
  std::uint32_t entries[256];
  constexpr Crc32cTable() noexcept : entries() {
    for (std::uint32_t i = 0; i < 256; ++i) {
      std::uint32_t crc = i;
      for (int bit = 0; bit < 8; ++bit) {
        crc = (crc & 1u) ? ((crc >> 1) ^ 0x82F63B78u) : (crc >> 1);
      }
      entries[i] = crc;
    }
  }
};

constexpr Crc32cTable kCrc32cTable{};

}  // namespace

Digest Digest::of(std::span<const std::byte> bytes) noexcept {
  Sha256State state;
  state.update(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
  Digest out;
  state.finish(out.raw_.data());
  return out;
}

Digest Digest::of(std::string_view text) noexcept {
  return of(std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size()));
}

Digest Digest::from_bytes(const std::array<std::uint8_t, kBytes>& raw) noexcept {
  Digest out;
  out.raw_ = raw;
  return out;
}

bool Digest::from_hex(std::string_view hex, Digest& out) noexcept {
  if (hex.size() != kBytes * 2) return false;
  std::array<std::uint8_t, kBytes> raw{};
  for (std::size_t i = 0; i < kBytes; ++i) {
    const int hi = hex_value(hex[i * 2]);
    const int lo = hex_value(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    raw[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  out.raw_ = raw;
  return true;
}

std::string Digest::to_hex() const {
  std::string out;
  out.resize(kBytes * 2);
  for (std::size_t i = 0; i < kBytes; ++i) {
    out[i * 2] = kHexDigits[raw_[i] >> 4];
    out[i * 2 + 1] = kHexDigits[raw_[i] & 0x0Fu];
  }
  return out;
}

std::string Digest::to_short_hex() const {
  const std::string full = to_hex();
  return full.substr(0, 16);
}

bool Digest::zero() const noexcept {
  for (std::uint8_t byte : raw_) {
    if (byte != 0) return false;
  }
  return true;
}

bool Digest::of_file(const std::filesystem::path& path, Digest& out, std::uint64_t max_bytes) noexcept {
  std::error_code ec;
  const std::uintmax_t size = std::filesystem::file_size(path, ec);
  if (ec) return false;
  if (size > max_bytes) return false;

  std::ifstream stream(path, std::ios::binary);
  if (!stream) return false;

  Sha256State state;
  std::vector<char> buffer(64 * 1024);
  std::uint64_t consumed = 0;
  while (stream) {
    stream.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const std::streamsize got = stream.gcount();
    if (got <= 0) break;
    consumed += static_cast<std::uint64_t>(got);
    if (consumed > max_bytes) return false;
    state.update(reinterpret_cast<const unsigned char*>(buffer.data()), static_cast<std::size_t>(got));
  }
  if (stream.bad()) return false;
  if (consumed != size) return false;   // file changed while hashing
  Digest digest;
  state.finish(digest.raw_.data());
  out = digest;
  return true;
}

struct Hasher::Impl {
  Sha256State state;
};

Hasher::Hasher() noexcept : impl_(new Impl()) {}
Hasher::~Hasher() { delete impl_; }

void Hasher::update(std::span<const std::byte> bytes) noexcept {
  impl_->state.update(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
}

void Hasher::update(std::string_view text) noexcept {
  update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size()));
}

void Hasher::update_byte(std::uint8_t value) noexcept {
  impl_->state.update(&value, 1);
}

void Hasher::update_u32(std::uint32_t value) noexcept {
  unsigned char raw[4];
  raw[0] = static_cast<unsigned char>(value & 0xFFu);
  raw[1] = static_cast<unsigned char>((value >> 8) & 0xFFu);
  raw[2] = static_cast<unsigned char>((value >> 16) & 0xFFu);
  raw[3] = static_cast<unsigned char>((value >> 24) & 0xFFu);
  impl_->state.update(raw, 4);
}

void Hasher::update_u64(std::uint64_t value) noexcept {
  update_u32(static_cast<std::uint32_t>(value & 0xFFFFFFFFu));
  update_u32(static_cast<std::uint32_t>(value >> 32));
}

void Hasher::update_length_prefixed(std::string_view text) noexcept {
  update_u64(text.size());
  update(text);
}

Digest Hasher::finish() noexcept {
  Digest out;
  impl_->state.finish(out.raw_.data());
  return out;
}

std::uint32_t crc32c(std::span<const std::byte> bytes) noexcept {
  std::uint32_t crc = 0xFFFFFFFFu;
  for (const std::byte value : bytes) {
    crc = kCrc32cTable.entries[(crc ^ static_cast<std::uint32_t>(value)) & 0xFFu] ^ (crc >> 8);
  }
  return crc ^ 0xFFFFFFFFu;
}

std::uint32_t crc32c(std::string_view text) noexcept {
  return crc32c(std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size()));
}

}  // namespace crf
