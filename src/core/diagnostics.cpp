#include "crf/diagnostics.hpp"

#include <algorithm>
#include <cctype>

namespace crf {
namespace {

enum class Dialect : std::uint8_t { msvc, nvcc };

CRF_NODISCARD bool is_severity_word(std::string_view text, std::size_t position,
                                    std::size_t& length, DiagnosticSeverity& severity) noexcept {
  struct Entry {
    std::string_view word;
    DiagnosticSeverity severity;
  };
  // Longest first so that "fatal error" wins over "error".
  static constexpr Entry kEntries[] = {
      {"fatal error", DiagnosticSeverity::fatal},
      {"internal error", DiagnosticSeverity::internal},
      {"fatal", DiagnosticSeverity::fatal},
      {"error", DiagnosticSeverity::error},
      {"warning", DiagnosticSeverity::warning},
      {"note", DiagnosticSeverity::info},
      {"info", DiagnosticSeverity::info},
      {"remark", DiagnosticSeverity::info},
  };
  for (const Entry& entry : kEntries) {
    if (position + entry.word.size() > text.size()) continue;
    if (!equals_ascii_ci(text.substr(position, entry.word.size()), entry.word)) continue;
    const std::size_t end = position + entry.word.size();
    if (end < text.size()) {
      const char next = text[end];
      if (std::isalnum(static_cast<unsigned char>(next)) != 0 || next == '_') continue;
    }
    length = entry.word.size();
    severity = entry.severity;
    return true;
  }
  return false;
}

/// Extract "path(line,col)" / "path(line)" / "path" from the text preceding a
/// severity keyword. Returns the number of characters consumed.
CRF_NODISCARD std::size_t parse_location(std::string_view text, Diagnostic& out) {
  std::string_view head = trim_ascii(text);
  if (head.empty()) return 0;

  // The trailing separator is " : " or ": " (MSVC writes " : " for linkers).
  std::size_t end = head.size();
  while (end > 0 && (head[end - 1] == ' ' || head[end - 1] == ':')) --end;
  head = head.substr(0, end);
  if (head.empty()) return 0;

  if (head.back() == ')') {
    const std::size_t open = head.rfind('(');
    if (open != std::string_view::npos) {
      const std::string_view inner = head.substr(open + 1, head.size() - open - 2);
      const std::vector<std::string> parts = split_ascii(inner, ',');
      bool numeric = !inner.empty();
      for (const std::string& part : parts) {
        const std::string trimmed = std::string(trim_ascii(part));
        if (trimmed.empty() ||
            !std::all_of(trimmed.begin(), trimmed.end(), [](char c) {
              return std::isdigit(static_cast<unsigned char>(c)) != 0;
            })) {
          numeric = false;
          break;
        }
      }
      if (numeric) {
        out.file = std::string(head.substr(0, open));
        if (!parts.empty()) {
          out.line = static_cast<std::uint32_t>(std::strtoul(parts[0].c_str(), nullptr, 10));
        }
        if (parts.size() > 1) {
          out.column = static_cast<std::uint32_t>(std::strtoul(parts[1].c_str(), nullptr, 10));
        }
        return text.size();
      }
    }
  }
  if (head.size() > 512) return 0;   // implausible path; keep it in the raw line only
  out.file = std::string(head);
  return text.size();
}

/// Extract a stable diagnostic code such as C2039, LNK2019, or 20012.
CRF_NODISCARD std::string parse_code(std::string_view text) {
  std::string_view head = trim_ascii(text);
  std::size_t end = 0;
  while (end < head.size() && (std::isalnum(static_cast<unsigned char>(head[end])) != 0)) ++end;
  if (end == 0 || end > 16) return {};
  const std::string_view token = head.substr(0, end);
  const bool has_alpha = std::any_of(token.begin(), token.end(), [](char c) {
    return std::isalpha(static_cast<unsigned char>(c)) != 0;
  });
  const bool has_digit = std::any_of(token.begin(), token.end(), [](char c) {
    return std::isdigit(static_cast<unsigned char>(c)) != 0;
  });
  if (!has_digit) return {};
  if (!has_alpha && token.size() < 4) return {};
  return std::string(token);
}

CRF_NODISCARD std::vector<Diagnostic> parse_lines(std::string_view output, std::string_view origin,
                                                  Dialect dialect) {
  std::vector<Diagnostic> out;
  std::size_t start = 0;
  while (start <= output.size()) {
    std::size_t position = output.find('\n', start);
    if (position == std::string_view::npos) position = output.size();
    std::string_view line = output.substr(start, position - start);
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    start = position + 1;
    if (trim_ascii(line).empty()) continue;

    Diagnostic diagnostic;
    diagnostic.origin = std::string(origin);
    if (line.size() > DiagnosticSet::kMaxMessageBytes) line = line.substr(0, DiagnosticSet::kMaxMessageBytes);
    diagnostic.raw = std::string(line);

    // Locate the severity keyword. The first match that is preceded by a
    // separator (or starts the line) wins.
    std::size_t cursor = 0;
    bool found = false;
    std::size_t severity_at = 0;
    std::size_t severity_length = 0;
    DiagnosticSeverity severity = DiagnosticSeverity::unknown;
    while (cursor < line.size()) {
      std::size_t word_length = 0;
      DiagnosticSeverity candidate = DiagnosticSeverity::unknown;
      if (is_severity_word(line, cursor, word_length, candidate)) {
        const bool at_start = cursor == 0;
        const bool after_separator =
            cursor > 0 && (line[cursor - 1] == ' ' || line[cursor - 1] == ':');
        if (at_start || after_separator) {
          found = true;
          severity_at = cursor;
          severity_length = word_length;
          severity = candidate;
          break;
        }
      }
      ++cursor;
    }

    if (!found) {
      diagnostic.severity = DiagnosticSeverity::unknown;
      diagnostic.message = std::string(trim_ascii(line));
      out.push_back(std::move(diagnostic));
      continue;
    }

    diagnostic.severity = severity;
    (void)parse_location(line.substr(0, severity_at), diagnostic);
    std::string_view rest = line.substr(severity_at + severity_length);
    if (dialect == Dialect::msvc) {
      // MSVC writes "<severity> <code>: <message>" and sometimes
      // "<severity>: <message>" for the linker and librarian.
      std::string_view trimmed = trim_ascii(rest);
      if (!trimmed.empty() && trimmed.front() == ':') {
        trimmed = trim_ascii(trimmed.substr(1));
      }
      const std::string code = parse_code(trimmed);
      if (!code.empty()) {
        diagnostic.code = code;
        std::string_view after = trim_ascii(trimmed.substr(code.size()));
        if (!after.empty() && after.front() == ':') after = trim_ascii(after.substr(1));
        trimmed = after;
      }
      diagnostic.message = std::string(trimmed);
    } else {
      std::string_view trimmed = trim_ascii(rest);
      while (!trimmed.empty() && trimmed.front() == ':') trimmed = trim_ascii(trimmed.substr(1));
      const std::string code = parse_code(trimmed);
      // nvcc emits a bare code only for ptxas/nvlink style messages.
      if (!code.empty() && code.size() > 4) {
        diagnostic.code = code;
        std::string_view after = trim_ascii(trimmed.substr(code.size()));
        while (!after.empty() && after.front() == ':') after = trim_ascii(after.substr(1));
        trimmed = after;
      }
      diagnostic.message = std::string(trimmed);
    }
    out.push_back(std::move(diagnostic));
  }
  return out;
}

}  // namespace

std::string_view to_string(DiagnosticSeverity value) noexcept {
  switch (value) {
    case DiagnosticSeverity::info: return "INFO";
    case DiagnosticSeverity::warning: return "WARNING";
    case DiagnosticSeverity::error: return "ERROR";
    case DiagnosticSeverity::fatal: return "FATAL";
    case DiagnosticSeverity::internal: return "INTERNAL";
    case DiagnosticSeverity::unknown: return "UNKNOWN";
  }
  return "UNKNOWN";
}

bool parse_diagnostic_severity(std::string_view text, DiagnosticSeverity& out) noexcept {
  static constexpr DiagnosticSeverity kValues[] = {
      DiagnosticSeverity::info,   DiagnosticSeverity::warning, DiagnosticSeverity::error,
      DiagnosticSeverity::fatal,  DiagnosticSeverity::internal, DiagnosticSeverity::unknown};
  for (DiagnosticSeverity value : kValues) {
    if (equals_ascii_ci(text, to_string(value))) {
      out = value;
      return true;
    }
  }
  return false;
}

Digest Diagnostic::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(to_string(severity));
  writer.text(code);
  writer.text(message);
  writer.text(file);
  writer.u32(line);
  writer.u32(column);
  writer.text(origin);
  return Digest::of(writer.bytes());
}

Digest DiagnosticSet::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(id.to_string());
  writer.u64(generation.value());
  writer.text(invocation.to_string());
  writer.text(phase.to_string());
  writer.text(toolchain.to_string());
  writer.text(target.to_string());
  writer.boolean(normalized);
  writer.boolean(truncated);
  writer.u64(raw_stdout_bytes);
  writer.u64(raw_stderr_bytes);
  writer.u64(dropped_stdout_bytes);
  writer.u64(dropped_stderr_bytes);
  writer.i32(exit_code);
  writer.boolean(process_crashed);
  writer.u32(error_count);
  writer.u32(warning_count);
  for (const Diagnostic& entry : entries) writer.text(entry.canonical_digest().to_hex());
  writer.text(raw_stdout_tail);
  writer.text(raw_stderr_tail);
  return Digest::of(writer.bytes());
}

Digest DiagnosticSet::normalized_digest() const {
  std::vector<std::string> digests;
  digests.reserve(entries.size());
  for (const Diagnostic& entry : entries) digests.push_back(entry.canonical_digest().to_hex());
  std::sort(digests.begin(), digests.end());
  CanonicalWriter writer;
  writer.u64(digests.size());
  for (const std::string& entry : digests) writer.text(entry);
  return Digest::of(writer.bytes());
}

std::vector<Diagnostic> normalize_msvc_output(std::string_view output, std::string_view origin) {
  return parse_lines(output, origin, Dialect::msvc);
}

std::vector<Diagnostic> normalize_nvcc_output(std::string_view output, std::string_view origin) {
  return parse_lines(output, origin, Dialect::nvcc);
}

std::vector<Diagnostic> normalize_generic_output(std::string_view output, std::string_view origin) {
  std::vector<Diagnostic> out;
  std::size_t start = 0;
  while (start <= output.size()) {
    std::size_t position = output.find('\n', start);
    if (position == std::string_view::npos) position = output.size();
    std::string_view line = output.substr(start, position - start);
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    start = position + 1;
    if (trim_ascii(line).empty()) continue;
    if (line.size() > DiagnosticSet::kMaxMessageBytes) {
      line = line.substr(0, DiagnosticSet::kMaxMessageBytes);
    }
    Diagnostic diagnostic;
    diagnostic.severity = DiagnosticSeverity::unknown;
    diagnostic.origin = std::string(origin);
    diagnostic.raw = std::string(line);
    diagnostic.message = diagnostic.raw;
    out.push_back(std::move(diagnostic));
  }
  return out;
}

void count_severities(const std::vector<Diagnostic>& entries, std::uint32_t& errors,
                      std::uint32_t& warnings) noexcept {
  errors = 0;
  warnings = 0;
  for (const Diagnostic& entry : entries) {
    switch (entry.severity) {
      case DiagnosticSeverity::error:
      case DiagnosticSeverity::fatal:
      case DiagnosticSeverity::internal:
        ++errors;
        break;
      case DiagnosticSeverity::warning:
        ++warnings;
        break;
      default:
        break;
    }
  }
}

Result<Ref<DiagnosticSetId>> DiagnosticStore::add(DiagnosticSet set) {
  if (entries_.size() >= kMaxSets) {
    return Status(StatusCode::capacity_exceeded, "diagnostic store is full");
  }
  set.id = allocator_.next();
  set.generation = DiagnosticGeneration::initial();
  const DiagnosticSetId id = set.id;
  entries_.emplace(id.value(), std::move(set));
  return Ref<DiagnosticSetId>{id, DiagnosticGeneration::initial()};
}

Result<Ref<DiagnosticSetId>> DiagnosticStore::add_as(DiagnosticSetId id, DiagnosticSet set) {
  if (!id.present()) {
    return Status(StatusCode::invalid_identity, "diagnostic set identity is absent");
  }
  allocator_.observe(id);
  set.id = id;
  if (!set.generation.present()) set.generation = DiagnosticGeneration::initial();
  entries_[id.value()] = std::move(set);
  return Ref<DiagnosticSetId>{id, entries_[id.value()].generation};
}

const DiagnosticSet* DiagnosticStore::find(DiagnosticSetId id) const noexcept {
  const auto found = entries_.find(id.value());
  if (found == entries_.end()) return nullptr;
  return &found->second;
}

std::vector<DiagnosticSet> DiagnosticStore::list() const {
  std::vector<DiagnosticSet> out;
  out.reserve(entries_.size());
  for (const auto& [key, entry] : entries_) {
    (void)key;
    out.push_back(entry);
  }
  std::sort(out.begin(), out.end(), [](const DiagnosticSet& a, const DiagnosticSet& b) {
    return a.id < b.id;
  });
  return out;
}

}  // namespace crf
