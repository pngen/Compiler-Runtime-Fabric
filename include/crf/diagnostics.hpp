#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "crf/canonical.hpp"
#include "crf/digest.hpp"
#include "crf/strong_id.hpp"
#include "crf/status.hpp"
#include "crf/target.hpp"

namespace crf {

enum class DiagnosticSeverity : std::uint8_t {
  info = 0,
  warning = 1,
  error = 2,
  fatal = 3,
  internal = 4,
  unknown = 5,
};

CRF_NODISCARD CRF_API std::string_view to_string(DiagnosticSeverity value) noexcept;
CRF_NODISCARD CRF_API bool parse_diagnostic_severity(std::string_view text,
                                                     DiagnosticSeverity& out) noexcept;

/// One normalised diagnostic. The raw line is retained verbatim so
/// normalisation never destroys evidence.
struct CRF_API Diagnostic {
  DiagnosticSeverity severity = DiagnosticSeverity::unknown;
  /// Stable compiler-reported code where the adapter can extract one, e.g.
  /// "C2039", "LNK2019", "20012". Empty when the compiler provided none.
  std::string code;
  std::string message;
  std::string file;
  std::uint32_t line = 0;
  std::uint32_t column = 0;
  /// Originating compiler component name, e.g. "cl" or "ptxas".
  std::string origin;
  /// The exact line the compiler emitted, truncated to the configured bound.
  std::string raw;

  CRF_NODISCARD Digest canonical_digest() const;
};

/// Bounded capture of a compiler invocation's diagnostic output.
struct CRF_API DiagnosticSet {
  static constexpr std::size_t kMaxEntries = 4096;
  static constexpr std::size_t kMaxMessageBytes = 8192;
  static constexpr std::size_t kMaxRawTailBytes = 16384;

  DiagnosticSetId id{};
  DiagnosticGeneration generation{};
  Ref<InvocationId> invocation{};
  Ref<CompilerPhaseId> phase{};
  Ref<ToolchainId> toolchain{};
  Ref<TargetId> target{};

  std::vector<Diagnostic> entries;
  bool normalized = false;
  /// True when entries or raw tails were dropped because a bound was reached.
  bool truncated = false;
  std::uint64_t raw_stdout_bytes = 0;
  std::uint64_t raw_stderr_bytes = 0;
  std::uint64_t dropped_stdout_bytes = 0;
  std::uint64_t dropped_stderr_bytes = 0;
  std::string raw_stdout_tail;
  std::string raw_stderr_tail;

  std::int32_t exit_code = 0;
  bool process_crashed = false;
  std::uint32_t error_count = 0;
  std::uint32_t warning_count = 0;

  CRF_NODISCARD bool has_errors() const noexcept { return error_count > 0; }
  CRF_NODISCARD Digest canonical_digest() const;
  /// Deterministic, order-independent digest of the normalised entries.
  CRF_NODISCARD Digest normalized_digest() const;
};

class CRF_API DiagnosticStore {
 public:
  static constexpr std::size_t kMaxSets = 16384;

  CRF_NODISCARD Result<Ref<DiagnosticSetId>> add(DiagnosticSet set);
  CRF_NODISCARD Result<Ref<DiagnosticSetId>> add_as(DiagnosticSetId id, DiagnosticSet set);
  CRF_NODISCARD const DiagnosticSet* find(DiagnosticSetId id) const noexcept;
  CRF_NODISCARD std::vector<DiagnosticSet> list() const;
  CRF_NODISCARD std::size_t size() const noexcept { return entries_.size(); }

 private:
  std::unordered_map<std::uint64_t, DiagnosticSet> entries_;
  IdAllocator<DiagnosticSetId> allocator_;
};

/// Normalisation of MSVC tool output. Recognises the canonical
/// "file(line,col): error C1234: message" form plus linker and librarian forms.
/// Never claims semantic equivalence with another compiler family.
CRF_NODISCARD CRF_API std::vector<Diagnostic> normalize_msvc_output(std::string_view output,
                                                                   std::string_view origin);

/// Normalisation of nvcc / cicc / ptxas / nvlink output.
CRF_NODISCARD CRF_API std::vector<Diagnostic> normalize_nvcc_output(std::string_view output,
                                                                   std::string_view origin);

/// Generic normalisation used when an adapter declares no structured parser:
/// every non-empty line becomes an UNKNOWN-severity diagnostic with the raw
/// text preserved.
CRF_NODISCARD CRF_API std::vector<Diagnostic> normalize_generic_output(std::string_view output,
                                                                      std::string_view origin);

/// Severity tally over a diagnostic list.
CRF_NODISCARD CRF_API void count_severities(const std::vector<Diagnostic>& entries,
                                            std::uint32_t& errors, std::uint32_t& warnings) noexcept;

}  // namespace crf
