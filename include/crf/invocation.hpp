#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "crf/component.hpp"
#include "crf/digest.hpp"
#include "crf/environment.hpp"
#include "crf/process.hpp"
#include "crf/status.hpp"
#include "crf/strong_id.hpp"
#include "crf/target.hpp"
#include "crf/toolchain.hpp"
#include "crf/workspace.hpp"

namespace crf {

/// How an argument vector is rendered into a single command line. The runtime
/// still passes an argument vector to the operating system; this only selects
/// the quoting dialect that the target compiler expects when it re-parses.
enum class ArgumentStyle : std::uint8_t {
  /// Microsoft C/C++ runtime rules (CommandLineToArgvW compatible).
  msvc = 0,
  /// POSIX shell-free rules: quote only when the argument needs it.
  posix = 1,
};

/// Quote one argument for the MSVC command line dialect.
CRF_NODISCARD CRF_API std::string quote_windows_argument(std::string_view argument);
/// Render an argument vector as a single command line. Deterministic.
CRF_NODISCARD CRF_API std::string render_command_line(const std::vector<std::string>& argv,
                                                      ArgumentStyle style);

struct CRF_API InputBinding {
  SourceId source{};
  SourceGeneration generation{};
  std::filesystem::path path;
  Digest content{};
  /// True when the runtime copied the input into the workspace instead of
  /// referencing the original location.
  bool staged = false;
  bool read_only = true;
};

struct CRF_API OutputBinding {
  std::string logical_name;
  std::filesystem::path path;
  ObjectFormat expected_format = ObjectFormat::unknown;
  bool required = true;
  bool allow_empty = false;
};

/// A fully validated intent to execute one compiler component.
struct CRF_API InvocationSpec {
  InvocationId id{};
  InvocationGeneration generation{};

  Ref<CompilerSessionId> session{};
  Ref<CompilerPhaseId> phase{};
  AttemptGeneration attempt_generation{};
  CompilerComponentId component{};
  CompilerComponentGeneration component_generation{};
  Ref<ToolchainId> toolchain{};
  Ref<TargetId> target{};
  Ref<EnvironmentId> environment{};
  Ref<PolicyId> policy{};

  std::filesystem::path executable;
  FileIdentity executable_identity{};
  std::vector<std::string> arguments;
  std::vector<EnvironmentVariable> environment_variables;
  std::filesystem::path working_directory;
  std::vector<InputBinding> inputs;
  std::vector<OutputBinding> expected_outputs;
  ArgumentStyle style = ArgumentStyle::msvc;
  std::string adapter_name;
  /// True when the executable is an artifact this session produced rather than a
  /// toolchain component. Such a launch is bound to the artifact's digest, not
  /// to a component identity.
  bool produced_executable = false;

  CRF_NODISCARD Digest canonical_digest() const;
  CRF_NODISCARD std::string render() const;
  CRF_NODISCARD Result<ProcessSpec> to_process_spec() const;
};

struct CRF_API InvocationLimits {
  std::size_t max_arguments = 4096;
  std::size_t max_argument_bytes = 32768;
  std::size_t max_command_line_bytes = 1u << 20;
  std::size_t max_environment_variables = 1024;
  std::size_t max_environment_bytes = 1u << 20;
  std::size_t max_outputs = 256;
  std::size_t max_inputs = 256;
};

/// Everything the validator needs to decide whether an invocation may launch.
struct CRF_API InvocationValidationContext {
  const Workspace* workspace = nullptr;
  ToolchainFamily family = ToolchainFamily::unknown;
  Architecture target_architecture = Architecture::unknown;
  /// Option strings the session policy forbids, matched case-insensitively as
  /// an exact argument or as a leading "name:" / "name=" form.
  std::vector<std::string> forbidden_options;
  InvocationLimits limits{};
  /// Require the executable to match a registered component identity. A launch
  /// whose executable cannot be tied to a component is refused.
  bool require_component_identity = true;
  /// Directories an executable may live in. Empty disables the check.
  std::vector<std::filesystem::path> allowed_executable_roots;
};

/// Validate a structured invocation before launch.
///
/// Refuses: missing or non-absolute executable, executable whose on-disk
/// identity no longer matches the bound component, malformed argument structure
/// (embedded NUL, control characters, over-long arguments), path traversal,
/// workspace escape, unexpected output locations, forbidden options, and an
/// unsupported target architecture.
CRF_NODISCARD CRF_API Result<InvocationSpec> validate_invocation(
    InvocationSpec spec, const InvocationValidationContext& context);

}  // namespace crf
