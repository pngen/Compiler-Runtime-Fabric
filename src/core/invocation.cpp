#include "crf/invocation.hpp"
#include "crf/canonical.hpp"

#include <algorithm>
#include <system_error>

namespace crf {
namespace {

CRF_NODISCARD bool argument_is_hostile(std::string_view argument) noexcept {
  for (const char c : argument) {
    const unsigned char byte = static_cast<unsigned char>(c);
    if (byte == 0) return true;
    // Control characters other than the horizontal tab have no legitimate role
    // in a compiler argument and are a classic log/response-file injection.
    if (byte < 0x20 && byte != '\t') return true;
    if (byte == 0x7F) return true;
  }
  return false;
}

CRF_NODISCARD bool argument_looks_like_switch(std::string_view argument) noexcept {
  return !argument.empty() && (argument.front() == '/' || argument.front() == '-');
}

}  // namespace

std::string quote_windows_argument(std::string_view argument) {
  const bool needs_quoting = argument.empty() ||
                             argument.find_first_of(" \t\"") != std::string_view::npos;
  if (!needs_quoting) return std::string(argument);

  std::string out;
  out.reserve(argument.size() + 2);
  out.push_back('"');
  std::size_t backslashes = 0;
  for (const char c : argument) {
    if (c == '\\') {
      ++backslashes;
      continue;
    }
    if (c == '"') {
      out.append(backslashes * 2 + 1, '\\');
      out.push_back('"');
      backslashes = 0;
      continue;
    }
    out.append(backslashes, '\\');
    backslashes = 0;
    out.push_back(c);
  }
  out.append(backslashes * 2, '\\');
  out.push_back('"');
  return out;
}

std::string render_command_line(const std::vector<std::string>& argv, ArgumentStyle style) {
  std::string out;
  for (std::size_t i = 0; i < argv.size(); ++i) {
    if (i != 0) out.push_back(' ');
    if (style == ArgumentStyle::msvc) {
      out.append(quote_windows_argument(argv[i]));
    } else {
      const bool needs_quoting = argv[i].empty() ||
                                 argv[i].find_first_of(" \t\"'") != std::string::npos;
      if (!needs_quoting) {
        out.append(argv[i]);
      } else {
        out.push_back('"');
        out.append(argv[i]);
        out.push_back('"');
      }
    }
  }
  return out;
}

VoidResult ProcessSpec::validate() const {
  if (executable.empty()) {
    return Status(StatusCode::invalid_argument, "process executable is empty");
  }
  if (!executable.is_absolute()) {
    return Status(StatusCode::path_not_absolute,
                  "process executable must be an absolute path: " + executable.string());
  }
  if (executable.string().find('\0') != std::string::npos) {
    return Status(StatusCode::invalid_argument, "process executable contains a NUL byte");
  }
  // A path that is not in normal form can reach the loader in a shape the
  // operating system rejects or resolves differently. The runtime normalises
  // every path it constructs; this guard keeps that invariant honest.
  if (normalize_path_string(executable) != executable.string()) {
    return Status(StatusCode::invalid_argument,
                  "process executable path is not canonical: " + executable.string());
  }
  if (arguments.size() > kMaxArguments) {
    return Status(StatusCode::capacity_exceeded, "argument count exceeds the ceiling");
  }
  std::size_t total_argument_bytes = 0;
  for (const std::string& argument : arguments) {
    if (argument.size() > kMaxArgumentBytes) {
      return Status(StatusCode::capacity_exceeded, "a single argument exceeds the byte ceiling");
    }
    if (argument.find('\0') != std::string::npos) {
      return Status(StatusCode::invalid_argument, "an argument contains a NUL byte");
    }
    total_argument_bytes += argument.size();
  }
  if (executable.string().size() + total_argument_bytes + arguments.size() > kMaxCommandLineBytes) {
    return Status(StatusCode::capacity_exceeded, "the rendered command line exceeds the ceiling");
  }
  if (!working_directory.empty()) {
    if (!working_directory.is_absolute()) {
      return Status(StatusCode::path_not_absolute, "process working directory must be absolute");
    }
    std::error_code ec;
    if (!std::filesystem::is_directory(working_directory, ec) || ec) {
      return Status(StatusCode::not_found,
                    "process working directory does not exist: " + working_directory.string());
    }
  }
  std::size_t environment_bytes = 0;
  for (const EnvironmentVariable& variable : environment) {
    if (variable.name.empty() || variable.name.find('=') != std::string::npos) {
      return Status(StatusCode::invalid_argument, "process environment contains an invalid name");
    }
    environment_bytes += variable.name.size() + variable.value.size() + 2;
  }
  if (environment_bytes > kMaxEnvironmentBytes) {
    return Status(StatusCode::capacity_exceeded, "the environment block exceeds the byte ceiling");
  }
  if (max_capture_bytes == 0 || max_capture_bytes > kMaxCaptureBytes) {
    return Status(StatusCode::invalid_argument, "capture ceiling is out of range");
  }
  return VoidResult{};
}

Digest ProcessSpec::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(canonical_path_key(executable));
  writer.u64(arguments.size());
  for (const std::string& argument : arguments) writer.text(argument);
  std::vector<EnvironmentVariable> environment_copy = environment;
  std::sort(environment_copy.begin(), environment_copy.end(),
            [](const EnvironmentVariable& a, const EnvironmentVariable& b) {
              return less_ascii_ci(a.name, b.name);
            });
  for (const EnvironmentVariable& variable : environment_copy) {
    writer.text(to_upper_ascii(variable.name));
    writer.text(variable.value);
  }
  writer.text(canonical_path_key(working_directory));
  writer.text(standard_input);
  writer.u32(timeout_millis);
  writer.u64(max_capture_bytes);
  return Digest::of(writer.bytes());
}

std::string ProcessSpec::render_command_line() const {
  std::vector<std::string> argv;
  argv.reserve(arguments.size() + 1);
  argv.push_back(executable.string());
  for (const std::string& argument : arguments) argv.push_back(argument);
  return crf::render_command_line(argv, ArgumentStyle::msvc);
}

Digest InvocationSpec::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(id.to_string());
  writer.u64(generation.value());
  writer.text(session.to_string());
  writer.text(phase.to_string());
  writer.u64(attempt_generation.value());
  writer.text(component.to_string());
  writer.u64(component_generation.value());
  writer.text(toolchain.to_string());
  writer.text(target.to_string());
  writer.text(environment.to_string());
  writer.text(policy.to_string());
  writer.text(canonical_path_key(executable));
  writer.text(executable_identity.canonical_digest().to_hex());
  for (const std::string& argument : arguments) writer.text(argument);
  std::vector<EnvironmentVariable> environment_copy = environment_variables;
  std::sort(environment_copy.begin(), environment_copy.end(),
            [](const EnvironmentVariable& a, const EnvironmentVariable& b) {
              return less_ascii_ci(a.name, b.name);
            });
  for (const EnvironmentVariable& variable : environment_copy) {
    writer.text(to_upper_ascii(variable.name));
    writer.text(variable.value);
  }
  writer.text(canonical_path_key(working_directory));
  std::vector<std::string> inputs_text;
  inputs_text.reserve(inputs.size());
  for (const InputBinding& binding : inputs) {
    inputs_text.push_back(binding.source.to_string() + "|" + canonical_path_key(binding.path) + "|" +
                          binding.content.to_hex() + "|" + (binding.staged ? "staged" : "in-place"));
  }
  std::sort(inputs_text.begin(), inputs_text.end());
  for (const std::string& entry : inputs_text) writer.text(entry);
  std::vector<std::string> outputs_text;
  outputs_text.reserve(expected_outputs.size());
  for (const OutputBinding& binding : expected_outputs) {
    outputs_text.push_back(binding.logical_name + "|" + canonical_path_key(binding.path) + "|" +
                           std::string(to_string(binding.expected_format)) + "|" +
                           (binding.required ? "required" : "optional"));
  }
  std::sort(outputs_text.begin(), outputs_text.end());
  for (const std::string& entry : outputs_text) writer.text(entry);
  writer.text(adapter_name);
  writer.u8(static_cast<std::uint8_t>(style));
  writer.boolean(produced_executable);
  return Digest::of(writer.bytes());
}

std::string InvocationSpec::render() const {
  std::vector<std::string> argv;
  argv.reserve(arguments.size() + 1);
  argv.push_back(executable.string());
  for (const std::string& argument : arguments) argv.push_back(argument);
  return crf::render_command_line(argv, style);
}

Result<ProcessSpec> InvocationSpec::to_process_spec() const {
  ProcessSpec spec;
  spec.executable = executable;
  spec.arguments = arguments;
  spec.environment = environment_variables;
  spec.working_directory = working_directory;
  if (const VoidResult valid = spec.validate(); !valid) return valid.status();
  return spec;
}

Result<InvocationSpec> validate_invocation(InvocationSpec spec,
                                           const InvocationValidationContext& context) {
  if (spec.executable.empty()) {
    return Status(StatusCode::invalid_argument, "invocation has no executable");
  }
  if (!spec.executable.is_absolute()) {
    return Status(StatusCode::path_not_absolute,
                  "invocation executable must be absolute: " + spec.executable.string());
  }
  if (spec.arguments.size() > context.limits.max_arguments) {
    return Status(StatusCode::capacity_exceeded, "invocation argument count exceeds the ceiling");
  }
  for (const std::string& argument : spec.arguments) {
    if (argument.size() > context.limits.max_argument_bytes) {
      return Status(StatusCode::capacity_exceeded, "invocation argument exceeds the byte ceiling");
    }
    if (argument_is_hostile(argument)) {
      return Status(StatusCode::invalid_argument,
                    "invocation argument contains a forbidden control character");
    }
  }
  if (spec.render().size() > context.limits.max_command_line_bytes) {
    return Status(StatusCode::capacity_exceeded, "invocation command line exceeds the ceiling");
  }
  if (spec.environment_variables.size() > context.limits.max_environment_variables) {
    return Status(StatusCode::capacity_exceeded, "invocation environment exceeds the entry ceiling");
  }
  std::size_t environment_bytes = 0;
  for (const EnvironmentVariable& variable : spec.environment_variables) {
    if (variable.name.empty() || variable.name.find('=') != std::string::npos) {
      return Status(StatusCode::invalid_argument, "invocation environment has an invalid name");
    }
    environment_bytes += variable.name.size() + variable.value.size() + 2;
  }
  if (environment_bytes > context.limits.max_environment_bytes) {
    return Status(StatusCode::capacity_exceeded, "invocation environment exceeds the byte ceiling");
  }
  if (spec.inputs.size() > context.limits.max_inputs) {
    return Status(StatusCode::capacity_exceeded, "invocation input count exceeds the ceiling");
  }
  if (spec.expected_outputs.size() > context.limits.max_outputs) {
    return Status(StatusCode::capacity_exceeded, "invocation output count exceeds the ceiling");
  }

  // The executable must still exist and, when a component identity was bound,
  // must still be the same file. A replaced binary at the same path is refused.
  std::error_code ec;
  if (!std::filesystem::exists(spec.executable, ec) || ec) {
    return Status(StatusCode::not_found,
                  "invocation executable does not exist: " + spec.executable.string());
  }
  if (context.require_component_identity && !spec.produced_executable) {
    if (!spec.executable_identity.content_hashed) {
      return Status(StatusCode::integrity_unproven,
                    "invocation executable identity was never content-verified");
    }
    const Result<FileIdentity> observed = probe_file_identity(spec.executable, true);
    if (!observed) return observed.status();
    if (!spec.executable_identity.same_binary_as(observed.value())) {
      return Status(StatusCode::component_mutated,
                    "invocation executable no longer matches the bound component identity");
    }
  }
  if (!context.allowed_executable_roots.empty()) {
    const bool allowed = std::any_of(
        context.allowed_executable_roots.begin(), context.allowed_executable_roots.end(),
        [&spec](const std::filesystem::path& root) { return path_is_within(spec.executable, root); });
    if (!allowed) {
      return Status(StatusCode::policy_refused,
                    "invocation executable is outside every permitted root");
    }
  }

  // Policy refusals are evaluated before workspace containment so that a
  // forbidden option is reported as a policy refusal, not a path problem.
  for (const std::string& argument : spec.arguments) {
    if (!argument_looks_like_switch(argument)) continue;
    for (const std::string& forbidden : context.forbidden_options) {
      if (equals_ascii_ci(argument, forbidden)) {
        return Status(StatusCode::policy_refused, "forbidden option: " + argument);
      }
      if (argument.size() > forbidden.size() && starts_with_ci(argument, forbidden)) {
        const char separator = argument[forbidden.size()];
        if (separator == ':' || separator == '=') {
          return Status(StatusCode::policy_refused, "forbidden option: " + argument);
        }
      }
    }
  }

  if (context.target_architecture == Architecture::unknown) {
    return Status(StatusCode::target_unsupported, "invocation has no resolved target architecture");
  }

  for (const InputBinding& binding : spec.inputs) {
    if (binding.path.empty()) {
      return Status(StatusCode::invalid_argument, "invocation input has an empty path");
    }
    if (path_has_traversal(binding.path)) {
      return Status(StatusCode::path_traversal, "invocation input path contains a parent component");
    }
    if (context.workspace != nullptr && binding.staged && !context.workspace->contains(binding.path)) {
      return Status(StatusCode::workspace_escape, "staged input is outside the workspace");
    }
  }

  for (const OutputBinding& binding : spec.expected_outputs) {
    if (binding.path.empty()) {
      return Status(StatusCode::invalid_argument, "invocation output has an empty path");
    }
    if (!binding.path.is_absolute()) {
      return Status(StatusCode::path_not_absolute,
                    "invocation output must be absolute: " + binding.path.string());
    }
    if (path_has_traversal(binding.path)) {
      return Status(StatusCode::path_traversal, "invocation output path contains a parent component");
    }
    if (binding.logical_name.empty()) {
      return Status(StatusCode::invalid_argument, "invocation output has no logical name");
    }
    if (context.workspace != nullptr) {
      if (!context.workspace->contains(binding.path)) {
        return Status(StatusCode::workspace_escape,
                      "invocation output escapes the workspace: " + binding.path.string());
      }
      const std::filesystem::path relative =
          normalize_path(binding.path).lexically_relative(normalize_path(context.workspace->root));
      if (relative.empty() || relative.generic_string().rfind("..", 0) == 0) {
        return Status(StatusCode::workspace_escape,
                      "invocation output is not addressable inside the workspace: " +
                          binding.path.string());
      }
      const Result<std::filesystem::path> checked = context.workspace->resolve(relative.string());
      if (!checked) return checked.status();
    }
  }

  if (spec.working_directory.empty() && context.workspace != nullptr) {
    spec.working_directory = context.workspace->root;
  }
  if (!spec.working_directory.empty()) {
    if (!spec.working_directory.is_absolute()) {
      return Status(StatusCode::path_not_absolute, "invocation working directory must be absolute");
    }
    if (context.workspace != nullptr && !context.workspace->contains(spec.working_directory)) {
      return Status(StatusCode::workspace_escape,
                    "invocation working directory is outside the workspace");
    }
  }

  const Result<ProcessSpec> process = spec.to_process_spec();
  if (!process) return process.status();
  return spec;
}

}  // namespace crf
