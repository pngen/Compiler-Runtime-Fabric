#include "crf/ipc.hpp"

#include "crf/canonical.hpp"
#include "crf/version.hpp"

#include <algorithm>

namespace crf {
namespace {

struct Packer {
  CanonicalWriter writer;
  void u8(std::uint8_t value) { writer.u8(value); }
  void u16(std::uint16_t value) { writer.u16(value); }
  void u32(std::uint32_t value) { writer.u32(value); }
  void u64(std::uint64_t value) { writer.u64(value); }
  void i32(std::int32_t value) { writer.i32(value); }
  void b(bool value) { writer.boolean(value); }
  void str(std::string_view value) { writer.text(value); }
  void path(const std::filesystem::path& value) { writer.text(value.string()); }
  void digest(const Digest& value) { writer.text(value.to_hex()); }
  std::string take() { return writer.take(); }
};

struct Unpacker {
  CanonicalReader reader;
  bool ok = true;
  explicit Unpacker(std::string_view bytes) : reader(bytes) {}
  void fail() { ok = false; }
  CRF_NODISCARD bool good() const { return ok; }
  std::uint8_t u8() { std::uint8_t v = 0; if (!reader.u8(v)) fail(); return v; }
  std::uint16_t u16() { std::uint16_t v = 0; if (!reader.u16(v)) fail(); return v; }
  std::uint32_t u32() { std::uint32_t v = 0; if (!reader.u32(v)) fail(); return v; }
  std::uint64_t u64() { std::uint64_t v = 0; if (!reader.u64(v)) fail(); return v; }
  std::int32_t i32() { std::int32_t v = 0; if (!reader.i32(v)) fail(); return v; }
  bool b() { bool v = false; if (!reader.boolean(v)) fail(); return v; }
  std::string str(std::size_t bound = 32768) {
    std::string v;
    if (!reader.text(v, bound)) fail();
    return v;
  }
  std::filesystem::path path() {
    std::string v;
    if (!reader.text(v, 32768)) fail();
    return std::filesystem::path(v);
  }
  Digest digest() {
    std::string hex;
    if (!reader.text(hex, 64) || hex.size() != 64) { fail(); return {}; }
    Digest value;
    if (!Digest::from_hex(hex, value)) fail();
    return value;
  }
  CRF_NODISCARD bool exhausted() const { return reader.exhausted(); }
};

constexpr std::size_t kMaxCollection = 4096;

void pack_environment(Packer& packer, const EnvironmentSpec& spec) {
  packer.path(spec.working_directory);
  packer.path(spec.temp_directory);
  packer.u64(spec.variables.size());
  for (const EnvironmentVariable& variable : spec.variables) {
    packer.str(variable.name);
    packer.str(variable.value);
  }
  const auto pack_paths = [&packer](const std::vector<std::filesystem::path>& paths) {
    packer.u64(paths.size());
    for (const std::filesystem::path& path : paths) packer.path(path);
  };
  pack_paths(spec.include_paths);
  pack_paths(spec.library_paths);
  pack_paths(spec.sdk_roots);
  pack_paths(spec.toolkit_roots);
  packer.u64(spec.inherited_variables.size());
  for (const std::string& name : spec.inherited_variables) packer.str(name);
  packer.u8(static_cast<std::uint8_t>(spec.locale_policy));
  packer.str(spec.locale_name);
  packer.b(spec.deterministic_controls);
}

EnvironmentSpec unpack_environment(Unpacker& unpacker) {
  EnvironmentSpec spec;
  spec.working_directory = unpacker.path();
  spec.temp_directory = unpacker.path();
  const std::uint64_t variable_count = unpacker.u64();
  if (variable_count > kMaxCollection) { unpacker.fail(); return spec; }
  for (std::uint64_t i = 0; i < variable_count && unpacker.good(); ++i) {
    EnvironmentVariable variable;
    variable.name = unpacker.str(4096);
    variable.value = unpacker.str(1u << 20);
    spec.variables.push_back(std::move(variable));
  }
  const auto unpack_paths = [&unpacker](std::vector<std::filesystem::path>& paths) {
    const std::uint64_t count = unpacker.u64();
    if (count > kMaxCollection) { unpacker.fail(); return; }
    for (std::uint64_t i = 0; i < count && unpacker.good(); ++i) paths.push_back(unpacker.path());
  };
  unpack_paths(spec.include_paths);
  unpack_paths(spec.library_paths);
  unpack_paths(spec.sdk_roots);
  unpack_paths(spec.toolkit_roots);
  const std::uint64_t inherited_count = unpacker.u64();
  if (inherited_count > kMaxCollection) { unpacker.fail(); return spec; }
  for (std::uint64_t i = 0; i < inherited_count && unpacker.good(); ++i) {
    spec.inherited_variables.push_back(unpacker.str(1024));
  }
  spec.locale_policy = static_cast<LocalePolicy>(unpacker.u8());
  spec.locale_name = unpacker.str(256);
  spec.deterministic_controls = unpacker.b();
  return spec;
}

void pack_policy(Packer& packer, const PolicySpec& spec) {
  packer.u8(static_cast<std::uint8_t>(spec.reproducibility));
  packer.u32(spec.max_retries_per_phase);
  packer.u32(spec.max_retries_per_session);
  packer.u64(spec.retryable_classes.size());
  for (const FailureClass value : spec.retryable_classes) packer.u8(static_cast<std::uint8_t>(value));
  packer.u64(spec.forbidden_options.size());
  for (const std::string& option : spec.forbidden_options) packer.str(option);
  packer.b(spec.allow_parallel_phases);
  packer.u64(spec.max_parallel_phases);
  packer.u32(spec.phase_timeout_millis);
  packer.u32(spec.validation_timeout_millis);
  packer.b(spec.run_smoke_test);
  packer.b(spec.require_content_digest);
  packer.u64(spec.max_diagnostic_entries);
  packer.u64(spec.max_diagnostic_bytes_per_stream);
  packer.b(spec.allow_local_cache);
}

PolicySpec unpack_policy(Unpacker& unpacker) {
  PolicySpec spec;
  spec.reproducibility = static_cast<ReproducibilityPolicy>(unpacker.u8());
  spec.max_retries_per_phase = unpacker.u32();
  spec.max_retries_per_session = unpacker.u32();
  const std::uint64_t class_count = unpacker.u64();
  if (class_count > 64) { unpacker.fail(); return spec; }
  for (std::uint64_t i = 0; i < class_count && unpacker.good(); ++i) {
    spec.retryable_classes.push_back(static_cast<FailureClass>(unpacker.u8()));
  }
  const std::uint64_t option_count = unpacker.u64();
  if (option_count > PolicySpec::kMaxForbiddenOptions) { unpacker.fail(); return spec; }
  for (std::uint64_t i = 0; i < option_count && unpacker.good(); ++i) {
    spec.forbidden_options.push_back(unpacker.str(4096));
  }
  spec.allow_parallel_phases = unpacker.b();
  spec.max_parallel_phases = unpacker.u64();
  spec.phase_timeout_millis = unpacker.u32();
  spec.validation_timeout_millis = unpacker.u32();
  spec.run_smoke_test = unpacker.b();
  spec.require_content_digest = unpacker.b();
  spec.max_diagnostic_entries = unpacker.u64();
  spec.max_diagnostic_bytes_per_stream = unpacker.u64();
  spec.allow_local_cache = unpacker.b();
  return spec;
}

void pack_target(Packer& packer, const TargetSpec& target) {
  packer.u8(static_cast<std::uint8_t>(target.architecture));
  packer.u8(static_cast<std::uint8_t>(target.os));
  packer.str(target.triple);
  packer.str(target.cpu);
  packer.str(target.device_arch);
  packer.str(target.device_virtual_arch);
  packer.str(target.abi);
  packer.u32(target.pointer_width_bits);
}

TargetSpec unpack_target(Unpacker& unpacker) {
  TargetSpec target;
  target.architecture = static_cast<Architecture>(unpacker.u8());
  target.os = static_cast<OperatingSystem>(unpacker.u8());
  target.triple = unpacker.str(256);
  target.cpu = unpacker.str(256);
  target.device_arch = unpacker.str(256);
  target.device_virtual_arch = unpacker.str(256);
  target.abi = unpacker.str(256);
  target.pointer_width_bits = unpacker.u32();
  return target;
}

CRF_NODISCARD Result<std::string> field_blob(std::string_view payload, std::uint16_t expected_id) {
  FieldReader reader(payload);
  Result<bool> next = reader.next();
  if (!next) return next.status();
  if (!next.value()) {
    return Status(StatusCode::protocol_malformed, "message payload is empty");
  }
  if (reader.id() != expected_id) {
    return Status(StatusCode::protocol_malformed, "message payload has an unexpected field id");
  }
  Result<std::string> blob = reader.as_blob();
  if (!blob) return blob.status();
  const VoidResult finished = reader.finish();
  if (!finished) return finished.status();
  return blob.value();
}

}  // namespace

std::string encode_hello(std::string_view runtime_name, std::string_view role, std::uint64_t epoch,
                         std::string_view detail) {
  FieldWriter writer;
  writer.text(1, runtime_name);
  writer.text(2, role);
  writer.u64(3, epoch);
  writer.text(4, detail);
  writer.u32(5, (static_cast<std::uint32_t>(protocol_version_major)) |
                    (static_cast<std::uint32_t>(protocol_version_minor) << 16));
  return writer.take();
}

Result<std::string> decode_hello_detail(std::string_view payload) {
  FieldReader reader(payload);
  std::string runtime_name;
  std::string role;
  std::uint64_t epoch = 0;
  std::string detail;
  for (;;) {
    Result<bool> next = reader.next();
    if (!next) return next.status();
    if (!next.value()) break;
    switch (reader.id()) {
      case 1: { Result<std::string> value = reader.as_text(); if (!value) return value.status(); runtime_name = value.value(); break; }
      case 2: { Result<std::string> value = reader.as_text(); if (!value) return value.status(); role = value.value(); break; }
      case 3: { Result<std::uint64_t> value = reader.as_u64(); if (!value) return value.status(); epoch = value.value(); break; }
      case 4: { Result<std::string> value = reader.as_text(); if (!value) return value.status(); detail = value.value(); break; }
      default: break;
    }
  }
  const VoidResult finished = reader.finish();
  if (!finished) return finished.status();
  return role + "|" + runtime_name + "|" + std::to_string(epoch) + "|" + detail;
}

std::string encode_error(StatusCode code, std::string_view detail, std::string_view subject) {
  FieldWriter writer;
  writer.u16(1, static_cast<std::uint16_t>(code));
  writer.text(2, detail);
  writer.text(3, subject);
  return writer.take();
}

Result<std::pair<StatusCode, std::string>> decode_error(std::string_view payload) {
  FieldReader reader(payload);
  StatusCode code = StatusCode::internal_error;
  std::string detail;
  for (;;) {
    Result<bool> next = reader.next();
    if (!next) return next.status();
    if (!next.value()) break;
    switch (reader.id()) {
      case 1: { Result<std::uint16_t> value = reader.as_u16(); if (!value) return value.status(); code = static_cast<StatusCode>(value.value()); break; }
      case 2: { Result<std::string> value = reader.as_text(); if (!value) return value.status(); detail = value.value(); break; }
      default: break;
    }
  }
  const VoidResult finished = reader.finish();
  if (!finished) return finished.status();
  return std::make_pair(code, detail);
}

std::string encode_compile_request(const CompileRequest& request) {
  Packer packer;
  packer.u64(request.request.value());
  packer.u64(request.compilation.value());
  packer.u64(request.compilation_generation.value());
  packer.u64(request.attempt.value());
  packer.u64(request.attempt_generation.value());
  packer.u8(static_cast<std::uint8_t>(request.toolchain_family));
  packer.u64(request.toolchain.value());
  pack_target(packer, request.target);
  packer.u64(request.sources.size());
  for (const std::filesystem::path& path : request.sources) packer.path(path);
  packer.u64(request.inline_sources.size());
  for (const auto& [name, contents] : request.inline_sources) {
    packer.str(name);
    packer.str(contents);
  }
  packer.path(request.output_directory);
  packer.str(request.final_artifact_name);
  pack_policy(packer, request.policy);
  pack_environment(packer, request.environment);
  packer.b(request.stage_inputs);
  packer.b(request.run_smoke_test);
  packer.u64(request.adapter_options.size());
  for (const EnvironmentVariable& option : request.adapter_options) {
    packer.str(option.name);
    packer.str(option.value);
  }
  FieldWriter writer;
  writer.blob(1, packer.take());
  return writer.take();
}

Result<CompileRequest> decode_compile_request(std::string_view payload) {
  const Result<std::string> blob = field_blob(payload, 1);
  if (!blob) return blob.status();
  Unpacker unpacker(blob.value());
  CompileRequest request;
  request.request = RequestId::from_value(unpacker.u64());
  request.compilation = CompilationId::from_value(unpacker.u64());
  request.compilation_generation = CompilationGeneration::from_value(unpacker.u64());
  request.attempt = AttemptId::from_value(unpacker.u64());
  request.attempt_generation = AttemptGeneration::from_value(unpacker.u64());
  request.toolchain_family = static_cast<ToolchainFamily>(unpacker.u8());
  request.toolchain = ToolchainId::from_value(unpacker.u64());
  request.target = unpack_target(unpacker);
  const std::uint64_t source_count = unpacker.u64();
  if (source_count > kMaxCollection) {
    return Status(StatusCode::capacity_exceeded, "compile request declares too many sources");
  }
  for (std::uint64_t i = 0; i < source_count && unpacker.good(); ++i) {
    request.sources.push_back(unpacker.path());
  }
  const std::uint64_t inline_count = unpacker.u64();
  if (inline_count > kMaxCollection) {
    return Status(StatusCode::capacity_exceeded, "compile request declares too many inline sources");
  }
  for (std::uint64_t i = 0; i < inline_count && unpacker.good(); ++i) {
    std::string name = unpacker.str(4096);
    std::string contents = unpacker.str(1u << 22);
    request.inline_sources.emplace_back(std::move(name), std::move(contents));
  }
  request.output_directory = unpacker.path();
  request.final_artifact_name = unpacker.str(4096);
  request.policy = unpack_policy(unpacker);
  request.environment = unpack_environment(unpacker);
  request.stage_inputs = unpacker.b();
  request.run_smoke_test = unpacker.b();
  const std::uint64_t option_count = unpacker.u64();
  if (option_count > kMaxCollection) {
    return Status(StatusCode::capacity_exceeded, "compile request declares too many options");
  }
  for (std::uint64_t i = 0; i < option_count && unpacker.good(); ++i) {
    EnvironmentVariable option;
    option.name = unpacker.str(4096);
    option.value = unpacker.str(1u << 16);
    request.adapter_options.push_back(std::move(option));
  }
  if (!unpacker.good()) return Status(StatusCode::protocol_malformed, "compile request is malformed");
  if (!unpacker.exhausted()) {
    return Status(StatusCode::protocol_malformed, "compile request has trailing bytes");
  }
  return request;
}

std::string encode_session_summary(const CompilerSession& session) {
  FieldWriter writer;
  writer.blob(1, encode_session(session));
  return writer.take();
}

Result<CompilerSession> decode_session_summary(std::string_view payload) {
  const Result<std::string> blob = field_blob(payload, 1);
  if (!blob) return blob.status();
  return decode_session(blob.value());
}

std::string encode_workspace_request(CompilerSessionId session,
                                     CompilerSessionGeneration session_generation,
                                     CompilerPhaseId phase,
                                     CompilerPhaseGeneration phase_generation) {
  FieldWriter writer;
  writer.u64(1, session.value());
  writer.u64(2, session_generation.value());
  writer.u64(3, phase.value());
  writer.u64(4, phase_generation.value());
  return writer.take();
}

Result<std::tuple<CompilerSessionId, CompilerSessionGeneration, CompilerPhaseId,
                  CompilerPhaseGeneration>>
decode_workspace_request(std::string_view payload) {
  FieldReader reader(payload);
  std::uint64_t session = 0;
  std::uint64_t session_generation = 0;
  std::uint64_t phase = 0;
  std::uint64_t phase_generation = 0;
  for (;;) {
    Result<bool> next = reader.next();
    if (!next) return next.status();
    if (!next.value()) break;
    // Only the numbered fields are numeric; a payload may carry other fields
    // that this decoder does not interpret.
    if (reader.id() < 1 || reader.id() > 4) continue;
    Result<std::uint64_t> value = reader.as_u64();
    if (!value) return value.status();
    switch (reader.id()) {
      case 1: session = value.value(); break;
      case 2: session_generation = value.value(); break;
      case 3: phase = value.value(); break;
      case 4: phase_generation = value.value(); break;
      default: break;
    }
  }
  const VoidResult finished = reader.finish();
  if (!finished) return finished.status();
  return std::make_tuple(CompilerSessionId::from_value(session),
                         CompilerSessionGeneration::from_value(session_generation),
                         CompilerPhaseId::from_value(phase),
                         CompilerPhaseGeneration::from_value(phase_generation));
}

std::string encode_invocation_order(const InvocationSpec& invocation, const ProcessSpec& process,
                                    std::string_view workspace_root,
                                    std::string_view phase_label) {
  Packer packer;
  packer.u64(invocation.id.value());
  packer.u64(invocation.generation.value());
  packer.u64(invocation.session.id.value());
  packer.u64(invocation.session.generation.value());
  packer.u64(invocation.phase.id.value());
  packer.u64(invocation.phase.generation.value());
  packer.u64(invocation.attempt_generation.value());
  packer.u64(invocation.component.value());
  packer.u64(invocation.component_generation.value());
  packer.u64(invocation.toolchain.id.value());
  packer.u64(invocation.toolchain.generation.value());
  packer.u64(invocation.target.id.value());
  packer.u64(invocation.target.generation.value());
  packer.u64(invocation.environment.id.value());
  packer.u64(invocation.environment.generation.value());
  packer.u64(invocation.policy.id.value());
  packer.u64(invocation.policy.generation.value());
  packer.path(invocation.executable);
  packer.digest(invocation.executable_identity.content);
  packer.u64(invocation.executable_identity.size_bytes);
  packer.u64(invocation.arguments.size());
  for (const std::string& argument : invocation.arguments) packer.str(argument);
  packer.u64(process.environment.size());
  for (const EnvironmentVariable& variable : process.environment) {
    packer.str(variable.name);
    packer.str(variable.value);
  }
  packer.path(process.working_directory);
  packer.path(invocation.working_directory);
  packer.u8(static_cast<std::uint8_t>(invocation.style));
  packer.str(invocation.adapter_name);
  packer.b(invocation.produced_executable);
  packer.u64(invocation.expected_outputs.size());
  for (const OutputBinding& binding : invocation.expected_outputs) {
    packer.str(binding.logical_name);
    packer.path(binding.path);
    packer.u8(static_cast<std::uint8_t>(binding.expected_format));
    packer.b(binding.required);
    packer.b(binding.allow_empty);
  }
  packer.u32(process.timeout_millis);
  packer.u64(process.max_capture_bytes);
  packer.str(workspace_root);
  packer.str(phase_label);
  FieldWriter writer;
  writer.blob(1, packer.take());
  return writer.take();
}

Result<InvocationSpec> decode_invocation_order(std::string_view payload, ProcessSpec& process,
                                               std::string& workspace_root,
                                               std::string& phase_label) {
  const Result<std::string> blob = field_blob(payload, 1);
  if (!blob) return blob.status();
  Unpacker unpacker(blob.value());
  InvocationSpec invocation;
  invocation.id = InvocationId::from_value(unpacker.u64());
  invocation.generation = InvocationGeneration::from_value(unpacker.u64());
  invocation.session.id = CompilerSessionId::from_value(unpacker.u64());
  invocation.session.generation = CompilerSessionGeneration::from_value(unpacker.u64());
  invocation.phase.id = CompilerPhaseId::from_value(unpacker.u64());
  invocation.phase.generation = CompilerPhaseGeneration::from_value(unpacker.u64());
  invocation.attempt_generation = AttemptGeneration::from_value(unpacker.u64());
  invocation.component = CompilerComponentId::from_value(unpacker.u64());
  invocation.component_generation = CompilerComponentGeneration::from_value(unpacker.u64());
  invocation.toolchain.id = ToolchainId::from_value(unpacker.u64());
  invocation.toolchain.generation = ToolchainGeneration::from_value(unpacker.u64());
  invocation.target.id = TargetId::from_value(unpacker.u64());
  invocation.target.generation = TargetGeneration::from_value(unpacker.u64());
  invocation.environment.id = EnvironmentId::from_value(unpacker.u64());
  invocation.environment.generation = EnvironmentGeneration::from_value(unpacker.u64());
  invocation.policy.id = PolicyId::from_value(unpacker.u64());
  invocation.policy.generation = PolicyGeneration::from_value(unpacker.u64());
  invocation.executable = unpacker.path();
  const Digest executable_digest = unpacker.digest();
  const std::uint64_t executable_size = unpacker.u64();
  const std::uint64_t argument_count = unpacker.u64();
  if (argument_count > kMaxArguments) {
    return Status(StatusCode::capacity_exceeded, "invocation declares too many arguments");
  }
  for (std::uint64_t i = 0; i < argument_count && unpacker.good(); ++i) {
    invocation.arguments.push_back(unpacker.str(kMaxArgumentBytes));
  }
  const std::uint64_t variable_count = unpacker.u64();
  if (variable_count > kMaxCollection) {
    return Status(StatusCode::capacity_exceeded, "invocation declares too many variables");
  }
  for (std::uint64_t i = 0; i < variable_count && unpacker.good(); ++i) {
    EnvironmentVariable variable;
    variable.name = unpacker.str(4096);
    variable.value = unpacker.str(1u << 16);
    process.environment.push_back(std::move(variable));
  }
  process.working_directory = unpacker.path();
  invocation.working_directory = unpacker.path();
  invocation.style = static_cast<ArgumentStyle>(unpacker.u8());
  invocation.adapter_name = unpacker.str(256);
  invocation.produced_executable = unpacker.b();
  const std::uint64_t output_count = unpacker.u64();
  if (output_count > 256) {
    return Status(StatusCode::capacity_exceeded, "invocation declares too many outputs");
  }
  for (std::uint64_t i = 0; i < output_count && unpacker.good(); ++i) {
    OutputBinding binding;
    binding.logical_name = unpacker.str(256);
    binding.path = unpacker.path();
    binding.expected_format = static_cast<ObjectFormat>(unpacker.u8());
    binding.required = unpacker.b();
    binding.allow_empty = unpacker.b();
    invocation.expected_outputs.push_back(std::move(binding));
  }
  process.timeout_millis = unpacker.u32();
  process.max_capture_bytes = static_cast<std::size_t>(unpacker.u64());
  workspace_root = unpacker.str(32768);
  phase_label = unpacker.str(256);
  if (!unpacker.good()) return Status(StatusCode::protocol_malformed, "invocation order is malformed");
  if (!unpacker.exhausted()) {
    return Status(StatusCode::protocol_malformed, "invocation order has trailing bytes");
  }
  invocation.executable_identity.canonical_path = invocation.executable;
  invocation.executable_identity.content = executable_digest;
  invocation.executable_identity.size_bytes = executable_size;
  invocation.executable_identity.content_hashed = !executable_digest.zero();
  process.executable = invocation.executable;
  process.arguments = invocation.arguments;
  return invocation;
}

std::string encode_execution_report(const ExecutionReport& report) {
  Packer packer;
  packer.b(report.executed);
  packer.u64(report.process.id.value());
  packer.u64(report.process.generation.value());
  packer.u64(report.process.invocation.id.value());
  packer.u64(report.process.invocation.generation.value());
  packer.u32(report.process.os_process_id);
  packer.u8(static_cast<std::uint8_t>(report.process.termination));
  packer.u32(report.process.exit_code);
  packer.str(report.process.capture.standard_output);
  packer.str(report.process.capture.standard_error);
  packer.u64(report.process.capture.standard_output_bytes);
  packer.u64(report.process.capture.standard_error_bytes);
  packer.u64(report.process.capture.dropped_standard_output_bytes);
  packer.u64(report.process.capture.dropped_standard_error_bytes);
  packer.b(report.process.capture.truncated);
  packer.u64(report.process.started_at_nanos);
  packer.u64(report.process.finished_at_nanos);
  packer.u16(static_cast<std::uint16_t>(report.status));
  packer.str(report.detail);
  packer.path(report.workspace_root);
  packer.digest(report.workspace_marker);
  packer.u64(report.outputs.size());
  for (const OutputDescriptor& output : report.outputs) {
    packer.str(output.logical_name);
    packer.path(output.path);
    packer.u8(static_cast<std::uint8_t>(output.format));
    packer.digest(output.content);
    packer.u64(output.size_bytes);
    packer.b(output.exists);
  }
  packer.u64(report.diagnostics.size());
  for (const Diagnostic& diagnostic : report.diagnostics) {
    packer.u8(static_cast<std::uint8_t>(diagnostic.severity));
    packer.str(diagnostic.code);
    packer.str(diagnostic.message);
    packer.str(diagnostic.file);
    packer.u32(diagnostic.line);
    packer.u32(diagnostic.column);
    packer.str(diagnostic.origin);
    packer.str(diagnostic.raw);
  }
  FieldWriter writer;
  writer.blob(1, packer.take());
  return writer.take();
}

Result<ExecutionReport> decode_execution_report(std::string_view payload) {
  const Result<std::string> blob = field_blob(payload, 1);
  if (!blob) return blob.status();
  Unpacker unpacker(blob.value());
  ExecutionReport report;
  report.executed = unpacker.b();
  report.process.id = ProcessId::from_value(unpacker.u64());
  report.process.generation = ProcessGeneration::from_value(unpacker.u64());
  report.process.invocation.id = InvocationId::from_value(unpacker.u64());
  report.process.invocation.generation = InvocationGeneration::from_value(unpacker.u64());
  report.process.os_process_id = unpacker.u32();
  report.process.termination = static_cast<ProcessTermination>(unpacker.u8());
  report.process.exit_code = unpacker.u32();
  report.process.capture.standard_output = unpacker.str(1u << 22);
  report.process.capture.standard_error = unpacker.str(1u << 22);
  report.process.capture.standard_output_bytes = unpacker.u64();
  report.process.capture.standard_error_bytes = unpacker.u64();
  report.process.capture.dropped_standard_output_bytes = unpacker.u64();
  report.process.capture.dropped_standard_error_bytes = unpacker.u64();
  report.process.capture.truncated = unpacker.b();
  report.process.started_at_nanos = unpacker.u64();
  report.process.finished_at_nanos = unpacker.u64();
  report.status = static_cast<StatusCode>(unpacker.u16());
  report.detail = unpacker.str(1u << 16);
  report.workspace_root = unpacker.path();
  report.workspace_marker = unpacker.digest();
  const std::uint64_t output_count = unpacker.u64();
  if (output_count > 256) {
    return Status(StatusCode::capacity_exceeded, "execution report declares too many outputs");
  }
  for (std::uint64_t i = 0; i < output_count && unpacker.good(); ++i) {
    OutputDescriptor output;
    output.logical_name = unpacker.str(256);
    output.path = unpacker.path();
    output.format = static_cast<ObjectFormat>(unpacker.u8());
    output.content = unpacker.digest();
    output.size_bytes = unpacker.u64();
    output.exists = unpacker.b();
    report.outputs.push_back(std::move(output));
  }
  const std::uint64_t diagnostic_count = unpacker.u64();
  if (diagnostic_count > DiagnosticSet::kMaxEntries) {
    return Status(StatusCode::capacity_exceeded,
                  "execution report declares too many diagnostics");
  }
  for (std::uint64_t i = 0; i < diagnostic_count && unpacker.good(); ++i) {
    Diagnostic diagnostic;
    diagnostic.severity = static_cast<DiagnosticSeverity>(unpacker.u8());
    diagnostic.code = unpacker.str(256);
    diagnostic.message = unpacker.str(DiagnosticSet::kMaxMessageBytes);
    diagnostic.file = unpacker.str(4096);
    diagnostic.line = unpacker.u32();
    diagnostic.column = unpacker.u32();
    diagnostic.origin = unpacker.str(256);
    diagnostic.raw = unpacker.str(DiagnosticSet::kMaxMessageBytes);
    report.diagnostics.push_back(std::move(diagnostic));
  }
  if (!unpacker.good()) return Status(StatusCode::protocol_malformed, "execution report is malformed");
  if (!unpacker.exhausted()) {
    return Status(StatusCode::protocol_malformed, "execution report has trailing bytes");
  }
  return report;
}

std::string encode_phase_reference(CompilerSessionId session, CompilerPhaseId phase,
                                   CompilerPhaseGeneration phase_generation,
                                   Ref<InvocationId> invocation) {
  FieldWriter writer;
  writer.u64(1, session.value());
  writer.u64(2, phase.value());
  writer.u64(3, phase_generation.value());
  writer.u64(4, invocation.id.value());
  writer.u64(5, invocation.generation.value());
  return writer.take();
}

Result<std::tuple<CompilerSessionId, CompilerPhaseId, CompilerPhaseGeneration, Ref<InvocationId>>>
decode_phase_reference(std::string_view payload) {
  FieldReader reader(payload);
  std::uint64_t values[5] = {0, 0, 0, 0, 0};
  for (;;) {
    Result<bool> next = reader.next();
    if (!next) return next.status();
    if (!next.value()) break;
    if (reader.id() < 1 || reader.id() > 5) continue;
    Result<std::uint64_t> value = reader.as_u64();
    if (!value) return value.status();
    values[reader.id() - 1] = value.value();
  }
  const VoidResult finished = reader.finish();
  if (!finished) return finished.status();
  Ref<InvocationId> invocation;
  invocation.id = InvocationId::from_value(values[3]);
  invocation.generation = InvocationGeneration::from_value(values[4]);
  return std::make_tuple(CompilerSessionId::from_value(values[0]),
                         CompilerPhaseId::from_value(values[1]),
                         CompilerPhaseGeneration::from_value(values[2]), invocation);
}

std::string encode_phase_report(const PhaseRunReport& report) {
  Packer packer;
  packer.u64(report.phase.id.value());
  packer.u64(report.phase.generation.value());
  packer.u8(static_cast<std::uint8_t>(report.state));
  packer.u16(static_cast<std::uint16_t>(report.status));
  packer.u8(static_cast<std::uint8_t>(report.failure));
  packer.u64(report.diagnostics.id.value());
  packer.u64(report.diagnostics.generation.value());
  packer.u64(report.invocation.id.value());
  packer.u64(report.invocation.generation.value());
  packer.u64(report.process.value());
  packer.u64(report.compiler_nanos);
  packer.u64(report.governance_nanos);
  packer.u8(static_cast<std::uint8_t>(report.authority));
  packer.str(report.detail);
  packer.u64(report.outputs.size());
  for (const Ref<IntermediateArtifactId>& output : report.outputs) {
    packer.u64(output.id.value());
    packer.u64(output.generation.value());
  }
  FieldWriter writer;
  writer.blob(1, packer.take());
  return writer.take();
}

Result<PhaseRunReport> decode_phase_report(std::string_view payload) {
  const Result<std::string> blob = field_blob(payload, 1);
  if (!blob) return blob.status();
  Unpacker unpacker(blob.value());
  PhaseRunReport report;
  report.phase.id = CompilerPhaseId::from_value(unpacker.u64());
  report.phase.generation = CompilerPhaseGeneration::from_value(unpacker.u64());
  report.state = static_cast<PhaseState>(unpacker.u8());
  report.status = static_cast<StatusCode>(unpacker.u16());
  report.failure = static_cast<FailureClass>(unpacker.u8());
  report.diagnostics.id = DiagnosticSetId::from_value(unpacker.u64());
  report.diagnostics.generation = DiagnosticGeneration::from_value(unpacker.u64());
  report.invocation.id = InvocationId::from_value(unpacker.u64());
  report.invocation.generation = InvocationGeneration::from_value(unpacker.u64());
  report.process = ProcessId::from_value(unpacker.u64());
  report.compiler_nanos = unpacker.u64();
  report.governance_nanos = unpacker.u64();
  report.authority = static_cast<AuthorityVerdict>(unpacker.u8());
  report.detail = unpacker.str(1u << 16);
  const std::uint64_t output_count = unpacker.u64();
  if (output_count > 256) {
    return Status(StatusCode::capacity_exceeded, "phase report declares too many outputs");
  }
  for (std::uint64_t i = 0; i < output_count && unpacker.good(); ++i) {
    Ref<IntermediateArtifactId> output;
    output.id = IntermediateArtifactId::from_value(unpacker.u64());
    output.generation = IntermediateArtifactGeneration::from_value(unpacker.u64());
    report.outputs.push_back(output);
  }
  if (!unpacker.good()) return Status(StatusCode::protocol_malformed, "phase report is malformed");
  if (!unpacker.exhausted()) {
    return Status(StatusCode::protocol_malformed, "phase report has trailing bytes");
  }
  return report;
}

std::string encode_audit_report(const AuditReport& report) {
  Packer packer;
  packer.u64(report.checks_run);
  packer.u64(report.sessions_audited);
  packer.u64(report.phases_audited);
  packer.u64(report.artifacts_audited);
  packer.u64(report.runtime_epoch);
  packer.u64(report.violations.size());
  for (const AuditViolation& violation : report.violations) {
    packer.u8(static_cast<std::uint8_t>(violation.code));
    packer.str(violation.subject);
    packer.str(violation.detail);
  }
  FieldWriter writer;
  writer.blob(1, packer.take());
  return writer.take();
}

Result<AuditReport> decode_audit_report(std::string_view payload) {
  const Result<std::string> blob = field_blob(payload, 1);
  if (!blob) return blob.status();
  Unpacker unpacker(blob.value());
  AuditReport report;
  report.checks_run = static_cast<std::size_t>(unpacker.u64());
  report.sessions_audited = static_cast<std::size_t>(unpacker.u64());
  report.phases_audited = static_cast<std::size_t>(unpacker.u64());
  report.artifacts_audited = static_cast<std::size_t>(unpacker.u64());
  report.runtime_epoch = unpacker.u64();
  const std::uint64_t violation_count = unpacker.u64();
  if (violation_count > kMaxCollection) {
    return Status(StatusCode::capacity_exceeded, "audit report declares too many violations");
  }
  for (std::uint64_t i = 0; i < violation_count && unpacker.good(); ++i) {
    AuditViolation violation;
    violation.code = static_cast<ViolationCode>(unpacker.u8());
    violation.subject = unpacker.str(4096);
    violation.detail = unpacker.str(1u << 16);
    report.violations.push_back(std::move(violation));
  }
  if (!unpacker.good()) return Status(StatusCode::protocol_malformed, "audit report is malformed");
  if (!unpacker.exhausted()) {
    return Status(StatusCode::protocol_malformed, "audit report has trailing bytes");
  }
  return report;
}

}  // namespace crf
