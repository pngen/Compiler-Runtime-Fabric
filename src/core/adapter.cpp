#include "crf/adapter.hpp"
#include "crf/canonical.hpp"

#include <algorithm>

namespace crf {

bool has_capability(std::uint32_t flags, AdapterCapability value) noexcept {
  return (flags & static_cast<std::uint32_t>(value)) != 0;
}

std::string describe_capabilities(std::uint32_t flags) {
  struct Entry {
    AdapterCapability capability;
    const char* name;
  };
  static constexpr Entry kEntries[] = {
      {AdapterCapability::preprocess, "preprocess"},
      {AdapterCapability::compile, "compile"},
      {AdapterCapability::assemble, "assemble"},
      {AdapterCapability::link, "link"},
      {AdapterCapability::device_compile, "device-compile"},
      {AdapterCapability::device_link, "device-link"},
      {AdapterCapability::static_library, "static-library"},
      {AdapterCapability::structured_diagnostics, "structured-diagnostics"},
      {AdapterCapability::object_validation, "object-validation"},
      {AdapterCapability::executable_validation, "executable-validation"},
      {AdapterCapability::smoke_test, "smoke-test"},
      {AdapterCapability::reproducible, "reproducible"},
      {AdapterCapability::parallel_translation_units, "parallel-translation-units"},
  };
  std::string out;
  for (const Entry& entry : kEntries) {
    if (!has_capability(flags, entry.capability)) continue;
    if (!out.empty()) out.push_back(',');
    out.append(entry.name);
  }
  if (out.empty()) out = "none";
  return out;
}

CompilerAdapter::~CompilerAdapter() = default;

Result<ToolchainIdentity> CompilerAdapter::reprobe_toolchain(const ToolchainIdentity& previous,
                                                            const ToolchainProbeRequest& request) const {
  Result<ToolchainIdentity> observed = probe_toolchain(request);
  if (!observed) return observed.status();
  ToolchainIdentity identity = observed.value();
  identity.id = previous.id;
  identity.generation = previous.generation;
  return identity;
}

Result<TargetSpec> CompilerAdapter::resolve_target(const ToolchainIdentity& toolchain,
                                                     const TargetSpec& requested) const {
  TargetSpec target = requested;
  if (target.architecture == Architecture::unknown) {
    if (toolchain.target_support.empty()) {
      return Status(StatusCode::target_unsupported,
                    "the toolchain declares no supported architecture");
    }
    target.architecture = toolchain.target_support.front();
  }
  if (!toolchain.target_support.empty() && !toolchain.supports(target.architecture)) {
    return Status(StatusCode::target_unsupported,
                  "the toolchain does not claim support for the requested architecture");
  }
  if (target.os == OperatingSystem::unknown) target.os = OperatingSystem::windows;
  if (target.pointer_width_bits == 0) target.pointer_width_bits = pointer_bits(target.architecture);
  if (target.abi.empty()) target.abi = "msvc";
  if (target.triple.empty()) {
    switch (target.architecture) {
      case Architecture::x64: target.triple = "x86_64-pc-windows-msvc"; break;
      case Architecture::x86: target.triple = "i686-pc-windows-msvc"; break;
      case Architecture::arm64: target.triple = "aarch64-pc-windows-msvc"; break;
      case Architecture::arm: target.triple = "armv7-pc-windows-msvc"; break;
      default: break;
    }
  }
  if (const VoidResult valid = target.validate(); !valid) return valid.status();
  return target;
}

Result<std::vector<Diagnostic>> CompilerAdapter::parse_diagnostics(
    const ProcessOutcome& outcome, const PhaseExecutionRequest& request) const {
  (void)request;
  std::vector<Diagnostic> diagnostics = normalize_generic_output(outcome.capture.standard_output, "stdout");
  std::vector<Diagnostic> errors = normalize_generic_output(outcome.capture.standard_error, "stderr");
  diagnostics.insert(diagnostics.end(), errors.begin(), errors.end());
  return diagnostics;
}

Result<SmokeTestEvidence> CompilerAdapter::run_smoke_test(const FinalCandidate& candidate,
                                                          const PhaseExecutionRequest& request) const {
  (void)candidate;
  (void)request;
  SmokeTestEvidence evidence;
  evidence.executed = false;
  evidence.passed = false;
  evidence.refusal = StatusCode::unsupported;
  evidence.detail = "this adapter does not implement an execution smoke test";
  return evidence;
}

bool CompilerAdapter::is_deterministic_phase(PhaseKind kind) const noexcept {
  switch (kind) {
    case PhaseKind::input_validate:
    case PhaseKind::preprocess:
    case PhaseKind::frontend:
    case PhaseKind::parse:
    case PhaseKind::semantic_analysis:
    case PhaseKind::ir_generate:
    case PhaseKind::codegen:
    case PhaseKind::assemble:
    case PhaseKind::device_compile:
    case PhaseKind::link:
    case PhaseKind::device_link:
      return true;
    default:
      // IR_OPTIMIZE, POSTPROCESS, VALIDATE and FINALIZE are not assumed
      // deterministic: an adapter that knows otherwise overrides this.
      return false;
  }
}

Result<EnvironmentSpec> CompilerAdapter::compose_environment(const ToolchainIdentity& toolchain,
                                                             const TargetSpec& target,
                                                             const EnvironmentSpec& caller_overrides) const {
  (void)target;
  EnvironmentSpec spec = caller_overrides;
  for (const EnvironmentVariable& variable : toolchain.environment_contract) {
    spec.set_variable(variable.name, variable.value);
  }
  if (const VoidResult valid = spec.canonicalize(); !valid) return valid.status();
  return spec;
}

const EnvironmentVariable* PhaseExecutionRequest::option(std::string_view name) const noexcept {
  for (const EnvironmentVariable& entry : adapter_options) {
    if (equals_ascii_ci(entry.name, name)) return &entry;
  }
  return nullptr;
}

std::string PhaseExecutionRequest::option_or(std::string_view name, std::string fallback) const {
  const EnvironmentVariable* found = option(name);
  return found != nullptr ? found->value : std::move(fallback);
}

void AdapterRegistry::add(std::shared_ptr<const CompilerAdapter> adapter) {
  if (adapter == nullptr) return;
  adapters_.push_back(std::move(adapter));
}

std::shared_ptr<const CompilerAdapter> AdapterRegistry::find(ToolchainFamily family) const noexcept {
  for (const std::shared_ptr<const CompilerAdapter>& adapter : adapters_) {
    if (adapter->describe().family == family) return adapter;
  }
  return nullptr;
}

std::shared_ptr<const CompilerAdapter> AdapterRegistry::find_by_name(std::string_view name) const noexcept {
  for (const std::shared_ptr<const CompilerAdapter>& adapter : adapters_) {
    if (equals_ascii_ci(adapter->describe().name, name)) return adapter;
  }
  return nullptr;
}

std::vector<AdapterDescriptor> AdapterRegistry::list() const {
  std::vector<AdapterDescriptor> out;
  out.reserve(adapters_.size());
  for (const std::shared_ptr<const CompilerAdapter>& adapter : adapters_) {
    out.push_back(adapter->describe());
  }
  std::sort(out.begin(), out.end(),
            [](const AdapterDescriptor& a, const AdapterDescriptor& b) { return a.name < b.name; });
  return out;
}

std::size_t AdapterRegistry::size() const noexcept { return adapters_.size(); }

}  // namespace crf
