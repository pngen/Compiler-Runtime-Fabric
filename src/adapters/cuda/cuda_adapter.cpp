#include "crf/adapter.hpp"
#include "crf/canonical.hpp"
#include "crf/version.hpp"

#include "common/msvc_env.hpp"
#include "common/pe_coff.hpp"

#include <algorithm>
#include <cstdlib>
#include <memory>
#include <system_error>

namespace crf {
namespace {

using adapters::MsvcToolset;
using adapters::PeImageInfo;

constexpr const char* kAdapterName = "nvcc";
constexpr const char* kDeviceArchOption = "cuda.device_arch";
constexpr const char* kExpectedStdoutOption = "cuda.expected_stdout";

struct CudaInstallation {
  std::filesystem::path root;
  std::string version;
  std::filesystem::path nvcc;
  std::filesystem::path ptxas;
  std::filesystem::path nvlink;
  std::filesystem::path cudart;
};

CRF_NODISCARD std::vector<std::filesystem::path> cuda_roots() {
  std::vector<std::filesystem::path> roots;
  std::error_code ec;
  const std::filesystem::path base("C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA");
  if (std::filesystem::is_directory(base, ec) && !ec) {
    for (const std::filesystem::directory_entry& entry :
         std::filesystem::directory_iterator(base, ec)) {
      if (ec) break;
      if (entry.is_directory(ec) && !ec) roots.push_back(entry.path());
    }
  }
  std::sort(roots.begin(), roots.end());
  return roots;
}

/// Compare two dotted version strings numerically; "13.1" sorts above "12.9".
CRF_NODISCARD bool version_less(const std::string& a, const std::string& b) {
  const std::vector<std::string> left = split_ascii(a, '.');
  const std::vector<std::string> right = split_ascii(b, '.');
  const std::size_t count = std::max(left.size(), right.size());
  for (std::size_t i = 0; i < count; ++i) {
    const unsigned long lv =
        i < left.size() ? std::strtoul(left[i].c_str(), nullptr, 10) : 0UL;
    const unsigned long rv =
        i < right.size() ? std::strtoul(right[i].c_str(), nullptr, 10) : 0UL;
    if (lv != rv) return lv < rv;
  }
  return false;
}

CRF_NODISCARD bool has_file(const std::filesystem::path& path) {
  std::error_code ec;
  return std::filesystem::is_regular_file(path, ec) && !ec;
}

CRF_NODISCARD Result<CudaInstallation> describe_installation(const std::filesystem::path& root) {
  CudaInstallation installation;
  installation.root = root;
  installation.version = root.filename().string();
  if (!installation.version.empty() && installation.version.front() == 'v') {
    installation.version.erase(0, 1);
  }
  installation.nvcc = root / "bin" / "nvcc.exe";
  installation.nvlink = root / "bin" / "nvlink.exe";
  installation.ptxas = root / "bin" / "ptxas.exe";
  if (!has_file(installation.ptxas)) {
    const std::filesystem::path candidate = root / "nvvm" / "bin" / "ptxas.exe";
    if (has_file(candidate)) installation.ptxas = candidate;
  }
  installation.cudart = root / "lib" / "x64" / "cudart.lib";
  if (!has_file(installation.nvcc)) {
    return Status(StatusCode::toolchain_not_found,
                  "nvcc.exe is missing from the CUDA installation at " + root.string());
  }
  return installation;
}

class CudaAdapter final : public CompilerAdapter {
 public:
  AdapterDescriptor describe() const override {
    AdapterDescriptor descriptor;
    descriptor.name = kAdapterName;
    descriptor.display_name = "NVIDIA CUDA Compiler (nvcc)";
    descriptor.version = version_string;
    descriptor.family = ToolchainFamily::nvcc;
    descriptor.capabilities = static_cast<std::uint32_t>(AdapterCapability::compile) |
                              static_cast<std::uint32_t>(AdapterCapability::device_compile) |
                              static_cast<std::uint32_t>(AdapterCapability::device_link) |
                              static_cast<std::uint32_t>(AdapterCapability::link) |
                              static_cast<std::uint32_t>(AdapterCapability::structured_diagnostics) |
                              static_cast<std::uint32_t>(AdapterCapability::object_validation) |
                              static_cast<std::uint32_t>(AdapterCapability::executable_validation) |
                              static_cast<std::uint32_t>(AdapterCapability::smoke_test) |
                              static_cast<std::uint32_t>(AdapterCapability::reproducible);
    descriptor.implemented_phases = {PhaseKind::input_validate, PhaseKind::device_compile,
                                     PhaseKind::link, PhaseKind::finalize};
    descriptor.produced_formats = {ObjectFormat::preprocessed_source, ObjectFormat::coff_object,
                                   ObjectFormat::coff_image};
    descriptor.evidence_class = EvidenceClass::real;
    return descriptor;
  }

  Result<ToolchainIdentity> probe_toolchain(const ToolchainProbeRequest& request) const override {
    const std::vector<std::filesystem::path> roots = cuda_roots();
    if (roots.empty()) {
      return Status(StatusCode::toolchain_not_found, "no CUDA installation was found");
    }
    std::vector<CudaInstallation> installations;
    for (const std::filesystem::path& root : roots) {
      const Result<CudaInstallation> described = describe_installation(root);
      if (described) installations.push_back(described.value());
    }
    if (installations.empty()) {
      return Status(StatusCode::toolchain_not_found, "no usable CUDA installation was found");
    }
    std::sort(installations.begin(), installations.end(),
              [](const CudaInstallation& a, const CudaInstallation& b) {
                return version_less(a.version, b.version);
              });

    const CudaInstallation* selected = nullptr;
    if (!request.explicit_root.empty()) {
      for (const CudaInstallation& installation : installations) {
        if (canonical_path_key(installation.root) == canonical_path_key(request.explicit_root) ||
            installation.version == request.explicit_root.string()) {
          selected = &installation;
          break;
        }
      }
      if (selected == nullptr) {
        return Status(StatusCode::toolchain_not_found,
                      "the requested CUDA installation was not found: " +
                          request.explicit_root.string());
      }
    } else if (!request.toolkit_preference.empty()) {
      for (const CudaInstallation& installation : installations) {
        if (installation.version == request.toolkit_preference) {
          selected = &installation;
          break;
        }
      }
      if (selected == nullptr) {
        return Status(StatusCode::toolchain_not_found,
                      "the requested CUDA toolkit version is not installed: " +
                          request.toolkit_preference);
      }
    } else {
      // Default selection is deterministic: the highest installed toolkit.
      selected = &installations.back();
    }

    const Result<MsvcToolset> host = adapters::discover_msvc_toolset();
    if (!host) {
      return Status(StatusCode::probe_failed,
                    "nvcc requires an MSVC host toolchain: " + host.status().message());
    }
    return build_identity(*selected, host.value(), request);
  }

  Result<ToolchainIdentity> reprobe_toolchain(const ToolchainIdentity& previous,
                                              const ToolchainProbeRequest& request) const override {
    ToolchainProbeRequest pinned = request;
    if (pinned.explicit_root.empty() && !previous.toolkit_root.empty()) {
      pinned.explicit_root = previous.toolkit_root;
    }
    // A re-probe must repeat the same probe inputs. When the caller does not
    // restate the device architecture, the one recorded on the previous
    // identity is reused; otherwise a re-probe would silently change the
    // identity it is supposed to be verifying.
    if (pinned.target.device_arch.empty()) {
      for (const EnvironmentVariable& attribute : previous.attributes) {
        if (equals_ascii_ci(attribute.name, "cuda.detected_device_arch") &&
            attribute.value != "sm_unknown") {
          pinned.target.device_arch = attribute.value;
          break;
        }
      }
    }
    Result<ToolchainIdentity> observed = probe_toolchain(pinned);
    if (!observed) return observed.status();
    ToolchainIdentity identity = observed.value();
    identity.id = previous.id;
    identity.generation = previous.generation;
    return identity;
  }

  Result<TargetSpec> resolve_target(const ToolchainIdentity& toolchain,
                                    const TargetSpec& requested) const override {
    TargetSpec target = requested;
    if (target.architecture == Architecture::unknown) target.architecture = Architecture::x64;
    if (target.architecture != Architecture::x64) {
      return Status(StatusCode::target_unsupported,
                    "the CUDA adapter targets x64 hosts for this release");
    }
    if (target.device_arch.empty()) {
      for (const EnvironmentVariable& attribute : toolchain.attributes) {
        if (equals_ascii_ci(attribute.name, "cuda.detected_device_arch")) {
          if (attribute.value != "sm_unknown") target.device_arch = attribute.value;
          break;
        }
      }
    }
    if (target.device_arch.empty()) {
      std::string reason;
      for (const EnvironmentVariable& attribute : toolchain.attributes) {
        if (equals_ascii_ci(attribute.name, "cuda.device-arch-probe")) reason = attribute.value;
      }
      return Status(StatusCode::target_unsupported,
                    "no CUDA device architecture could be determined (" + reason +
                        "); supply target.device_arch explicitly");
    }
    if (target.device_virtual_arch.empty()) {
      std::string virtual_arch = target.device_arch;
      const std::size_t underscore = virtual_arch.find('_');
      if (underscore != std::string::npos && virtual_arch.rfind("sm_", 0) == 0) {
        virtual_arch.replace(0, 3, "compute_");
      }
      target.device_virtual_arch = virtual_arch;
    }
    return CompilerAdapter::resolve_target(toolchain, target);
  }

  Result<PhasePlan> build_plan(const PhasePlanRequest& request) const override {
    if (request.toolchain == nullptr) {
      return Status(StatusCode::invalid_argument, "phase plan requires a probed toolchain");
    }
    if (request.translation_unit_count != 1) {
      return Status(StatusCode::unsupported,
                    "the CUDA adapter compiles exactly one device translation unit per session");
    }
    IdAllocator<CompilerPhaseId> ids;
    std::vector<PhaseNode> nodes;

    PhaseNode validate;
    validate.id = ids.next();
    validate.kind = PhaseKind::input_validate;
    validate.adapter_phase = "preprocess-device-source";
    validate.mandatory = true;
    validate.expected_outputs = {ObjectFormat::preprocessed_source};
    nodes.push_back(validate);

    PhaseNode compile;
    compile.id = ids.next();
    compile.kind = PhaseKind::device_compile;
    compile.adapter_phase = "device-compile";
    compile.depends_on = {validate.id};
    compile.mandatory = true;
    compile.expected_outputs = {ObjectFormat::coff_object};
    nodes.push_back(compile);

    PhaseNode link;
    link.id = ids.next();
    link.kind = PhaseKind::link;
    link.adapter_phase = "device-link";
    link.depends_on = {compile.id};
    link.mandatory = true;
    link.fan_in = true;
    link.required_inputs = 1;
    link.expected_outputs = {ObjectFormat::coff_image};
    nodes.push_back(link);

    if (request.want_smoke_test) {
      PhaseNode finalize;
      finalize.id = ids.next();
      finalize.kind = PhaseKind::finalize;
      finalize.adapter_phase = "execute-candidate";
      finalize.depends_on = {link.id};
      finalize.mandatory = true;
      nodes.push_back(finalize);
    }
    return PhasePlan::build(std::move(nodes));
  }

  Result<InvocationSpec> build_invocation(const PhaseExecutionRequest& request) const override {
    if (request.workspace == nullptr || request.toolchain == nullptr || request.target == nullptr) {
      return Status(StatusCode::integrity_unproven, "phase execution context is incomplete");
    }
    const std::string arch = request.target->spec.device_arch;
    if (arch.empty() || arch == "sm_unknown") {
      return Status(StatusCode::target_unsupported,
                    "the resolved target has no usable device architecture");
    }
    const ComponentIdentity* nvcc = request.toolchain->find_component(ComponentKind::device_compiler);
    if (nvcc == nullptr) {
      return Status(StatusCode::component_not_found, "the CUDA toolchain lacks nvcc.exe");
    }
    if (request.sources.size() != 1 || request.sources.front() == nullptr) {
      return Status(StatusCode::invalid_argument,
                    "the CUDA adapter requires exactly one device translation unit");
    }
    const SourceUnit& unit = *request.sources.front();
    InvocationSpec spec;
    spec.adapter_name = kAdapterName;
    spec.style = ArgumentStyle::msvc;
    spec.working_directory = request.workspace->root;
    spec.executable = nvcc->file.canonical_path;

    switch (request.kind) {
      case PhaseKind::input_validate: {
        const Result<std::filesystem::path> preprocessed =
            request.workspace->resolve("outputs/preprocessed-device.cpp");
        if (!preprocessed) return preprocessed.status();
        spec.arguments = {"-std=c++20", "-arch=" + arch, "-E", unit.path.string(), "-o",
                          preprocessed.value().string()};
        OutputBinding output;
        output.logical_name = "preprocessed";
        output.path = preprocessed.value();
        output.expected_format = ObjectFormat::preprocessed_source;
        output.required = true;
        spec.expected_outputs.push_back(std::move(output));
        InputBinding binding;
        binding.source = unit.id;
        binding.generation = unit.generation;
        binding.path = unit.path;
        binding.content = unit.content;
        spec.inputs.push_back(std::move(binding));
        return spec;
      }
      case PhaseKind::device_compile: {
        const Result<std::filesystem::path> object = request.workspace->resolve("outputs/device.obj");
        if (!object) return object.status();
        spec.arguments = {"-std=c++20", "-arch=" + arch, "-c", unit.path.string(), "-o",
                          object.value().string()};
        InputBinding binding;
        binding.source = unit.id;
        binding.generation = unit.generation;
        binding.path = unit.path;
        binding.content = unit.content;
        spec.inputs.push_back(std::move(binding));
        OutputBinding output;
        output.logical_name = "device-object";
        output.path = object.value();
        output.expected_format = ObjectFormat::coff_object;
        output.required = true;
        spec.expected_outputs.push_back(std::move(output));
        return spec;
      }
      case PhaseKind::link: {
        const IntermediateArtifact* object = nullptr;
        for (const Ref<IntermediateArtifactId>& reference : request.resolved_inputs) {
          const IntermediateArtifact* artifact =
              request.artifacts != nullptr ? request.artifacts->find(reference.id) : nullptr;
          if (artifact == nullptr) continue;
          if (artifact->format == ObjectFormat::coff_object) {
            object = artifact;
            break;
          }
        }
        if (object == nullptr) {
          return Status(StatusCode::fan_in_incomplete,
                        "the device link phase received no device object");
        }
        std::string name = request.final_artifact_name.empty() ? std::string("cuda-candidate.exe")
                                                               : request.final_artifact_name;
        const Result<std::filesystem::path> image = request.workspace->resolve("outputs/" + name);
        if (!image) return image.status();
        spec.arguments = {"-std=c++20", "-arch=" + arch, object->path.string(), "-o",
                          image.value().string()};
        InputBinding binding;
        binding.source = object->source.id;
        binding.generation = object->source.generation;
        binding.path = object->path;
        binding.content = object->content;
        spec.inputs.push_back(std::move(binding));
        OutputBinding output;
        output.logical_name = "image";
        output.path = image.value();
        output.expected_format = ObjectFormat::coff_image;
        output.required = true;
        spec.expected_outputs.push_back(std::move(output));
        return spec;
      }
      case PhaseKind::finalize: {
        const IntermediateArtifact* image = nullptr;
        for (const Ref<IntermediateArtifactId>& reference : request.resolved_inputs) {
          const IntermediateArtifact* artifact =
              request.artifacts != nullptr ? request.artifacts->find(reference.id) : nullptr;
          if (artifact == nullptr) continue;
          if (artifact->format == ObjectFormat::coff_image) {
            image = artifact;
            break;
          }
        }
        if (image == nullptr) {
          return Status(StatusCode::fan_in_incomplete,
                        "the finalize phase found no linked CUDA image among its inputs");
        }
        spec.executable = image->path;
        spec.produced_executable = true;
        return spec;
      }
      default:
        break;
    }
    return Status(StatusCode::unsupported,
                  std::string("the CUDA adapter does not implement phase ") +
                      std::string(to_string(request.kind)));
  }

  Result<std::vector<Diagnostic>> parse_diagnostics(
      const ProcessOutcome& outcome, const PhaseExecutionRequest& request) const override {
    (void)request;
    std::vector<Diagnostic> diagnostics = normalize_nvcc_output(outcome.capture.standard_output, "nvcc");
    const std::vector<Diagnostic> errors = normalize_nvcc_output(outcome.capture.standard_error, "nvcc");
    diagnostics.insert(diagnostics.end(), errors.begin(), errors.end());
    return diagnostics;
  }

  Result<ValidationEvidence> validate_outputs(const OutputValidationRequest& request) const override {
    ValidationEvidence evidence;
    if (request.context == nullptr || request.artifacts == nullptr) {
      return Status(StatusCode::integrity_unproven, "validation context is incomplete");
    }
    const PhaseExecutionRequest& context = *request.context;
    switch (context.kind) {
      case PhaseKind::input_validate: {
        for (const Ref<IntermediateArtifactId>& reference : request.candidate_outputs) {
          const IntermediateArtifact* artifact = request.artifacts->find(reference.id);
          if (artifact == nullptr) continue;
          if (!std::filesystem::exists(artifact->path) || artifact->size_bytes == 0) {
            evidence.refusal = StatusCode::output_missing;
            evidence.state = ArtifactState::stale;
            evidence.detail = "the preprocessed device source is missing or empty";
            return evidence;
          }
          evidence.checks.push_back("preprocessed device source present");
        }
        evidence.accepted = true;
        evidence.state = ArtifactState::valid;
        evidence.format = ObjectFormat::preprocessed_source;
        evidence.detail = "device source preprocessed by nvcc";
        return evidence;
      }
      case PhaseKind::device_compile: {
        const IntermediateArtifact* object = nullptr;
        for (const Ref<IntermediateArtifactId>& reference : request.candidate_outputs) {
          const IntermediateArtifact* artifact = request.artifacts->find(reference.id);
          if (artifact == nullptr) continue;
          if (artifact->format == ObjectFormat::coff_object) {
            object = artifact;
            break;
          }
        }
        if (object == nullptr) {
          evidence.refusal = StatusCode::output_missing;
          evidence.state = ArtifactState::stale;
          evidence.detail = "the device compile phase produced no object";
          return evidence;
        }
        const Result<adapters::CoffObjectInfo> parsed = adapters::inspect_coff_object(object->path);
        if (!parsed) {
          evidence.refusal = parsed.code();
          evidence.state = ArtifactState::corrupt;
          evidence.detail = parsed.status().message();
          return evidence;
        }
        if (parsed.value().machine != coff_machine_for(Architecture::x64)) {
          evidence.refusal = StatusCode::output_wrong_target;
          evidence.state = ArtifactState::incompatible;
          evidence.detail = "device object machine does not match the x64 host target";
          return evidence;
        }
        evidence.checks.push_back("device object is a COFF object");
        if (!parsed.value().has_device_code) {
          evidence.refusal = StatusCode::output_unexpected_format;
          evidence.state = ArtifactState::incompatible;
          evidence.detail =
              "the object embeds no device code section, so no device artifact was produced";
          return evidence;
        }
        evidence.checks.push_back("device code section present (nv_fatbin)");
        evidence.format = ObjectFormat::coff_object;
        evidence.accepted = true;
        evidence.state = ArtifactState::valid;
        evidence.detail = parsed.value().detail;
        return evidence;
      }
      case PhaseKind::link: {
        const IntermediateArtifact* image = nullptr;
        for (const Ref<IntermediateArtifactId>& reference : request.candidate_outputs) {
          const IntermediateArtifact* artifact = request.artifacts->find(reference.id);
          if (artifact == nullptr) continue;
          if (artifact->format == ObjectFormat::coff_image) {
            image = artifact;
            break;
          }
        }
        if (image == nullptr) {
          evidence.refusal = StatusCode::output_missing;
          evidence.state = ArtifactState::stale;
          evidence.detail = "the device link phase produced no image";
          return evidence;
        }
        const Result<PeImageInfo> parsed = adapters::inspect_pe_image(image->path);
        if (!parsed) {
          evidence.refusal = parsed.code();
          evidence.state = ArtifactState::corrupt;
          evidence.detail = parsed.status().message();
          return evidence;
        }
        if (!parsed.value().is_executable) {
          evidence.refusal = StatusCode::output_unexpected_format;
          evidence.state = ArtifactState::incompatible;
          evidence.detail = "the CUDA candidate is not an executable image";
          return evidence;
        }
        evidence.checks.push_back("cuda image is a PE executable");
        evidence.format = ObjectFormat::coff_image;
        evidence.accepted = true;
        evidence.state = ArtifactState::valid;
        evidence.detail = parsed.value().detail;
        return evidence;
      }
      case PhaseKind::finalize: {
        if (request.process == nullptr) {
          evidence.refusal = StatusCode::integrity_unproven;
          evidence.detail = "no process evidence is available for the CUDA smoke test";
          return evidence;
        }
        evidence.checks.push_back("cuda candidate executed");
        if (!request.process->exited_zero()) {
          evidence.refusal = StatusCode::smoke_test_failed;
          evidence.state = ArtifactState::corrupt;
          evidence.detail = "the CUDA candidate did not exit with code 0";
          return evidence;
        }
        const std::string expected = context.option_or(kExpectedStdoutOption, "");
        if (!expected.empty() &&
            request.process->capture.standard_output.find(expected) == std::string::npos) {
          evidence.refusal = StatusCode::smoke_test_failed;
          evidence.state = ArtifactState::corrupt;
          evidence.detail = "the CUDA candidate did not report the expected result marker";
          return evidence;
        }
        evidence.accepted = true;
        evidence.state = ArtifactState::valid;
        evidence.format = ObjectFormat::metadata;
        evidence.detail = "CUDA candidate executed and reported the expected result";
        return evidence;
      }
      default:
        break;
    }
    evidence.accepted = true;
    evidence.state = ArtifactState::valid;
    evidence.detail = "no output validation is defined for this phase";
    return evidence;
  }

  bool is_deterministic_phase(PhaseKind kind) const noexcept override {
    switch (kind) {
      case PhaseKind::input_validate:
      case PhaseKind::device_compile:
        return true;
      default:
        return false;
    }
  }

 private:
  CRF_NODISCARD static Result<ToolchainIdentity> build_identity(const CudaInstallation& installation,
                                                               const MsvcToolset& host,
                                                               const ToolchainProbeRequest& request) {
    ToolchainIdentity identity;
    identity.family = ToolchainFamily::nvcc;
    identity.display_name = "NVIDIA CUDA Toolkit " + installation.version;
    identity.toolkit_root = installation.root;
    identity.sdk_root = host.sdk_root;
    identity.target_support = {Architecture::x64};
    identity.object_formats = {ObjectFormat::coff_object, ObjectFormat::coff_image,
                               ObjectFormat::preprocessed_source};
    identity.evidence_class = EvidenceClass::real;
    identity.version = installation.version;

    const Result<std::string> nvcc_banner =
        adapters::probe_component_banner(installation.nvcc, {"--version"});
    const std::string nvcc_version =
        nvcc_banner ? adapters::extract_version(nvcc_banner.value(), "release") : std::string{};
    if (!nvcc_version.empty()) identity.version = nvcc_version;

    struct ComponentSpec {
      ComponentKind kind;
      const char* name;
      std::filesystem::path path;
      std::string version;
    };
    const std::vector<ComponentSpec> specs = {
        {ComponentKind::device_compiler, "nvcc", installation.nvcc, identity.version},
        {ComponentKind::device_assembler, "ptxas", installation.ptxas, {}},
        {ComponentKind::device_assembler, "nvlink", installation.nvlink, {}},
        {ComponentKind::host_cxx_compiler, "cl", host.cl, host.compiler_version},
        {ComponentKind::linker, "link", host.link, host.linker_version}};

    IdAllocator<CompilerComponentId> component_ids;
    Hasher hasher;
    for (const ComponentSpec& spec : specs) {
      if (spec.path.empty() || !has_file(spec.path)) continue;
      const Result<FileIdentity> file = probe_file_identity(spec.path, true);
      if (!file) {
        return Status(StatusCode::probe_failed,
                      "component could not be probed: " + spec.path.string());
      }
      ComponentIdentity component;
      component.id = component_ids.next();
      component.generation = CompilerComponentGeneration::initial();
      component.kind = spec.kind;
      component.name = spec.name;
      component.version = spec.version;
      component.file = file.value();
      component.target_support = {Architecture::x64};
      component.evidence_class = EvidenceClass::real;
      if (spec.kind == ComponentKind::device_compiler) {
        component.command_capabilities = {"-arch", "-c", "-E", "-o", "-std=c++20"};
        component.object_formats = {ObjectFormat::coff_object, ObjectFormat::cubin};
      }
      hasher.update_length_prefixed(component.name);
      hasher.update_length_prefixed(component.file.content.to_hex());
      hasher.update_length_prefixed(component.version);
      identity.components.push_back(std::move(component));
    }
    if (identity.find_component(ComponentKind::device_compiler) == nullptr) {
      return Status(StatusCode::probe_failed, "nvcc.exe could not be probed");
    }

    // The detected device architecture participates in toolchain identity.
    // The device architecture is either supplied by the caller or probed from
    // the driver. Which one happened is recorded: a supplied architecture is an
    // input to the compilation, and the resulting binary's device execution is
    // what proves it was correct.
    std::string device_arch = request.target.device_arch;
    std::string source = "request";
    std::string probe_detail = "supplied by the caller";
    if (device_arch.empty()) {
      const Result<std::string> detected = detect_device_arch();
      if (detected) {
        device_arch = detected.value();
        source = "nvidia-smi";
        probe_detail = "probed from the driver";
      } else {
        source = "unavailable";
        probe_detail = detected.status().message();
      }
    }
    identity.attributes.push_back(EnvironmentVariable{"cuda.toolkit-version", identity.version});
    identity.attributes.push_back(EnvironmentVariable{"cuda.detected_device_arch",
                                                      device_arch.empty() ? "sm_unknown" : device_arch});
    identity.attributes.push_back(EnvironmentVariable{"cuda.device-arch-source", source});
    identity.attributes.push_back(EnvironmentVariable{"cuda.device-arch-probe", probe_detail});
    identity.attributes.push_back(EnvironmentVariable{"cuda.toolkit-root",
                                                      installation.root.string()});
    (void)request;

    // nvcc drives a host toolchain and consults the same integration variables a
    // developer prompt would set. They are derived from the discovered toolset
    // and recorded in the contract, so they are part of environment identity
    // rather than inherited silently.
    identity.environment_contract.push_back(
        EnvironmentVariable{"VCINSTALLDIR", (host.vs_root / "VC").string() + "\\"});
    identity.environment_contract.push_back(
        EnvironmentVariable{"VCToolsInstallDir", host.vc_tools_root.string() + "\\"});
    identity.environment_contract.push_back(
        EnvironmentVariable{"VSINSTALLDIR", host.vs_root.string() + "\\"});
    identity.environment_contract.push_back(
        EnvironmentVariable{"VCToolsVersion", host.toolset_version});
    if (!host.sdk_root.empty()) {
      identity.environment_contract.push_back(
          EnvironmentVariable{"WindowsSdkDir", host.sdk_root.string() + "\\"});
      identity.environment_contract.push_back(
          EnvironmentVariable{"WindowsSDKVersion", host.sdk_version + "\\"});
      identity.environment_contract.push_back(
          EnvironmentVariable{"UCRTVersion", host.sdk_version});
    }
    identity.environment_contract.push_back(
        EnvironmentVariable{"CUDA_PATH", installation.root.string()});
    identity.environment_contract.push_back(
        EnvironmentVariable{"CUDA_HOME", installation.root.string()});
    std::string path_value = (installation.root / "bin").string();
    path_value.push_back(';');
    path_value.append(host.path_value());
    identity.environment_contract.push_back(EnvironmentVariable{"PATH", path_value});
    std::string include_value = (installation.root / "include").string();
    include_value.push_back(';');
    include_value.append(host.include_value());
    identity.environment_contract.push_back(EnvironmentVariable{"INCLUDE", include_value});
    std::string lib_value = (installation.root / "lib" / "x64").string();
    lib_value.push_back(';');
    lib_value.append(host.lib_value());
    identity.environment_contract.push_back(EnvironmentVariable{"LIB", lib_value});

    Digest cudart_digest;
    if (has_file(installation.cudart) && Digest::of_file(installation.cudart, cudart_digest)) {
      hasher.update_length_prefixed(cudart_digest.to_hex());
    }
    identity.standard_library_identity = "cuda-" + identity.version + "/host-msvc-" +
                                         host.toolset_version;
    hasher.update_length_prefixed(identity.standard_library_identity);
    hasher.update_length_prefixed(device_arch);
    identity.evidence_digest = hasher.finish();
    return identity;
  }

  /// Ask the driver for the compute capability of device 0. Returns "sm_XYZ".
  ///
  /// The refusal carries its reason so that a machine where the query fails
  /// reports why instead of silently claiming an unknown architecture.
  CRF_NODISCARD static Result<std::string> detect_device_arch() {
    std::error_code ec;
    std::filesystem::path tool;
    for (const char* candidate : {"C:/Windows/System32/nvidia-smi.exe",
                                  "C:/Program Files/NVIDIA Corporation/NVSMI/nvidia-smi.exe"}) {
      const std::filesystem::path path = normalize_path(std::filesystem::path(candidate));
      if (std::filesystem::is_regular_file(path, ec) && !ec) {
        tool = path;
        break;
      }
    }
    if (tool.empty()) {
      return Status(StatusCode::not_found, "nvidia-smi was not found in any known location");
    }
    ProcessSpec spec;
    spec.executable = tool;
    spec.arguments = {"--query-gpu=compute_cap", "--format=csv,noheader"};
    spec.max_capture_bytes = 4096;
    // The driver query tool is a vendor tool that expects the environment it was
    // installed into.
    spec.inherit_ambient_environment = true;
    ProcessSupervisor supervisor;
    const Result<ProcessOutcome> outcome = supervisor.run(
        spec, Ref<InvocationId>{InvocationId::from_value(1), InvocationGeneration::initial()});
    supervisor.close();
    if (!outcome) return outcome.status();
    if (!outcome.value().exited_zero()) {
      std::string detail = outcome.value().capture.standard_error;
      if (detail.empty()) detail = outcome.value().capture.standard_output;
      if (detail.size() > 200) detail.resize(200);
      return Status(StatusCode::probe_failed,
                    "nvidia-smi exited with code " + std::to_string(outcome.value().exit_code) +
                        " termination=" +
                        std::string(to_string(outcome.value().termination)) + " output=\"" + detail +
                        "\"");
    }
    std::string text = outcome.value().capture.standard_output;
    text = std::string(trim_ascii(text));
    const std::size_t newline = text.find_first_of("\r\n");
    if (newline != std::string::npos) text.resize(newline);
    if (text.empty()) return Status(StatusCode::probe_failed, "nvidia-smi produced no output");
    // "12.0" becomes "120": the compute capability major and minor digits are
    // concatenated into the sm_XXX architecture name.
    std::string digits;
    for (const char c : text) {
      if (c >= '0' && c <= '9') {
        digits.push_back(c);
        continue;
      }
      if (c == '.') continue;
      if (!digits.empty()) break;
    }
    if (digits.empty()) {
      return Status(StatusCode::probe_failed,
                    "nvidia-smi reported an unparsable compute capability: " + text);
    }
    return "sm_" + digits;
  }
};

}  // namespace

std::shared_ptr<const CompilerAdapter> make_cuda_adapter() {
  std::error_code ec;
  const std::filesystem::path base("C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA");
  if (!std::filesystem::is_directory(base, ec) || ec) return nullptr;
  return std::make_shared<const CudaAdapter>();
}

}  // namespace crf
