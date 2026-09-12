#include "crf/adapter.hpp"
#include "crf/canonical.hpp"
#include "crf/version.hpp"

#include "common/msvc_env.hpp"
#include "common/pe_coff.hpp"

#include <algorithm>
#include <cstdlib>
#include <memory>

namespace crf {
namespace {

using adapters::CoffObjectInfo;
using adapters::MsvcToolset;
using adapters::PeImageInfo;

constexpr const char* kAdapterName = "msvc";
constexpr const char* kExpectedStdoutOption = "msvc.expected_stdout";
constexpr const char* kStandardOption = "msvc.standard";

/// Render a 16-bit machine code as "0x8664" rather than a decimal number.
CRF_NODISCARD std::string hex16(std::uint16_t value) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out = "0x0000";
  for (int i = 0; i < 4; ++i) {
    out[static_cast<std::size_t>(5 - i)] = kDigits[(value >> (i * 4)) & 0xF];
  }
  return out;
}

CRF_NODISCARD std::string source_stem(const SourceUnit& unit) {
  std::string name = unit.path.filename().string();
  const std::size_t dot = name.rfind('.');
  if (dot != std::string::npos && dot != 0) name.resize(dot);
  if (name.empty()) name = "translation-unit";
  return name;
}

CRF_NODISCARD std::string default_final_name(const PhaseExecutionRequest& request) {
  if (!request.final_artifact_name.empty()) return request.final_artifact_name;
  if (!request.sources.empty()) return source_stem(*request.sources.front()) + ".exe";
  return "candidate.exe";
}

/// Parse the trailing "#<index>" of an adapter phase name.
CRF_NODISCARD bool parse_phase_index(std::string_view name, std::size_t& out) {
  const std::size_t hash = name.rfind('#');
  if (hash == std::string_view::npos) return false;
  const std::string digits(name.substr(hash + 1));
  if (digits.empty() ||
      !std::all_of(digits.begin(), digits.end(),
                   [](char c) { return c >= '0' && c <= '9'; })) {
    return false;
  }
  out = static_cast<std::size_t>(std::strtoull(digits.c_str(), nullptr, 10));
  return true;
}

class MsvcAdapter final : public CompilerAdapter {
 public:
  MsvcAdapter() = default;

  AdapterDescriptor describe() const override {
    AdapterDescriptor descriptor;
    descriptor.name = kAdapterName;
    descriptor.display_name = "Microsoft Visual C++ (cl.exe and link.exe)";
    descriptor.version = version_string;
    descriptor.family = ToolchainFamily::msvc;
    descriptor.capabilities = static_cast<std::uint32_t>(AdapterCapability::compile) |
                              static_cast<std::uint32_t>(AdapterCapability::link) |
                              static_cast<std::uint32_t>(AdapterCapability::static_library) |
                              static_cast<std::uint32_t>(AdapterCapability::structured_diagnostics) |
                              static_cast<std::uint32_t>(AdapterCapability::object_validation) |
                              static_cast<std::uint32_t>(AdapterCapability::executable_validation) |
                              static_cast<std::uint32_t>(AdapterCapability::smoke_test) |
                              static_cast<std::uint32_t>(AdapterCapability::reproducible) |
                              static_cast<std::uint32_t>(AdapterCapability::parallel_translation_units);
    descriptor.implemented_phases = {PhaseKind::input_validate, PhaseKind::codegen, PhaseKind::link,
                                     PhaseKind::finalize};
    descriptor.produced_formats = {ObjectFormat::coff_object, ObjectFormat::coff_image,
                                   ObjectFormat::linker_map};
    descriptor.evidence_class = EvidenceClass::real;
    return descriptor;
  }

  Result<ToolchainIdentity> probe_toolchain(const ToolchainProbeRequest& request) const override {
    (void)request;
    const Result<MsvcToolset> toolset = adapters::discover_msvc_toolset();
    if (!toolset) return toolset.status();
    return build_identity(toolset.value());
  }

  Result<ToolchainIdentity> reprobe_toolchain(const ToolchainIdentity& previous,
                                              const ToolchainProbeRequest& request) const override {
    Result<ToolchainIdentity> observed = probe_toolchain(request);
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
                    "the detected MSVC toolset is a Hostx64/x64 toolset and targets x64 only");
    }
    return CompilerAdapter::resolve_target(toolchain, target);
  }

  Result<PhasePlan> build_plan(const PhasePlanRequest& request) const override {
    if (request.toolchain == nullptr) {
      return Status(StatusCode::invalid_argument, "phase plan requires a probed toolchain");
    }
    const std::size_t units = std::max<std::size_t>(1, request.translation_unit_count);
    if (units > 64) {
      return Status(StatusCode::capacity_exceeded,
                    "the MSVC adapter supports at most 64 translation units per session");
    }
    IdAllocator<CompilerPhaseId> ids;
    std::vector<PhaseNode> nodes;

    PhaseNode validate;
    validate.id = ids.next();
    validate.kind = PhaseKind::input_validate;
    validate.adapter_phase = "validate-inputs";
    validate.mandatory = true;
    nodes.push_back(validate);

    std::vector<CompilerPhaseId> compile_ids;
    for (std::size_t i = 0; i < units; ++i) {
      PhaseNode compile;
      compile.id = ids.next();
      compile.kind = PhaseKind::codegen;
      compile.adapter_phase = "compile#" + std::to_string(i);
      compile.depends_on = {validate.id};
      compile.mandatory = true;
      compile.expected_outputs = {ObjectFormat::coff_object};
      compile_ids.push_back(compile.id);
      nodes.push_back(compile);
    }

    PhaseNode link;
    link.id = ids.next();
    link.kind = PhaseKind::link;
    link.adapter_phase = "link";
    link.depends_on = compile_ids;
    link.mandatory = true;
    link.fan_in = true;
    link.required_inputs = compile_ids.size();
    link.expected_outputs = {ObjectFormat::coff_image, ObjectFormat::linker_map};
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
    if (request.workspace == nullptr || request.toolchain == nullptr || request.target == nullptr ||
        request.environment == nullptr) {
      return Status(StatusCode::integrity_unproven, "phase execution context is incomplete");
    }
    const ComponentIdentity* compiler = request.toolchain->find_component(ComponentKind::host_cxx_compiler);
    const ComponentIdentity* linker = request.toolchain->find_component(ComponentKind::linker);
    if (compiler == nullptr || linker == nullptr) {
      return Status(StatusCode::component_not_found, "the MSVC toolchain lacks cl.exe or link.exe");
    }
    InvocationSpec spec;
    spec.adapter_name = kAdapterName;
    spec.style = ArgumentStyle::msvc;
    spec.working_directory = request.workspace->root;

    switch (request.kind) {
      case PhaseKind::input_validate: {
        if (request.sources.empty()) {
          return Status(StatusCode::invalid_argument, "input validation requires at least one source");
        }
        spec.executable = compiler->file.canonical_path;
        spec.arguments = {"/nologo", "/Zs", "/std:c++20", "/EHsc", "/Brepro"};
        for (const SourceUnit* unit : request.sources) {
          if (unit == nullptr) continue;
          spec.arguments.push_back(unit->path.string());
          InputBinding binding;
          binding.source = unit->id;
          binding.generation = unit->generation;
          binding.path = unit->path;
          binding.content = unit->content;
          binding.staged = false;
          spec.inputs.push_back(std::move(binding));
        }
        return spec;
      }
      case PhaseKind::codegen: {
        // The plan names each compile phase "compile#<index>"; the index is the
        // translation-unit ordinal inside this session.
        std::size_t index = 0;
        if (!parse_phase_index(request.adapter_phase, index)) {
          return Status(StatusCode::invalid_argument,
                        "compile phase is missing its translation-unit ordinal");
        }
        if (index >= request.sources.size()) {
          return Status(StatusCode::invalid_argument,
                        "compile phase names a translation unit that is not part of the session");
        }
        const SourceUnit* unit = request.sources[index];
        if (unit == nullptr) {
          return Status(StatusCode::invalid_argument, "translation unit is not admitted");
        }
        const std::string stem = source_stem(*unit);
        const Result<std::filesystem::path> object =
            request.workspace->resolve("outputs/" + stem + "-" + std::to_string(index) + ".obj");
        if (!object) return object.status();
        spec.executable = compiler->file.canonical_path;
        spec.arguments = {"/nologo", "/c",
                          std::string("/std:") + request.option_or(kStandardOption, "c++20"), "/EHsc",
                          "/Brepro", "/Fo" + object.value().string(), unit->path.string()};
        InputBinding binding;
        binding.source = unit->id;
        binding.generation = unit->generation;
        binding.path = unit->path;
        binding.content = unit->content;
        spec.inputs.push_back(std::move(binding));
        OutputBinding output;
        output.logical_name = "object";
        output.path = object.value();
        output.expected_format = ObjectFormat::coff_object;
        output.required = true;
        spec.expected_outputs.push_back(std::move(output));
        return spec;
      }
      case PhaseKind::link: {
        if (request.resolved_inputs.empty()) {
          return Status(StatusCode::fan_in_incomplete, "link phase received no object inputs");
        }
        const std::string final_name = default_final_name(request);
        const Result<std::filesystem::path> image = request.workspace->resolve("outputs/" + final_name);
        if (!image) return image.status();
        std::string stem = final_name;
        const std::size_t dot = stem.rfind('.');
        if (dot != std::string::npos) stem.resize(dot);
        const Result<std::filesystem::path> map = request.workspace->resolve("outputs/" + stem + ".map");
        if (!map) return map.status();
        spec.executable = linker->file.canonical_path;
        spec.arguments = {"/nologo", "/Brepro", "/INCREMENTAL:NO", "/OUT:" + image.value().string(),
                          "/MAP:" + map.value().string()};
        for (const Ref<IntermediateArtifactId>& reference : request.resolved_inputs) {
          const IntermediateArtifact* artifact =
              request.artifacts != nullptr ? request.artifacts->find(reference.id) : nullptr;
          if (artifact == nullptr) {
            return Status(StatusCode::not_found, "link input artifact is not registered");
          }
          if (artifact->format != ObjectFormat::coff_object) continue;
          spec.arguments.push_back(artifact->path.string());
          InputBinding binding;
          binding.source = artifact->source.id;
          binding.generation = artifact->source.generation;
          binding.path = artifact->path;
          binding.content = artifact->content;
          spec.inputs.push_back(std::move(binding));
        }
        OutputBinding image_binding;
        image_binding.logical_name = "image";
        image_binding.path = image.value();
        image_binding.expected_format = ObjectFormat::coff_image;
        image_binding.required = true;
        spec.expected_outputs.push_back(std::move(image_binding));
        OutputBinding map_binding;
        map_binding.logical_name = "map";
        map_binding.path = map.value();
        map_binding.expected_format = ObjectFormat::linker_map;
        map_binding.required = false;
        map_binding.allow_empty = true;
        spec.expected_outputs.push_back(std::move(map_binding));
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
                        "finalize phase found no linked image among its inputs");
        }
        spec.executable = image->path;
        spec.produced_executable = true;
        spec.working_directory = request.workspace->root;
        // The executable is executed as a governed compiler-runtime phase so
        // that the smoke test result is a first-class, evidenced outcome.
        return spec;
      }
      default:
        break;
    }
    return Status(StatusCode::unsupported,
                  std::string("the MSVC adapter does not implement phase ") +
                      std::string(to_string(request.kind)));
  }

  Result<std::vector<Diagnostic>> parse_diagnostics(
      const ProcessOutcome& outcome, const PhaseExecutionRequest& request) const override {
    (void)request;
    std::vector<Diagnostic> diagnostics =
        normalize_msvc_output(outcome.capture.standard_output, "cl");
    const std::vector<Diagnostic> errors =
        normalize_msvc_output(outcome.capture.standard_error, "cl");
    diagnostics.insert(diagnostics.end(), errors.begin(), errors.end());
    if (diagnostics.empty() && outcome.capture.truncated) {
      Diagnostic marker;
      marker.severity = DiagnosticSeverity::warning;
      marker.origin = "runtime";
      marker.message = "compiler output was truncated at the configured capture ceiling";
      marker.raw = marker.message;
      diagnostics.push_back(std::move(marker));
    }
    return diagnostics;
  }

  Result<ValidationEvidence> validate_outputs(const OutputValidationRequest& request) const override {
    ValidationEvidence evidence;
    if (request.context == nullptr || request.artifacts == nullptr) {
      return Status(StatusCode::integrity_unproven, "validation context is incomplete");
    }
    const PhaseExecutionRequest& context = *request.context;
    const Architecture expected = request.context->target != nullptr
                                      ? request.context->target->spec.architecture
                                      : Architecture::unknown;
    const std::uint16_t expected_machine = coff_machine_for(expected);

    switch (context.kind) {
      case PhaseKind::input_validate:
        evidence.accepted = true;
        evidence.state = ArtifactState::valid;
        evidence.checks.push_back("compiler accepted the translation unit with /Zs");
        evidence.detail = "input validation succeeded";
        return evidence;
      case PhaseKind::codegen: {
        if (request.candidate_outputs.empty()) {
          evidence.refusal = StatusCode::output_missing;
          evidence.state = ArtifactState::stale;
          evidence.detail = "the compile phase produced no object file";
          return evidence;
        }
        for (const Ref<IntermediateArtifactId>& reference : request.candidate_outputs) {
          const IntermediateArtifact* artifact = request.artifacts->find(reference.id);
          if (artifact == nullptr) {
            evidence.refusal = StatusCode::output_missing;
            evidence.state = ArtifactState::stale;
            evidence.detail = "candidate object is not registered";
            return evidence;
          }
          evidence.checks.push_back("object exists: " + artifact->path.filename().string());
          if (!std::filesystem::exists(artifact->path)) {
            evidence.refusal = StatusCode::output_missing;
            evidence.state = ArtifactState::stale;
            evidence.detail = "object file is missing: " + artifact->path.string();
            return evidence;
          }
          if (artifact->size_bytes == 0) {
            evidence.refusal = StatusCode::output_empty;
            evidence.state = ArtifactState::corrupt;
            evidence.detail = "object file is empty: " + artifact->path.string();
            return evidence;
          }
          const Result<CoffObjectInfo> object = adapters::inspect_coff_object(artifact->path);
          if (!object) {
            evidence.refusal = object.code();
            evidence.state = ArtifactState::corrupt;
            evidence.detail = object.status().message();
            return evidence;
          }
          if (object.value().machine != expected_machine) {
            evidence.refusal = StatusCode::output_wrong_target;
            evidence.state = ArtifactState::incompatible;
            evidence.detail = "object machine 0x" + std::to_string(object.value().machine) +
                              " does not match the requested target";
            return evidence;
          }
          evidence.checks.push_back("coff machine " + hex16(object.value().machine));
          evidence.checks.push_back("coff sections " + std::to_string(object.value().section_count));
          evidence.format = ObjectFormat::coff_object;
        }
        evidence.accepted = true;
        evidence.state = ArtifactState::valid;
        evidence.detail = "object file validated";
        return evidence;
      }
      case PhaseKind::link: {
        const IntermediateArtifact* image = nullptr;
        for (const Ref<IntermediateArtifactId>& reference : request.candidate_outputs) {
          const IntermediateArtifact* artifact = request.artifacts->find(reference.id);
          if (artifact == nullptr) continue;
          if (artifact->format != ObjectFormat::coff_image) continue;
          image = artifact;
          break;
        }
        if (image == nullptr) {
          evidence.refusal = StatusCode::output_missing;
          evidence.state = ArtifactState::stale;
          evidence.detail = "the link phase produced no image";
          return evidence;
        }
        evidence.checks.push_back("image exists: " + image->path.filename().string());
        const Result<PeImageInfo> parsed = adapters::inspect_pe_image(image->path);
        if (!parsed) {
          evidence.refusal = parsed.code();
          evidence.state = ArtifactState::corrupt;
          evidence.detail = parsed.status().message();
          return evidence;
        }
        if (parsed.value().machine != expected_machine) {
          evidence.refusal = StatusCode::output_wrong_target;
          evidence.state = ArtifactState::incompatible;
          evidence.detail = "image machine does not match the requested target";
          return evidence;
        }
        if (!parsed.value().is_executable) {
          evidence.refusal = StatusCode::output_unexpected_format;
          evidence.state = ArtifactState::incompatible;
          evidence.detail = "linked image is not an executable";
          return evidence;
        }
        evidence.checks.push_back("pe machine " + hex16(parsed.value().machine));
        evidence.checks.push_back("pe subsystem " + std::to_string(parsed.value().subsystem));
        evidence.checks.push_back("pe sections " + std::to_string(parsed.value().section_count));
        evidence.format = ObjectFormat::coff_image;
        evidence.accepted = true;
        evidence.state = ArtifactState::valid;
        evidence.detail = parsed.value().detail;
        return evidence;
      }
      case PhaseKind::finalize: {
        evidence.checks.push_back("candidate executed");
        const std::string expected_output = context.option_or(kExpectedStdoutOption, "");
        if (request.process == nullptr) {
          evidence.refusal = StatusCode::integrity_unproven;
          evidence.detail = "no process evidence is available for the smoke test";
          return evidence;
        }
        if (!request.process->exited_zero()) {
          evidence.refusal = StatusCode::smoke_test_failed;
          evidence.state = ArtifactState::corrupt;
          evidence.detail = "the produced executable did not exit with code 0";
          return evidence;
        }
        evidence.checks.push_back("candidate exit code 0");
        if (!expected_output.empty() &&
            request.process->capture.standard_output.find(expected_output) == std::string::npos) {
          evidence.refusal = StatusCode::smoke_test_failed;
          evidence.state = ArtifactState::corrupt;
          evidence.detail = "the produced executable did not print the expected marker";
          return evidence;
        }
        if (!expected_output.empty()) {
          evidence.checks.push_back("expected stdout marker observed");
        }
        evidence.accepted = true;
        evidence.state = ArtifactState::valid;
        evidence.format = ObjectFormat::metadata;
        evidence.detail = "candidate execution smoke test passed";
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
      case PhaseKind::codegen:
      case PhaseKind::link:
        return true;
      default:
        return false;
    }
  }

 private:
  CRF_NODISCARD static Result<ToolchainIdentity> build_identity(const MsvcToolset& toolset) {
    ToolchainIdentity identity;
    identity.family = ToolchainFamily::msvc;
    identity.display_name = "Microsoft Visual C++ " + toolset.toolset_version;
    identity.version = toolset.compiler_version;
    identity.toolkit_root = toolset.vc_tools_root;
    identity.sdk_root = toolset.sdk_root;
    identity.target_support = {Architecture::x64};
    identity.object_formats = {ObjectFormat::coff_object, ObjectFormat::coff_image,
                               ObjectFormat::linker_map};
    identity.evidence_class = EvidenceClass::real;

    struct ComponentSpec {
      ComponentKind kind;
      const char* name;
      std::filesystem::path path;
      std::string version;
    };
    const std::vector<ComponentSpec> specs = {
        {ComponentKind::host_cxx_compiler, "cl", toolset.cl, toolset.compiler_version},
        {ComponentKind::linker, "link", toolset.link, toolset.linker_version},
        {ComponentKind::librarian, "lib", toolset.lib, {}}};

    IdAllocator<CompilerComponentId> component_ids;
    DigestBuilder builder;
    for (const ComponentSpec& spec : specs) {
      if (spec.path.empty()) continue;
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
      if (spec.kind == ComponentKind::host_cxx_compiler) {
        component.command_capabilities = {"/std:c++20", "/std:c++17", "/Zs", "/E", "/c", "/Brepro",
                                          "/Fo"};
        component.object_formats = {ObjectFormat::coff_object};
      } else if (spec.kind == ComponentKind::linker) {
        component.command_capabilities = {"/Brepro", "/INCREMENTAL:NO", "/OUT:", "/MAP:"};
        component.object_formats = {ObjectFormat::coff_image, ObjectFormat::linker_map};
      } else {
        component.command_capabilities = {"/OUT:"};
        component.object_formats = {ObjectFormat::archive};
      }
      builder.update(component.name);
      builder.update(component.file.content.to_hex());
      builder.update(component.version);
      identity.components.push_back(std::move(component));
    }
    if (identity.components.size() < 2) {
      return Status(StatusCode::probe_failed, "the MSVC toolchain is missing cl.exe or link.exe");
    }

    // Environment contract. INCLUDE, LIB and PATH are constructed from the
    // discovered installation; nothing is inherited from the ambient process.
    identity.environment_contract.push_back(EnvironmentVariable{"INCLUDE", toolset.include_value()});
    identity.environment_contract.push_back(EnvironmentVariable{"LIB", toolset.lib_value()});
    identity.environment_contract.push_back(EnvironmentVariable{"PATH", toolset.path_value()});
    identity.environment_contract.push_back(EnvironmentVariable{"VSCMD_ARG_TGT_ARCH", "x64"});

    DigestBuilder library_builder;
    library_builder.update(toolset.toolset_version);
    library_builder.update(toolset.sdk_version);
    if (!toolset.standard_library.empty()) {
      Digest library_digest;
      if (Digest::of_file(toolset.standard_library, library_digest)) {
        library_builder.update(library_digest.to_hex());
      }
    }
    identity.standard_library_identity =
        "msvc-" + toolset.toolset_version + "/sdk-" + toolset.sdk_version + "/" +
        library_builder.finish().to_short_hex();

    builder.update(toolset.toolset_version);
    builder.update(toolset.sdk_version);
    builder.update(identity.standard_library_identity);
    identity.evidence_digest = builder.finish();
    return identity;
  }

  /// Small deterministic digest accumulator used for evidence digests.
  class DigestBuilder {
   public:
    void update(std::string_view text) { hasher_.update_length_prefixed(text); }
    CRF_NODISCARD Digest finish() noexcept { return hasher_.finish(); }

   private:
    Hasher hasher_;
  };
};

}  // namespace

std::shared_ptr<const CompilerAdapter> make_msvc_adapter() {
  return std::make_shared<const MsvcAdapter>();
}

}  // namespace crf
