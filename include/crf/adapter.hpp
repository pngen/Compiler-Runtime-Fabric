#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "crf/artifact.hpp"
#include "crf/component.hpp"
#include "crf/diagnostics.hpp"
#include "crf/environment.hpp"
#include "crf/invocation.hpp"
#include "crf/phase.hpp"
#include "crf/phase_plan.hpp"
#include "crf/policy.hpp"
#include "crf/process.hpp"
#include "crf/source.hpp"
#include "crf/target.hpp"
#include "crf/toolchain.hpp"
#include "crf/workspace.hpp"

namespace crf {

/// Adapter capability bits. An adapter declares what it actually implements;
/// the runtime refuses to run a phase the selected adapter does not claim.
enum class AdapterCapability : std::uint32_t {
  none = 0,
  preprocess = 1u << 0,
  compile = 1u << 1,
  assemble = 1u << 2,
  link = 1u << 3,
  device_compile = 1u << 4,
  device_link = 1u << 5,
  static_library = 1u << 6,
  structured_diagnostics = 1u << 7,
  object_validation = 1u << 8,
  executable_validation = 1u << 9,
  smoke_test = 1u << 10,
  reproducible = 1u << 11,
  parallel_translation_units = 1u << 12,
};

CRF_NODISCARD CRF_API bool has_capability(std::uint32_t flags, AdapterCapability value) noexcept;
CRF_NODISCARD CRF_API std::string describe_capabilities(std::uint32_t flags);

struct CRF_API AdapterDescriptor {
  std::string name;
  std::string display_name;
  std::string version;
  ToolchainFamily family = ToolchainFamily::unknown;
  std::uint32_t capabilities = 0;
  /// Phases this adapter genuinely implements. Claiming a phase here is a
  /// statement that the adapter can build a real invocation for it.
  std::vector<PhaseKind> implemented_phases;
  std::vector<ObjectFormat> produced_formats;
  EvidenceClass evidence_class = EvidenceClass::unknown;
};

struct CRF_API ToolchainProbeRequest {
  ToolchainFamily family = ToolchainFamily::unknown;
  /// Explicit toolchain root, when the caller wants a specific installation.
  std::filesystem::path explicit_root;
  TargetSpec target{};
  /// Hash component contents during the probe. Honest but slower; the runtime
  /// re-probes at commit, so a cheap probe is not a substitute.
  bool hash_components = true;
  /// Highest CUDA/device toolkit generation to accept, adapter specific.
  std::string toolkit_preference;
};

struct CRF_API PhasePlanRequest {
  ToolchainFamily family = ToolchainFamily::unknown;
  const ToolchainIdentity* toolchain = nullptr;
  const TargetSpec* target = nullptr;
  SourceLanguage language = SourceLanguage::unknown;
  std::size_t translation_unit_count = 1;
  bool want_link = true;
  bool want_smoke_test = true;
  bool want_parallel_translation_units = false;
  PolicySpec policy{};
};

/// Everything an adapter needs to build one phase invocation.
struct CRF_API PhaseExecutionRequest {
  Ref<CompilerSessionId> session{};
  CompilationGeneration compilation_generation{};
  AttemptGeneration attempt_generation{};
  Ref<CompilerPhaseId> phase{};
  PhaseKind kind = PhaseKind::unknown;
  /// Adapter-specific phase name from the plan, e.g. "compile#2".
  std::string adapter_phase;

  const ToolchainIdentity* toolchain = nullptr;
  const TargetIdentity* target = nullptr;
  const EnvironmentSpec* environment = nullptr;
  const PolicySpec* policy = nullptr;

  std::vector<const SourceUnit*> sources;
  std::vector<Ref<IntermediateArtifactId>> resolved_inputs;
  const ArtifactRegistry* artifacts = nullptr;

  const Workspace* workspace = nullptr;
  /// Where the phase should place its declared outputs. Always inside the
  /// workspace; the runtime re-checks containment after the adapter builds it.
  std::filesystem::path output_directory;
  /// Name of the artifact the finalize phase must produce.
  std::string final_artifact_name;
  /// Set for the second execution of a reproducibility check. An adapter that
  /// cannot vary a legitimate input must refuse rather than silently produce an
  /// identical command line and call the result independent.
  bool reproducibility_second_run = false;
  std::vector<EnvironmentVariable> adapter_options;

  CRF_NODISCARD const EnvironmentVariable* option(std::string_view name) const noexcept;
  CRF_NODISCARD std::string option_or(std::string_view name, std::string fallback) const;
};

struct CRF_API OutputValidationRequest {
  const PhaseExecutionRequest* context = nullptr;
  const ProcessOutcome* process = nullptr;
  const ArtifactRegistry* artifacts = nullptr;
  std::vector<Ref<IntermediateArtifactId>> candidate_outputs;
  /// Outputs the invocation declared; validation covers exactly this set.
  std::vector<OutputBinding> declared_outputs;
};

struct CRF_API ValidationEvidence {
  bool accepted = false;
  ArtifactState state = ArtifactState::unknown;
  ObjectFormat format = ObjectFormat::unknown;
  StatusCode refusal = StatusCode::ok;
  /// Deterministic list of checks that ran, in the order they ran.
  std::vector<std::string> checks;
  std::string detail;
};

struct CRF_API SmokeTestEvidence {
  bool executed = false;
  bool passed = false;
  std::int32_t exit_code = 0;
  std::string expected_stdout;
  std::string observed_stdout_tail;
  std::string detail;
  StatusCode refusal = StatusCode::ok;
};

/// The adapter contract.
///
/// Adapters are the only place vendor-specific knowledge lives. The core
/// governance model never branches on vendor identity.
class CRF_API CompilerAdapter {
 public:
  virtual ~CompilerAdapter();
  CompilerAdapter(const CompilerAdapter&) = delete;
  CompilerAdapter& operator=(const CompilerAdapter&) = delete;

  CRF_NODISCARD virtual AdapterDescriptor describe() const = 0;

  /// Discover and probe the real toolchain. Every claim made here is evidence:
  /// paths, file identities, content digests, and version output.
  CRF_NODISCARD virtual Result<ToolchainIdentity> probe_toolchain(
      const ToolchainProbeRequest& request) const = 0;

  /// Re-probe an already registered toolchain for the commit-time authority
  /// check. The default implementation re-probes through probe_toolchain and
  /// compares canonical digests.
  CRF_NODISCARD virtual Result<ToolchainIdentity> reprobe_toolchain(
      const ToolchainIdentity& previous, const ToolchainProbeRequest& request) const;

  /// Resolve the effective target for a request. The default implementation
  /// fills an unspecified architecture from the toolchain's declared support,
  /// rejects an architecture the toolchain does not claim, and completes the
  /// triple, ABI, and pointer width.
  CRF_NODISCARD virtual Result<TargetSpec> resolve_target(const ToolchainIdentity& toolchain,
                                                          const TargetSpec& requested) const;

  /// Construct the phase plan for this request. Only phases the adapter truly
  /// implements may appear.
  CRF_NODISCARD virtual Result<PhasePlan> build_plan(const PhasePlanRequest& request) const = 0;

  /// Build the structured invocation for one phase.
  CRF_NODISCARD virtual Result<InvocationSpec> build_invocation(
      const PhaseExecutionRequest& request) const = 0;

  /// Parse compiler output into diagnostics. The default implementation keeps
  /// every non-empty line as an UNKNOWN-severity diagnostic.
  CRF_NODISCARD virtual Result<std::vector<Diagnostic>> parse_diagnostics(
      const ProcessOutcome& outcome, const PhaseExecutionRequest& request) const;

  /// Validate the declared outputs of a phase before commit.
  CRF_NODISCARD virtual Result<ValidationEvidence> validate_outputs(
      const OutputValidationRequest& request) const = 0;

  /// Execute the adapter's smoke test for a final candidate. The default
  /// implementation reports NOT executed with an explicit UNSUPPORTED refusal.
  CRF_NODISCARD virtual Result<SmokeTestEvidence> run_smoke_test(
      const FinalCandidate& candidate, const PhaseExecutionRequest& request) const;

  /// True when repeating this phase with identical authoritative inputs is
  /// expected to produce identical output under the adapter contract.
  CRF_NODISCARD virtual bool is_deterministic_phase(PhaseKind kind) const noexcept;

  /// Merge the toolchain's environment contract into a session environment
  /// spec. The default implementation applies the contract verbatim and keeps
  /// the caller's explicit variables.
  CRF_NODISCARD virtual Result<EnvironmentSpec> compose_environment(
      const ToolchainIdentity& toolchain, const TargetSpec& target,
      const EnvironmentSpec& caller_overrides) const;

 protected:
  CompilerAdapter() = default;
};

/// Adapter registry used by the runtime to resolve an adapter by family.
class CRF_API AdapterRegistry {
 public:
  void add(std::shared_ptr<const CompilerAdapter> adapter);
  CRF_NODISCARD std::shared_ptr<const CompilerAdapter> find(ToolchainFamily family) const noexcept;
  CRF_NODISCARD std::shared_ptr<const CompilerAdapter> find_by_name(std::string_view name) const noexcept;
  CRF_NODISCARD std::vector<AdapterDescriptor> list() const;
  CRF_NODISCARD std::size_t size() const noexcept;

 private:
  std::vector<std::shared_ptr<const CompilerAdapter>> adapters_;
};

/// Built-in adapter factories. Each returns nullptr when the required tooling is
/// not installed; the caller decides whether that is fatal.
CRF_NODISCARD CRF_API std::shared_ptr<const CompilerAdapter> make_msvc_adapter();
CRF_NODISCARD CRF_API std::shared_ptr<const CompilerAdapter> make_cuda_adapter();
/// A modelling adapter that exercises governance paths without real tooling.
/// Everything it produces is labelled SYNTHETIC.
CRF_NODISCARD CRF_API std::shared_ptr<const CompilerAdapter> make_synthetic_adapter(
    ToolchainFamily family, std::string display_name);

}  // namespace crf
