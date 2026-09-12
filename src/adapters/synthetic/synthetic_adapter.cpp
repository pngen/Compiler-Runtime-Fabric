#include "crf/adapter.hpp"
#include "crf/canonical.hpp"
#include "crf/version.hpp"

#include <memory>

namespace crf {
namespace {

/// A modelling adapter for compiler families whose tooling is not installed on
/// this machine.
///
/// It exists so that toolchain identity, target selection, plan construction,
/// environment contracting, and refusal paths can be exercised and tested
/// without pretending that a compiler ran. Every identity it produces is
/// labelled SYNTHETIC, and every attempt to execute a phase through it is
/// refused with UNSUPPORTED. No artifact it could produce is ever described as
/// real compiler output.
class SyntheticAdapter final : public CompilerAdapter {
 public:
  SyntheticAdapter(ToolchainFamily family, std::string display_name)
      : family_(family), display_name_(std::move(display_name)) {}

  AdapterDescriptor describe() const override {
    AdapterDescriptor descriptor;
    descriptor.name = std::string(to_string(family_)) + "-synthetic";
    descriptor.display_name = display_name_;
    descriptor.version = version_string;
    descriptor.family = family_;
    descriptor.capabilities = static_cast<std::uint32_t>(AdapterCapability::compile) |
                              static_cast<std::uint32_t>(AdapterCapability::link);
    descriptor.implemented_phases = {};
    descriptor.produced_formats = {};
    descriptor.evidence_class = EvidenceClass::synthetic;
    return descriptor;
  }

  Result<ToolchainIdentity> probe_toolchain(const ToolchainProbeRequest& request) const override {
    ToolchainIdentity identity;
    identity.family = family_;
    identity.display_name = display_name_;
    identity.version = "modelled";
    identity.evidence_class = EvidenceClass::synthetic;
    identity.target_support = {Architecture::unknown, Architecture::x64, Architecture::arm64};
    identity.object_formats = {ObjectFormat::elf, ObjectFormat::metadata};
    identity.standard_library_identity = "synthetic/" + std::string(to_string(family_));
    Hasher hasher;
    hasher.update_length_prefixed(to_string(family_));
    hasher.update_length_prefixed(display_name_);
    hasher.update_length_prefixed(request.target.triple);
    identity.evidence_digest = hasher.finish();
    identity.attributes.push_back(EnvironmentVariable{"toolchain.evidence", "modelled"});
    identity.attributes.push_back(
        EnvironmentVariable{"toolchain.real-tooling-present", "false"});
    return identity;
  }

  Result<TargetSpec> resolve_target(const ToolchainIdentity& toolchain,
                                    const TargetSpec& requested) const override {
    TargetSpec target = requested;
    if (target.architecture == Architecture::unknown) target.architecture = Architecture::x64;
    if (target.os == OperatingSystem::unknown) target.os = OperatingSystem::linux_kernel;
    if (target.abi.empty()) target.abi = "modelled";
    if (target.triple.empty()) {
      target.triple = target.architecture == Architecture::arm64 ? "aarch64-unknown-linux-gnu"
                                                                 : "x86_64-unknown-linux-gnu";
    }
    if (target.pointer_width_bits == 0) target.pointer_width_bits = pointer_bits(target.architecture);
    if (const VoidResult valid = target.validate(); !valid) return valid.status();
    (void)toolchain;
    return target;
  }

  Result<PhasePlan> build_plan(const PhasePlanRequest& request) const override {
    (void)request;
    return Status(StatusCode::unsupported,
                  "the synthetic adapter builds no executable phase plan; no real tooling for " +
                      std::string(to_string(family_)) + " is installed");
  }

  Result<InvocationSpec> build_invocation(const PhaseExecutionRequest& request) const override {
    (void)request;
    return Status(StatusCode::unsupported,
                  "the synthetic adapter does not execute compiler processes; " +
                      std::string(to_string(family_)) +
                      " tooling is not installed on this machine");
  }

  Result<ValidationEvidence> validate_outputs(const OutputValidationRequest& request) const override {
    (void)request;
    return Status(StatusCode::unsupported,
                  "the synthetic adapter validates no outputs because it produces none");
  }

  bool is_deterministic_phase(PhaseKind kind) const noexcept override {
    (void)kind;
    return false;
  }

 private:
  ToolchainFamily family_;
  std::string display_name_;
};

}  // namespace

std::shared_ptr<const CompilerAdapter> make_synthetic_adapter(ToolchainFamily family,
                                                             std::string display_name) {
  return std::make_shared<const SyntheticAdapter>(family, std::move(display_name));
}

}  // namespace crf
