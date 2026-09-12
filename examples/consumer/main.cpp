// Independent downstream consumer of the installed Compiler Runtime Fabric.
//
// This program is built outside the source tree against an installed package via
// find_package(CompilerRuntimeFabric CONFIG REQUIRED). It:
//
//   * creates a compiler-session model with strongly typed identities;
//   * validates a toolchain contract against a real discovered toolchain;
//   * exercises a meaningful installed API (phase-plan validation and the
//     invariant audit) without using anything from the source tree.

#include <cstdio>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#include <crf/adapter.hpp>
#include <crf/audit.hpp>
#include <crf/explain.hpp>
#include <crf/phase_plan.hpp>
#include <crf/policy.hpp>
#include <crf/runtime.hpp>
#include <crf/version.hpp>

namespace {

void print(const std::string& text) {
  std::printf("%s\n", text.c_str());
  std::fflush(stdout);
}

}  // namespace

int main() {
  print(std::string("installed consumer using Compiler Runtime Fabric ") + crf::version_string);

  const std::filesystem::path root =
      std::filesystem::temp_directory_path() / "crf-installed-consumer";
  std::error_code ec;
  std::filesystem::remove_all(root, ec);

  crf::RuntimeOptions options;
  options.runtime_name = "installed-consumer";
  options.state_directory = root / "state";
  options.workspace_root = root / "workspaces";
  crf::Result<std::unique_ptr<crf::Runtime>> runtime = crf::Runtime::create(options);
  if (!runtime) {
    print(std::string("runtime creation refused: ") + runtime.status().to_string());
    return 1;
  }
  crf::Runtime& fabric = *runtime.value();

  // ---- 1. a compiler-session model with strongly typed identities ----------
  crf::CompileRequest request;
  request.toolchain_family = crf::ToolchainFamily::msvc;
  request.inline_sources.push_back({"consumer.cpp",
                                    "#include <cstdio>\n"
                                    "int main() { std::printf(\"CRF-CONSUMER-OK\\n\"); return 0; }\n"});
  request.run_smoke_test = true;
  request.adapter_options.push_back(
      crf::EnvironmentVariable{"msvc.expected_stdout", "CRF-CONSUMER-OK"});

  crf::Result<crf::Ref<crf::ToolchainId>> toolchain =
      fabric.discover_toolchain(crf::ToolchainFamily::msvc);
  if (!toolchain) {
    print(std::string("no MSVC toolchain is available to this consumer: ") +
          toolchain.status().to_string());
    print("the consumer still validated the installed package and its targets");
    const crf::VoidResult stopped = fabric.shutdown();
    (void)stopped;
    return 0;
  }

  // ---- 2. validate the toolchain contract ---------------------------------
  const crf::ToolchainIdentity* identity = fabric.toolchains().find(toolchain.value().id);
  if (identity == nullptr) return 1;
  print("toolchain contract: " + identity->describe());
  bool contract_ok = identity->evidence_class == crf::EvidenceClass::real;
  contract_ok = contract_ok && identity->find_component(crf::ComponentKind::host_cxx_compiler) != nullptr;
  contract_ok = contract_ok && identity->find_component(crf::ComponentKind::linker) != nullptr;
  contract_ok = contract_ok && identity->supports(crf::Architecture::x64);
  bool has_include = false;
  bool has_lib = false;
  for (const crf::EnvironmentVariable& variable : identity->environment_contract) {
    if (variable.name == "INCLUDE" && !variable.value.empty()) has_include = true;
    if (variable.name == "LIB" && !variable.value.empty()) has_lib = true;
  }
  contract_ok = contract_ok && has_include && has_lib;
  print(std::string("toolchain contract validated: ") + (contract_ok ? "yes" : "no"));
  if (!contract_ok) return 1;

  // ---- 3. exercise the installed API: create, run, audit, explain ----------
  crf::Result<crf::Ref<crf::CompilerSessionId>> session = fabric.create_session(request);
  if (!session) {
    print(std::string("session creation refused: ") + session.status().to_string());
    return 1;
  }
  crf::Result<crf::CompileOutcome> outcome = fabric.run_session(session.value().id);
  if (!outcome) {
    print(std::string("session execution refused: ") + outcome.status().to_string());
    return 1;
  }
  print("session: " + session.value().id.to_string());
  print("phases committed: " + std::to_string(outcome.value().phases.size()));
  if (!outcome.value().candidate.path.empty()) {
    print("candidate: " + outcome.value().candidate.path.string());
    print("candidate sha256: " + outcome.value().candidate.content.to_hex());
  }
  const crf::Explanation explanation = crf::explain_session(fabric, session.value().id);
  print("--- explanation ---");
  print(explanation.render());

  // ---- 4. phase-plan validation through the installed API -----------------
  crf::IdAllocator<crf::CompilerPhaseId> ids;
  std::vector<crf::PhaseNode> nodes(2);
  nodes[0].id = ids.next();
  nodes[0].kind = crf::PhaseKind::codegen;
  nodes[0].mandatory = true;
  nodes[1].id = ids.next();
  nodes[1].kind = crf::PhaseKind::link;
  nodes[1].mandatory = true;
  nodes[1].fan_in = true;
  nodes[1].required_inputs = 1;
  nodes[1].depends_on = {nodes[0].id};
  crf::Result<crf::PhasePlan> plan = crf::PhasePlan::build(nodes);
  if (!plan) {
    print(std::string("plan validation refused: ") + plan.status().to_string());
    return 1;
  }
  print("consumer-built plan digest: " + plan.value().canonical_digest().to_hex());

  // ---- 5. the invariant audit ---------------------------------------------
  crf::Result<crf::AuditReport> audit = fabric.audit();
  if (!audit) {
    print(std::string("audit refused: ") + audit.status().to_string());
    return 1;
  }
  print(audit.value().render());
  if (!audit.value().zero_violations()) return 1;

  const crf::VoidResult stopped = fabric.shutdown();
  (void)stopped;
  std::filesystem::remove_all(root, ec);
  print("CONSUMER-OK");
  return 0;
}
