// Example: a real MSVC compiler session with lineage and diagnostics.
//
// This example compiles, links and executes a C++20 program through the
// governed runtime and prints the phase lineage, the diagnostics, the final
// candidate and the invariant audit.

#include "crf_example.hpp"

#include "crf/explain.hpp"

using namespace crf;
using namespace crf::examples;

int main() {
  banner("MSVC compiler session");
  Scratch scratch("msvc-compile-session");
  RuntimeOptions options = runtime_options(scratch, "msvc-example");
  Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  if (!runtime) {
    refusal("runtime creation", runtime.status());
    return 1;
  }
  Runtime& crf = *runtime.value();

  const std::filesystem::path source =
      scratch.write("hello.cpp", hello_source("CRF-EXAMPLE-OK"));

  Result<Ref<ToolchainId>> toolchain = crf.discover_toolchain(ToolchainFamily::msvc);
  if (!toolchain) {
    refusal("toolchain discovery", toolchain.status());
    return 1;
  }
  const ToolchainIdentity* identity = crf.toolchains().find(toolchain.value().id);
  if (identity != nullptr) {
    line("toolchain: " + identity->describe());
    for (const ComponentIdentity& component : identity->components) {
      line("  component " + component.name + " " + component.version + " " +
           component.file.content.to_short_hex() + " fileid=" + component.file.volume_serial_hex +
           ":" + component.file.file_index_hex);
    }
  }

  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {source};
  request.run_smoke_test = true;
  request.adapter_options.push_back(EnvironmentVariable{"msvc.expected_stdout", "CRF-EXAMPLE-OK"});

  Result<Ref<CompilerSessionId>> session = crf.create_session(request);
  if (!session) {
    refusal("session creation", session.status());
    return 1;
  }
  line("session: " + session.value().id.to_string());

  Result<CompileOutcome> outcome = crf.run_session(session.value().id);
  if (!outcome) {
    refusal("session execution", outcome.status());
    return 1;
  }

  line("");
  line("phase plan and outcome:");
  for (const PhaseRunReport& report : outcome.value().phases) {
    line("  " + report.phase.id.to_string() + " " +
         std::string(to_string(report.state)) + " status=" + std::string(to_string(report.status)) +
         " compiler-nanos=" + std::to_string(report.compiler_nanos) +
         " governance-nanos=" + std::to_string(report.governance_nanos));
  }

  line("");
  line("intermediate lineage:");
  for (const IntermediateArtifact& artifact : crf.artifacts().list()) {
    line("  " + artifact.id.to_string() + " " + std::string(to_string(artifact.format)) +
         " state=" + std::string(to_string(artifact.state)) +
         " authority=" + std::string(to_string(artifact.authority)) +
         " sha256=" + artifact.content.to_short_hex() + " inputs=" +
         std::to_string(artifact.lineage_inputs.size()));
  }

  line("");
  line("diagnostics:");
  for (const PhaseRunReport& report : outcome.value().phases) {
    if (!report.diagnostics.present()) continue;
    const DiagnosticSet* set = crf.diagnostics().find(report.diagnostics.id);
    if (set == nullptr) continue;
    line("  set " + set->id.to_string() + " errors=" + std::to_string(set->error_count) +
         " warnings=" + std::to_string(set->warning_count) +
         " raw-stdout=" + std::to_string(set->raw_stdout_bytes) +
         " raw-stderr=" + std::to_string(set->raw_stderr_bytes));
    for (const Diagnostic& entry : set->entries) {
      line("    " + std::string(to_string(entry.severity)) + " " + entry.code + " " + entry.message);
    }
  }

  if (!outcome.value().candidate.path.empty()) {
    line("");
    line("final candidate: " + outcome.value().candidate.path.string());
    line("  sha256 " + outcome.value().candidate.content.to_hex());
    line("  size   " + std::to_string(outcome.value().candidate.size_bytes));
    line("  lineage-digest " + outcome.value().candidate.lineage_digest.to_hex());
  }

  Result<AuditReport> audit = crf.audit();
  if (audit) {
    line("");
    line(audit.value().render());
  }
  const VoidResult stopped = crf.shutdown();
  (void)stopped;
  return outcome.value().candidate.path.empty() ? 1 : 0;
}
