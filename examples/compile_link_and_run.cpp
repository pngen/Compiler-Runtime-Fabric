// Example: compile, link, validate and execute a real C++20 program.
//
// Demonstrates that a process exit code of zero is not authority: the runtime
// validates the produced object and image before either becomes current, and
// executes the candidate as a governed phase.

#include "crf_example.hpp"

using namespace crf;
using namespace crf::examples;

int main() {
  banner("Compile, link, execute");
  Scratch scratch("compile-link-run");
  RuntimeOptions options = runtime_options(scratch, "compile-link-run");
  Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  if (!runtime) {
    refusal("runtime creation", runtime.status());
    return 1;
  }
  Runtime& crf = *runtime.value();
  Result<Ref<ToolchainId>> toolchain = crf.discover_toolchain(ToolchainFamily::msvc);
  if (!toolchain) {
    refusal("toolchain discovery", toolchain.status());
    return 1;
  }

  // Two translation units so the link phase performs a real fan-in.
  const std::filesystem::path first = scratch.write(
      "main.cpp",
      "#include <cstdio>\n"
      "int crf_add(int a, int b);\n"
      "int main() { std::printf(\"SUM=%d\\n\", crf_add(20, 22)); return 0; }\n");
  const std::filesystem::path second = scratch.write("add.cpp",
                                                     "int crf_add(int a, int b) { return a + b; }\n");

  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {first, second};
  request.run_smoke_test = true;
  request.adapter_options.push_back(EnvironmentVariable{"msvc.expected_stdout", "SUM=42"});

  Result<Ref<CompilerSessionId>> session = crf.create_session(request);
  if (!session) {
    refusal("session creation", session.status());
    return 1;
  }
  Result<CompileOutcome> outcome = crf.run_session(session.value().id);
  if (!outcome) {
    refusal("session execution", outcome.status());
    return 1;
  }
  line("phases: " + std::to_string(outcome.value().phases.size()));
  for (const PhaseRunReport& report : outcome.value().phases) {
    line("  " + std::string(to_string(report.state)) + " " + report.phase.id.to_string());
  }
  if (outcome.value().candidate.path.empty()) {
    line("no candidate was produced");
    const VoidResult stopped = crf.shutdown();
    (void)stopped;
    return 1;
  }
  line("executed candidate: " + outcome.value().candidate.path.string());
  line("the smoke-test phase observed the expected stdout marker SUM=42");

  Result<AuditReport> audit = crf.audit();
  if (audit) line(audit.value().render());
  const VoidResult stopped = crf.shutdown();
  (void)stopped;
  return 0;
}
