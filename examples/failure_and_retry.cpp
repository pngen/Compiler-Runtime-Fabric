// Example: a real compiler-process failure and a governed retry.
//
// The compile of a large translation unit is killed while the compiler child is
// running. The runtime classifies the failure, refuses to let the partial work
// commit, and permits a retry with fresh invocation authority.

#include "crf_example.hpp"

#include <atomic>
#include <thread>

using namespace crf;
using namespace crf::examples;

namespace {

std::string heavy_source(int functions) {
  std::string out = "#include <cstdio>\n";
  for (int i = 0; i < functions; ++i) {
    out += "int crf_example_fn_" + std::to_string(i) + "() { return " + std::to_string(i) + "; }\n";
  }
  out += "int main() { std::printf(\"CRF-EXAMPLE-OK\\n\"); return 0; }\n";
  return out;
}

}  // namespace

int main() {
  banner("Compiler-process failure and retry");
  Scratch scratch("failure-and-retry");
  RuntimeOptions options = runtime_options(scratch, "failure-and-retry");
  Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  if (!runtime) {
    refusal("runtime creation", runtime.status());
    return 1;
  }
  Runtime& crf = *runtime.value();
  if (!crf.discover_toolchain(ToolchainFamily::msvc)) {
    line("no MSVC toolchain is installed");
    return 1;
  }
  const std::filesystem::path source = scratch.write("heavy.cpp", heavy_source(9000));

  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {source};
  request.adapter_options.push_back(EnvironmentVariable{"msvc.expected_stdout", "CRF-EXAMPLE-OK"});
  Result<Ref<CompilerSessionId>> session = crf.create_session(request);
  if (!session) {
    refusal("session creation", session.status());
    return 1;
  }
  Result<CompilerSession> loaded = crf.require_session(session.value().id);
  if (!loaded) return 1;
  const std::vector<CompilerPhaseId> order = loaded.value().plan.topological_order();
  const Result<PhaseRunReport> validated = crf.run_phase(session.value().id, order[0]);
  if (!validated) return 1;
  line("phase " + order[0].to_string() + " committed: " +
       (validated.value().committed() ? "yes" : "no"));

  std::atomic<bool> done{false};
  Result<PhaseRunReport> compiled = Status(StatusCode::internal_error, "not run");
  std::thread runner([&]() {
    compiled = crf.run_phase(session.value().id, order[1]);
    done.store(true);
  });
  while (crf.processes().live_count() == 0 && !done.load()) std::this_thread::yield();
  const std::size_t killed = crf.processes().terminate_all("example killed the compiler child");
  runner.join();

  line("compiler children terminated: " + std::to_string(killed));
  if (compiled) {
    line("phase state: " + std::string(to_string(compiled.value().state)));
    line("failure class: " + std::string(to_string(compiled.value().failure)));
    line("retry permitted: " + std::string(compiled.value().retry.legal ? "yes" : "no"));
    line("reason: " + compiled.value().retry.reason);
  } else {
    refusal("phase execution", compiled.status());
  }

  Result<PhaseRunReport> retried = crf.retry_phase(session.value().id, order[1]);
  if (!retried) {
    refusal("retry", retried.status());
  } else {
    line("retry committed: " + std::string(retried.value().committed() ? "yes" : "no"));
    line("retry used fresh invocation authority: " +
         std::string((compiled && retried.value().invocation.id != compiled.value().invocation.id)
                         ? "yes"
                         : "unknown"));
  }

  Result<AuditReport> audit = crf.audit();
  if (audit) line(audit.value().render());
  const VoidResult stopped = crf.shutdown();
  (void)stopped;
  return 0;
}
