// Example: durable state, a runtime restart, and conservative recovery.
//
// A phase commits, the runtime stops without retiring the session, a new runtime
// loads the durable state, and the committed phase is recovered as committed
// while everything that was in flight stays fenced.

#include "crf_example.hpp"

#include "crf/explain.hpp"

using namespace crf;
using namespace crf::examples;

int main() {
  banner("Runtime restart and recovery");
  Scratch scratch("restart-recovery");
  RuntimeOptions options = runtime_options(scratch, "restart-recovery");
  const std::filesystem::path source = scratch.write("restart.cpp", hello_source("CRF-RESTART-OK"));

  Ref<CompilerSessionId> session;
  {
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
    line("runtime epoch: " + std::to_string(crf.epoch()));
    CompileRequest request;
    request.toolchain_family = ToolchainFamily::msvc;
    request.sources = {source};
    request.adapter_options.push_back(EnvironmentVariable{"msvc.expected_stdout", "CRF-RESTART-OK"});
    Result<Ref<CompilerSessionId>> created = crf.create_session(request);
    if (!created) {
      refusal("session creation", created.status());
      return 1;
    }
    session = created.value();
    Result<CompilerSession> loaded = crf.require_session(session.id);
    if (!loaded) return 1;
    const std::vector<CompilerPhaseId> order = loaded.value().plan.topological_order();
    const Result<PhaseRunReport> validated = crf.run_phase(session.id, order[0]);
    if (!validated) return 1;
    const Result<PhaseRunReport> compiled = crf.run_phase(session.id, order[1]);
    if (!compiled) {
      refusal("compile", compiled.status());
      return 1;
    }
    line("compile committed: " + std::string(compiled.value().committed() ? "yes" : "no"));
    line("the compiler output is durable before this process exits");
    const VoidResult stopped = crf.shutdown();
    (void)stopped;
  }

  banner("Second runtime over the same durable state");
  Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  if (!runtime) {
    refusal("runtime creation", runtime.status());
    return 1;
  }
  Runtime& crf = *runtime.value();
  line("runtime epoch after restart: " + std::to_string(crf.epoch()));
  Result<CompilerSession> recovered = crf.require_session(session.id);
  if (!recovered) {
    refusal("session recovery", recovered.status());
    return 1;
  }
  line("session state: " + std::string(to_string(recovered.value().state)));
  line("recovery state: " + std::string(to_string(recovered.value().recovery_state)));
  const std::vector<CompilerPhaseId> committed = recovered.value().committed_phases();
  line("committed phases recovered: " + std::to_string(committed.size()));
  for (const CompilerPhaseId id : committed) {
    const PhaseRecord* phase = recovered.value().find_phase(id);
    if (phase == nullptr) continue;
    line("  " + id.to_string() + " commit=" + phase->commit.to_string() +
         " digest=" + phase->committed_output_digest.to_short_hex());
  }

  const Explanation explanation = explain_recovery(crf, session.id);
  line("");
  line(explanation.render());

  Result<RecoveryPlan> applied = crf.apply_recovery(session.id);
  if (!applied) {
    refusal("recovery", applied.status());
  } else {
    line("recovery applied: " + std::string(to_string(applied.value().headline)));
  }
  Result<AuditReport> audit = crf.audit();
  if (audit) line(audit.value().render());
  const VoidResult stopped = crf.shutdown();
  (void)stopped;
  return 0;
}
