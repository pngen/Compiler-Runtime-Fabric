// Example: a toolchain and an environment that change while a phase runs.
//
// Both cases end the same way: the compiler physically finishes, but its output
// may not become current because the authority it was bound to has moved.

#include "crf_example.hpp"

#include <memory>

using namespace crf;
using namespace crf::examples;

namespace {

/// Executes the real invocation and then runs a hook, so the example can change
/// authority at the exact moment between physical completion and commit.
class HookedExecutor final : public PhaseExecutor {
 public:
  explicit HookedExecutor(std::shared_ptr<PhaseExecutor> inner) : inner_(std::move(inner)) {}
  void set_hook(std::function<void()> hook) { hook_ = std::move(hook); }
  Result<ExecutionReport> execute(const InvocationSpec& invocation, const ProcessSpec& process,
                                  const Workspace& workspace, std::string_view label) override {
    Result<ExecutionReport> report = inner_->execute(invocation, process, workspace, label);
    if (hook_) hook_();
    return report;
  }
  VoidResult cancel(Ref<InvocationId> invocation, std::string reason) override {
    return inner_->cancel(invocation, reason);
  }
  std::string describe() const override { return "hooked"; }
  bool remote() const noexcept override { return false; }

 private:
  std::shared_ptr<PhaseExecutor> inner_;
  std::function<void()> hook_;
};

}  // namespace

int main() {
  banner("Stale toolchain and stale environment are refused");
  Scratch scratch("stale-toolchain");
  RuntimeOptions options = runtime_options(scratch, "stale-authority");
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

  // ---- toolchain generation moves during the compile phase -----------------
  {
    auto hooked = std::make_shared<HookedExecutor>(make_local_executor(crf));
    bool mutated = false;
    hooked->set_hook([&crf, &toolchain, &mutated]() {
      if (mutated) return;
      mutated = true;
      const Result<ToolchainMutation> mutation = crf.invalidate_toolchain(
          toolchain.value().id, "example retired this toolchain generation mid-phase");
      if (mutation) {
        line("toolchain generation advanced to " + mutation.value().current_generation.to_string());
      }
    });
    crf.set_executor(hooked);

    const std::filesystem::path source = scratch.write("stale_toolchain.cpp", hello_source());
    CompileRequest request;
    request.toolchain_family = ToolchainFamily::msvc;
    request.sources = {source};
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
    const Result<PhaseRunReport> compiled = crf.run_phase(session.value().id, order[1]);
    if (compiled) {
      line("phase state: " + std::string(to_string(compiled.value().state)));
      line("refusal: " + std::string(to_string(compiled.value().status)));
      line("committed: " + std::string(compiled.value().committed() ? "yes" : "no"));
      line("the compiler physically finished; its output was refused because authority moved");
    } else {
      refusal("phase execution", compiled.status());
    }
    crf.set_executor(make_local_executor(crf));
  }

  // ---- environment generation moves during the compile phase ---------------
  {
    // A fresh runtime because the toolchain generation of this one is retired.
    Scratch second_scratch("stale-environment");
    RuntimeOptions second_options = runtime_options(second_scratch, "stale-environment");
    Result<std::unique_ptr<Runtime>> second = Runtime::create(second_options);
    if (!second) {
      refusal("second runtime creation", second.status());
      return 1;
    }
    Runtime& crf2 = *second.value();
    if (!crf2.discover_toolchain(ToolchainFamily::msvc)) return 1;
    auto hooked = std::make_shared<HookedExecutor>(make_local_executor(crf2));
    bool mutated = false;
    hooked->set_hook([&crf2, &mutated]() {
      if (mutated) return;
      mutated = true;
      const std::vector<EnvironmentIdentity> environments = crf2.environments().list();
      if (environments.empty()) return;
      EnvironmentSpec spec = environments.front().spec;
      spec.deterministic_controls = false;
      const Result<Ref<EnvironmentId>> revised =
          crf2.environments().revise(environments.front().id, spec);
      if (revised) {
        line("environment generation advanced to " + revised.value().generation.to_string());
      }
    });

    const std::filesystem::path source = second_scratch.write("stale_env.cpp", hello_source());
    CompileRequest request;
    request.toolchain_family = ToolchainFamily::msvc;
    request.sources = {source};
    Result<Ref<CompilerSessionId>> session = crf2.create_session(request);
    if (!session) {
      refusal("session creation", session.status());
      return 1;
    }
    Result<CompilerSession> loaded = crf2.require_session(session.value().id);
    if (!loaded) return 1;
    const std::vector<CompilerPhaseId> order = loaded.value().plan.topological_order();
    const Result<PhaseRunReport> validated = crf2.run_phase(session.value().id, order[0]);
    if (!validated) return 1;
    crf2.set_executor(hooked);
    const Result<PhaseRunReport> compiled = crf2.run_phase(session.value().id, order[1]);
    if (compiled) {
      line("phase state: " + std::string(to_string(compiled.value().state)));
      line("refusal: " + std::string(to_string(compiled.value().status)));
      line("committed: " + std::string(compiled.value().committed() ? "yes" : "no"));
    } else {
      refusal("phase execution", compiled.status());
    }
    const VoidResult stopped = crf2.shutdown();
    (void)stopped;
  }

  const VoidResult stopped = crf.shutdown();
  (void)stopped;
  return 0;
}
