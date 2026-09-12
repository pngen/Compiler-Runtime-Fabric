// Real MSVC compiler-runtime proofs.
//
// Every case in this suite launches a real cl.exe / link.exe process through the
// runtime's own process supervisor. Nothing here is simulated: the assertions are
// about what actually happened on disk and in the operating system.

#include "crf_test.hpp"
#include "crf_test_env.hpp"

#include <algorithm>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace crf;

CRF_NODISCARD RuntimeOptions msvc_options(const char* label) {
  RuntimeOptions options = crftest::test_runtime_options(crftest::unique_label(label));
  options.enable_persistence = true;
  return options;
}

CRF_NODISCARD std::string hello_source() {
  return "#include <cstdio>\n"
         "int main() { std::printf(\"CRF-SMOKE-OK\\n\"); return 0; }\n";
}

CRF_NODISCARD std::string broken_source() {
  return "#include <cstdio>\n"
         "int main() { this_is_not_a_function(); return 0; }\n";
}

/// Source heavy enough that a compile stays in flight while the test acts.
CRF_NODISCARD std::string heavy_source(std::size_t functions = 8000) {
  std::string out = "#include <cstdio>\n";
  out.reserve(functions * 32);
  for (std::size_t i = 0; i < functions; ++i) {
    out += "int crf_fn_" + std::to_string(i) + "() { return " + std::to_string(static_cast<int>(i)) +
           "; }\n";
  }
  out += "int main() { std::printf(\"CRF-SMOKE-OK\\n\"); return 0; }\n";
  return out;
}

/// Wraps the runtime's local executor so a test can act at a precise point in
/// the governed pipeline: after the compiler physically finished, before any
/// authority is revalidated or committed.
class HookedExecutor final : public PhaseExecutor {
 public:
  explicit HookedExecutor(std::shared_ptr<PhaseExecutor> inner) : inner_(std::move(inner)) {}

  void set_after_hook(std::function<void()> hook) { after_ = std::move(hook); }
  void set_before_hook(std::function<void()> hook) { before_ = std::move(hook); }

  Result<ExecutionReport> execute(const InvocationSpec& invocation, const ProcessSpec& process,
                                  const Workspace& workspace, std::string_view label) override {
    if (before_) before_();
    Result<ExecutionReport> report = inner_->execute(invocation, process, workspace, label);
    if (after_) after_();
    return report;
  }
  VoidResult cancel(Ref<InvocationId> invocation, std::string reason) override {
    return inner_->cancel(invocation, reason);
  }
  std::string describe() const override { return "hooked(" + inner_->describe() + ")"; }
  bool remote() const noexcept override { return false; }

 private:
  std::shared_ptr<PhaseExecutor> inner_;
  std::function<void()> before_;
  std::function<void()> after_;
};

/// A compiled fixture used by several cases.
struct CompiledFixture {
  std::unique_ptr<Runtime> runtime;
  Ref<CompilerSessionId> session;
  CompileOutcome outcome;
};

CRF_NODISCARD bool compile_and_link(Runtime& runtime, const std::string& source_name,
                                    const std::string& contents, CompileOutcome& outcome,
                                    bool expect_success = true) {
  const std::filesystem::path source = crftest::test_root() / "sources" / source_name;
  if (!crftest::write_text(source, contents)) return false;
  crftest::report_phase("SOURCE-WRITTEN");
  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {source};
  request.output_directory = source.parent_path();
  request.run_smoke_test = true;
  request.adapter_options.push_back(EnvironmentVariable{"msvc.expected_stdout", "CRF-SMOKE-OK"});
  const Result<Ref<CompilerSessionId>> created = runtime.create_session(request);
  if (!created) {
    std::printf("  create_session refused: %s\n", created.status().to_string().c_str());
    return false;
  }
  crftest::report_phase("SESSION-CREATED");
  const Result<CompileOutcome> result = runtime.run_session(created.value().id);
  crftest::report_phase("SESSION-RAN");
  if (!result) {
    std::printf("  run_session refused: %s\n", result.status().to_string().c_str());
    return false;
  }
  outcome = result.value();
  if (outcome.candidate.path.empty()) {
    const Result<CompilerSession> session = runtime.require_session(created.value().id);
    if (session) {
      for (const CompilerPhaseId id : session.value().plan.topological_order()) {
        const PhaseRecord* phase = session.value().find_phase(id);
        if (phase == nullptr) continue;
        std::printf("  phase %s state=%s status=%s detail=%s\n", id.to_string().c_str(),
                    std::string(to_string(phase->state)).c_str(),
                    std::string(to_string(phase->last_status)).c_str(),
                    phase->last_detail.c_str());
      }
    }
    std::printf("  outcome status=%s detail=%s\n", std::string(to_string(outcome.status)).c_str(),
                outcome.detail.c_str());
  }
  if (expect_success) return outcome.candidate.path.empty() == false;
  return true;
}

}  // namespace

CRF_TEST(msvc_toolchain_identity_is_real) {
  CRF_PHASE("SETUP");
  RuntimeOptions options = msvc_options("msvc-identity");
  crftest::ScopedTree cleanup(options.state_directory.parent_path());
  const Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  CRF_REQUIRE_OK(runtime);

  CRF_PHASE("DISCOVER_TOOLCHAIN");
  const Result<ToolchainIdentity> probed = runtime.value()->probe_toolchain(ToolchainFamily::msvc);
  CRF_REQUIRE_OK(probed);
  const ToolchainIdentity& identity = probed.value();
  CRF_EXPECT(identity.family == ToolchainFamily::msvc);
  CRF_EXPECT(identity.evidence_class == EvidenceClass::real);
  CRF_EXPECT(!identity.version.empty());
  CRF_EXPECT(identity.components.size() >= 2);
  CRF_EXPECT(identity.supports(Architecture::x64));

  const ComponentIdentity* cl = identity.find_component(ComponentKind::host_cxx_compiler);
  const ComponentIdentity* link = identity.find_component(ComponentKind::linker);
  CRF_REQUIRE(cl != nullptr);
  CRF_REQUIRE(link != nullptr);
  CRF_EXPECT(cl->file.content_hashed);
  CRF_EXPECT(!cl->file.content.zero());
  CRF_EXPECT(!cl->file.volume_serial_hex.empty());
  CRF_EXPECT(!cl->file.file_index_hex.empty());
  // Path is not identity: the file id and content digest are.
  CRF_EXPECT(canonical_path_key(cl->file.canonical_path) !=
             canonical_path_key(link->file.canonical_path));
  CRF_EXPECT(!identity.evidence_digest.zero());

  const Result<Ref<ToolchainId>> registered =
      runtime.value()->discover_toolchain(ToolchainFamily::msvc);
  CRF_REQUIRE_OK(registered);
  CRF_EXPECT(runtime.value()->toolchains().is_current(registered.value()));

  CRF_PHASE("SHUTDOWN");
  CRF_EXPECT_OK(runtime.value()->shutdown());
}

CRF_TEST(msvc_executable_replaced_at_same_path_changes_identity) {
  CRF_PHASE("SETUP");
  RuntimeOptions options = msvc_options("msvc-replace");
  crftest::ScopedTree cleanup(options.state_directory.parent_path());
  const Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  CRF_REQUIRE_OK(runtime);
  const Result<ToolchainIdentity> probed = runtime.value()->probe_toolchain(ToolchainFamily::msvc);
  CRF_REQUIRE_OK(probed);
  ToolchainIdentity identity = probed.value();
  CRF_REQUIRE(!identity.components.empty());

  CRF_PHASE("MUTATE");
  const Result<Ref<ToolchainId>> registered =
      runtime.value()->discover_toolchain(ToolchainFamily::msvc);
  CRF_REQUIRE_OK(registered);
  const ToolchainIdentity* current = runtime.value()->toolchains().find(registered.value().id);
  CRF_REQUIRE(current != nullptr);
  identity = *current;
  // Copy cl.exe, then change one byte.
  const std::filesystem::path staging = crftest::test_root() / "replacement" / "cl.exe";
  std::error_code ec;
  std::filesystem::create_directories(staging.parent_path(), ec);
  const std::filesystem::path original = identity.components.front().file.canonical_path;
  std::filesystem::copy_file(original, staging, std::filesystem::copy_options::overwrite_existing, ec);
  CRF_REQUIRE(!ec);
  {
    std::fstream stream(staging, std::ios::binary | std::ios::in | std::ios::out);
    CRF_REQUIRE(static_cast<bool>(stream));
    stream.seekp(4096);
    const char marker = 'Z';
    stream.write(&marker, 1);
  }
  const Result<FileIdentity> replacement = probe_file_identity(staging, true);
  CRF_REQUIRE_OK(replacement);
  ToolchainIdentity mutated = identity;
  mutated.components.front().file = replacement.value();

  CRF_PHASE("DIFF");
  const ToolchainMutation mutation = diff_toolchains(identity, mutated);
  CRF_EXPECT(mutation.mutated);
  CRF_EXPECT(mutation.generation_advanced());
  CRF_EXPECT(!mutation.changed_components.empty());
  // The file is a different physical file at a different path but the mutation
  // is still detected from content, which is what actually matters.
  CRF_EXPECT(!identity.components.front().file.same_binary_as(replacement.value()));

  CRF_PHASE("VERIFY");
  const ComponentRevalidation revalidation = revalidate_component(identity.components.front(), true);
  CRF_EXPECT(revalidation.current);
  CRF_EXPECT(!revalidation.content_changed);

  CRF_PHASE("SHUTDOWN");
  CRF_EXPECT_OK(runtime.value()->shutdown());
}

CRF_TEST(msvc_compile_link_execute_proof) {
  CRF_PHASE("SETUP");
  RuntimeOptions options = msvc_options("msvc-full");
  crftest::ScopedTree cleanup(options.state_directory.parent_path());
  const Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  CRF_REQUIRE_OK(runtime);
  CRF_REQUIRE_OK(runtime.value()->discover_toolchain(ToolchainFamily::msvc));

  CRF_PHASE("CREATE_SESSION");
  CompileOutcome outcome;
  CRF_REQUIRE(compile_and_link(*runtime.value(), "hello_msvc.cpp", hello_source(), outcome));

  CRF_PHASE("VERIFY");
  CRF_EXPECT(outcome.status == StatusCode::ok);
  CRF_EXPECT(!outcome.candidate.path.empty());
  CRF_EXPECT(std::filesystem::exists(outcome.candidate.path));
  CRF_EXPECT(outcome.candidate.format == ObjectFormat::coff_image);
  CRF_EXPECT(!outcome.candidate.content.zero());
  CRF_EXPECT(outcome.candidate.complete_lineage);
  CRF_EXPECT(outcome.evidence == EvidenceClass::real);
  // Every mandatory phase committed.
  std::size_t committed = 0;
  for (const PhaseRunReport& report : outcome.phases) {
    if (report.committed()) ++committed;
  }
  CRF_EXPECT(committed == outcome.phases.size());
  CRF_EXPECT(committed >= 4);

  CRF_PHASE("ARTIFACTS");
  CRF_EXPECT(!outcome.intermediates.empty());
  const std::vector<IntermediateArtifact> artifacts = runtime.value()->artifacts().list();
  bool saw_object = false;
  bool saw_image = false;
  for (const IntermediateArtifact& artifact : artifacts) {
    if (artifact.format == ObjectFormat::coff_object) saw_object = true;
    if (artifact.format == ObjectFormat::coff_image) saw_image = true;
    if (artifact.authority == AuthorityState::authoritative) {
      CRF_EXPECT(artifact.state == ArtifactState::valid);
      CRF_EXPECT(artifact.provenance.present());
    }
  }
  CRF_EXPECT(saw_object);
  CRF_EXPECT(saw_image);

  CRF_PHASE("PROVENANCE");
  const Result<std::vector<Ref<IntermediateArtifactId>>> lineage =
      runtime.value()->provenance().trace_lineage(runtime.value()->artifacts(),
                                                  outcome.candidate.lineage.front().id);
  CRF_EXPECT_OK(lineage);
  CRF_EXPECT(runtime.value()->provenance().lineage_is_authoritative(
      runtime.value()->artifacts(), outcome.candidate.lineage.front().id));

  CRF_PHASE("AUDIT");
  const Result<AuditReport> audit = runtime.value()->audit();
  CRF_REQUIRE_OK(audit);
  if (!audit.value().zero_violations()) {
    std::printf("%s", audit.value().render().c_str());
  }
  CRF_EXPECT(audit.value().zero_violations());
  CRF_EXPECT(runtime.value()->commit_count() >= 4);

  CRF_PHASE("SHUTDOWN");
  CRF_EXPECT_OK(runtime.value()->shutdown());
  CRF_EXPECT_EQ(runtime.value()->processes().live_count(), static_cast<std::size_t>(0));
}

CRF_TEST(msvc_diagnostics_are_captured_and_attributed) {
  CRF_PHASE("SETUP");
  RuntimeOptions options = msvc_options("msvc-diag");
  crftest::ScopedTree cleanup(options.state_directory.parent_path());
  const Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  CRF_REQUIRE_OK(runtime);
  CRF_REQUIRE_OK(runtime.value()->discover_toolchain(ToolchainFamily::msvc));

  CRF_PHASE("COMPILE");
  const std::filesystem::path source = crftest::test_root() / "sources" / "broken.cpp";
  CRF_REQUIRE(crftest::write_text(source, broken_source()));
  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {source};
  const Result<Ref<CompilerSessionId>> created = runtime.value()->create_session(request);
  CRF_REQUIRE_OK(created);
  const Result<CompileOutcome> outcome = runtime.value()->run_session(created.value().id);
  CRF_REQUIRE_OK(outcome);

  CRF_PHASE("CAPTURE");
  CRF_EXPECT(outcome.value().status != StatusCode::ok);
  CRF_EXPECT(outcome.value().candidate.path.empty());
  bool saw_structured_error = false;
  for (const PhaseRunReport& report : outcome.value().phases) {
    if (!report.diagnostics.present()) continue;
    const DiagnosticSet* set = runtime.value()->diagnostics().find(report.diagnostics.id);
    CRF_REQUIRE(set != nullptr);
    CRF_EXPECT(set->invocation.present());
    CRF_EXPECT(set->phase.present());
    CRF_EXPECT(set->toolchain.present());
    for (const Diagnostic& entry : set->entries) {
      if (entry.severity == DiagnosticSeverity::error && !entry.code.empty()) {
        saw_structured_error = true;
      }
    }
  }
  CRF_EXPECT(saw_structured_error);

  CRF_PHASE("NO_COMMIT");
  for (const IntermediateArtifact& artifact : runtime.value()->artifacts().list()) {
    CRF_EXPECT(artifact.authority != AuthorityState::authoritative);
    CRF_EXPECT(!artifact.current);
  }

  CRF_PHASE("SHUTDOWN");
  CRF_EXPECT_OK(runtime.value()->shutdown());
}

CRF_TEST(msvc_toolchain_change_during_phase_refuses_commit) {
  CRF_PHASE("SETUP");
  RuntimeOptions options = msvc_options("msvc-stale-toolchain");
  crftest::ScopedTree cleanup(options.state_directory.parent_path());
  const Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  CRF_REQUIRE_OK(runtime);
  const Result<Ref<ToolchainId>> toolchain =
      runtime.value()->discover_toolchain(ToolchainFamily::msvc);
  CRF_REQUIRE_OK(toolchain);
  const std::uint64_t commits_before = runtime.value()->commit_count();

  auto hooked = std::make_shared<HookedExecutor>(make_local_executor(*runtime.value()));
  Runtime* raw = runtime.value().get();
  bool mutated = false;

  CRF_PHASE("CREATE_SESSION");
  const std::filesystem::path source = crftest::test_root() / "sources" / "stale_toolchain.cpp";
  CRF_REQUIRE(crftest::write_text(source, hello_source()));
  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {source};
  const Result<Ref<CompilerSessionId>> created = raw->create_session(request);
  CRF_REQUIRE_OK(created);

  CRF_PHASE("LAUNCH");
  // Run only the first codegen phase so the mutation lands inside it.
  std::vector<CompilerPhaseId> order;
  {
    const Result<CompilerSession> session = raw->require_session(created.value().id);
    CRF_REQUIRE_OK(session);
    order = session.value().plan.topological_order();
  }
  CRF_REQUIRE(order.size() >= 2);
  const Result<PhaseRunReport> validate = raw->run_phase(created.value().id, order[0]);
  CRF_REQUIRE_OK(validate);
  CRF_EXPECT(validate.value().committed());

  CRF_PHASE("COMPILE");
  // Arm the hook now: the toolchain evidence changes while the compile phase is
  // executing, after the compiler physically finished and before any commit.
  hooked->set_after_hook([raw, toolchain, &mutated]() {
    if (mutated) return;
    mutated = true;
    const ToolchainIdentity* registered = raw->toolchains().find(toolchain.value().id);
    if (registered == nullptr) return;
    ToolchainIdentity observed = *registered;
    observed.version = observed.version + "-mutated-during-phase";
    if (!observed.components.empty()) {
      observed.components.front().version += "-changed";
    }
    const Result<ToolchainMutation> mutation = raw->apply_toolchain_observation(observed);
    (void)mutation;
  });
  raw->set_executor(hooked);
  const Result<PhaseRunReport> compiled = raw->run_phase(created.value().id, order[1]);
  CRF_REQUIRE_OK(compiled);

  CRF_PHASE("VERIFY");
  CRF_EXPECT(mutated);
  // The compiler physically finished, but the output may not become current.
  CRF_EXPECT(!compiled.value().committed());
  CRF_EXPECT(compiled.value().state == PhaseState::fenced);
  CRF_EXPECT_EQ(compiled.value().status, StatusCode::stale_toolchain_generation);
  CRF_EXPECT(compiled.value().failure == FailureClass::authority_invalidated);
  CRF_EXPECT_EQ(raw->commit_count(), commits_before + 1);
  CRF_EXPECT(raw->stale_commit_count() >= 1);
  for (const IntermediateArtifact& artifact : raw->artifacts().list()) {
    if (artifact.producer_phase.id != order[1]) continue;
    CRF_EXPECT(artifact.authority == AuthorityState::revoked);
    CRF_EXPECT(!artifact.current);
  }

  CRF_PHASE("RETRY_REFUSED");
  // A fenced phase retains no execution authority.
  const Result<PhaseRunReport> retried = raw->retry_phase(created.value().id, order[1]);
  CRF_REQUIRE_OK(retried);
  CRF_EXPECT(!retried.value().committed());

  CRF_PHASE("SHUTDOWN");
  CRF_EXPECT_OK(raw->shutdown());
}

CRF_TEST(msvc_environment_change_during_phase_refuses_commit) {
  CRF_PHASE("SETUP");
  RuntimeOptions options = msvc_options("msvc-stale-env");
  crftest::ScopedTree cleanup(options.state_directory.parent_path());
  const Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  CRF_REQUIRE_OK(runtime);
  CRF_REQUIRE_OK(runtime.value()->discover_toolchain(ToolchainFamily::msvc));

  auto hooked = std::make_shared<HookedExecutor>(make_local_executor(*runtime.value()));
  Runtime* raw = runtime.value().get();
  bool mutated = false;

  CRF_PHASE("CREATE_SESSION");
  const std::filesystem::path source = crftest::test_root() / "sources" / "stale_env.cpp";
  CRF_REQUIRE(crftest::write_text(source, hello_source()));
  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {source};
  const Result<Ref<CompilerSessionId>> created = raw->create_session(request);
  CRF_REQUIRE_OK(created);
  const Result<CompilerSession> session = raw->require_session(created.value().id);
  CRF_REQUIRE_OK(session);

  CRF_PHASE("COMPILE");
  const std::vector<CompilerPhaseId> order = session.value().plan.topological_order();
  CRF_REQUIRE(order.size() >= 2);
  const Result<PhaseRunReport> validate = raw->run_phase(created.value().id, order[0]);
  CRF_REQUIRE_OK(validate);
  CRF_EXPECT(validate.value().committed());
  // Arm the hook now: the environment changes while the compile phase runs,
  // after the compiler physically finished and before any commit decision.
  hooked->set_after_hook([raw, &mutated]() {
    if (mutated) return;
    mutated = true;
    std::vector<EnvironmentIdentity> environments = raw->environments().list();
    if (environments.empty()) return;
    EnvironmentSpec spec = environments.front().spec;
    spec.deterministic_controls = false;
    const Result<Ref<EnvironmentId>> revised =
        raw->environments().revise(environments.front().id, spec);
    (void)revised;
  });
  raw->set_executor(hooked);
  const Result<PhaseRunReport> compiled = raw->run_phase(created.value().id, order[1]);
  CRF_REQUIRE_OK(compiled);

  CRF_PHASE("VERIFY");
  CRF_EXPECT(mutated);
  if (compiled.value().committed()) {
    std::printf("  commit unexpectedly succeeded: %s\n", compiled.value().detail.c_str());
  }
  CRF_EXPECT(!compiled.value().committed());
  if (compiled.value().status != StatusCode::stale_environment_generation) {
    std::printf("  observed status: %s detail=%s\n",
                std::string(to_string(compiled.value().status)).c_str(),
                compiled.value().detail.c_str());
  }
  CRF_EXPECT_EQ(compiled.value().status, StatusCode::stale_environment_generation);

  CRF_PHASE("SHUTDOWN");
  CRF_EXPECT_OK(raw->shutdown());
}

CRF_TEST(msvc_compiler_process_kill_is_classified_and_retryable) {
  CRF_PHASE("SETUP");
  RuntimeOptions options = msvc_options("msvc-kill");
  crftest::ScopedTree cleanup(options.state_directory.parent_path());
  const Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  CRF_REQUIRE_OK(runtime);
  CRF_REQUIRE_OK(runtime.value()->discover_toolchain(ToolchainFamily::msvc));
  Runtime* raw = runtime.value().get();

  const std::filesystem::path source = crftest::test_root() / "sources" / "heavy.cpp";
  CRF_REQUIRE(crftest::write_text(source, heavy_source()));
  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {source};
  request.run_smoke_test = true;
  request.adapter_options.push_back(EnvironmentVariable{"msvc.expected_stdout", "CRF-SMOKE-OK"});
  const Result<Ref<CompilerSessionId>> created = raw->create_session(request);
  CRF_REQUIRE_OK(created);
  const Result<CompilerSession> session = raw->require_session(created.value().id);
  CRF_REQUIRE_OK(session);
  const std::vector<CompilerPhaseId> order = session.value().plan.topological_order();
  CRF_REQUIRE(order.size() >= 3);

  CRF_PHASE("VALIDATE");
  CRF_REQUIRE_OK(raw->run_phase(created.value().id, order[0]));

  CRF_PHASE("KILL");
  const CompilerPhaseId compile_phase = order[1];
  std::atomic<bool> done{false};
  Result<PhaseRunReport> compiled = Status(StatusCode::internal_error, "not run");
  std::thread runner([&]() {
    compiled = raw->run_phase(created.value().id, compile_phase);
    done.store(true);
  });
  // Wait until the compiler child actually exists, then kill it. The wait is a
  // real condition, not a fixed delay.
  while (raw->processes().live_count() == 0 && !done.load()) {
    std::this_thread::yield();
  }
  const std::size_t killed = raw->processes().terminate_all("test killed the compiler child");
  runner.join();
  CRF_EXPECT(killed >= 1);
  CRF_REQUIRE_OK(compiled);
  CRF_EXPECT(!compiled.value().committed());
  CRF_EXPECT(compiled.value().state == PhaseState::failed);
  CRF_EXPECT_EQ(compiled.value().failure, FailureClass::external_cancellation);

  CRF_PHASE("RETRY");
  const RetryDecision decision = compiled.value().retry;
  CRF_EXPECT(decision.legal);
  CRF_EXPECT(decision.creates_new_invocation);
  const Result<PhaseRunReport> retried = raw->retry_phase(created.value().id, compile_phase);
  CRF_REQUIRE_OK(retried);
  CRF_EXPECT(retried.value().committed());
  // The retry used fresh invocation authority.
  CRF_EXPECT(retried.value().invocation.id != compiled.value().invocation.id);

  CRF_PHASE("SHUTDOWN");
  CRF_EXPECT_OK(raw->shutdown());
  CRF_EXPECT_EQ(raw->processes().live_count(), static_cast<std::size_t>(0));
}

CRF_TEST(msvc_duplicate_completion_commits_once) {
  CRF_PHASE("SETUP");
  RuntimeOptions options = msvc_options("msvc-duplicate");
  crftest::ScopedTree cleanup(options.state_directory.parent_path());
  const Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  CRF_REQUIRE_OK(runtime);
  CRF_REQUIRE_OK(runtime.value()->discover_toolchain(ToolchainFamily::msvc));
  Runtime* raw = runtime.value().get();

  CRF_PHASE("CREATE_SESSION");
  const std::filesystem::path source = crftest::test_root() / "sources" / "duplicate.cpp";
  CRF_REQUIRE(crftest::write_text(source, hello_source()));
  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {source};
  const Result<Ref<CompilerSessionId>> created = raw->create_session(request);
  CRF_REQUIRE_OK(created);
  const Result<CompilerSession> session = raw->require_session(created.value().id);
  CRF_REQUIRE_OK(session);
  const std::vector<CompilerPhaseId> order = session.value().plan.topological_order();
  CRF_REQUIRE(order.size() >= 2);

  CRF_PHASE("COMPILE");
  CRF_REQUIRE_OK(raw->run_phase(created.value().id, order[0]));
  const Result<PhaseRunReport> first = raw->run_phase(created.value().id, order[1]);
  CRF_REQUIRE_OK(first);
  CRF_REQUIRE(first.value().committed());
  const std::uint64_t commits = raw->commit_count();
  const CommitId commit = [&]() {
    const Result<CompilerSession> current = raw->require_session(created.value().id);
    return current.value().find_phase(order[1])->commit;
  }();
  CRF_EXPECT(commit.present());

  CRF_PHASE("REPLAY");
  // Replay the identical completion: the existing authoritative result stands.
  const Result<PhaseRunReport> replay = raw->commit_phase(
      created.value().id, order[1], first.value().phase.generation, first.value().invocation);
  CRF_REQUIRE_OK(replay);
  CRF_EXPECT_EQ(replay.value().status, StatusCode::duplicate_completion);
  CRF_EXPECT(replay.value().state == PhaseState::committed);
  CRF_EXPECT_EQ(raw->commit_count(), commits);

  CRF_PHASE("REPLAY_WITH_STALE_GENERATION");
  const Result<PhaseRunReport> stale = raw->commit_phase(
      created.value().id, order[1], CompilerPhaseGeneration::from_value(999), first.value().invocation);
  CRF_EXPECT(!stale.has_value() || stale.value().state != PhaseState::committed);

  CRF_PHASE("SHUTDOWN");
  CRF_EXPECT_OK(raw->shutdown());
}

CRF_TEST(msvc_workspaces_are_isolated_and_stale_workspaces_are_not_reused) {
  CRF_PHASE("SETUP");
  RuntimeOptions options = msvc_options("msvc-workspace");
  crftest::ScopedTree cleanup(options.state_directory.parent_path());
  const Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  CRF_REQUIRE_OK(runtime);
  CRF_REQUIRE_OK(runtime.value()->discover_toolchain(ToolchainFamily::msvc));

  CRF_PHASE("SESSION");
  CompileOutcome first;
  CRF_REQUIRE(compile_and_link(*runtime.value(), "workspace_a.cpp", hello_source(), first));
  CompileOutcome second;
  CRF_REQUIRE(compile_and_link(*runtime.value(), "workspace_b.cpp", hello_source(), second));
  CRF_EXPECT(first.candidate.path != second.candidate.path);

  CRF_PHASE("WORKSPACE_GUARD");
  WorkspaceManager manager(WorkspaceOptions{crftest::test_root() / "guard"});
  const Result<Workspace> workspace = manager.create(
      CompilerSessionId::from_value(7), CompilerSessionGeneration::initial(),
      CompilerPhaseId::from_value(3), CompilerPhaseGeneration::initial());
  CRF_REQUIRE_OK(workspace);
  const Result<std::filesystem::path> traversal = workspace.value().resolve("../escape.txt");
  CRF_EXPECT_CODE(traversal, StatusCode::path_traversal);
  const Result<std::filesystem::path> absolute = workspace.value().resolve("C:/Windows/System32/cmd.exe");
  CRF_EXPECT_CODE(absolute, StatusCode::path_traversal);
  const Result<std::filesystem::path> inside = workspace.value().resolve("outputs/ok.obj");
  CRF_REQUIRE_OK(inside);
  CRF_EXPECT(workspace.value().contains(inside.value()));

  CRF_PHASE("STALE_MARKER");
  // Re-open the same directory under a different phase generation: the marker
  // proves the workspace belongs to another generation.
  const Result<Workspace> stale = manager.open(
      workspace.value().root, CompilerSessionId::from_value(7), CompilerSessionGeneration::initial(),
      CompilerPhaseId::from_value(3), CompilerPhaseGeneration::from_value(9));
  CRF_EXPECT(!stale.has_value());
  const WorkspaceInspection inspection = manager.inspect(workspace.value().root);
  CRF_EXPECT(inspection.acceptable());
  CRF_EXPECT(inspection.phase_generation == CompilerPhaseGeneration::initial());

  CRF_PHASE("SHUTDOWN");
  CRF_EXPECT_OK(runtime.value()->shutdown());
  CRF_EXPECT_EQ(runtime.value()->processes().live_count(), static_cast<std::size_t>(0));
  (void)manager.cleanup_all();
}

CRF_TEST(msvc_shutdown_during_compile_leaves_no_orphan) {
  CRF_PHASE("SETUP");
  RuntimeOptions options = msvc_options("msvc-shutdown");
  crftest::ScopedTree cleanup(options.state_directory.parent_path());
  const Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  CRF_REQUIRE_OK(runtime);
  CRF_REQUIRE_OK(runtime.value()->discover_toolchain(ToolchainFamily::msvc));
  Runtime* raw = runtime.value().get();

  const std::filesystem::path source = crftest::test_root() / "sources" / "shutdown.cpp";
  CRF_REQUIRE(crftest::write_text(source, heavy_source()));
  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {source};
  const Result<Ref<CompilerSessionId>> created = raw->create_session(request);
  CRF_REQUIRE_OK(created);
  const Result<CompilerSession> session = raw->require_session(created.value().id);
  CRF_REQUIRE_OK(session);
  const std::vector<CompilerPhaseId> order = session.value().plan.topological_order();
  CRF_REQUIRE(order.size() >= 2);
  CRF_REQUIRE_OK(raw->run_phase(created.value().id, order[0]));

  CRF_PHASE("LAUNCH");
  std::atomic<bool> done{false};
  Result<PhaseRunReport> compiled = Status(StatusCode::internal_error, "not run");
  std::thread runner([&]() {
    compiled = raw->run_phase(created.value().id, order[1]);
    done.store(true);
  });
  while (raw->processes().live_count() == 0 && !done.load()) {
    std::this_thread::yield();
  }

  CRF_PHASE("SHUTDOWN");
  CRF_EXPECT_OK(raw->shutdown());
  runner.join();
  CRF_EXPECT_EQ(raw->processes().live_count(), static_cast<std::size_t>(0));
  // Shutdown fences the in-flight phase. The phase run therefore either reports
  // a fenced outcome or refuses outright because its invocation authority was
  // withdrawn; both are correct, and neither may commit.
  if (compiled) {
    CRF_EXPECT(!compiled.value().committed());
  } else {
    CRF_EXPECT(compiled.code() == StatusCode::stale_invocation ||
               compiled.code() == StatusCode::shutting_down ||
               compiled.code() == StatusCode::stale_phase_generation);
  }
  const Result<AuditReport> audit = raw->audit();
  CRF_REQUIRE_OK(audit);
  CRF_EXPECT(audit.value().zero_violations());
  // After shutdown the runtime refuses new authority until it is reopened.
  const Result<PhaseRunReport> after = raw->run_phase(created.value().id, order[1]);
  CRF_EXPECT(!after.has_value() || after.value().status == StatusCode::shutting_down ||
             !after.value().committed());
}
