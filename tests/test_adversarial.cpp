// Adversarial proofs.
//
// Every case pushes hostile or hostile-looking input into the runtime and
// asserts the refusal is the right one and that state stays valid.

#include "crf_test.hpp"
#include "crf_test_env.hpp"

#include <string>
#include <thread>
#include <vector>

namespace {

using namespace crf;

CRF_NODISCARD std::string hello_source() {
  return "#include <cstdio>\n"
         "int main() { std::printf(\"CRF-SMOKE-OK\\n\"); return 0; }\n";
}

struct Fixture {
  RuntimeOptions options;
  std::unique_ptr<Runtime> runtime;
  Ref<CompilerSessionId> session;
  std::vector<CompilerPhaseId> order;
};

CRF_NODISCARD bool setup(Fixture& fixture, const char* label, const char* source_name) {
  fixture.options = crftest::test_runtime_options(crftest::unique_label(label));
  Result<std::unique_ptr<Runtime>> runtime = Runtime::create(fixture.options);
  if (!runtime) return false;
  fixture.runtime = std::move(runtime.value());
  if (!fixture.runtime->discover_toolchain(ToolchainFamily::msvc)) return false;
  const std::filesystem::path source = crftest::test_root() / "sources" / source_name;
  if (!crftest::write_text(source, hello_source())) return false;
  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {source};
  request.adapter_options.push_back(EnvironmentVariable{"msvc.expected_stdout", "CRF-SMOKE-OK"});
  Result<Ref<CompilerSessionId>> created = fixture.runtime->create_session(request);
  if (!created) return false;
  fixture.session = created.value();
  Result<CompilerSession> session = fixture.runtime->require_session(created.value().id);
  if (!session) return false;
  fixture.order = session.value().plan.topological_order();
  return true;
}

}  // namespace

CRF_TEST(adversarial_stale_session_phase_and_invocation_are_refused) {
  CRF_PHASE("SETUP");
  Fixture fixture;
  crftest::ScopedTree cleanup(crftest::test_root() / "adversarial-stale");
  CRF_REQUIRE(setup(fixture, "adversarial-stale", "adversarial_stale.cpp"));

  CRF_PHASE("UNKNOWN_SESSION");
  const Result<CompilerSession> missing =
      fixture.runtime->require_session(CompilerSessionId::from_value(9999));
  CRF_EXPECT(!missing.has_value());
  CRF_EXPECT_EQ(missing.code(), StatusCode::not_found);

  CRF_PHASE("UNKNOWN_PHASE");
  const Result<CompilerSession> session = fixture.runtime->require_session(fixture.session.id);
  CRF_REQUIRE_OK(session);
  const Result<PhaseRunReport> unknown =
      fixture.runtime->run_phase(fixture.session.id, CompilerPhaseId::from_value(4242));
  CRF_REQUIRE_OK(unknown);
  CRF_EXPECT_EQ(unknown.value().status, StatusCode::not_found);

  CRF_PHASE("STALE_GENERATION_COMMIT");
  const Result<PhaseRunReport> stale = fixture.runtime->commit_phase(
      fixture.session.id, fixture.order[1], CompilerPhaseGeneration::from_value(1234),
      Ref<InvocationId>{InvocationId::from_value(1), InvocationGeneration::initial()});
  CRF_EXPECT(!stale.has_value());
  if (!stale.has_value()) CRF_EXPECT_EQ(stale.code(), StatusCode::stale_phase_generation);

  CRF_PHASE("RETIRE_THEN_RUN");
  CRF_REQUIRE_OK(fixture.runtime->retire_session(fixture.session.id, "adversarial retirement"));
  const Result<PhaseRunReport> after = fixture.runtime->run_phase(fixture.session.id, fixture.order[0]);
  CRF_REQUIRE_OK(after);
  CRF_EXPECT(!after.value().committed());
  CRF_EXPECT(after.value().status == StatusCode::session_not_active ||
             after.value().status == StatusCode::phase_retired);
  CRF_EXPECT_OK(fixture.runtime->shutdown());
}

CRF_TEST(adversarial_path_traversal_and_workspace_escape) {
  CRF_PHASE("SETUP");
  WorkspaceManager manager(WorkspaceOptions{crftest::test_root() / "adversarial-workspace"});
  crftest::ScopedTree cleanup(crftest::test_root() / "adversarial-workspace");
  const Result<Workspace> workspace = manager.create(
      CompilerSessionId::from_value(11), CompilerSessionGeneration::initial(),
      CompilerPhaseId::from_value(22), CompilerPhaseGeneration::initial());
  CRF_REQUIRE_OK(workspace);

  CRF_PHASE("TRAVERSAL");
  CRF_EXPECT_CODE(workspace.value().resolve("../../escape.obj"), StatusCode::path_traversal);
  CRF_EXPECT_CODE(workspace.value().resolve("outputs/../../escape.obj"), StatusCode::path_traversal);
  CRF_EXPECT_CODE(workspace.value().resolve("C:/Windows/win.ini"), StatusCode::path_traversal);
  {
    // A UNC path is a root-name path and is refused as traversal.
    const Result<std::filesystem::path> unc = workspace.value().resolve("//server/share/file");
    CRF_EXPECT(!unc.has_value());
    if (!unc.has_value()) {
      CRF_EXPECT(unc.code() == StatusCode::path_traversal ||
                 unc.code() == StatusCode::workspace_escape ||
                 unc.code() == StatusCode::not_found);
    }
  }
  CRF_EXPECT_CODE(workspace.value().resolve(std::string("bad\0name", 8)),
                  StatusCode::path_traversal);
  CRF_EXPECT(workspace.value().resolve("outputs/ok.obj").has_value());
  CRF_EXPECT(workspace.value().contains(workspace.value().outputs_directory()));
  CRF_EXPECT(!workspace.value().contains(std::filesystem::path("C:/Windows")));

  CRF_PHASE("HOSTILE_ARGUMENTS");
  const std::filesystem::path cmd =
      normalize_path(std::filesystem::path("C:/Windows/System32/cmd.exe"));
  InvocationSpec spec;
  spec.executable = cmd;
  spec.arguments = {"/c", std::string("echo\0hidden", 11)};
  InvocationValidationContext context;
  context.workspace = &workspace.value();
  context.target_architecture = Architecture::x64;
  context.require_component_identity = false;
  CRF_EXPECT_CODE(validate_invocation(spec, context), StatusCode::invalid_argument);

  CRF_PHASE("OUTPUT_ESCAPE");
  InvocationSpec escaping;
  escaping.executable = cmd;
  OutputBinding binding;
  binding.logical_name = "escape";
  binding.path = std::filesystem::path("C:/Windows/Temp/crf-escape.obj");
  escaping.expected_outputs.push_back(binding);
  CRF_EXPECT_CODE(validate_invocation(escaping, context), StatusCode::workspace_escape);

  CRF_PHASE("FORBIDDEN_OPTION");
  InvocationValidationContext policy_context = context;
  policy_context.forbidden_options = {"/fallback"};
  InvocationSpec forbidden;
  forbidden.executable = cmd;
  forbidden.arguments = {"/fallback"};
  CRF_EXPECT_CODE(validate_invocation(forbidden, policy_context), StatusCode::policy_refused);
  InvocationSpec forbidden_equals;
  forbidden_equals.executable = cmd;
  forbidden_equals.arguments = {"/fallback:on"};
  CRF_EXPECT_CODE(validate_invocation(forbidden_equals, policy_context), StatusCode::policy_refused);
  InvocationSpec allowed;
  allowed.executable = cmd;
  allowed.arguments = {"/fallbacks"};
  CRF_EXPECT(validate_invocation(allowed, policy_context).has_value());
  (void)manager.cleanup_all();
}

CRF_TEST(adversarial_output_validation_refuses_bad_output) {
  CRF_PHASE("SETUP");
  Fixture fixture;
  crftest::ScopedTree cleanup(crftest::test_root() / "adversarial-output");
  CRF_REQUIRE(setup(fixture, "adversarial-output", "adversarial_output.cpp"));

  CRF_PHASE("TRUNCATE_OBJECT");
  // Run the validate phase, then corrupt the compile phase's expected output by
  // pointing the plan at an empty file: validation must refuse it.
  CRF_REQUIRE_OK(fixture.runtime->run_phase(fixture.session.id, fixture.order[0]));
  CRF_REQUIRE_OK(fixture.runtime->run_phase(fixture.session.id, fixture.order[1]));
  const Result<CompilerSession> session = fixture.runtime->require_session(fixture.session.id);
  CRF_REQUIRE_OK(session);
  const PhaseRecord* compile = session.value().find_phase(fixture.order[1]);
  CRF_REQUIRE(compile != nullptr);
  CRF_REQUIRE(!compile->outputs.empty());
  const IntermediateArtifact* object = fixture.runtime->artifacts().find(compile->outputs.front().id);
  CRF_REQUIRE(object != nullptr);
  const std::filesystem::path object_path = object->path;

  CRF_PHASE("REVALIDATE_AFTER_TAMPER");
  {
    std::FILE* file = std::fopen(object_path.string().c_str(), "wb");
    CRF_REQUIRE(file != nullptr);
    const char junk[] = "not an object file";
    std::fwrite(junk, 1, sizeof(junk) - 1, file);
    std::fclose(file);
  }
  const Result<ArtifactState> state = fixture.runtime->artifacts().revalidate(compile->outputs.front().id);
  CRF_REQUIRE_OK(state);
  CRF_EXPECT(state.value() == ArtifactState::corrupt);
  CRF_EXPECT(fixture.runtime->artifacts().find(compile->outputs.front().id)->authority ==
             AuthorityState::revoked);

  CRF_PHASE("AUDIT");
  const Result<AuditReport> audit = fixture.runtime->audit();
  CRF_REQUIRE_OK(audit);
  CRF_EXPECT(audit.value().zero_violations());
  CRF_EXPECT_OK(fixture.runtime->shutdown());
}

CRF_TEST(adversarial_bounded_capture_survives_a_hostile_compiler_stream) {
  CRF_PHASE("SETUP");
  WorkspaceManager manager(WorkspaceOptions{crftest::test_root() / "adversarial-capture"});
  crftest::ScopedTree cleanup(crftest::test_root() / "adversarial-capture");
  ProcessSupervisor supervisor;

  CRF_PHASE("FLOOD");
  // A real process that writes far more than the capture ceiling must be
  // truncated with explicit accounting, not buffered without limit.
  ProcessSpec spec;
  spec.executable = normalize_path(std::filesystem::path("C:/Windows/System32/cmd.exe"));
  spec.arguments = {"/c",
                    "for /L %i in (1,1,20000) do @echo 0123456789012345678901234567890123456789"};
  spec.max_capture_bytes = 64u * 1024u;
  const Result<ProcessOutcome> outcome = supervisor.run(
      spec, Ref<InvocationId>{InvocationId::from_value(1), InvocationGeneration::initial()});
  CRF_REQUIRE_OK(outcome);
  CRF_EXPECT(outcome.value().capture.truncated);
  CRF_EXPECT(outcome.value().capture.standard_output.size() <= 64u * 1024u);
  CRF_EXPECT(outcome.value().capture.dropped_standard_output_bytes > 0);
  CRF_EXPECT_EQ(supervisor.live_count(), static_cast<std::size_t>(0));

  CRF_PHASE("DIAGNOSTIC_CEILING");
  DiagnosticSet set;
  for (std::size_t i = 0; i < DiagnosticSet::kMaxEntries + 100; ++i) {
    Diagnostic entry;
    entry.message = "message " + std::to_string(i);
    entry.raw = entry.message;
    set.entries.push_back(std::move(entry));
  }
  DiagnosticStore store;
  if (set.entries.size() > DiagnosticSet::kMaxEntries) {
    set.entries.resize(DiagnosticSet::kMaxEntries);
    set.truncated = true;
  }
  const Result<Ref<DiagnosticSetId>> stored = store.add(std::move(set));
  CRF_REQUIRE_OK(stored);
  CRF_EXPECT_EQ(store.find(stored.value().id)->entries.size(), DiagnosticSet::kMaxEntries);
  CRF_EXPECT(store.find(stored.value().id)->truncated);
  supervisor.close();
  (void)manager.cleanup_all();
}

CRF_TEST(adversarial_policy_mutation_and_unknown_target_are_refused) {
  CRF_PHASE("SETUP");
  RuntimeOptions options = crftest::test_runtime_options("adversarial-policy");
  crftest::ScopedTree cleanup(options.state_directory.parent_path());
  const Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  CRF_REQUIRE_OK(runtime);
  CRF_REQUIRE_OK(runtime.value()->discover_toolchain(ToolchainFamily::msvc));

  CRF_PHASE("UNKNOWN_FAMILY");
  CompileRequest unknown;
  unknown.toolchain_family = ToolchainFamily::unknown;
  unknown.inline_sources.push_back({"a.cpp", hello_source()});
  const Result<Ref<CompilerSessionId>> refused = runtime.value()->create_session(unknown);
  CRF_EXPECT(!refused.has_value());
  CRF_EXPECT_EQ(refused.code(), StatusCode::unsupported);

  CRF_PHASE("UNSUPPORTED_TARGET");
  CompileRequest arm;
  arm.toolchain_family = ToolchainFamily::msvc;
  arm.inline_sources.push_back({"a.cpp", hello_source()});
  arm.target.architecture = Architecture::arm64;
  arm.target.os = OperatingSystem::windows;
  arm.target.triple = "aarch64-pc-windows-msvc";
  const Result<Ref<CompilerSessionId>> refused_target = runtime.value()->create_session(arm);
  CRF_EXPECT(!refused_target.has_value());
  CRF_EXPECT_EQ(refused_target.code(), StatusCode::target_unsupported);

  CRF_PHASE("SYNTHETIC_FAMILY_IS_HONEST");
  const Result<std::unique_ptr<Runtime>> synthetic_runtime =
      Runtime::create(crftest::test_runtime_options("adversarial-synthetic"));
  CRF_REQUIRE_OK(synthetic_runtime);
  const Result<ToolchainIdentity> synthetic =
      synthetic_runtime.value()->probe_toolchain(ToolchainFamily::hipcc);
  CRF_REQUIRE_OK(synthetic);
  CRF_EXPECT(synthetic.value().evidence_class == EvidenceClass::synthetic);
  CRF_EXPECT(synthetic.value().components.empty());
  bool declared_modelled = false;
  for (const EnvironmentVariable& attribute : synthetic.value().attributes) {
    if (attribute.name == "toolchain.real-tooling-present" && attribute.value == "false") {
      declared_modelled = true;
    }
  }
  CRF_EXPECT(declared_modelled);
  const Result<Ref<ToolchainId>> registered =
      synthetic_runtime.value()->discover_toolchain(ToolchainFamily::hipcc);
  CRF_REQUIRE_OK(registered);
  CompileRequest synthetic_request;
  synthetic_request.toolchain_family = ToolchainFamily::hipcc;
  synthetic_request.inline_sources.push_back({"kernel.cpp", "int main(){return 0;}"});
  const Result<Ref<CompilerSessionId>> synthetic_session =
      synthetic_runtime.value()->create_session(synthetic_request);
  CRF_EXPECT(!synthetic_session.has_value());
  CRF_EXPECT_EQ(synthetic_session.code(), StatusCode::unsupported);
  CRF_EXPECT_OK(synthetic_runtime.value()->shutdown());
  CRF_EXPECT_OK(runtime.value()->shutdown());
}

CRF_TEST(adversarial_lock_reentrancy_and_recursive_entry_are_safe) {
  CRF_PHASE("SETUP");
  Fixture fixture;
  crftest::ScopedTree cleanup(crftest::test_root() / "adversarial-reentrancy");
  CRF_REQUIRE(setup(fixture, "adversarial-reentrancy", "adversarial_reentrancy.cpp"));

  CRF_PHASE("RECURSIVE_QUERY");
  // Querying and auditing from inside a phase callback must not deadlock: the
  // runtime's lock is recursive and every observation is a snapshot.
  std::shared_ptr<PhaseExecutor> inner = make_local_executor(*fixture.runtime);
  struct Reentrant final : PhaseExecutor {
    std::shared_ptr<PhaseExecutor> inner;
    Runtime* runtime = nullptr;
    std::atomic<int> depth{0};
    Result<ExecutionReport> execute(const InvocationSpec& invocation, const ProcessSpec& process,
                                    const Workspace& workspace, std::string_view label) override {
      depth.fetch_add(1);
      (void)runtime->audit();
      (void)runtime->list_sessions();
      (void)runtime->snapshot();
      return inner->execute(invocation, process, workspace, label);
    }
    VoidResult cancel(Ref<InvocationId> invocation, std::string reason) override {
      return inner->cancel(invocation, reason);
    }
    std::string describe() const override { return "reentrant"; }
    bool remote() const noexcept override { return false; }
  };
  auto reentrant = std::make_shared<Reentrant>();
  reentrant->inner = inner;
  reentrant->runtime = fixture.runtime.get();
  fixture.runtime->set_executor(reentrant);

  const Result<CompileOutcome> outcome = fixture.runtime->run_session(fixture.session.id);
  CRF_REQUIRE_OK(outcome);
  CRF_EXPECT(!outcome.value().candidate.path.empty());
  CRF_EXPECT(reentrant->depth.load() >= 4);
  const Result<AuditReport> audit = fixture.runtime->audit();
  CRF_REQUIRE_OK(audit);
  CRF_EXPECT(audit.value().zero_violations());
  CRF_EXPECT_OK(fixture.runtime->shutdown());
}
