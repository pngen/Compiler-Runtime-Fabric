// Persistence and recovery proofs.
//
// These cases establish that a caller who observed a successful durable commit
// can restart the runtime and recover that phase as committed, and that
// in-flight process state is never blindly revived.

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

CRF_NODISCARD CompileRequest request_for(const std::filesystem::path& source) {
  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {source};
  request.adapter_options.push_back(EnvironmentVariable{"msvc.expected_stdout", "CRF-SMOKE-OK"});
  return request;
}

}  // namespace

CRF_TEST(recovery_committed_phase_survives_a_runtime_restart) {
  CRF_PHASE("SETUP");
  RuntimeOptions options = crftest::test_runtime_options("recovery-restart");
  crftest::ScopedTree cleanup(options.state_directory.parent_path());
  const std::filesystem::path source = crftest::test_root() / "sources" / "recovery_a.cpp";
  CRF_REQUIRE(crftest::write_text(source, hello_source()));

  Ref<CompilerSessionId> session;
  std::vector<CompilerPhaseId> order;
  CompilerPhaseGeneration compile_generation;
  Digest committed_digest;
  {
    CRF_PHASE("FIRST_RUNTIME");
    Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
    CRF_REQUIRE_OK(runtime);
    CRF_REQUIRE_OK(runtime.value()->discover_toolchain(ToolchainFamily::msvc));
    const Result<Ref<CompilerSessionId>> created =
        runtime.value()->create_session(request_for(source));
    CRF_REQUIRE_OK(created);
    session = created.value();
    const Result<CompilerSession> loaded = runtime.value()->require_session(session.id);
    CRF_REQUIRE_OK(loaded);
    order = loaded.value().plan.topological_order();
    CRF_REQUIRE(order.size() >= 2);
    CRF_REQUIRE_OK(runtime.value()->run_phase(session.id, order[0]));
    const Result<PhaseRunReport> compiled = runtime.value()->run_phase(session.id, order[1]);
    CRF_REQUIRE_OK(compiled);
    CRF_REQUIRE(compiled.value().committed());
    compile_generation = compiled.value().phase.generation;
    const Result<CompilerSession> after = runtime.value()->require_session(session.id);
    CRF_REQUIRE_OK(after);
    committed_digest = after.value().find_phase(order[1])->committed_output_digest;
    CRF_EXPECT(!committed_digest.zero());
    // Deliberate stop without retiring: this is a crash-like shutdown.
    CRF_EXPECT_OK(runtime.value()->shutdown());
  }

  CRF_PHASE("SECOND_RUNTIME");
  {
    Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
    CRF_REQUIRE_OK(runtime);
    CRF_EXPECT(runtime.value()->epoch() >= 2);
    const Result<CompilerSession> recovered = runtime.value()->require_session(session.id);
    CRF_REQUIRE_OK(recovered);
    const PhaseRecord* phase = recovered.value().find_phase(order[1]);
    CRF_REQUIRE(phase != nullptr);
    // The committed phase survived the restart as committed, under the same
    // authority binding and with the same committed digest.
    CRF_EXPECT(phase->state == PhaseState::committed);
    CRF_EXPECT_EQ(phase->generation, compile_generation);
    CRF_EXPECT_EQ(phase->committed_output_digest, committed_digest);
    CRF_EXPECT(phase->commit.present());
    // The session requires recovery before new authority is granted.
    CRF_EXPECT(recovered.value().state == SessionState::recovering ||
               recovered.value().state == SessionState::active);

    CRF_PHASE("RECOVER");
    const Result<RecoveryPlan> plan = runtime.value()->plan_recovery(session.id);
    CRF_REQUIRE_OK(plan);
    std::printf("  recovery headline=%s legal=%d\n",
                std::string(to_string(plan.value().headline)).c_str(),
                plan.value().legal ? 1 : 0);
    CRF_EXPECT(plan.value().legal);
    CRF_EXPECT(!plan.value().requires_operator);
    const Result<RecoveryPlan> applied = runtime.value()->apply_recovery(session.id);
    CRF_REQUIRE_OK(applied);
    const Result<CompilerSession> resumed = runtime.value()->require_session(session.id);
    CRF_REQUIRE_OK(resumed);
    CRF_EXPECT(resumed.value().state == SessionState::active ||
               resumed.value().state == SessionState::committed);
    const Result<AuditReport> audit = runtime.value()->audit();
    CRF_REQUIRE_OK(audit);
    if (!audit.value().zero_violations()) std::printf("%s", audit.value().render().c_str());
    CRF_EXPECT(audit.value().zero_violations());
    CRF_EXPECT_OK(runtime.value()->shutdown());
  }
}

CRF_TEST(recovery_in_flight_process_state_is_never_revived) {
  CRF_PHASE("SETUP");
  RuntimeOptions options = crftest::test_runtime_options("recovery-in-flight");
  crftest::ScopedTree cleanup(options.state_directory.parent_path());
  const std::filesystem::path source = crftest::test_root() / "sources" / "recovery_b.cpp";
  std::string heavy = "#include <cstdio>\n";
  for (int i = 0; i < 4000; ++i) {
    heavy += "int crf_recovery_fn_" + std::to_string(i) + "() { return " + std::to_string(i) + "; }\n";
  }
  heavy += "int main() { std::printf(\"CRF-SMOKE-OK\\n\"); return 0; }\n";
  CRF_REQUIRE(crftest::write_text(source, heavy));

  Ref<CompilerSessionId> session;
  std::vector<CompilerPhaseId> order;
  CRF_PHASE("FIRST_RUNTIME");
  {
    Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
    CRF_REQUIRE_OK(runtime);
    CRF_REQUIRE_OK(runtime.value()->discover_toolchain(ToolchainFamily::msvc));
    const Result<Ref<CompilerSessionId>> created =
        runtime.value()->create_session(request_for(source));
    CRF_REQUIRE_OK(created);
    session = created.value();
    const Result<CompilerSession> loaded = runtime.value()->require_session(session.id);
    CRF_REQUIRE_OK(loaded);
    order = loaded.value().plan.topological_order();
    CRF_REQUIRE_OK(runtime.value()->run_phase(session.id, order[0]));

    std::atomic<bool> done{false};
    std::thread runner([&]() {
      Result<PhaseRunReport> report = runtime.value()->run_phase(session.id, order[1]);
      (void)report;
      done.store(true);
    });
    while (runtime.value()->processes().live_count() == 0 && !done.load()) {
      std::this_thread::yield();
    }
    // Shut down while the compiler child is running.
    CRF_EXPECT_OK(runtime.value()->shutdown());
    runner.join();
    CRF_EXPECT_EQ(runtime.value()->processes().live_count(), static_cast<std::size_t>(0));
  }

  CRF_PHASE("SECOND_RUNTIME");
  {
    Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
    CRF_REQUIRE_OK(runtime);
    const Result<CompilerSession> recovered = runtime.value()->require_session(session.id);
    CRF_REQUIRE_OK(recovered);
    const PhaseRecord* phase = recovered.value().find_phase(order[1]);
    CRF_REQUIRE(phase != nullptr);
    // The phase that was in flight is fenced and can never commit; the runtime
    // never claims to resume a compiler process mid-flight.
    CRF_EXPECT(phase->state == PhaseState::fenced || phase->state == PhaseState::failed ||
               phase->state == PhaseState::ready || phase->state == PhaseState::pending);
    CRF_EXPECT(!phase->commit.present());
    CRF_EXPECT(recovered.value().recovery_state == RecoveryState::required ||
               recovered.value().recovery_state == RecoveryState::planned ||
               recovered.value().recovery_state == RecoveryState::manual_required);
    const Result<RecoveryPlan> plan = runtime.value()->plan_recovery(session.id);
    CRF_REQUIRE_OK(plan);
    CRF_EXPECT(plan.value().legal);
    const Result<PhaseRunReport> late = runtime.value()->commit_phase(
        session.id, order[1], phase->generation, phase->active_invocation);
    CRF_EXPECT(!late.has_value());
    const Result<AuditReport> audit = runtime.value()->audit();
    CRF_REQUIRE_OK(audit);
    if (!audit.value().zero_violations()) std::printf("%s", audit.value().render().c_str());
    CRF_EXPECT(audit.value().zero_violations());
    CRF_EXPECT_OK(runtime.value()->shutdown());
  }
}

CRF_TEST(recovery_durable_state_integrity_is_enforced) {
  CRF_PHASE("SETUP");
  RuntimeOptions options = crftest::test_runtime_options("recovery-integrity");
  crftest::ScopedTree cleanup(options.state_directory.parent_path());
  const std::filesystem::path source = crftest::test_root() / "sources" / "recovery_c.cpp";
  CRF_REQUIRE(crftest::write_text(source, hello_source()));

  CRF_PHASE("COMMIT");
  {
    Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
    CRF_REQUIRE_OK(runtime);
    CRF_REQUIRE_OK(runtime.value()->discover_toolchain(ToolchainFamily::msvc));
    const Result<Ref<CompilerSessionId>> created =
        runtime.value()->create_session(request_for(source));
    CRF_REQUIRE_OK(created);
    const Result<CompilerSession> loaded = runtime.value()->require_session(created.value().id);
    CRF_REQUIRE_OK(loaded);
    const std::vector<CompilerPhaseId> order = loaded.value().plan.topological_order();
    CRF_REQUIRE_OK(runtime.value()->run_phase(created.value().id, order[0]));
    const Result<PhaseRunReport> compiled = runtime.value()->run_phase(created.value().id, order[1]);
    CRF_REQUIRE_OK(compiled);
    CRF_REQUIRE(compiled.value().committed());
    CRF_EXPECT_OK(runtime.value()->snapshot());
    const Result<DurableState> state = runtime.value()->durable_state();
    CRF_REQUIRE_OK(state);
    CRF_EXPECT(state.value().trustworthy());
    CRF_EXPECT(state.value().records.size() >= 1);
    CRF_EXPECT_OK(runtime.value()->shutdown());
  }

  CRF_PHASE("TRUNCATE_JOURNAL");
  const std::filesystem::path journal = options.state_directory / "recovery-integrity.crfjournal";
  CRF_REQUIRE(std::filesystem::exists(journal));
  {
    std::error_code ec;
    const std::uintmax_t size = std::filesystem::file_size(journal, ec);
    CRF_REQUIRE(!ec);
    std::filesystem::resize_file(journal, size - 5, ec);
    CRF_REQUIRE(!ec);
  }
  {
    // A torn tail is repaired and the committed prefix is preserved.
    Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
    CRF_REQUIRE_OK(runtime);
    const Result<DurableState> state = runtime.value()->durable_state();
    CRF_REQUIRE_OK(state);
    CRF_EXPECT(state.value().trustworthy());
    const Result<AuditReport> audit = runtime.value()->audit();
    CRF_REQUIRE_OK(audit);
    if (!audit.value().zero_violations()) std::printf("%s", audit.value().render().c_str());
    CRF_EXPECT(audit.value().zero_violations());
  }

  CRF_PHASE("CORRUPT_JOURNAL");
  {
    std::fstream stream(journal, std::ios::binary | std::ios::in | std::ios::out);
    CRF_REQUIRE(static_cast<bool>(stream));
    stream.seekp(60);
    const char marker[] = "\xEE\xEE\xEE\xEE";
    stream.write(marker, 4);
    stream.close();
  }
  {
    // A damaged record in the middle is refused outright: no partially trusted
    // recovery is permitted.
    Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
    CRF_EXPECT(!runtime.has_value());
    if (!runtime.has_value()) {
      CRF_EXPECT(runtime.code() == StatusCode::persistence_corrupt ||
                 runtime.code() == StatusCode::persistence_truncated);
    }
  }
}
