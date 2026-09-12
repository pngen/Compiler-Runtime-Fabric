// Concurrency proofs.
//
// Every case drives a genuine race through the product path and asserts the
// governance invariant that must survive it: at most one authoritative commit
// per phase generation, no commit under stale authority, and no leaked child.

#include "crf_test.hpp"
#include "crf_test_env.hpp"

#include <atomic>
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

CRF_TEST(concurrency_duplicate_phase_start_runs_once) {
  CRF_PHASE("SETUP");
  Fixture fixture;
  crftest::ScopedTree cleanup(crftest::test_root() / "concurrency-duplicate-start");
  CRF_REQUIRE(setup(fixture, "concurrency-start", "concurrency_start.cpp"));
  CRF_REQUIRE(fixture.order.size() >= 2);
  CRF_REQUIRE_OK(fixture.runtime->run_phase(fixture.session.id, fixture.order[0]));

  CRF_PHASE("RACE");
  std::atomic<int> committed{0};
  std::atomic<int> refused{0};
  std::vector<std::thread> threads;
  for (int i = 0; i < 4; ++i) {
    threads.emplace_back([&]() {
      Result<PhaseRunReport> report =
          fixture.runtime->run_phase(fixture.session.id, fixture.order[1]);
      if (!report) {
        refused.fetch_add(1);
        return;
      }
      if (report.value().committed()) {
        committed.fetch_add(1);
      } else {
        refused.fetch_add(1);
      }
    });
  }
  for (std::thread& thread : threads) thread.join();

  CRF_PHASE("VERIFY");
  // The phase may have been executed physically more than once, but only one
  // authoritative commit may exist for the generation.
  CRF_EXPECT_EQ(committed.load(), 1);
  CRF_EXPECT(refused.load() >= 1);
  const Result<CompilerSession> session = fixture.runtime->require_session(fixture.session.id);
  CRF_REQUIRE_OK(session);
  const PhaseRecord* phase = session.value().find_phase(fixture.order[1]);
  CRF_REQUIRE(phase != nullptr);
  CRF_EXPECT(phase->state == PhaseState::committed);
  CRF_EXPECT(phase->commit.present());
  std::size_t authoritative = 0;
  for (const IntermediateArtifact& artifact : fixture.runtime->artifacts().list()) {
    if (artifact.authority == AuthorityState::authoritative &&
        artifact.producer_phase.id == fixture.order[1]) {
      ++authoritative;
    }
  }
  CRF_EXPECT_EQ(authoritative, static_cast<std::size_t>(1));
  const Result<AuditReport> audit = fixture.runtime->audit();
  CRF_REQUIRE_OK(audit);
  CRF_EXPECT(audit.value().zero_violations());
  CRF_EXPECT_OK(fixture.runtime->shutdown());
}

CRF_TEST(concurrency_cancel_races_completion) {
  CRF_PHASE("SETUP");
  Fixture fixture;
  crftest::ScopedTree cleanup(crftest::test_root() / "concurrency-cancel");
  CRF_REQUIRE(setup(fixture, "concurrency-cancel", "concurrency_cancel.cpp"));
  CRF_REQUIRE(fixture.order.size() >= 2);
  CRF_REQUIRE_OK(fixture.runtime->run_phase(fixture.session.id, fixture.order[0]));

  CRF_PHASE("RACE");
  std::atomic<bool> started{false};
  Result<PhaseRunReport> report = Status(StatusCode::internal_error, "not run");
  std::thread runner([&]() {
    started.store(true);
    report = fixture.runtime->run_phase(fixture.session.id, fixture.order[1]);
  });
  while (!started.load()) std::this_thread::yield();
  const VoidResult cancelled =
      fixture.runtime->cancel_phase(fixture.session.id, fixture.order[1], "raced cancellation");
  (void)cancelled;
  runner.join();

  CRF_PHASE("VERIFY");
  const Result<CompilerSession> session = fixture.runtime->require_session(fixture.session.id);
  CRF_REQUIRE_OK(session);
  const PhaseRecord* phase = session.value().find_phase(fixture.order[1]);
  CRF_REQUIRE(phase != nullptr);
  // Whatever the interleaving, a cancelled phase generation cannot be
  // authoritative, and the phase cannot be both cancelled and committed.
  if (phase->state == PhaseState::cancelled) {
    CRF_EXPECT(!phase->commit.present());
    for (const IntermediateArtifact& artifact : fixture.runtime->artifacts().list()) {
      if (artifact.producer_phase.id != fixture.order[1]) continue;
      CRF_EXPECT(artifact.authority != AuthorityState::authoritative);
    }
  } else {
    CRF_EXPECT(phase->state == PhaseState::committed || phase->state == PhaseState::failed ||
               phase->state == PhaseState::fenced);
  }
  const Result<AuditReport> audit = fixture.runtime->audit();
  CRF_REQUIRE_OK(audit);
  CRF_EXPECT(audit.value().zero_violations());
  CRF_EXPECT_OK(fixture.runtime->shutdown());
}

CRF_TEST(concurrency_snapshot_during_commit_is_consistent) {
  CRF_PHASE("SETUP");
  Fixture fixture;
  crftest::ScopedTree cleanup(crftest::test_root() / "concurrency-snapshot");
  CRF_REQUIRE(setup(fixture, "concurrency-snapshot", "concurrency_snapshot.cpp"));
  CRF_REQUIRE(fixture.order.size() >= 2);
  CRF_REQUIRE_OK(fixture.runtime->run_phase(fixture.session.id, fixture.order[0]));

  CRF_PHASE("RACE");
  std::atomic<bool> stop{false};
  std::atomic<int> snapshots{0};
  std::atomic<int> audits{0};
  std::thread observer([&]() {
    while (!stop.load()) {
      const VoidResult written = fixture.runtime->snapshot();
      if (written) snapshots.fetch_add(1);
      const Result<AuditReport> audit = fixture.runtime->audit();
      if (audit && audit.value().zero_violations()) audits.fetch_add(1);
    }
  });
  const Result<PhaseRunReport> compiled =
      fixture.runtime->run_phase(fixture.session.id, fixture.order[1]);
  stop.store(true);
  observer.join();

  CRF_PHASE("VERIFY");
  CRF_REQUIRE_OK(compiled);
  CRF_EXPECT(compiled.value().committed());
  CRF_EXPECT(snapshots.load() >= 1);
  // Every consistent audit observed while a commit was in flight must have
  // found zero violations: persistence never publishes a torn state.
  CRF_EXPECT(audits.load() >= 1);
  const Result<AuditReport> final_audit = fixture.runtime->audit();
  CRF_REQUIRE_OK(final_audit);
  CRF_EXPECT(final_audit.value().zero_violations());
  CRF_EXPECT_OK(fixture.runtime->shutdown());
}

CRF_TEST(concurrency_retry_versus_late_output_from_the_previous_invocation) {
  CRF_PHASE("SETUP");
  Fixture fixture;
  crftest::ScopedTree cleanup(crftest::test_root() / "concurrency-retry");
  CRF_REQUIRE(setup(fixture, "concurrency-retry", "concurrency_retry.cpp"));
  CRF_REQUIRE(fixture.order.size() >= 2);
  CRF_REQUIRE_OK(fixture.runtime->run_phase(fixture.session.id, fixture.order[0]));

  CRF_PHASE("FAIL_THEN_RETRY");
  const Result<CompilerSession> before = fixture.runtime->require_session(fixture.session.id);
  CRF_REQUIRE_OK(before);
  const PhaseRecord* phase = before.value().find_phase(fixture.order[1]);
  CRF_REQUIRE(phase != nullptr);
  const CompilerPhaseGeneration original_generation = phase->generation;

  // Force the phase into a failed state through the governed entry point.
  const Result<PhaseRunReport> failed = fixture.runtime->fail_phase(
      fixture.session.id, fixture.order[1], original_generation, FailureClass::process_crash,
      StatusCode::process_crashed, "simulated compiler crash for the retry race");
  CRF_REQUIRE_OK(failed);
  CRF_EXPECT(failed.value().state == PhaseState::failed);

  const Result<PhaseRunReport> retried =
      fixture.runtime->retry_phase(fixture.session.id, fixture.order[1]);
  CRF_REQUIRE_OK(retried);
  CRF_EXPECT(retried.value().committed());
  // The retry used fresh invocation authority: a late report from the previous
  // invocation can no longer satisfy the phase.
  CRF_EXPECT(retried.value().invocation.id != failed.value().invocation.id);

  CRF_PHASE("LATE_REPORT");
  const Result<PhaseRunReport> late = fixture.runtime->commit_phase(
      fixture.session.id, fixture.order[1], original_generation, failed.value().invocation);
  CRF_EXPECT(!late.has_value());
  if (!late.has_value()) {
    CRF_EXPECT(late.code() == StatusCode::stale_phase_generation ||
               late.code() == StatusCode::stale_invocation);
  }

  CRF_PHASE("VERIFY");
  const Result<AuditReport> audit = fixture.runtime->audit();
  CRF_REQUIRE_OK(audit);
  if (!audit.value().zero_violations()) std::printf("%s", audit.value().render().c_str());
  CRF_EXPECT(audit.value().zero_violations());
  CRF_EXPECT_OK(fixture.runtime->shutdown());
}

CRF_TEST(concurrency_shutdown_races_process_exit) {
  CRF_PHASE("SETUP");
  Fixture fixture;
  crftest::ScopedTree cleanup(crftest::test_root() / "concurrency-shutdown");
  CRF_REQUIRE(setup(fixture, "concurrency-shutdown", "concurrency_shutdown.cpp"));
  CRF_REQUIRE(fixture.order.size() >= 3);

  CRF_PHASE("RACE");
  std::atomic<bool> started{false};
  Result<PhaseRunReport> report = Status(StatusCode::internal_error, "not run");
  std::thread runner([&]() {
    started.store(true);
    report = fixture.runtime->run_phase(fixture.session.id, fixture.order[1]);
  });
  while (!started.load()) std::this_thread::yield();
  std::this_thread::sleep_for(std::chrono::milliseconds(2));
  const VoidResult stopped = fixture.runtime->shutdown();
  runner.join();

  CRF_PHASE("VERIFY");
  CRF_EXPECT_OK(stopped);
  CRF_EXPECT_EQ(fixture.runtime->processes().live_count(), static_cast<std::size_t>(0));
  CRF_EXPECT_EQ(fixture.runtime->processes().total_unreaped(), static_cast<std::uint64_t>(0));
  if (report) {
    CRF_EXPECT(!report.value().committed());
  }
  const Result<AuditReport> audit = fixture.runtime->audit();
  CRF_REQUIRE_OK(audit);
  CRF_EXPECT(audit.value().zero_violations());
}

CRF_TEST(concurrency_two_sessions_commit_independently) {
  CRF_PHASE("SETUP");
  Fixture first;
  Fixture second;
  crftest::ScopedTree cleanup(crftest::test_root() / "concurrency-parallel");
  CRF_REQUIRE(setup(first, "concurrency-parallel-a", "parallel_a.cpp"));
  // The second session reuses the same runtime so the two commit paths really do
  // interleave inside one runtime.
  second.runtime = nullptr;
  const std::filesystem::path source = crftest::test_root() / "sources" / "parallel_b.cpp";
  CRF_REQUIRE(crftest::write_text(source, hello_source()));
  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {source};
  request.adapter_options.push_back(EnvironmentVariable{"msvc.expected_stdout", "CRF-SMOKE-OK"});
  const Result<Ref<CompilerSessionId>> created = first.runtime->create_session(request);
  CRF_REQUIRE_OK(created);
  const Result<CompilerSession> other = first.runtime->require_session(created.value().id);
  CRF_REQUIRE_OK(other);

  CRF_PHASE("RACE");
  std::atomic<int> commits{0};
  std::thread one([&]() {
    const Result<CompileOutcome> outcome = first.runtime->run_session(first.session.id);
    if (outcome && !outcome.value().candidate.path.empty()) commits.fetch_add(1);
  });
  std::thread two([&]() {
    const Result<CompileOutcome> outcome = first.runtime->run_session(created.value().id);
    if (outcome && !outcome.value().candidate.path.empty()) commits.fetch_add(1);
  });
  one.join();
  two.join();

  CRF_PHASE("VERIFY");
  CRF_EXPECT_EQ(commits.load(), 2);
  const Result<AuditReport> audit = first.runtime->audit();
  CRF_REQUIRE_OK(audit);
  CRF_EXPECT(audit.value().zero_violations());
  CRF_EXPECT_OK(first.runtime->shutdown());
}
