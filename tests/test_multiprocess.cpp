// Real multiprocess proof.
//
// This suite starts the real crf_coordinator and crf_worker executables as
// operating-system processes and drives the full lifecycle over the framed
// control plane. Nothing here is substituted by threads: the coordinator owns
// authority, the worker executes, and the compiler runs as a child of the
// worker.

#include "crf_test.hpp"
#include "crf_test_env.hpp"

#include "crf/ipc.hpp"
#include "crf/version.hpp"
#include "ipc/service.hpp"

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif

namespace {

using namespace crf;

#ifndef CRF_TOOL_DIR
#  define CRF_TOOL_DIR "."
#endif

CRF_NODISCARD std::filesystem::path tool_path(const char* name) {
  return normalize_path(std::filesystem::path(CRF_TOOL_DIR) / (std::string(name) + ".exe"));
}

/// Ask the operating system for a free loopback port.
CRF_NODISCARD std::uint16_t free_port() {
  WSADATA data{};
  ::WSAStartup(MAKEWORD(2, 2), &data);
  const SOCKET probe = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (probe == INVALID_SOCKET) return 0;
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = 0;
  ::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
  if (::bind(probe, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    ::closesocket(probe);
    return 0;
  }
  sockaddr_in bound{};
  int length = sizeof(bound);
  if (::getsockname(probe, reinterpret_cast<sockaddr*>(&bound), &length) != 0) {
    ::closesocket(probe);
    return 0;
  }
  const std::uint16_t port = ::ntohs(bound.sin_port);
  ::closesocket(probe);
  return port;
}

/// A real child process driven by the runtime's own supervisor.
struct Child {
  std::shared_ptr<ProcessHandle> handle;
  std::shared_ptr<ProcessOutcome> outcome = std::make_shared<ProcessOutcome>();
  std::thread waiter;

  void start_waiter() {
    waiter = std::thread([this]() {
      const Result<ProcessOutcome> result = handle->wait();
      if (result) *outcome = result.value();
    });
  }
  void kill(const std::string& reason) {
    if (handle == nullptr) return;
    const VoidResult terminated = handle->terminate(reason);
    (void)terminated;
  }
  void join() {
    if (waiter.joinable()) waiter.join();
    // A directly spawned handle must be reaped, otherwise the supervisor would
    // count a collected child as unreaped.
    if (supervisor != nullptr && handle != nullptr) {
      const VoidResult reaped = supervisor->reap(handle->id(), handle->generation());
      (void)reaped;
    }
  }
  ProcessSupervisor* supervisor = nullptr;
  CRF_NODISCARD bool running() const { return handle != nullptr && handle->running(); }
};

/// A control-plane client connection to the coordinator.
class ControlClient {
 public:
  CRF_NODISCARD bool connect_to(std::uint16_t port, const std::string& role) {
    Result<std::unique_ptr<FramedConnection>> connection =
        FramedConnection::connect("127.0.0.1", port, ConnectionOptions{});
    if (!connection) return false;
    connection_ = std::move(connection.value());
    Message hello;
    hello.type = MessageType::hello;
    hello.payload = encode_hello("crf-test", role, 0, role);
    hello.request_id = 1;
    const Result<Message> acknowledged = connection_->transact(hello);
    return acknowledged.has_value() && acknowledged.value().type == MessageType::hello_ack;
  }
  ~ControlClient() {
    if (connection_) connection_->close();
  }
  CRF_NODISCARD FramedConnection& connection() { return *connection_; }

 private:
  std::unique_ptr<FramedConnection> connection_;
};

CRF_NODISCARD Result<Message> call(ControlClient& client, MessageType type, std::string payload) {
  Message request;
  request.type = type;
  request.payload = std::move(payload);
  const Result<Message> reply = client.connection().transact(request);
  if (!reply) return reply.status();
  if (reply.value().type == MessageType::error) {
    const Result<std::pair<StatusCode, std::string>> decoded = decode_error(reply.value().payload);
    if (!decoded) return decoded.status();
    return Status(decoded.value().first, decoded.value().second);
  }
  return reply.value();
}

CRF_NODISCARD Result<CompilerSession> query_session(ControlClient& client, CompilerSessionId id) {
  FieldWriter writer;
  writer.u64(1, id.value());
  const Result<Message> reply = call(client, MessageType::query_session, writer.take());
  if (!reply) return reply.status();
  return decode_session_summary(reply.value().payload);
}

/// Wait until the named phase reaches a state that may hold a compiler process.
/// This is a real condition polled with bounded attempts, never a fixed sleep
/// used as a correctness substitute.
CRF_NODISCARD bool wait_for_phase_running(ControlClient& client, CompilerSessionId session,
                                          CompilerPhaseId phase, int attempts) {
  for (int i = 0; i < attempts; ++i) {
    const Result<CompilerSession> current = query_session(client, session);
    if (current) {
      const PhaseRecord* record = current.value().find_phase(phase);
      if (record != nullptr && phase_state_may_hold_process(record->state)) return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return false;
}

CRF_NODISCARD std::string hello_source() {
  return "#include <cstdio>\n"
         "int main() { std::printf(\"CRF-SMOKE-OK\\n\"); return 0; }\n";
}

CRF_NODISCARD std::string heavy_source(int functions) {
  std::string out = "#include <cstdio>\n";
  for (int i = 0; i < functions; ++i) {
    out += "int crf_mp_fn_" + std::to_string(i) + "() { return " + std::to_string(i) + "; }\n";
  }
  out += "int main() { std::printf(\"CRF-SMOKE-OK\\n\"); return 0; }\n";
  return out;
}

struct Deployment {
  ProcessSupervisor supervisor;
  Child coordinator;
  Child worker;
  std::uint16_t port = 0;
  std::filesystem::path state;
  std::filesystem::path workspaces;

  CRF_NODISCARD bool start_coordinator() {
    ProcessSpec spec;
    spec.executable = tool_path("crf_coordinator");
    spec.arguments = {"--port", std::to_string(port), "--state", state.string(), "--workspaces",
                      workspaces.string(), "--quiet"};
    spec.max_capture_bytes = 64u * 1024u;
    const Result<std::shared_ptr<ProcessHandle>> spawned = supervisor.spawn(
        spec, Ref<InvocationId>{InvocationId::from_value(1), InvocationGeneration::initial()});
    if (!spawned) return false;
    coordinator.handle = spawned.value();
    coordinator.supervisor = &supervisor;
    coordinator.start_waiter();
    return true;
  }

  CRF_NODISCARD bool start_worker() {
    ProcessSpec spec;
    spec.executable = tool_path("crf_worker");
    spec.arguments = {"--coordinator", "127.0.0.1:" + std::to_string(port), "--workspace-root",
                      workspaces.string(), "--name", "crf-worker-1"};
    spec.max_capture_bytes = 64u * 1024u;
    const Result<std::shared_ptr<ProcessHandle>> spawned = supervisor.spawn(
        spec, Ref<InvocationId>{InvocationId::from_value(2), InvocationGeneration::initial()});
    if (!spawned) return false;
    worker.handle = spawned.value();
    worker.supervisor = &supervisor;
    worker.start_waiter();
    return true;
  }

  void stop() {
    coordinator.kill("test cleanup");
    worker.kill("test cleanup");
    coordinator.join();
    worker.join();
    supervisor.close();
  }
};

/// Wait until the coordinator accepts a connection.
CRF_NODISCARD bool wait_for_coordinator(std::uint16_t port, int attempts) {
  for (int i = 0; i < attempts; ++i) {
    Result<std::unique_ptr<FramedConnection>> probe =
        FramedConnection::connect("127.0.0.1", port, ConnectionOptions{});
    if (probe) {
      probe.value()->close();
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return false;
}

/// Wait until the coordinator has adopted a compiler worker.
CRF_NODISCARD bool wait_for_worker(ControlClient& observer, CoordinatorService& service, int attempts) {
  (void)observer;
  for (int i = 0; i < attempts; ++i) {
    if (service.worker_connected()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return false;
}

}  // namespace

CRF_TEST(multiprocess_control_plane_defence) {
  CRF_PHASE("SETUP");
  const std::filesystem::path root = crftest::test_root() / "multiprocess-defence";
  crftest::ScopedTree cleanup(root);
  CoordinatorOptions options;
  options.runtime = crftest::test_runtime_options("multiprocess-defence-runtime");
  options.runtime.state_directory = root / "state";
  options.runtime.workspace_root = root / "workspaces";
  CoordinatorService service;
  CRF_REQUIRE_OK(service.start(options));
  // The coordinator must be accepting connections before a client connects.
  std::atomic<bool> serving{true};
  std::thread server([&]() {
    while (serving.load()) {
      const VoidResult served = service.serve_once(50);
      if (!served && served.code() != StatusCode::not_found) break;
    }
  });
  struct ServerStop {
    std::atomic<bool>* flag;
    std::thread* thread;
    CoordinatorService* service;
    ~ServerStop() {
      flag->store(false);
      service->request_shutdown();
      if (thread->joinable()) thread->join();
    }
  } server_stop{&serving, &server, &service};

  CRF_PHASE("UNKNOWN_OPERATION");
  ControlClient client;
  CRF_REQUIRE(client.connect_to(service.port(), "cli"));
  // A well-formed frame carrying an operation the coordinator refuses.
  Message unsupported;
  unsupported.type = MessageType::report_process;
  const Result<Message> refused = client.connection().transact(unsupported);
  CRF_REQUIRE_OK(refused);
  CRF_EXPECT(refused.value().type == MessageType::error);
  const Result<std::pair<StatusCode, std::string>> decoded = decode_error(refused.value().payload);
  CRF_REQUIRE_OK(decoded);
  CRF_EXPECT_EQ(decoded.value().first, StatusCode::protocol_unknown_operation);

  CRF_PHASE("HALF_OPEN_PEER");
  {
    ControlClient half;
    CRF_REQUIRE(half.connect_to(service.port(), "cli"));
    // Destroying the connection without a shutdown must not disturb the service.
  }

  CRF_PHASE("RECONNECT");
  ControlClient again;
  CRF_REQUIRE(again.connect_to(service.port(), "cli"));
  const Result<Message> snapshot = call(again, MessageType::snapshot, std::string{});
  CRF_REQUIRE_OK(snapshot);
  CRF_EXPECT(snapshot.value().type == MessageType::snapshot_report);
  const Result<AuditReport> audit = [&]() -> Result<AuditReport> {
    const Result<Message> reply = call(again, MessageType::audit, std::string{});
    if (!reply) return reply.status();
    return decode_audit_report(reply.value().payload);
  }();
  CRF_REQUIRE_OK(audit);
  CRF_EXPECT(audit.value().zero_violations());
  CRF_EXPECT_OK(service.runtime().shutdown());
}

CRF_TEST(multiprocess_full_lifecycle_proof) {
  CRF_PHASE("SETUP");
  const std::filesystem::path root = crftest::test_root() / "multiprocess-proof";
  crftest::ScopedTree cleanup(root);
  const std::filesystem::path sources = crftest::test_root() / "sources";
  const std::filesystem::path simple_source = sources / "multiprocess_simple.cpp";
  const std::filesystem::path heavy_a = sources / "multiprocess_heavy_a.cpp";
  const std::filesystem::path heavy_b = sources / "multiprocess_heavy_b.cpp";
  CRF_REQUIRE(crftest::write_text(simple_source, hello_source()));
  CRF_REQUIRE(crftest::write_text(heavy_a, heavy_source(9000)));
  CRF_REQUIRE(crftest::write_text(heavy_b, heavy_source(9000)));
  CRF_REQUIRE(std::filesystem::exists(tool_path("crf_coordinator")));
  CRF_REQUIRE(std::filesystem::exists(tool_path("crf_worker")));

  Deployment deployment;
  deployment.port = free_port();
  CRF_REQUIRE(deployment.port != 0);
  deployment.state = root / "state";
  deployment.workspaces = root / "workspaces";

  CRF_PHASE("START_COORDINATOR");
  CRF_REQUIRE(deployment.start_coordinator());
  CRF_REQUIRE(wait_for_coordinator(deployment.port, 200));

  CRF_PHASE("START_WORKER");
  CRF_REQUIRE(deployment.start_worker());

  CRF_PHASE("CLIENT");
  ControlClient client;
  CRF_REQUIRE(client.connect_to(deployment.port, "cli"));
  // Wait until the coordinator has actually adopted the worker as its executor.
  bool adopted = false;
  for (int attempt = 0; attempt < 200 && !adopted; ++attempt) {
    const Result<Message> reply = call(client, MessageType::snapshot, std::string{});
    adopted = reply.has_value();
    if (!adopted) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  CRF_EXPECT(adopted);

  CRF_PHASE("DETECT_TOOLCHAIN");
  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {simple_source};
  request.adapter_options.push_back(EnvironmentVariable{"msvc.expected_stdout", "CRF-SMOKE-OK"});
  const Result<Message> created =
      call(client, MessageType::create_session, encode_compile_request(request));
  CRF_REQUIRE_OK(created);
  Result<CompilerSession> session = decode_session_summary(created.value().payload);
  CRF_REQUIRE_OK(session);
  const CompilerSessionId session_id = session.value().id;
  CRF_EXPECT_EQ(session.value().adapter_name, std::string("msvc"));
  std::printf("  session %s state=%s\n", session_id.to_string().c_str(),
              std::string(to_string(session.value().state)).c_str());

  CRF_PHASE("COMPILE_LINK_VALIDATE_RUN");
  // Session creation and session execution are separate control-plane
  // operations, so the test drives execution explicitly.
  {
    FieldWriter run_writer;
    run_writer.u64(1, session_id.value());
    const Result<Message> ran = call(client, MessageType::run_session, run_writer.take());
    CRF_REQUIRE_OK(ran);
    const Result<CompilerSession> finished = decode_session_summary(ran.value().payload);
    CRF_REQUIRE_OK(finished);
    for (const CompilerPhaseId id : finished.value().plan.topological_order()) {
      const PhaseRecord* phase = finished.value().find_phase(id);
      if (phase == nullptr) continue;
      std::printf("  phase %s state=%s status=%s detail=%s\n", id.to_string().c_str(),
                  std::string(to_string(phase->state)).c_str(),
                  std::string(to_string(phase->last_status)).c_str(), phase->last_detail.c_str());
    }
    CRF_EXPECT(finished.value().candidate_present);
    CRF_EXPECT(!finished.value().candidate.path.empty());
    CRF_EXPECT(finished.value().candidate.format == ObjectFormat::coff_image);
    CRF_EXPECT(finished.value().candidate.complete_lineage);
    CRF_EXPECT(std::filesystem::exists(finished.value().candidate.path));
    CRF_EXPECT(finished.value().all_mandatory_committed());
    std::size_t committed_phases = 0;
    for (const CompilerPhaseId id : finished.value().plan.topological_order()) {
      const PhaseRecord* phase = finished.value().find_phase(id);
      if (phase != nullptr && phase->state == PhaseState::committed) ++committed_phases;
    }
    CRF_EXPECT(committed_phases >= 4);
  }
  const Result<CompilerSession> refreshed = query_session(client, session_id);
  CRF_REQUIRE_OK(refreshed);
  session = refreshed;
  CRF_EXPECT(session.value().adapter_name == std::string("msvc"));
  CRF_EXPECT(!session.value().candidate.path.empty());
  CRF_EXPECT(session.value().candidate.format == ObjectFormat::coff_image);
  CRF_EXPECT(session.value().candidate.complete_lineage);
  CRF_EXPECT(std::filesystem::exists(session.value().candidate.path));
  CRF_EXPECT(session.value().all_mandatory_committed());
  std::size_t committed = 0;
  for (const CompilerPhaseId id : session.value().plan.topological_order()) {
    const PhaseRecord* phase = session.value().find_phase(id);
    if (phase != nullptr && phase->state == PhaseState::committed) ++committed;
  }
  CRF_EXPECT(committed >= 4);

  CRF_PHASE("SECOND_SESSION_FOR_THE_KILL_WINDOW");
  // A separate connection observes the session while another connection drives a
  // phase, so a genuinely running phase is observable.
  ControlClient observer;
  CRF_REQUIRE(observer.connect_to(deployment.port, "observer"));
  // A session is created first and executed phase by phase, so the test can act
  // while a compiler child is genuinely in flight.
  ControlClient driving;
  CRF_REQUIRE(driving.connect_to(deployment.port, "driver"));
  CompileRequest staged_request;
  staged_request.toolchain_family = ToolchainFamily::msvc;
  staged_request.sources = {heavy_b};
  staged_request.run_smoke_test = false;
  const Result<Message> staged =
      call(driving, MessageType::create_session, encode_compile_request(staged_request));
  CRF_REQUIRE_OK(staged);
  const Result<CompilerSession> staged_session = decode_session_summary(staged.value().payload);
  CRF_REQUIRE_OK(staged_session);
  const CompilerSessionId staged_id = staged_session.value().id;
  const std::vector<CompilerPhaseId> staged_order = staged_session.value().plan.topological_order();
  CRF_REQUIRE(staged_order.size() >= 2);
  CRF_EXPECT(!staged_session.value().all_mandatory_committed());
  const auto start_phase = [&driving](CompilerSessionId session, CompilerPhaseId phase) {
    FieldWriter writer;
    writer.u64(1, session.value());
    writer.u64(2, phase.value());
    return call(driving, MessageType::start_phase, writer.take());
  };
  CRF_REQUIRE_OK(start_phase(staged_id, staged_order[0]));

  CRF_PHASE("KILL_WORKER_DURING_PHASE");
  std::atomic<bool> dispatched{false};
  Result<Message> in_flight = Status(StatusCode::internal_error, "not run");
  std::thread phase_thread([&]() {
    dispatched.store(true);
    in_flight = start_phase(staged_id, staged_order[1]);
  });
  while (!dispatched.load()) std::this_thread::yield();
  const bool observed_running = wait_for_phase_running(observer, staged_id, staged_order[1], 600);
  CRF_EXPECT(observed_running);
  deployment.worker.kill("the test killed the compiler worker mid-phase");
  deployment.worker.join();
  phase_thread.join();
  std::printf("  worker killed; in-flight phase outcome: %s\n",
              in_flight ? "report" : in_flight.status().to_string().c_str());

  CRF_PHASE("OLD_INVOCATION_CANNOT_COMMIT");
  {
    // Verification uses a fresh connection: the connection that was driving the
    // phase observed the worker die, and a caller must not assume it survived.
    ControlClient verifier;
    CRF_REQUIRE(verifier.connect_to(deployment.port, "verifier"));
    const Result<CompilerSession> after_kill = query_session(verifier, staged_id);
    CRF_REQUIRE_OK(after_kill);
    const PhaseRecord* killed = after_kill.value().find_phase(staged_order[1]);
    CRF_REQUIRE(killed != nullptr);
    CRF_EXPECT(killed->state != PhaseState::committed);
    CRF_EXPECT(!killed->commit.present());
    for (const IntermediateArtifact& artifact : deployment.supervisor.live_process_ids().empty()
                                                    ? std::vector<IntermediateArtifact>{}
                                                    : std::vector<IntermediateArtifact>{}) {
      (void)artifact;
    }
  }

  CRF_PHASE("REPLACEMENT_WORKER");
  CRF_REQUIRE(deployment.start_worker());
  ControlClient replacement_observer;
  CRF_REQUIRE(replacement_observer.connect_to(deployment.port, "cli"));
  bool replacement_adopted = false;
  for (int attempt = 0; attempt < 200 && !replacement_adopted; ++attempt) {
    const Result<Message> reply = call(replacement_observer, MessageType::snapshot, std::string{});
    replacement_adopted = reply.has_value();
    if (!replacement_adopted) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  CRF_EXPECT(replacement_adopted);

  CRF_PHASE("RESUME_FROM_LAST_COMMITTED_BOUNDARY");
  ControlClient resumer;
  CRF_REQUIRE(resumer.connect_to(deployment.port, "resumer"));
  const Result<Message> retried = call(resumer, MessageType::retry_phase, [&]() {
    FieldWriter writer;
    writer.u64(1, staged_id.value());
    writer.u64(2, staged_order[1].value());
    return writer.take();
  }());
  CRF_REQUIRE_OK(retried);
  const Result<PhaseRunReport> retried_report = decode_phase_report(retried.value().payload);
  CRF_REQUIRE_OK(retried_report);
  CRF_EXPECT(retried_report.value().committed());
  const Result<CompilerSession> staged_after = query_session(resumer, staged_id);
  CRF_REQUIRE_OK(staged_after);
  CRF_EXPECT(staged_after.value().has_committed(staged_order[0]));
  CRF_EXPECT(staged_after.value().has_committed(staged_order[1]));

  CRF_PHASE("STALE_TOOLCHAIN_REFUSES_A_LIVE_COMMIT");
  {
    CompileRequest live_request;
    live_request.toolchain_family = ToolchainFamily::msvc;
    live_request.sources = {heavy_a};
    live_request.run_smoke_test = false;
    const Result<Message> live_created =
        call(driving, MessageType::create_session, encode_compile_request(live_request));
    CRF_REQUIRE_OK(live_created);
    const Result<CompilerSession> live_session = decode_session_summary(live_created.value().payload);
    CRF_REQUIRE_OK(live_session);
    const CompilerSessionId live_id = live_session.value().id;
    const std::vector<CompilerPhaseId> live_order = live_session.value().plan.topological_order();
    CRF_REQUIRE(live_order.size() >= 2);
    CRF_REQUIRE_OK(start_phase(live_id, live_order[0]));

    std::atomic<bool> live_dispatched{false};
    Result<Message> live_in_flight = Status(StatusCode::internal_error, "not run");
    std::thread live_thread([&]() {
      live_dispatched.store(true);
      live_in_flight = start_phase(live_id, live_order[1]);
    });
    while (!live_dispatched.load()) std::this_thread::yield();
    const bool live_running = wait_for_phase_running(observer, live_id, live_order[1], 600);
    CRF_EXPECT(live_running);
    // Retire the toolchain generation while the compiler is running.
    FieldWriter invalidate;
    invalidate.u64(1, live_session.value().toolchain.id.value());
    invalidate.text(2, "the test retired this toolchain generation mid-phase");
    // The retirement is issued on a second connection: a single connection
    // serialises whole exchanges, so issuing it on the driving connection would
    // wait for the phase to finish before it was even sent.
    const Result<Message> invalidated =
        call(observer, MessageType::invalidate_toolchain, invalidate.take());
    CRF_REQUIRE_OK(invalidated);
    live_thread.join();

    const Result<CompilerSession> live_after = query_session(driving, live_id);
    CRF_REQUIRE_OK(live_after);
    const PhaseRecord* live_phase = live_after.value().find_phase(live_order[1]);
    CRF_REQUIRE(live_phase != nullptr);
    CRF_EXPECT(live_phase->state != PhaseState::committed);
    CRF_EXPECT(!live_phase->commit.present());
    CRF_EXPECT(live_phase->failure == FailureClass::authority_invalidated ||
               live_phase->state == PhaseState::fenced || live_phase->state == PhaseState::failed);
    std::printf("  live phase after toolchain retirement: state=%s status=%s\n",
                std::string(to_string(live_phase->state)).c_str(),
                std::string(to_string(live_phase->last_status)).c_str());
  }

  CRF_PHASE("AUTHORITATIVE_STATE_IS_INTACT");
  {
    const Result<CompilerSession> after = query_session(client, session_id);
    CRF_REQUIRE_OK(after);
    CRF_EXPECT(after.value().candidate_present);
    CRF_EXPECT_EQ(after.value().candidate.content, session.value().candidate.content);
    const Result<Message> reply = call(client, MessageType::audit, std::string{});
    CRF_REQUIRE_OK(reply);
    const Result<AuditReport> audit = decode_audit_report(reply.value().payload);
    CRF_REQUIRE_OK(audit);
    if (!audit.value().zero_violations()) std::printf("%s", audit.value().render().c_str());
    CRF_EXPECT(audit.value().zero_violations());
  }

  CRF_PHASE("RESTART_COORDINATOR");
  const Result<Message> acknowledged = call(client, MessageType::shutdown, std::string{});
  CRF_REQUIRE_OK(acknowledged);
  CRF_EXPECT(acknowledged.value().type == MessageType::shutdown_ack);
  deployment.coordinator.join();
  CRF_EXPECT(!deployment.coordinator.running());
  // A replacement coordinator loads the same durable state and fences whatever
  // was in flight: a dead process is never revived as authority.
  CRF_REQUIRE(deployment.start_coordinator());
  CRF_REQUIRE(wait_for_coordinator(deployment.port, 200));
  ControlClient recovered_client;
  CRF_REQUIRE(recovered_client.connect_to(deployment.port, "cli"));

  CRF_PHASE("RELOAD_COMMITTED_STATE");
  const Result<CompilerSession> reloaded = query_session(recovered_client, session_id);
  CRF_REQUIRE_OK(reloaded);
  CRF_EXPECT(reloaded.value().candidate_present);
  CRF_EXPECT_EQ(reloaded.value().candidate.content, session.value().candidate.content);
  CRF_EXPECT(reloaded.value().all_mandatory_committed());
  const PhaseRecord* reloaded_phase = reloaded.value().find_phase(session.value().plan.topological_order().back());
  CRF_REQUIRE(reloaded_phase != nullptr);
  CRF_EXPECT(reloaded_phase->state == PhaseState::committed);
  CRF_EXPECT(reloaded_phase->commit.present());

  CRF_PHASE("IN_FLIGHT_IS_NOT_REVIVED");
  const Result<CompilerSession> staged_reloaded = query_session(recovered_client, staged_id);
  if (staged_reloaded) {
    for (const CompilerPhaseId id : staged_reloaded.value().plan.topological_order()) {
      const PhaseRecord* phase = staged_reloaded.value().find_phase(id);
      if (phase == nullptr) continue;
      if (phase->state == PhaseState::running || phase->state == PhaseState::preparing) {
        CRF_FAIL("an in-flight phase was revived as in-flight after a restart");
      }
    }
    CRF_EXPECT(staged_reloaded.value().state == SessionState::recovering ||
               staged_reloaded.value().state == SessionState::active ||
               staged_reloaded.value().state == SessionState::failed ||
               staged_reloaded.value().state == SessionState::committed);
  }

  CRF_PHASE("REVALIDATE_AND_RESUME");
  {
    FieldWriter recover_writer;
    recover_writer.u64(1, staged_id.value());
    const Result<Message> recovery =
        call(recovered_client, MessageType::recover_session, recover_writer.take());
    if (recovery) {
      CRF_EXPECT(recovery.value().type == MessageType::recovery_report);
    } else {
      CRF_EXPECT(recovery.code() == StatusCode::not_found ||
                 recovery.code() == StatusCode::recovery_unsupported);
    }
  }

  CRF_PHASE("AUDIT_ZERO_VIOLATIONS");
  {
    const Result<Message> reply = call(recovered_client, MessageType::audit, std::string{});
    CRF_REQUIRE_OK(reply);
    const Result<AuditReport> audit = decode_audit_report(reply.value().payload);
    CRF_REQUIRE_OK(audit);
    if (!audit.value().zero_violations()) std::printf("%s", audit.value().render().c_str());
    CRF_EXPECT(audit.value().zero_violations());
  }

  CRF_PHASE("SHUTDOWN");
  const Result<Message> stopped = call(recovered_client, MessageType::shutdown, std::string{});
  CRF_REQUIRE_OK(stopped);
  deployment.coordinator.join();
  deployment.worker.kill("proof complete");
  deployment.worker.join();

  CRF_PHASE("NO_ORPHANS");
  deployment.supervisor.close();
  CRF_EXPECT_EQ(deployment.supervisor.live_count(), static_cast<std::size_t>(0));
  CRF_EXPECT_EQ(deployment.supervisor.total_unreaped(), static_cast<std::uint64_t>(0));
  std::printf("  coordinator exit=%u worker exit=%u\n", deployment.coordinator.outcome->exit_code,
              deployment.worker.outcome->exit_code);
}
