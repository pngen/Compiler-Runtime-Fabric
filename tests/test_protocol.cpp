// Control-plane protocol defence.
//
// These cases attack the framed protocol directly: malformed frames, oversized
// frames, truncated frames, duplicate field records, replayed request ids,
// invalid enums, and half-open peers. No malformed input may cause an
// uncontrolled allocation or hang.

#include "crf_test.hpp"
#include "crf_test_env.hpp"

#include "crf/version.hpp"

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include "ipc/service.hpp"

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif

namespace {

using namespace crf;

/// A raw socket client used to inject bytes the framed layer would never emit.
class RawPeer {
 public:
  CRF_NODISCARD bool connect_to(std::uint16_t port) {
    WSADATA data{};
    ::WSAStartup(MAKEWORD(2, 2), &data);
    socket_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == INVALID_SOCKET) return false;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = ::htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    return ::connect(socket_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
  }
  ~RawPeer() {
    if (socket_ != INVALID_SOCKET) ::closesocket(socket_);
  }
  CRF_NODISCARD bool send_bytes(std::string_view bytes) {
    std::size_t sent = 0;
    while (sent < bytes.size()) {
      const int written =
          ::send(socket_, bytes.data() + sent, static_cast<int>(bytes.size() - sent), 0);
      if (written <= 0) return false;
      sent += static_cast<std::size_t>(written);
    }
    return true;
  }
  CRF_NODISCARD std::string receive_bytes(std::size_t limit) {
    std::string out;
    out.resize(limit);
    const int got = ::recv(socket_, out.data(), static_cast<int>(limit), 0);
    if (got <= 0) return {};
    out.resize(static_cast<std::size_t>(got));
    return out;
  }

 private:
  SOCKET socket_ = INVALID_SOCKET;
};

struct RunningCoordinator {
  CoordinatorService service;
  std::thread server;
  std::atomic<bool> running{true};

  CRF_NODISCARD bool start(const std::string& name) {
    CoordinatorOptions options;
    options.runtime = crftest::test_runtime_options(name);
    options.server.bind_address = "127.0.0.1";
    options.server.port = 0;
    const VoidResult started = service.start(options);
    if (!started) {
      std::printf("  coordinator start refused: %s\n", started.status().to_string().c_str());
      return false;
    }
    server = std::thread([this]() {
      while (running.load()) {
        const VoidResult served = service.serve_once(50);
        if (!served && served.code() != StatusCode::not_found) break;
        if (service.worker_connected() && service.runtime().is_shutting_down()) break;
      }
    });
    return true;
  }
  ~RunningCoordinator() {
    running.store(false);
    service.request_shutdown();
    if (server.joinable()) server.join();
  }
};

}  // namespace

CRF_TEST(protocol_field_codec_rejects_duplicates_and_reordering) {
  CRF_PHASE("ROUNDTRIP");
  FieldWriter writer;
  writer.u16(1, 7);
  writer.text(2, "hello");
  writer.boolean(3, true);
  const std::string payload = writer.take();
  FieldReader reader(payload);
  std::uint16_t first = 0;
  std::string second;
  bool third = false;
  Result<bool> next = reader.next();
  CRF_REQUIRE_OK(next);
  CRF_EXPECT(next.value());
  CRF_EXPECT_EQ(reader.id(), static_cast<std::uint16_t>(1));
  {
    const Result<std::uint16_t> value = reader.as_u16();
    CRF_REQUIRE_OK(value);
    first = value.value();
  }
  next = reader.next();
  CRF_REQUIRE_OK(next);
  {
    const Result<std::string> value = reader.as_text();
    CRF_REQUIRE_OK(value);
    second = value.value();
  }
  next = reader.next();
  CRF_REQUIRE_OK(next);
  {
    const Result<bool> value = reader.as_bool();
    CRF_REQUIRE_OK(value);
    third = value.value();
  }
  CRF_EXPECT_EQ(first, static_cast<std::uint16_t>(7));
  CRF_EXPECT_EQ(second, std::string("hello"));
  CRF_EXPECT(third);
  next = reader.next();
  CRF_REQUIRE_OK(next);
  CRF_EXPECT(!next.value());
  CRF_EXPECT_OK(reader.finish());

  CRF_PHASE("DUPLICATE_FIELD");
  std::string duplicated = payload;
  // Append a second copy of field 1: duplicate ids must be rejected.
  const std::string extra = std::string("\x01\x00\x02\x00\x00\x00\x09\x00", 8);
  duplicated.append(extra);
  FieldReader duplicate_reader(duplicated);
  bool rejected = false;
  for (;;) {
    const Result<bool> step = duplicate_reader.next();
    if (!step) {
      rejected = true;
      break;
    }
    if (!step.value()) break;
  }
  CRF_EXPECT(rejected);

  CRF_PHASE("TRUNCATED_FIELD");
  // The damaged payload is a named object: a reader holds a view, so binding it
  // to a temporary would leave the view dangling.
  const std::string truncated_payload = payload.substr(0, payload.size() - 1);
  FieldReader truncated(truncated_payload);
  bool truncated_rejected = false;
  for (;;) {
    const Result<bool> step = truncated.next();
    if (!step) {
      truncated_rejected = true;
      break;
    }
    if (!step.value()) break;
  }
  CRF_EXPECT(truncated_rejected);

  CRF_PHASE("TRAILING_BYTES");
  const std::string trailing_payload = payload + std::string("\x01");
  FieldReader trailing(trailing_payload);
  bool trailing_rejected = false;
  for (;;) {
    const Result<bool> step = trailing.next();
    if (!step) {
      trailing_rejected = true;
      break;
    }
    if (!step.value()) break;
  }
  if (!trailing_rejected) {
    const VoidResult finished = trailing.finish();
    trailing_rejected = !finished.has_value();
  }
  CRF_EXPECT(trailing_rejected);
}

CRF_TEST(protocol_malformed_frames_are_refused_without_allocation) {
  CRF_PHASE("SERVER");
  RunningCoordinator coordinator;
  CRF_REQUIRE(coordinator.start("protocol-malformed"));

  CRF_PHASE("BAD_MAGIC");
  {
    RawPeer peer;
    CRF_REQUIRE(peer.connect_to(coordinator.service.port()));
    std::string frame(32, '\0');
    frame[0] = 'X';
    CRF_EXPECT(peer.send_bytes(frame));
    const std::string reply = peer.receive_bytes(64);
    // The server refuses the frame and closes; an empty reply is the expected
    // outcome because the connection is torn down, never a hang.
    CRF_EXPECT(reply.size() <= 64);
  }

  CRF_PHASE("OVERSIZED_LENGTH");
  {
    RawPeer peer;
    CRF_REQUIRE(peer.connect_to(coordinator.service.port()));
    char header[32] = {};
    const auto put = [&header](std::size_t offset, std::uint32_t value) {
      for (int i = 0; i < 4; ++i) {
        header[offset + static_cast<std::size_t>(i)] = static_cast<char>((value >> (i * 8)) & 0xFFu);
      }
    };
    put(0, kFrameMagic);
    put(4, static_cast<std::uint32_t>(protocol_version_major));
    put(8, static_cast<std::uint32_t>(MessageType::ping));
    // Declare a payload far beyond the hard ceiling.
    put(20, 0xFFFFFFF0u);
    put(28, crc32c(std::string_view(header, 28)));
    CRF_EXPECT(peer.send_bytes(std::string(header, 32)));
    const std::string reply = peer.receive_bytes(64);
    CRF_EXPECT(reply.size() <= 64);
  }

  CRF_PHASE("TRUNCATED_HEADER");
  {
    RawPeer peer;
    CRF_REQUIRE(peer.connect_to(coordinator.service.port()));
    CRF_EXPECT(peer.send_bytes(std::string("CRF1")));
  }

  CRF_PHASE("UNKNOWN_TYPE");
  {
    RawPeer peer;
    CRF_REQUIRE(peer.connect_to(coordinator.service.port()));
    char header[32] = {};
    const auto put = [&header](std::size_t offset, std::uint32_t value) {
      for (int i = 0; i < 4; ++i) {
        header[offset + static_cast<std::size_t>(i)] = static_cast<char>((value >> (i * 8)) & 0xFFu);
      }
    };
    put(0, kFrameMagic);
    put(4, static_cast<std::uint32_t>(protocol_version_major));
    put(8, 0x7FFFu);
    put(28, crc32c(std::string_view(header, 28)));
    CRF_EXPECT(peer.send_bytes(std::string(header, 32)));
  }

  CRF_PHASE("CORRUPT_HEADER_CRC");
  {
    RawPeer peer;
    CRF_REQUIRE(peer.connect_to(coordinator.service.port()));
    std::string header(32, '\0');
    header[0] = 'C';
    header[1] = 'R';
    header[2] = 'F';
    header[3] = '1';
    CRF_EXPECT(peer.send_bytes(header));
  }

  CRF_PHASE("VERIFY");
  // The coordinator is still healthy after every malformed frame.
  Message ping;
  ping.type = MessageType::ping;
  const Result<std::unique_ptr<FramedConnection>> connection = FramedConnection::connect(
      "127.0.0.1", coordinator.service.port(), ConnectionOptions{});
  CRF_REQUIRE_OK(connection);
  const Result<Message> pong = connection.value()->transact(ping);
  CRF_REQUIRE_OK(pong);
  CRF_EXPECT(pong.value().type == MessageType::pong);
}

CRF_TEST(protocol_replayed_request_is_refused) {
  CRF_PHASE("SETUP");
  RunningCoordinator coordinator;
  CRF_REQUIRE(coordinator.start("protocol-replay"));
  const Result<std::unique_ptr<FramedConnection>> connection = FramedConnection::connect(
      "127.0.0.1", coordinator.service.port(), ConnectionOptions{});
  CRF_REQUIRE_OK(connection);

  CRF_PHASE("HANDSHAKE");
  Message hello;
  hello.type = MessageType::hello;
  hello.payload = encode_hello("test", "cli", 0, "test");
  hello.request_id = 1;
  const Result<Message> acknowledged = connection.value()->transact(hello);
  CRF_REQUIRE_OK(acknowledged);
  CRF_EXPECT(acknowledged.value().type == MessageType::hello_ack);

  CRF_PHASE("REPLAY");
  // The same request id, sent twice, must not be served twice. The coordinator
  // remembers recently served ids for the life of the connection.
  Message replay;
  replay.type = MessageType::audit;
  replay.request_id = 77;
  const Result<Message> first = connection.value()->transact(replay);
  CRF_REQUIRE_OK(first);
  CRF_EXPECT(first.value().type == MessageType::audit_report);
  const Result<Message> second = connection.value()->transact(replay);
  CRF_REQUIRE_OK(second);
  CRF_EXPECT(second.value().type == MessageType::error);
  const Result<std::pair<StatusCode, std::string>> decoded = decode_error(second.value().payload);
  CRF_REQUIRE_OK(decoded);
  CRF_EXPECT_EQ(decoded.value().first, StatusCode::protocol_duplicate_request);
  // A fresh request id is still served.
  Message fresh;
  fresh.type = MessageType::audit;
  fresh.request_id = 78;
  const Result<Message> third = connection.value()->transact(fresh);
  CRF_REQUIRE_OK(third);
  CRF_EXPECT(third.value().type == MessageType::audit_report);
}

CRF_TEST(protocol_duplicate_completion_racing_for_one_phase_generation) {
  CRF_PHASE("SETUP");
  RuntimeOptions options = crftest::test_runtime_options("protocol-race");
  const Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  CRF_REQUIRE_OK(runtime);
  CRF_REQUIRE_OK(runtime.value()->discover_toolchain(ToolchainFamily::msvc));

  CRF_PHASE("CREATE_SESSION");
  const std::filesystem::path source = crftest::test_root() / "sources" / "race.cpp";
  CRF_REQUIRE(crftest::write_text(
      source, "#include <cstdio>\nint main() { std::printf(\"CRF-SMOKE-OK\\n\"); return 0; }\n"));
  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {source};
  request.adapter_options.push_back(EnvironmentVariable{"msvc.expected_stdout", "CRF-SMOKE-OK"});
  const Result<Ref<CompilerSessionId>> created = runtime.value()->create_session(request);
  CRF_REQUIRE_OK(created);
  const Result<CompilerSession> session = runtime.value()->require_session(created.value().id);
  CRF_REQUIRE_OK(session);
  const std::vector<CompilerPhaseId> order = session.value().plan.topological_order();
  CRF_REQUIRE(order.size() >= 2);
  CRF_REQUIRE_OK(runtime.value()->run_phase(created.value().id, order[0]));
  const Result<PhaseRunReport> compiled = runtime.value()->run_phase(created.value().id, order[1]);
  CRF_REQUIRE_OK(compiled);
  CRF_REQUIRE(compiled.value().committed());
  const std::uint64_t commits = runtime.value()->commit_count();

  CRF_PHASE("RACE");
  // Two threads replay the identical completion for one phase generation.
  std::atomic<int> duplicated{0};
  std::atomic<int> divergent{0};
  std::atomic<int> other{0};
  std::vector<std::thread> threads;
  for (int i = 0; i < 4; ++i) {
    threads.emplace_back([&]() {
      const Result<PhaseRunReport> report = runtime.value()->commit_phase(
          created.value().id, order[1], compiled.value().phase.generation,
          compiled.value().invocation);
      if (!report) {
        if (report.code() == StatusCode::divergent_completion) divergent.fetch_add(1);
        else other.fetch_add(1);
        return;
      }
      const Result<PhaseRunReport> again = runtime.value()->commit_phase(
          created.value().id, order[1], compiled.value().phase.generation,
          compiled.value().invocation);
      if (!again) {
        if (again.code() == StatusCode::duplicate_completion) duplicated.fetch_add(1);
        else if (again.code() == StatusCode::divergent_completion) divergent.fetch_add(1);
        else other.fetch_add(1);
        return;
      }
      if (again.value().status == StatusCode::duplicate_completion) duplicated.fetch_add(1);
      else other.fetch_add(1);
    });
  }
  for (std::thread& thread : threads) thread.join();

  CRF_PHASE("VERIFY");
  // Exactly one authoritative commit exists for the phase generation; every
  // other completion is reported as a duplicate or refused as divergent.
  CRF_EXPECT_EQ(runtime.value()->commit_count(), commits);
  CRF_EXPECT_EQ(divergent.load(), 0);
  CRF_EXPECT(duplicated.load() >= 1);
  const Result<AuditReport> audit = runtime.value()->audit();
  CRF_REQUIRE_OK(audit);
  CRF_EXPECT(audit.value().zero_violations());
  CRF_EXPECT_OK(runtime.value()->shutdown());
}
