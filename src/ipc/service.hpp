#pragma once

// Control-plane services.
//
// The coordinator owns compiler-session authority and durable state. A worker
// owns nothing: it receives a fully specified execution order, proves the order
// is well formed, runs the compiler locally, and reports evidence back.

#include <atomic>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include "crf/ipc.hpp"
#include "crf/runtime.hpp"

namespace crf {

/// A bidirectional message channel over one framed connection.
///
/// One reader thread owns the socket's receive side and routes each inbound
/// frame either to a waiting request or to the inbound handler. That is what
/// lets a coordinator both serve a worker and dispatch work to it over the same
/// connection without two threads fighting over the socket.
class CRF_API PeerChannel {
 public:
  using Handler = std::function<Result<Message>(const Message&)>;

  explicit PeerChannel(std::unique_ptr<FramedConnection> connection);
  ~PeerChannel();
  PeerChannel(const PeerChannel&) = delete;
  PeerChannel& operator=(const PeerChannel&) = delete;

  /// Start the reader thread with the inbound request handler.
  void start(Handler handler);
  /// Send a request and wait for the reply carrying the same request id.
  CRF_NODISCARD Result<Message> request(Message message);
  void close();
  CRF_NODISCARD bool open() const;
  CRF_NODISCARD const std::string& peer() const;
  CRF_NODISCARD std::uint64_t sent_requests() const noexcept;
  CRF_NODISCARD std::uint64_t received_requests() const noexcept;

 private:
  void pump();
  CRF_NODISCARD std::uint64_t next_request_id() noexcept;

  std::unique_ptr<FramedConnection> connection_;
  Handler handler_;
  std::thread reader_;
  std::mutex mutex_;
  std::unordered_map<std::uint64_t, std::shared_ptr<std::promise<Message>>> pending_;
  std::atomic<std::uint64_t> request_counter_{0};
  std::atomic<std::uint64_t> sent_{0};
  std::atomic<std::uint64_t> received_{0};
  std::atomic<bool> closed_{false};
};

/// Executor that dispatches phase execution to a connected worker.
class CRF_API RemotePhaseExecutor final : public PhaseExecutor {
 public:
  /// Bind to a provider that returns the current worker channel, or nullptr when
  /// no worker is connected.
  explicit RemotePhaseExecutor(std::function<std::shared_ptr<PeerChannel>()> provider);

  Result<ExecutionReport> execute(const InvocationSpec& invocation, const ProcessSpec& process,
                                  const Workspace& workspace, std::string_view phase_label) override;
  VoidResult cancel(Ref<InvocationId> invocation, std::string reason) override;
  std::string describe() const override;
  bool remote() const noexcept override { return true; }

  /// Force every dispatch to fail. Used to prove that a killed worker cannot
  /// satisfy a phase.
  void set_offline(bool offline) { offline_.store(offline); }
  /// The currently bound worker channel, or nullptr when none is connected.
  CRF_NODISCARD std::shared_ptr<PeerChannel> channel() const {
    return provider_ ? provider_() : nullptr;
  }

 private:
  std::function<std::shared_ptr<PeerChannel>()> provider_;
  std::atomic<bool> offline_{false};
};

struct CRF_API CoordinatorOptions {
  RuntimeOptions runtime{};
  ServerOptions server{};
  /// Use a connected worker when one is available; otherwise execute locally.
  bool prefer_worker = true;
};

/// The coordinator's control-plane service. It owns the authoritative runtime.
class CRF_API CoordinatorService {
 public:
  CoordinatorService();
  ~CoordinatorService();
  CoordinatorService(const CoordinatorService&) = delete;
  CoordinatorService& operator=(const CoordinatorService&) = delete;

  CRF_NODISCARD VoidResult start(CoordinatorOptions options);
  /// Accept and serve connections until a shutdown request arrives.
  CRF_NODISCARD VoidResult serve_forever();
  /// Serve exactly one accepted connection. Used by tests that drive precise
  /// interleavings.
  CRF_NODISCARD VoidResult serve_once(std::uint32_t accept_timeout_millis);

  CRF_NODISCARD Runtime& runtime() noexcept;
  CRF_NODISCARD const Runtime& runtime() const noexcept;
  CRF_NODISCARD std::uint16_t port() const noexcept;
  CRF_NODISCARD const std::string& endpoint() const noexcept;
  CRF_NODISCARD bool worker_connected() const;
  CRF_NODISCARD std::size_t connection_count() const;
  void request_shutdown();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

struct CRF_API WorkerOptions {
  std::string coordinator_host = "127.0.0.1";
  std::uint16_t coordinator_port = 0;
  std::string name = "crf-worker";
  std::filesystem::path workspace_root;
  ConnectionOptions connection{};
  /// Exit after serving this many requests; 0 means never.
  std::size_t max_requests = 0;
};

/// The compiler worker. It holds no authority; it executes and reports.
class CRF_API WorkerService {
 public:
  WorkerService();
  ~WorkerService();
  WorkerService(const WorkerService&) = delete;
  WorkerService& operator=(const WorkerService&) = delete;

  CRF_NODISCARD VoidResult connect(WorkerOptions options);
  /// Serve inbound orders until the peer closes or a shutdown is requested.
  CRF_NODISCARD VoidResult serve();
  CRF_NODISCARD std::uint64_t executed_phases() const noexcept;
  CRF_NODISCARD ProcessSupervisor& processes() noexcept;
  void request_shutdown();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace crf
