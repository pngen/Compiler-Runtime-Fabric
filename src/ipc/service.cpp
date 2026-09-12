#include "service.hpp"

#include "crf/canonical.hpp"
#include "crf/version.hpp"

#include <algorithm>
#include <condition_variable>
#include <vector>

namespace crf {

// ---------------------------------------------------------------------------
// PeerChannel
// ---------------------------------------------------------------------------
PeerChannel::PeerChannel(std::unique_ptr<FramedConnection> connection)
    : connection_(std::move(connection)) {}

PeerChannel::~PeerChannel() { close(); }

void PeerChannel::start(Handler handler) {
  handler_ = std::move(handler);
  reader_ = std::thread([this]() { pump(); });
}

std::uint64_t PeerChannel::next_request_id() noexcept {
  return request_counter_.fetch_add(1) + 1;
}

Result<Message> PeerChannel::request(Message message) {
  if (!open()) {
    return Status(StatusCode::protocol_peer_closed, "channel is not open");
  }
  if (message.request_id == 0) message.request_id = next_request_id();
  auto promise = std::make_shared<std::promise<Message>>();
  std::future<Message> future = promise->get_future();
  {
    const std::lock_guard<std::mutex> guard(mutex_);
    pending_[message.request_id] = promise;
  }
  const VoidResult sent = connection_->send(message);
  if (!sent) {
    const std::lock_guard<std::mutex> guard(mutex_);
    pending_.erase(message.request_id);
    return sent.status();
  }
  sent_.fetch_add(1);
  // A peer that dies mid-request must produce a refusal, never an exception
  // escaping into the executor: the runtime classifies a lost worker as an
  // interrupted process, and an exception here would tear the runtime down.
  try {
    return future.get();
  } catch (const std::exception& error) {
    return Status(StatusCode::protocol_peer_closed, error.what());
  } catch (...) {
    return Status(StatusCode::protocol_peer_closed, "the peer closed before replying");
  }
}

void PeerChannel::pump() {
  for (;;) {
    Result<Message> inbound = connection_->receive();
    if (!inbound) {
      break;
    }
    received_.fetch_add(1);
    Message message = inbound.value();
    if (message.type != MessageType::hello && connection_ != nullptr &&
        !connection_->note_request(message.request_id)) {
      Message failure;
      failure.type = MessageType::error;
      failure.request_id = message.request_id;
      failure.payload = encode_error(StatusCode::protocol_duplicate_request,
                                     "this request id was already served on this connection");
      const VoidResult sent = connection_->send(failure);
      (void)sent;
      continue;
    }
    std::shared_ptr<std::promise<Message>> waiting;
    {
      const std::lock_guard<std::mutex> guard(mutex_);
      const auto found = pending_.find(message.request_id);
      if (found != pending_.end()) {
        waiting = found->second;
        pending_.erase(found);
      }
    }
    if (waiting != nullptr) {
      waiting->set_value(std::move(message));
      continue;
    }
    if (handler_ == nullptr) continue;
    Result<Message> reply = handler_(message);
    if (reply) {
      Message response = reply.value();
      response.request_id = message.request_id;
      const VoidResult sent = connection_->send(response);
      (void)sent;
    } else {
      Message failure;
      failure.type = MessageType::error;
      failure.request_id = message.request_id;
      failure.payload = encode_error(reply.code(), reply.status().message());
      const VoidResult sent = connection_->send(failure);
      (void)sent;
    }
  }
  // The reader stopped: close the socket so the peer observes the end of the
  // connection instead of blocking on a half-open socket, then fail every
  // waiting request rather than hanging.
  if (connection_) connection_->close();
  std::unordered_map<std::uint64_t, std::shared_ptr<std::promise<Message>>> pending;
  {
    const std::lock_guard<std::mutex> guard(mutex_);
    pending.swap(pending_);
  }
  for (auto& [key, promise] : pending) {
    (void)key;
    try {
      promise->set_exception(std::make_exception_ptr(
          std::runtime_error("peer channel closed before the reply arrived")));
    } catch (...) {
    }
  }
}

void PeerChannel::close() {
  if (closed_.exchange(true)) return;
  if (connection_) connection_->close();
  if (reader_.joinable() && reader_.get_id() != std::this_thread::get_id()) {
    reader_.join();
  }
}

bool PeerChannel::open() const { return connection_ && connection_->open(); }

const std::string& PeerChannel::peer() const {
  static const std::string kEmpty;
  return connection_ ? connection_->peer() : kEmpty;
}

std::uint64_t PeerChannel::sent_requests() const noexcept { return sent_.load(); }
std::uint64_t PeerChannel::received_requests() const noexcept { return received_.load(); }

// ---------------------------------------------------------------------------
// RemotePhaseExecutor
// ---------------------------------------------------------------------------
RemotePhaseExecutor::RemotePhaseExecutor(std::function<std::shared_ptr<PeerChannel>()> provider)
    : provider_(std::move(provider)) {}

Result<ExecutionReport> RemotePhaseExecutor::execute(const InvocationSpec& invocation,
                                                     const ProcessSpec& process,
                                                     const Workspace& workspace,
                                                     std::string_view phase_label) {
  ExecutionReport report;
  report.workspace_root = workspace.root;
  report.workspace_marker = workspace.marker_digest;
  if (offline_.load()) {
    report.status = StatusCode::protocol_peer_closed;
    report.detail = "the worker is offline; no physical execution is possible";
    return report;
  }
  std::shared_ptr<PeerChannel> channel = provider_ ? provider_() : nullptr;
  if (channel == nullptr || !channel->open()) {
    report.status = StatusCode::protocol_peer_closed;
    report.detail = "no compiler worker is connected";
    return report;
  }

  // The worker validates the workspace marker before it is allowed to execute
  // inside it, so a stale or foreign directory cannot receive output.
  Message prepare;
  prepare.type = MessageType::prepare_workspace;
  prepare.payload = [&]() {
    FieldWriter writer;
    writer.u64(1, invocation.session.id.value());
    writer.u64(2, invocation.session.generation.value());
    writer.u64(3, invocation.phase.id.value());
    writer.u64(4, invocation.phase.generation.value());
    writer.blob(5, workspace.root.string());
    return writer.take();
  }();
  const Result<Message> ready = channel->request(prepare);
  if (!ready) {
    report.status = ready.code();
    report.detail = ready.status().message();
    return report;
  }
  if (ready.value().type == MessageType::error) {
    const Result<std::pair<StatusCode, std::string>> decoded = decode_error(ready.value().payload);
    report.status = decoded ? decoded.value().first : StatusCode::protocol_malformed;
    report.detail = decoded ? decoded.value().second : std::string("malformed error reply");
    return report;
  }

  Message order;
  order.type = MessageType::start_phase;
  order.payload = encode_invocation_order(invocation, process, workspace.root.string(), phase_label);
  const Result<Message> executed = channel->request(order);
  if (!executed) {
    report.status = executed.code();
    report.detail = executed.status().message();
    return report;
  }
  if (executed.value().type == MessageType::error) {
    const Result<std::pair<StatusCode, std::string>> decoded =
        decode_error(executed.value().payload);
    report.status = decoded ? decoded.value().first : StatusCode::protocol_malformed;
    report.detail = decoded ? decoded.value().second : std::string("malformed error reply");
    return report;
  }
  const Result<ExecutionReport> decoded = decode_execution_report(executed.value().payload);
  if (!decoded) {
    report.status = decoded.code();
    report.detail = decoded.status().message();
    return report;
  }
  ExecutionReport remote = decoded.value();
  remote.workspace_root = workspace.root;
  remote.workspace_marker = workspace.marker_digest;
  return remote;
}

VoidResult RemotePhaseExecutor::cancel(Ref<InvocationId> invocation, std::string reason) {
  std::shared_ptr<PeerChannel> channel = provider_ ? provider_() : nullptr;
  if (channel == nullptr || !channel->open()) {
    return Status(StatusCode::protocol_peer_closed, "no compiler worker is connected");
  }
  FieldWriter writer;
  writer.u64(1, invocation.id.value());
  writer.u64(2, invocation.generation.value());
  writer.text(3, reason);
  Message message;
  message.type = MessageType::cancel_phase;
  message.payload = writer.take();
  const Result<Message> reply = channel->request(message);
  if (!reply) return reply.status();
  return VoidResult{};
}

std::string RemotePhaseExecutor::describe() const {
  return offline_.load() ? "remote worker executor (offline)" : "remote worker executor";
}

// ---------------------------------------------------------------------------
// Coordinator
// ---------------------------------------------------------------------------
struct CoordinatorService::Impl {
  CoordinatorOptions options;
  std::unique_ptr<Runtime> runtime;
  std::unique_ptr<ControlServer> server;
  std::shared_ptr<PeerChannel> worker;
  std::shared_ptr<RemotePhaseExecutor> remote;
  mutable std::mutex mutex;
  std::vector<std::shared_ptr<PeerChannel>> connections;
  std::atomic<bool> shutdown_requested{false};
  std::unique_ptr<WorkspaceManager> workspaces;

  CRF_NODISCARD Result<Message> handle(const Message& request,
                                       const std::shared_ptr<PeerChannel>& origin) {
    Message reply;
    const auto failure = [&request](const Status& status) {
      Message message;
      message.type = MessageType::error;
      message.request_id = request.request_id;
      message.payload = encode_error(status.code(), status.message());
      return message;
    };
    switch (request.type) {
      case MessageType::hello: {
        const Result<std::string> detail = decode_hello_detail(request.payload);
        if (!detail) return failure(detail.status());
        const bool is_worker = detail.value().rfind("worker|", 0) == 0;
        if (is_worker && origin != nullptr) {
          // Only a peer that identifies itself as a worker is adopted as the
          // execution backend. A client connection never displaces it.
          const std::lock_guard<std::mutex> guard(mutex);
          worker = origin;
        }
        reply.type = MessageType::hello_ack;
        reply.payload = encode_hello(options.runtime.runtime_name, "coordinator", runtime->epoch(),
                                     is_worker ? "worker registered" : "client");
        return reply;
      }
      case MessageType::ping:
        reply.type = MessageType::pong;
        return reply;
      case MessageType::refresh_toolchain:
      case MessageType::invalidate_toolchain: {
        FieldReader reader(request.payload);
        std::uint64_t id = 0;
        std::string reason;
        for (;;) {
          const Result<bool> next = reader.next();
          if (!next) return failure(next.status());
          if (!next.value()) break;
          if (reader.id() == 1) {
            const Result<std::uint64_t> value = reader.as_u64();
            if (!value) return failure(value.status());
            id = value.value();
          } else if (reader.id() == 2) {
            const Result<std::string> value = reader.as_text();
            if (!value) return failure(value.status());
            reason = value.value();
          }
        }
        const Result<ToolchainMutation> mutation =
            request.type == MessageType::refresh_toolchain
                ? runtime->refresh_toolchain(ToolchainId::from_value(id))
                : runtime->invalidate_toolchain(ToolchainId::from_value(id), std::move(reason));
        if (!mutation) return failure(mutation.status());
        FieldWriter writer;
        writer.boolean(1, mutation.value().mutated);
        writer.u64(2, mutation.value().current_generation.value());
        writer.text(3, mutation.value().detail);
        reply.type = MessageType::toolchain_report;
        reply.payload = writer.take();
        return reply;
      }
      case MessageType::recover_session: {
        FieldReader reader(request.payload);
        const Result<bool> next = reader.next();
        if (!next) return failure(next.status());
        const Result<std::uint64_t> id = reader.as_u64();
        if (!id) return failure(id.status());
        const Result<RecoveryPlan> applied =
            runtime->apply_recovery(CompilerSessionId::from_value(id.value()));
        if (!applied) return failure(applied.status());
        FieldWriter writer;
        writer.u8(1, static_cast<std::uint8_t>(applied.value().headline));
        writer.boolean(2, applied.value().legal);
        writer.boolean(3, applied.value().requires_operator);
        writer.text(4, applied.value().rationale);
        reply.type = MessageType::recovery_report;
        reply.payload = writer.take();
        return reply;
      }
      case MessageType::create_session: {
        const Result<CompileRequest> decoded = decode_compile_request(request.payload);
        if (!decoded) return failure(decoded.status());
        // The control plane discovers the toolchain on demand so that a caller
        // never has to know whether the coordinator has probed yet.
        if (runtime->toolchains().find_latest(decoded.value().toolchain_family) == nullptr) {
          const Result<Ref<ToolchainId>> discovered =
              runtime->discover_toolchain(decoded.value().toolchain_family);
          if (!discovered) return failure(discovered.status());
        }
        // Session creation is separate from session execution so that a caller
        // can drive phases one at a time and observe each boundary.
        const Result<Ref<CompilerSessionId>> created = runtime->create_session(decoded.value());
        if (!created) return failure(created.status());
        const Result<CompilerSession> session = runtime->require_session(created.value().id);
        if (!session) return failure(session.status());
        reply.type = MessageType::session_created;
        reply.payload = encode_session_summary(session.value());
        return reply;
      }
      case MessageType::run_session: {
        FieldReader reader(request.payload);
        const Result<bool> next = reader.next();
        if (!next) return failure(next.status());
        const Result<std::uint64_t> id = reader.as_u64();
        if (!id) return failure(id.status());
        const Result<CompileOutcome> outcome =
            runtime->run_session(CompilerSessionId::from_value(id.value()));
        if (!outcome) return failure(outcome.status());
        const Result<CompilerSession> session =
            runtime->require_session(CompilerSessionId::from_value(id.value()));
        if (!session) return failure(session.status());
        reply.type = MessageType::session_ran;
        reply.payload = encode_session_summary(session.value());
        return reply;
      }
      case MessageType::query_session: {
        FieldReader reader(request.payload);
        const Result<bool> next = reader.next();
        if (!next) return failure(next.status());
        const Result<std::uint64_t> id = reader.as_u64();
        if (!id) return failure(id.status());
        const Result<CompilerSession> session =
            runtime->require_session(CompilerSessionId::from_value(id.value()));
        if (!session) return failure(session.status());
        reply.type = MessageType::session_report;
        reply.payload = encode_session_summary(session.value());
        return reply;
      }
      case MessageType::session_list: {
        FieldWriter writer;
        std::string blob;
        CanonicalWriter canonical;
        const std::vector<CompilerSession> sessions = runtime->list_sessions();
        canonical.u64(sessions.size());
        for (const CompilerSession& session : sessions) canonical.text(encode_session(session));
        writer.blob(1, canonical.bytes());
        reply.type = MessageType::session_list;
        reply.payload = writer.take();
        return reply;
      }
      case MessageType::start_phase: {
        FieldReader reader(request.payload);
        const Result<bool> next = reader.next();
        if (!next) return failure(next.status());
        const Result<std::uint64_t> session = reader.as_u64();
        if (!session) return failure(session.status());
        const Result<bool> next_phase = reader.next();
        if (!next_phase) return failure(next_phase.status());
        const Result<std::uint64_t> phase = reader.as_u64();
        if (!phase) return failure(phase.status());
        const Result<PhaseRunReport> report = runtime->run_phase(
            CompilerSessionId::from_value(session.value()), CompilerPhaseId::from_value(phase.value()));
        if (!report) return failure(report.status());
        reply.type = MessageType::phase_started;
        reply.payload = encode_phase_report(report.value());
        return reply;
      }
      case MessageType::retry_phase: {
        FieldReader reader(request.payload);
        std::uint64_t values[2] = {0, 0};
        for (;;) {
          const Result<bool> next = reader.next();
          if (!next) return failure(next.status());
          if (!next.value()) break;
          if (reader.id() < 1 || reader.id() > 2) continue;
          const Result<std::uint64_t> value = reader.as_u64();
          if (!value) return failure(value.status());
          values[reader.id() - 1] = value.value();
        }
        const Result<PhaseRunReport> report =
            runtime->retry_phase(CompilerSessionId::from_value(values[0]),
                                 CompilerPhaseId::from_value(values[1]));
        if (!report) return failure(report.status());
        reply.type = MessageType::phase_started;
        reply.payload = encode_phase_report(report.value());
        return reply;
      }
      case MessageType::commit_phase: {
        const Result<std::tuple<CompilerSessionId, CompilerPhaseId, CompilerPhaseGeneration,
                                Ref<InvocationId>>> decoded = decode_phase_reference(request.payload);
        if (!decoded) return failure(decoded.status());
        const auto& [session, phase, generation, invocation] = decoded.value();
        const Result<PhaseRunReport> report =
            runtime->commit_phase(session, phase, generation, invocation);
        if (!report) return failure(report.status());
        reply.type = MessageType::phase_committed;
        reply.payload = encode_phase_report(report.value());
        return reply;
      }
      case MessageType::report_output: {
        const Result<std::tuple<CompilerSessionId, CompilerPhaseId, CompilerPhaseGeneration,
                                Ref<InvocationId>>> decoded = decode_phase_reference(request.payload);
        if (!decoded) return failure(decoded.status());
        const auto& [session, phase, generation, invocation] = decoded.value();
        const Result<PhaseRunReport> report =
            runtime->commit_phase(session, phase, generation, invocation);
        if (!report) return failure(report.status());
        reply.type = MessageType::output_reported;
        reply.payload = encode_phase_report(report.value());
        return reply;
      }
      case MessageType::cancel_phase: {
        FieldReader reader(request.payload);
        std::uint64_t values[2] = {0, 0};
        std::string reason;
        for (;;) {
          const Result<bool> next = reader.next();
          if (!next) return failure(next.status());
          if (!next.value()) break;
          if (reader.id() == 1 || reader.id() == 2) {
            const Result<std::uint64_t> value = reader.as_u64();
            if (!value) return failure(value.status());
            values[reader.id() - 1] = value.value();
          } else if (reader.id() == 3) {
            const Result<std::string> value = reader.as_text();
            if (!value) return failure(value.status());
            reason = value.value();
          }
        }
        const VoidResult cancelled =
            runtime->cancel_phase(CompilerSessionId::from_value(values[0]),
                                  CompilerPhaseId::from_value(values[1]), reason);
        if (!cancelled) return failure(cancelled.status());
        reply.type = MessageType::phase_cancelled;
        return reply;
      }
      case MessageType::query_authority: {
        FieldReader reader(request.payload);
        std::uint64_t values[2] = {0, 0};
        for (;;) {
          const Result<bool> next = reader.next();
          if (!next) return failure(next.status());
          if (!next.value()) break;
          if (reader.id() < 1 || reader.id() > 2) continue;
          const Result<std::uint64_t> value = reader.as_u64();
          if (!value) return failure(value.status());
          values[reader.id() - 1] = value.value();
        }
        const Result<AuthorityVerdict> verdict =
            runtime->check_authority(CompilerSessionId::from_value(values[0]),
                                     CompilerPhaseId::from_value(values[1]));
        if (!verdict) return failure(verdict.status());
        FieldWriter writer;
        writer.u8(1, static_cast<std::uint8_t>(verdict.value()));
        reply.type = MessageType::authority_report;
        reply.payload = writer.take();
        return reply;
      }
      case MessageType::query_diagnostics: {
        FieldReader reader(request.payload);
        const Result<bool> next = reader.next();
        if (!next) return failure(next.status());
        const Result<std::uint64_t> id = reader.as_u64();
        if (!id) return failure(id.status());
        const DiagnosticSet* set = runtime->diagnostics().find(DiagnosticSetId::from_value(id.value()));
        if (set == nullptr) {
          return failure(Status(StatusCode::not_found, "diagnostic set is not registered"));
        }
        FieldWriter writer;
        writer.blob(1, encode_diagnostic_set(*set));
        reply.type = MessageType::diagnostics_report;
        reply.payload = writer.take();
        return reply;
      }
      case MessageType::snapshot: {
        const VoidResult written = runtime->snapshot();
        if (!written) return failure(written.status());
        FieldWriter writer;
        writer.boolean(1, true);
        reply.type = MessageType::snapshot_report;
        reply.payload = writer.take();
        return reply;
      }
      case MessageType::audit: {
        const Result<AuditReport> report = runtime->audit();
        if (!report) return failure(report.status());
        reply.type = MessageType::audit_report;
        reply.payload = encode_audit_report(report.value());
        return reply;
      }
      case MessageType::shutdown: {
        reply.type = MessageType::shutdown_ack;
        shutdown_requested.store(true);
        return reply;
      }
      default:
        return failure(Status(StatusCode::protocol_unknown_operation,
                              std::string("unsupported operation ") +
                                  std::string(to_string(request.type))));
    }
  }
};

CoordinatorService::CoordinatorService() : impl_(std::make_unique<Impl>()) {}
CoordinatorService::~CoordinatorService() { request_shutdown(); }

VoidResult CoordinatorService::start(CoordinatorOptions options) {
  impl_->options = std::move(options);
  Result<std::unique_ptr<Runtime>> runtime = Runtime::create(impl_->options.runtime);
  if (!runtime) return runtime.status();
  impl_->runtime = std::move(runtime.value());
  Result<std::unique_ptr<ControlServer>> server = ControlServer::listen(impl_->options.server);
  if (!server) return server.status();
  impl_->server = std::move(server.value());
  // The coordinator dispatches to a worker when one is connected and executes
  // locally otherwise; both paths use the same governed pipeline.
  impl_->remote = std::make_shared<RemotePhaseExecutor>([this]() -> std::shared_ptr<PeerChannel> {
    const std::lock_guard<std::mutex> guard(impl_->mutex);
    if (impl_->worker == nullptr || !impl_->worker->open()) return nullptr;
    return impl_->worker;
  });
  auto local = make_local_executor(*impl_->runtime);
  // A connected worker is used whenever one is present; the local path keeps the
  // coordinator useful on its own. Using the local path is never a silent
  // substitute for a worker that was expected to be there: the caller sees the
  // executor description in the runtime explanation.
  struct AdaptiveExecutor final : PhaseExecutor {
    std::shared_ptr<RemotePhaseExecutor> worker_executor;
    std::shared_ptr<PhaseExecutor> local_executor;
    Result<ExecutionReport> execute(const InvocationSpec& invocation, const ProcessSpec& process,
                                    const Workspace& workspace, std::string_view label) override {
      if (worker_executor != nullptr) {
        std::shared_ptr<PeerChannel> channel = worker_executor->channel();
        if (channel != nullptr && channel->open()) {
          return worker_executor->execute(invocation, process, workspace, label);
        }
      }
      return local_executor->execute(invocation, process, workspace, label);
    }
    VoidResult cancel(Ref<InvocationId> invocation, std::string reason) override {
      if (worker_executor != nullptr) {
        std::shared_ptr<PeerChannel> channel = worker_executor->channel();
        if (channel != nullptr && channel->open()) return worker_executor->cancel(invocation, reason);
      }
      return local_executor->cancel(invocation, reason);
    }
    std::string describe() const override {
      const std::shared_ptr<PeerChannel> channel =
          worker_executor != nullptr ? worker_executor->channel() : nullptr;
      return channel != nullptr && channel->open()
                 ? "worker-preferred executor (worker connected)"
                 : "worker-preferred executor (local fallback)";
    }
    bool remote() const noexcept override { return false; }
  };
  auto adaptive = std::make_shared<AdaptiveExecutor>();
  adaptive->worker_executor = impl_->remote;
  adaptive->local_executor = local;
  impl_->runtime->set_executor(adaptive);
  return VoidResult{};
}

Runtime& CoordinatorService::runtime() noexcept { return *impl_->runtime; }
const Runtime& CoordinatorService::runtime() const noexcept { return *impl_->runtime; }
std::uint16_t CoordinatorService::port() const noexcept { return impl_->server->port(); }
const std::string& CoordinatorService::endpoint() const noexcept { return impl_->server->endpoint(); }
void CoordinatorService::request_shutdown() { impl_->shutdown_requested.store(true); }

bool CoordinatorService::worker_connected() const {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->worker != nullptr && impl_->worker->open();
}

std::size_t CoordinatorService::connection_count() const {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->connections.size();
}

VoidResult CoordinatorService::serve_once(std::uint32_t accept_timeout_millis) {
  Result<std::unique_ptr<FramedConnection>> accepted = impl_->server->accept(accept_timeout_millis);
  if (!accepted) return accepted.status();
  auto channel = std::make_shared<PeerChannel>(std::move(accepted.value()));
  {
    const std::lock_guard<std::mutex> guard(impl_->mutex);
    impl_->connections.push_back(channel);
  }
  channel->start([this, channel](const Message& message) { return impl_->handle(message, channel); });
  return VoidResult{};
}

VoidResult CoordinatorService::serve_forever() {
  while (!impl_->shutdown_requested.load()) {
    const VoidResult served = serve_once(200);
    if (!served) {
      if (served.code() == StatusCode::not_found) continue;
      return served.status();
    }
  }
  return VoidResult{};
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------
struct WorkerService::Impl {
  WorkerOptions options;
  std::unique_ptr<FramedConnection> connection;
  std::unique_ptr<WorkspaceManager> workspaces;
  ProcessSupervisor processes{};
  std::atomic<std::uint64_t> executed{0};
  std::atomic<bool> shutdown_requested{false};
  std::mutex mutex;
  std::unordered_map<std::uint64_t, Result<ExecutionReport>> results;

  CRF_NODISCARD Result<Message> handle(const Message& request) {
    Message reply;
    const auto failure = [&request](const Status& status) {
      Message message;
      message.type = MessageType::error;
      message.request_id = request.request_id;
      message.payload = encode_error(status.code(), status.message());
      return message;
    };
    switch (request.type) {
      case MessageType::hello: {
        reply.type = MessageType::hello_ack;
        reply.payload = encode_hello(options.name, "worker", 0, "worker ready");
        return reply;
      }
      case MessageType::ping:
        reply.type = MessageType::pong;
        return reply;
      case MessageType::prepare_workspace: {
        const Result<std::tuple<CompilerSessionId, CompilerSessionGeneration, CompilerPhaseId,
                                CompilerPhaseGeneration>> decoded =
            decode_workspace_request(request.payload);
        if (!decoded) return failure(decoded.status());
        const auto& [session, session_generation, phase, phase_generation] = decoded.value();
        FieldReader reader(request.payload);
        std::string root;
        for (;;) {
          const Result<bool> next = reader.next();
          if (!next) return failure(next.status());
          if (!next.value()) break;
          if (reader.id() != 5) continue;
          const Result<std::string> value = reader.as_text();
          if (!value) return failure(value.status());
          root = value.value();
        }
        if (root.empty()) {
          return failure(Status(StatusCode::invalid_argument, "workspace root was not supplied"));
        }
        const std::filesystem::path workspace_root = normalize_path(std::filesystem::path(root));
        // The worker refuses to execute anywhere outside its configured root.
        if (!options.workspace_root.empty() &&
            !path_is_within(workspace_root, options.workspace_root)) {
          return failure(Status(StatusCode::workspace_escape,
                                "ordered workspace is outside the worker's permitted root"));
        }
        const Result<Workspace> workspace = workspaces->open(workspace_root, session,
                                                             session_generation, phase,
                                                             phase_generation);
        if (!workspace) return failure(workspace.status());
        FieldWriter writer;
        writer.boolean(1, true);
        writer.blob(2, workspace.value().marker_digest.to_hex());
        reply.type = MessageType::workspace_ready;
        reply.payload = writer.take();
        return reply;
      }
      case MessageType::start_phase: {
        ProcessSpec process;
        std::string workspace_root;
        std::string phase_label;
        Result<InvocationSpec> invocation = decode_invocation_order(request.payload, process,
                                                                    workspace_root, phase_label);
        if (!invocation) return failure(invocation.status());
        InvocationSpec spec = invocation.value();

        // The worker proves the order is well formed before launching anything,
        // and re-proves the executable bytes against the digest it was given.
        InvocationValidationContext context;
        context.family = ToolchainFamily::unknown;
        context.target_architecture = Architecture::x64;
        context.require_component_identity = false;
        const Result<InvocationSpec> validated = validate_invocation(std::move(spec), context);
        if (!validated) return failure(validated.status());
        const InvocationSpec& checked = validated.value();
        if (!checked.executable_identity.content.zero()) {
          const Result<FileIdentity> observed = probe_file_identity(checked.executable, true);
          if (!observed) return failure(observed.status());
          if (observed.value().content != checked.executable_identity.content) {
            return failure(Status(StatusCode::component_mutated,
                                  "the ordered executable no longer matches the digest it was "
                                  "ordered with"));
          }
        }
        Result<ProcessSpec> effective = checked.to_process_spec();
        if (!effective) return failure(effective.status());
        effective.value().environment = process.environment;
        effective.value().timeout_millis = process.timeout_millis;
        effective.value().max_capture_bytes =
            process.max_capture_bytes == 0 ? kDefaultCaptureBytes : process.max_capture_bytes;
        effective.value().working_directory = process.working_directory;

        ExecutionReport report;
        const Result<ProcessOutcome> outcome = processes.run(
            effective.value(), Ref<InvocationId>{checked.id, checked.generation});
        if (!outcome) return failure(outcome.status());
        report.executed = true;
        report.process = outcome.value();
        report.status = report.process.status.code();
        report.detail = report.process.status.message();
        for (const OutputBinding& binding : checked.expected_outputs) {
          OutputDescriptor descriptor;
          descriptor.logical_name = binding.logical_name;
          descriptor.path = binding.path;
          descriptor.format = binding.expected_format;
          std::error_code ec;
          if (std::filesystem::is_regular_file(binding.path, ec) && !ec) {
            descriptor.exists = true;
            descriptor.size_bytes =
                static_cast<std::uint64_t>(std::filesystem::file_size(binding.path, ec));
            Digest content;
            if (Digest::of_file(binding.path, content)) descriptor.content = content;
          }
          report.outputs.push_back(std::move(descriptor));
        }
        executed.fetch_add(1);
        reply.type = MessageType::phase_started;
        reply.payload = encode_execution_report(report);
        return reply;
      }
      case MessageType::cancel_phase: {
        FieldReader reader(request.payload);
        std::uint64_t values[2] = {0, 0};
        std::string reason;
        for (;;) {
          const Result<bool> next = reader.next();
          if (!next) return failure(next.status());
          if (!next.value()) break;
          if (reader.id() == 1 || reader.id() == 2) {
            const Result<std::uint64_t> value = reader.as_u64();
            if (!value) return failure(value.status());
            values[reader.id() - 1] = value.value();
          } else if (reader.id() == 3) {
            const Result<std::string> value = reader.as_text();
            if (!value) return failure(value.status());
            reason = value.value();
          }
        }
        Ref<InvocationId> invocation;
        invocation.id = InvocationId::from_value(values[0]);
        invocation.generation = InvocationGeneration::from_value(values[1]);
        (void)reason;
        reply.type = MessageType::phase_cancelled;
        return reply;
      }
      case MessageType::shutdown: {
        reply.type = MessageType::shutdown_ack;
        shutdown_requested.store(true);
        return reply;
      }
      default:
        return failure(Status(StatusCode::protocol_unknown_operation,
                              std::string("unsupported worker operation ") +
                                  std::string(to_string(request.type))));
    }
  }
};

WorkerService::WorkerService() : impl_(std::make_unique<Impl>()) {}
WorkerService::~WorkerService() { impl_->processes.close(); }

VoidResult WorkerService::connect(WorkerOptions options) {
  impl_->options = std::move(options);
  impl_->options.workspace_root = normalize_path(impl_->options.workspace_root);
  std::error_code ec;
  std::filesystem::create_directories(impl_->options.workspace_root, ec);
  if (ec) {
    return Status(StatusCode::permission_denied,
                  "worker workspace root could not be created: " + ec.message());
  }
  WorkspaceOptions workspace_options;
  workspace_options.base_directory = impl_->options.workspace_root;
  impl_->workspaces = std::make_unique<WorkspaceManager>(workspace_options);

  Result<std::unique_ptr<FramedConnection>> connection = FramedConnection::connect(
      impl_->options.coordinator_host, impl_->options.coordinator_port, impl_->options.connection);
  if (!connection) return connection.status();
  impl_->connection = std::move(connection.value());

  Message hello;
  hello.type = MessageType::hello;
  hello.payload = encode_hello(impl_->options.name, "worker", 0, "worker ready");
  const Result<Message> acknowledged = impl_->connection->transact(hello);
  if (!acknowledged) return acknowledged.status();
  if (acknowledged.value().type != MessageType::hello_ack) {
    return Status(StatusCode::protocol_malformed, "coordinator did not acknowledge the handshake");
  }
  const Result<std::string> detail = decode_hello_detail(acknowledged.value().payload);
  if (!detail) return detail.status();
  if (detail.value().rfind("coordinator|", 0) != 0) {
    return Status(StatusCode::protocol_malformed, "peer is not a coordinator");
  }
  return VoidResult{};
}

VoidResult WorkerService::serve() {
  std::size_t served = 0;
  while (!impl_->shutdown_requested.load()) {
    Result<Message> inbound = impl_->connection->receive();
    if (!inbound) {
      if (inbound.code() == StatusCode::protocol_peer_closed ||
          inbound.code() == StatusCode::protocol_frame_truncated) {
        return VoidResult{};
      }
      return inbound.status();
    }
    if (!impl_->connection->note_request(inbound.value().request_id)) {
      Message failure;
      failure.type = MessageType::error;
      failure.request_id = inbound.value().request_id;
      failure.payload = encode_error(StatusCode::protocol_duplicate_request,
                                     "this request id was already served on this connection");
      const VoidResult sent = impl_->connection->send(failure);
      (void)sent;
      continue;
    }
    Result<Message> reply = impl_->handle(inbound.value());
    if (reply) {
      Message response = reply.value();
      response.request_id = inbound.value().request_id;
      const VoidResult sent = impl_->connection->send(response);
      if (!sent) return sent.status();
    } else {
      Message failure;
      failure.type = MessageType::error;
      failure.request_id = inbound.value().request_id;
      failure.payload = encode_error(reply.code(), reply.status().message());
      const VoidResult sent = impl_->connection->send(failure);
      if (!sent) return sent.status();
    }
    if (impl_->shutdown_requested.load()) return VoidResult{};
    ++served;
    if (impl_->options.max_requests != 0 && served >= impl_->options.max_requests) return VoidResult{};
  }
  return VoidResult{};
}

std::uint64_t WorkerService::executed_phases() const noexcept { return impl_->executed.load(); }
ProcessSupervisor& WorkerService::processes() noexcept { return impl_->processes; }
void WorkerService::request_shutdown() { impl_->shutdown_requested.store(true); }

}  // namespace crf
