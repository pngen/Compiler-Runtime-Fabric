#include "crf/ipc.hpp"

#include "crf/canonical.hpp"
#include "crf/version.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_set>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#endif

namespace crf {
namespace {

#if defined(_WIN32)
using SocketHandle = SOCKET;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;

struct WinsockScope {
  WinsockScope() {
    WSADATA data{};
    ::WSAStartup(MAKEWORD(2, 2), &data);
  }
  ~WinsockScope() { ::WSACleanup(); }
};

void ensure_winsock() {
  static WinsockScope scope;
  (void)scope;
}

CRF_NODISCARD bool would_block() noexcept {
  const int error = ::WSAGetLastError();
  return error == WSAETIMEDOUT || error == WSAEWOULDBLOCK;
}
#endif

CRF_NODISCARD Result<Message> malformed(std::string_view detail) {
  return Status(StatusCode::protocol_malformed, std::string(detail));
}

}  // namespace

std::string_view to_string(MessageType value) noexcept {
  switch (value) {
    case MessageType::invalid: return "INVALID";
    case MessageType::hello: return "HELLO";
    case MessageType::hello_ack: return "HELLO_ACK";
    case MessageType::ping: return "PING";
    case MessageType::pong: return "PONG";
    case MessageType::error: return "ERROR";
    case MessageType::create_session: return "CREATE_SESSION";
    case MessageType::session_created: return "SESSION_CREATED";
    case MessageType::query_session: return "QUERY_SESSION";
    case MessageType::session_report: return "SESSION_REPORT";
    case MessageType::list_sessions: return "LIST_SESSIONS";
    case MessageType::session_list: return "SESSION_LIST";
    case MessageType::prepare_workspace: return "PREPARE_WORKSPACE";
    case MessageType::workspace_ready: return "WORKSPACE_READY";
    case MessageType::start_phase: return "START_PHASE";
    case MessageType::phase_started: return "PHASE_STARTED";
    case MessageType::cancel_phase: return "CANCEL_PHASE";
    case MessageType::phase_cancelled: return "PHASE_CANCELLED";
    case MessageType::report_process: return "REPORT_PROCESS";
    case MessageType::process_reported: return "PROCESS_REPORTED";
    case MessageType::report_output: return "REPORT_OUTPUT";
    case MessageType::output_reported: return "OUTPUT_REPORTED";
    case MessageType::commit_phase: return "COMMIT_PHASE";
    case MessageType::phase_committed: return "PHASE_COMMITTED";
    case MessageType::fail_phase: return "FAIL_PHASE";
    case MessageType::phase_failed: return "PHASE_FAILED";
    case MessageType::retry_phase: return "RETRY_PHASE";
    case MessageType::query_authority: return "QUERY_AUTHORITY";
    case MessageType::authority_report: return "AUTHORITY_REPORT";
    case MessageType::validate_artifact: return "VALIDATE_ARTIFACT";
    case MessageType::artifact_report: return "ARTIFACT_REPORT";
    case MessageType::query_diagnostics: return "QUERY_DIAGNOSTICS";
    case MessageType::diagnostics_report: return "DIAGNOSTICS_REPORT";
    case MessageType::recover_session: return "RECOVER_SESSION";
    case MessageType::recovery_report: return "RECOVERY_REPORT";
    case MessageType::snapshot: return "SNAPSHOT";
    case MessageType::snapshot_report: return "SNAPSHOT_REPORT";
    case MessageType::audit: return "AUDIT";
    case MessageType::audit_report: return "AUDIT_REPORT";
    case MessageType::shutdown: return "SHUTDOWN";
    case MessageType::shutdown_ack: return "SHUTDOWN_ACK";
    case MessageType::refresh_toolchain: return "REFRESH_TOOLCHAIN";
    case MessageType::invalidate_toolchain: return "INVALIDATE_TOOLCHAIN";
    case MessageType::run_session: return "RUN_SESSION";
    case MessageType::session_ran: return "SESSION_RAN";
    case MessageType::toolchain_report: return "TOOLCHAIN_REPORT";
  }
  return "INVALID";
}

bool parse_message_type(std::uint16_t raw, MessageType& out) noexcept {
  switch (raw) {
    case 1: out = MessageType::hello; return true;
    case 2: out = MessageType::hello_ack; return true;
    case 3: out = MessageType::ping; return true;
    case 4: out = MessageType::pong; return true;
    case 5: out = MessageType::error; return true;
    case 10: out = MessageType::create_session; return true;
    case 11: out = MessageType::session_created; return true;
    case 12: out = MessageType::query_session; return true;
    case 13: out = MessageType::session_report; return true;
    case 14: out = MessageType::list_sessions; return true;
    case 15: out = MessageType::session_list; return true;
    case 20: out = MessageType::prepare_workspace; return true;
    case 21: out = MessageType::workspace_ready; return true;
    case 22: out = MessageType::start_phase; return true;
    case 23: out = MessageType::phase_started; return true;
    case 24: out = MessageType::cancel_phase; return true;
    case 25: out = MessageType::phase_cancelled; return true;
    case 26: out = MessageType::report_process; return true;
    case 27: out = MessageType::process_reported; return true;
    case 28: out = MessageType::report_output; return true;
    case 29: out = MessageType::output_reported; return true;
    case 30: out = MessageType::commit_phase; return true;
    case 31: out = MessageType::phase_committed; return true;
    case 32: out = MessageType::fail_phase; return true;
    case 33: out = MessageType::phase_failed; return true;
    case 34: out = MessageType::retry_phase; return true;
    case 35: out = MessageType::query_authority; return true;
    case 36: out = MessageType::authority_report; return true;
    case 40: out = MessageType::validate_artifact; return true;
    case 41: out = MessageType::artifact_report; return true;
    case 42: out = MessageType::query_diagnostics; return true;
    case 43: out = MessageType::diagnostics_report; return true;
    case 44: out = MessageType::recover_session; return true;
    case 45: out = MessageType::recovery_report; return true;
    case 46: out = MessageType::snapshot; return true;
    case 47: out = MessageType::snapshot_report; return true;
    case 48: out = MessageType::audit; return true;
    case 49: out = MessageType::audit_report; return true;
    case 50: out = MessageType::shutdown; return true;
    case 51: out = MessageType::shutdown_ack; return true;
    case 52: out = MessageType::refresh_toolchain; return true;
    case 54: out = MessageType::invalidate_toolchain; return true;
    case 55: out = MessageType::run_session; return true;
    case 56: out = MessageType::session_ran; return true;
    case 53: out = MessageType::toolchain_report; return true;
    default: return false;
  }
}

// ---------------------------------------------------------------------------
// Field writer / reader.
// ---------------------------------------------------------------------------
void FieldWriter::emit(std::uint16_t id, std::string_view bytes) {
  if (has_last_ && id <= last_id_) {
    // Writers emit ascending field ids; a caller that violates this is a defect,
    // and the reader would reject the payload anyway.
    return;
  }
  last_id_ = id;
  has_last_ = true;
  buffer_.push_back(static_cast<char>(id & 0xFFu));
  buffer_.push_back(static_cast<char>((id >> 8) & 0xFFu));
  const std::uint32_t length = static_cast<std::uint32_t>(bytes.size());
  for (int i = 0; i < 4; ++i) {
    buffer_.push_back(static_cast<char>((length >> (i * 8)) & 0xFFu));
  }
  buffer_.append(bytes.data(), bytes.size());
}

void FieldWriter::u8(std::uint16_t id, std::uint8_t value) {
  emit(id, std::string_view(reinterpret_cast<const char*>(&value), 1));
}

void FieldWriter::u16(std::uint16_t id, std::uint16_t value) {
  char raw[2];
  raw[0] = static_cast<char>(value & 0xFFu);
  raw[1] = static_cast<char>((value >> 8) & 0xFFu);
  emit(id, std::string_view(raw, 2));
}

void FieldWriter::u32(std::uint16_t id, std::uint32_t value) {
  char raw[4];
  for (int i = 0; i < 4; ++i) raw[i] = static_cast<char>((value >> (i * 8)) & 0xFFu);
  emit(id, std::string_view(raw, 4));
}

void FieldWriter::u64(std::uint16_t id, std::uint64_t value) {
  char raw[8];
  for (int i = 0; i < 8; ++i) raw[i] = static_cast<char>((value >> (i * 8)) & 0xFFu);
  emit(id, std::string_view(raw, 8));
}

void FieldWriter::boolean(std::uint16_t id, bool value) { u8(id, value ? 1u : 0u); }

void FieldWriter::text(std::uint16_t id, std::string_view value) {
  if (value.size() > kMaxFieldBytes) return;
  emit(id, value);
}

void FieldWriter::blob(std::uint16_t id, std::string_view value) {
  if (value.size() > kMaxFieldBytes) return;
  emit(id, value);
}

std::string FieldWriter::take() { return std::move(buffer_); }

Result<bool> FieldReader::next() {
  if (cursor_ == payload_.size()) return false;
  if (payload_.size() - cursor_ < 6) {
    return Status(StatusCode::protocol_malformed, "field header is truncated");
  }
  const std::uint16_t id = static_cast<std::uint16_t>(
      static_cast<unsigned char>(payload_[cursor_]) |
      (static_cast<std::uint16_t>(static_cast<unsigned char>(payload_[cursor_ + 1])) << 8));
  std::uint32_t length = 0;
  for (int i = 0; i < 4; ++i) {
    length |= static_cast<std::uint32_t>(
                  static_cast<unsigned char>(payload_[cursor_ + 2 + static_cast<std::size_t>(i)]))
              << (i * 8);
  }
  if (length > kMaxFieldBytes) {
    return Status(StatusCode::protocol_malformed, "field length exceeds the protocol ceiling");
  }
  if (has_last_ && id <= last_id_) {
    return Status(StatusCode::protocol_malformed,
                  "field ids must be strictly ascending; duplicate or reordered field record");
  }
  const std::size_t value_at = cursor_ + 6;
  if (length > payload_.size() - value_at) {
    return Status(StatusCode::protocol_malformed, "field value is truncated");
  }
  current_id_ = id;
  current_value_ = payload_.substr(value_at, length);
  cursor_ = value_at + length;
  last_id_ = id;
  has_last_ = true;
  return true;
}

void FieldReader::skip() { current_value_ = {}; }

Result<std::uint8_t> FieldReader::as_u8() const {
  if (current_value_.size() != 1) return Status(StatusCode::protocol_malformed, "field is not a u8");
  return static_cast<std::uint8_t>(static_cast<unsigned char>(current_value_[0]));
}

Result<std::uint16_t> FieldReader::as_u16() const {
  if (current_value_.size() != 2) return Status(StatusCode::protocol_malformed, "field is not a u16");
  return static_cast<std::uint16_t>(
      static_cast<unsigned char>(current_value_[0]) |
      (static_cast<std::uint16_t>(static_cast<unsigned char>(current_value_[1])) << 8));
}

Result<std::uint32_t> FieldReader::as_u32() const {
  if (current_value_.size() != 4) return Status(StatusCode::protocol_malformed, "field is not a u32");
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(
                 static_cast<unsigned char>(current_value_[static_cast<std::size_t>(i)]))
             << (i * 8);
  }
  return value;
}

Result<std::uint64_t> FieldReader::as_u64() const {
  if (current_value_.size() != 8) return Status(StatusCode::protocol_malformed, "field is not a u64");
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(
                 static_cast<unsigned char>(current_value_[static_cast<std::size_t>(i)]))
             << (i * 8);
  }
  return value;
}

Result<bool> FieldReader::as_bool() const {
  const Result<std::uint8_t> raw = as_u8();
  if (!raw) return raw.status();
  return raw.value() != 0;
}

Result<std::string> FieldReader::as_text() const { return std::string(current_value_); }
Result<std::string> FieldReader::as_blob() const { return std::string(current_value_); }

VoidResult FieldReader::finish() const {
  if (cursor_ != payload_.size()) {
    return Status(StatusCode::protocol_malformed, "message payload has trailing bytes");
  }
  return VoidResult{};
}

// ---------------------------------------------------------------------------
// Framed connection.
// ---------------------------------------------------------------------------
struct FramedConnection::Impl {
  SocketHandle socket = kInvalidSocket;
  std::string peer;
  ConnectionOptions options;
  std::mutex send_mutex;
  /// Serialises whole request/response exchanges. A connection may legitimately
  /// be used from several threads; interleaving two receive loops on one socket
  /// would corrupt the framing.
  std::mutex transact_mutex;
  std::uint64_t rejected = 0;
  std::deque<std::uint64_t> recent_requests;
  std::unordered_set<std::uint64_t> recent_set;
  std::uint64_t next_request_id = 1;

  ~Impl() {
    if (socket != kInvalidSocket) {
      ::closesocket(socket);
      socket = kInvalidSocket;
    }
  }

  CRF_NODISCARD bool send_all(std::string_view bytes) {
    std::size_t sent = 0;
    while (sent < bytes.size()) {
      const int chunk = static_cast<int>(
          std::min<std::size_t>(bytes.size() - sent, 1u << 20));
      const int written = ::send(socket, bytes.data() + sent, chunk, 0);
      if (written <= 0) return false;
      sent += static_cast<std::size_t>(written);
    }
    return true;
  }

  CRF_NODISCARD bool recv_all(char* target, std::size_t count) {
    std::size_t received = 0;
    while (received < count) {
      const int chunk = static_cast<int>(std::min<std::size_t>(count - received, 1u << 20));
      const int got = ::recv(socket, target + received, chunk, 0);
      if (got <= 0) return false;
      received += static_cast<std::size_t>(got);
    }
    return true;
  }
};

FramedConnection::FramedConnection() : impl_(std::make_unique<Impl>()) {}
FramedConnection::~FramedConnection() = default;

void FramedConnection::close() noexcept {
  if (impl_ && impl_->socket != kInvalidSocket) {
    ::shutdown(impl_->socket, SD_BOTH);
    ::closesocket(impl_->socket);
    impl_->socket = kInvalidSocket;
  }
}

bool FramedConnection::open() const noexcept {
  return impl_ && impl_->socket != kInvalidSocket;
}

const std::string& FramedConnection::peer() const noexcept { return impl_->peer; }

std::uint64_t FramedConnection::rejected_frames() const noexcept { return impl_->rejected; }

bool FramedConnection::is_replay(std::uint64_t request_id) const noexcept {
  return impl_->recent_set.count(request_id) != 0;
}

bool FramedConnection::note_request(std::uint64_t request_id) {
  if (request_id == 0) return true;
  if (!impl_->recent_set.insert(request_id).second) return false;
  impl_->recent_requests.push_back(request_id);
  while (impl_->recent_requests.size() > impl_->options.replay_window) {
    const std::uint64_t oldest = impl_->recent_requests.front();
    impl_->recent_requests.pop_front();
    impl_->recent_set.erase(oldest);
  }
  return true;
}

Result<std::unique_ptr<FramedConnection>> FramedConnection::connect(std::string_view host,
                                                                    std::uint16_t port,
                                                                    ConnectionOptions options) {
  ensure_winsock();
  auto connection = std::unique_ptr<FramedConnection>(new FramedConnection());
  connection->impl_->options = options;
  const SocketHandle socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket == kInvalidSocket) {
    return Status(StatusCode::protocol_io, "socket creation failed");
  }
  connection->impl_->socket = socket;
  if (options.tcp_no_delay) {
    BOOL enabled = TRUE;
    ::setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&enabled),
                 sizeof(enabled));
  }
  if (options.io_timeout_millis != 0) {
    const DWORD timeout = options.io_timeout_millis;
    ::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout),
                 sizeof(timeout));
    ::setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout),
                 sizeof(timeout));
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = ::htons(port);
  const std::string host_text(host);
  if (::inet_pton(AF_INET, host_text.c_str(), &address.sin_addr) != 1) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* resolved = nullptr;
    if (::getaddrinfo(host_text.c_str(), nullptr, &hints, &resolved) != 0 || resolved == nullptr) {
      return Status(StatusCode::protocol_io, "peer address could not be resolved");
    }
    address.sin_addr = reinterpret_cast<sockaddr_in*>(resolved->ai_addr)->sin_addr;
    ::freeaddrinfo(resolved);
  }
  if (::connect(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    return Status(StatusCode::protocol_io, "connect failed");
  }
  connection->impl_->peer = host_text + ":" + std::to_string(port);
  return connection;
}

Result<std::unique_ptr<FramedConnection>> FramedConnection::adopt(std::uintptr_t socket_handle,
                                                                  std::string peer_description,
                                                                  ConnectionOptions options) {
  ensure_winsock();
  auto connection = std::unique_ptr<FramedConnection>(new FramedConnection());
  connection->impl_->socket = static_cast<SocketHandle>(socket_handle);
  connection->impl_->peer = std::move(peer_description);
  connection->impl_->options = options;
  if (options.io_timeout_millis != 0) {
    const DWORD timeout = options.io_timeout_millis;
    ::setsockopt(connection->impl_->socket, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    ::setsockopt(connection->impl_->socket, SOL_SOCKET, SO_SNDTIMEO,
                 reinterpret_cast<const char*>(&timeout), sizeof(timeout));
  }
  return connection;
}

VoidResult FramedConnection::send(const Message& message) {
  if (!open()) return Status(StatusCode::protocol_peer_closed, "connection is closed");
  if (message.payload.size() > impl_->options.max_frame_payload) {
    return Status(StatusCode::protocol_frame_too_large,
                  "outbound payload exceeds the configured frame ceiling");
  }
  char header[kFrameHeaderBytes];
  std::memset(header, 0, sizeof(header));
  const auto put = [&header](std::size_t offset, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
      header[offset + static_cast<std::size_t>(i)] = static_cast<char>((value >> (i * 8)) & 0xFFu);
    }
  };
  put(0, kFrameMagic);
  put(4, static_cast<std::uint32_t>(protocol_version_major) |
             (static_cast<std::uint32_t>(protocol_version_minor) << 16));
  put(8, static_cast<std::uint32_t>(message.type) | (static_cast<std::uint32_t>(message.flags) << 16));
  put(12, static_cast<std::uint32_t>(message.request_id & 0xFFFFFFFFull));
  put(16, static_cast<std::uint32_t>(message.request_id >> 32));
  put(20, static_cast<std::uint32_t>(message.payload.size()));
  put(24, crc32c(message.payload));
  put(28, crc32c(std::string_view(header, 28)));

  std::string frame(header, kFrameHeaderBytes);
  frame.append(message.payload);
  const std::lock_guard<std::mutex> guard(impl_->send_mutex);
  if (!impl_->send_all(frame)) {
    return Status(StatusCode::protocol_io, "frame send failed");
  }
  return VoidResult{};
}

Result<Message> FramedConnection::receive() {
  if (!open()) return Status(StatusCode::protocol_peer_closed, "connection is closed");
  char header[kFrameHeaderBytes];
  if (!impl_->recv_all(header, kFrameHeaderBytes)) {
    ++impl_->rejected;
    return Status(StatusCode::protocol_frame_truncated, "frame header was not received in full");
  }
  const auto get = [&header](std::size_t offset) {
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
      value |= static_cast<std::uint32_t>(
                   static_cast<unsigned char>(header[offset + static_cast<std::size_t>(i)]))
               << (i * 8);
    }
    return value;
  };
  if (get(0) != kFrameMagic) {
    ++impl_->rejected;
    return malformed("frame magic is invalid");
  }
  if (get(28) != crc32c(std::string_view(header, 28))) {
    ++impl_->rejected;
    return malformed("frame header checksum failed");
  }
  const std::uint32_t version = get(4);
  if ((version & 0xFFFFu) != protocol_version_major) {
    ++impl_->rejected;
    return Status(StatusCode::protocol_version_mismatch, "frame protocol major version mismatch");
  }
  const std::uint32_t payload_length = get(20);
  // The length is validated before any allocation happens.
  if (payload_length > impl_->options.max_frame_payload) {
    ++impl_->rejected;
    return Status(StatusCode::protocol_frame_too_large,
                  "inbound payload exceeds the configured frame ceiling");
  }
  Message message;
  if (!parse_message_type(static_cast<std::uint16_t>(get(8) & 0xFFFFu), message.type)) {
    ++impl_->rejected;
    return malformed("frame carries an unknown message type");
  }
  message.flags = static_cast<std::uint16_t>((get(8) >> 16) & 0xFFFFu);
  message.request_id = static_cast<std::uint64_t>(get(12)) |
                       (static_cast<std::uint64_t>(get(16)) << 32);
  message.payload.resize(payload_length);
  if (payload_length != 0 && !impl_->recv_all(message.payload.data(), payload_length)) {
    ++impl_->rejected;
    return Status(StatusCode::protocol_frame_truncated, "frame payload was not received in full");
  }
  if (crc32c(message.payload) != get(24)) {
    ++impl_->rejected;
    return malformed("frame payload checksum failed");
  }
  return message;
}

Result<Message> FramedConnection::transact(const Message& request) {
  const std::lock_guard<std::mutex> guard(impl_->transact_mutex);
  VoidResult sent = send(request);
  if (!sent) return sent.status();
  for (;;) {
    Result<Message> response = receive();
    if (!response) return response.status();
    if (response.value().request_id == request.request_id) return response.value();
  }
}

Result<Message> FramedConnection::transact(std::uint64_t request_id, const Message& request) {
  Message copy = request;
  copy.request_id = request_id;
  return transact(copy);
}

// ---------------------------------------------------------------------------
// Control server.
// ---------------------------------------------------------------------------
struct ControlServer::Impl {
  SocketHandle socket = kInvalidSocket;
  std::uint16_t port = 0;
  std::string endpoint;
  ServerOptions options;

  ~Impl() {
    if (socket != kInvalidSocket) {
      ::closesocket(socket);
      socket = kInvalidSocket;
    }
  }
};

ControlServer::ControlServer() : impl_(std::make_unique<Impl>()) {}
ControlServer::~ControlServer() = default;

Result<std::unique_ptr<ControlServer>> ControlServer::listen(ServerOptions options) {
  ensure_winsock();
  auto server = std::unique_ptr<ControlServer>(new ControlServer());
  server->impl_->options = options;
  const SocketHandle socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket == kInvalidSocket) {
    return Status(StatusCode::protocol_io, "listener socket creation failed");
  }
  server->impl_->socket = socket;
  BOOL reuse = TRUE;
  ::setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = ::htons(options.port);
  if (::inet_pton(AF_INET, options.bind_address.c_str(), &address.sin_addr) != 1) {
    return Status(StatusCode::invalid_argument,
                  "bind address must be a numeric IPv4 address: " + options.bind_address);
  }
  if (::bind(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    return Status(StatusCode::protocol_io, "listener bind failed");
  }
  if (::listen(socket, static_cast<int>(options.backlog)) != 0) {
    return Status(StatusCode::protocol_io, "listener listen failed");
  }
  sockaddr_in bound{};
  int bound_length = sizeof(bound);
  if (::getsockname(socket, reinterpret_cast<sockaddr*>(&bound), &bound_length) != 0) {
    return Status(StatusCode::protocol_io, "listener endpoint lookup failed");
  }
  server->impl_->port = ::ntohs(bound.sin_port);
  server->impl_->endpoint = options.bind_address + ":" + std::to_string(server->impl_->port);
  return server;
}

std::uint16_t ControlServer::port() const noexcept { return impl_->port; }
const std::string& ControlServer::endpoint() const noexcept { return impl_->endpoint; }

Result<std::unique_ptr<FramedConnection>> ControlServer::accept(std::uint32_t timeout_millis) {
  if (impl_->socket == kInvalidSocket) {
    return Status(StatusCode::protocol_io, "listener is closed");
  }
  if (timeout_millis != 0) {
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(impl_->socket, &read_set);
    timeval timeout{};
    timeout.tv_sec = static_cast<long>(timeout_millis / 1000);
    timeout.tv_usec = static_cast<long>((timeout_millis % 1000) * 1000);
    const int ready = ::select(0, &read_set, nullptr, nullptr, &timeout);
    if (ready == 0) {
      return Status(StatusCode::not_found, "no connection arrived before the accept window closed");
    }
    if (ready < 0) {
      return Status(StatusCode::protocol_io, "accept select failed");
    }
  }
  sockaddr_in peer{};
  int peer_length = sizeof(peer);
  const SocketHandle client =
      ::accept(impl_->socket, reinterpret_cast<sockaddr*>(&peer), &peer_length);
  if (client == kInvalidSocket) {
    return Status(StatusCode::protocol_io, "accept failed");
  }
  char text[64] = {};
  ::inet_ntop(AF_INET, &peer.sin_addr, text, sizeof(text));
  const std::string description = std::string(text) + ":" + std::to_string(::ntohs(peer.sin_port));
  return FramedConnection::adopt(static_cast<std::uintptr_t>(client), description,
                                 impl_->options.connection);
}

void ControlServer::close() noexcept {
  if (impl_->socket != kInvalidSocket) {
    ::shutdown(impl_->socket, SD_BOTH);
    ::closesocket(impl_->socket);
    impl_->socket = kInvalidSocket;
  }
}

}  // namespace crf
