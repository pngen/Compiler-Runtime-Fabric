#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "crf/diagnostics.hpp"
#include "crf/process.hpp"
#include "crf/runtime.hpp"
#include "crf/status.hpp"

namespace crf {

/// Wire protocol message types. Values are part of the protocol schema.
enum class MessageType : std::uint16_t {
  invalid = 0,
  hello = 1,
  hello_ack = 2,
  ping = 3,
  pong = 4,
  error = 5,

  create_session = 10,
  session_created = 11,
  query_session = 12,
  session_report = 13,
  list_sessions = 14,
  session_list = 15,

  prepare_workspace = 20,
  workspace_ready = 21,
  start_phase = 22,
  phase_started = 23,
  cancel_phase = 24,
  phase_cancelled = 25,
  report_process = 26,
  process_reported = 27,
  report_output = 28,
  output_reported = 29,
  commit_phase = 30,
  phase_committed = 31,
  fail_phase = 32,
  phase_failed = 33,
  retry_phase = 34,
  query_authority = 35,
  authority_report = 36,

  validate_artifact = 40,
  artifact_report = 41,
  query_diagnostics = 42,
  diagnostics_report = 43,
  recover_session = 44,
  recovery_report = 45,
  snapshot = 46,
  snapshot_report = 47,
  audit = 48,
  audit_report = 49,
  shutdown = 50,
  shutdown_ack = 51,
  refresh_toolchain = 52,
  toolchain_report = 53,
  invalidate_toolchain = 54,
  run_session = 55,
  session_ran = 56,
};

CRF_NODISCARD CRF_API std::string_view to_string(MessageType value) noexcept;
CRF_NODISCARD CRF_API bool parse_message_type(std::uint16_t raw, MessageType& out) noexcept;

inline constexpr std::uint32_t kFrameMagic = 0x31465243u;   // "CRF1"
inline constexpr std::size_t kFrameHeaderBytes = 32;
inline constexpr std::uint32_t kDefaultMaxFramePayload = 4u << 20;
inline constexpr std::uint32_t kHardMaxFramePayload = 16u << 20;
inline constexpr std::uint16_t kMaxFieldsPerMessage = 512;
inline constexpr std::uint32_t kMaxFieldBytes = 1u << 20;

/// A decoded protocol message.
struct CRF_API Message {
  MessageType type = MessageType::invalid;
  std::uint16_t flags = 0;
  std::uint64_t request_id = 0;
  /// Encoded payload fields, in canonical ascending field-id order.
  std::string payload;

  CRF_NODISCARD bool valid() const noexcept { return type != MessageType::invalid; }
};

/// Field-oriented payload writer. Fields are emitted in ascending id order and
/// duplicate ids are refused at write time.
class CRF_API FieldWriter {
 public:
  void u8(std::uint16_t id, std::uint8_t value);
  void u16(std::uint16_t id, std::uint16_t value);
  void u32(std::uint16_t id, std::uint32_t value);
  void u64(std::uint16_t id, std::uint64_t value);
  void boolean(std::uint16_t id, bool value);
  void text(std::uint16_t id, std::string_view value);
  void blob(std::uint16_t id, std::string_view value);
  CRF_NODISCARD std::string take();

 private:
  void emit(std::uint16_t id, std::string_view bytes);
  std::string buffer_;
  std::uint16_t last_id_ = 0;
  bool has_last_ = false;
};

/// Field-oriented payload reader. Enforces strictly ascending field ids, which
/// rejects duplicate field records and reordered payloads, and bounds every
/// length against the configured ceiling.
class CRF_API FieldReader {
 public:
  explicit FieldReader(std::string_view payload) noexcept : payload_(payload) {}

  CRF_NODISCARD Result<bool> next();
  CRF_NODISCARD std::uint16_t id() const noexcept { return current_id_; }
  CRF_NODISCARD Result<std::uint8_t> as_u8() const;
  CRF_NODISCARD Result<std::uint16_t> as_u16() const;
  CRF_NODISCARD Result<std::uint32_t> as_u32() const;
  CRF_NODISCARD Result<std::uint64_t> as_u64() const;
  CRF_NODISCARD Result<bool> as_bool() const;
  CRF_NODISCARD Result<std::string> as_text() const;
  CRF_NODISCARD Result<std::string> as_blob() const;
  void skip();
  /// Refuse a payload with trailing or missing required fields.
  CRF_NODISCARD VoidResult finish() const;
  CRF_NODISCARD std::uint16_t last_id() const noexcept { return last_id_; }

 private:
  std::string_view payload_;
  std::size_t cursor_ = 0;
  std::uint16_t current_id_ = 0;
  std::string_view current_value_;
  std::uint16_t last_id_ = 0;
  bool has_last_ = false;
};

struct CRF_API ConnectionOptions {
  std::uint32_t max_frame_payload = kDefaultMaxFramePayload;
  std::uint32_t io_timeout_millis = 30000;
  /// Number of recently seen request ids remembered for duplicate detection.
  std::size_t replay_window = 4096;
  bool tcp_no_delay = true;
};

/// A framed, bounded, versioned connection to a peer.
class CRF_API FramedConnection {
 public:
  ~FramedConnection();
  FramedConnection(const FramedConnection&) = delete;
  FramedConnection& operator=(const FramedConnection&) = delete;

  CRF_NODISCARD static Result<std::unique_ptr<FramedConnection>> connect(
      std::string_view host, std::uint16_t port, ConnectionOptions options = {});
  /// Adopt an already accepted socket. The handle is owned by the connection.
  CRF_NODISCARD static Result<std::unique_ptr<FramedConnection>> adopt(
      std::uintptr_t socket_handle, std::string peer_description, ConnectionOptions options = {});

  /// Send one frame. Never blocks indefinitely.
  CRF_NODISCARD VoidResult send(const Message& message);
  /// Receive one frame, validating magic, version, length, and checksums.
  CRF_NODISCARD Result<Message> receive();
  /// Send a request and receive the response with the same request id.
  CRF_NODISCARD Result<Message> transact(const Message& request);
  /// Send a message and read messages until one carries the given request id.
  CRF_NODISCARD Result<Message> transact(std::uint64_t request_id, const Message& request);

  void close() noexcept;
  CRF_NODISCARD bool open() const noexcept;
  CRF_NODISCARD const std::string& peer() const noexcept;
  /// Number of frames rejected for protocol defects.
  CRF_NODISCARD std::uint64_t rejected_frames() const noexcept;
  /// True when the given request id was seen before on this connection.
  CRF_NODISCARD bool is_replay(std::uint64_t request_id) const noexcept;
  /// Remember an inbound request id. Returns false when it is a replay.
  CRF_NODISCARD bool note_request(std::uint64_t request_id);

 private:
  FramedConnection();
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

struct CRF_API ServerOptions {
  std::string bind_address = "127.0.0.1";
  std::uint16_t port = 0;   // 0 selects an ephemeral port
  std::uint32_t backlog = 16;
  ConnectionOptions connection{};
  std::filesystem::path token_file;
};

class CRF_API ControlServer {
 public:
  ~ControlServer();
  ControlServer(const ControlServer&) = delete;
  ControlServer& operator=(const ControlServer&) = delete;

  CRF_NODISCARD static Result<std::unique_ptr<ControlServer>> listen(ServerOptions options);
  /// Accept one connection. When timeout_millis is non-zero, returns a
  /// not_found refusal on timeout instead of blocking forever.
  CRF_NODISCARD Result<std::unique_ptr<FramedConnection>> accept(std::uint32_t timeout_millis);
  CRF_NODISCARD std::uint16_t port() const noexcept;
  CRF_NODISCARD const std::string& endpoint() const noexcept;
  void close() noexcept;

 private:
  ControlServer();
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Message payload helpers. Every encoder bounds its inputs; every decoder
// refuses a missing, duplicated, or out-of-range field.
// ---------------------------------------------------------------------------
CRF_NODISCARD CRF_API std::string encode_hello(std::string_view runtime_name,
                                               std::string_view role,
                                               std::uint64_t epoch,
                                               std::string_view detail);
CRF_NODISCARD CRF_API Result<std::string> decode_hello_detail(std::string_view payload);

CRF_NODISCARD CRF_API std::string encode_error(StatusCode code, std::string_view detail,
                                               std::string_view subject = {});
CRF_NODISCARD CRF_API Result<std::pair<StatusCode, std::string>> decode_error(std::string_view payload);

CRF_NODISCARD CRF_API std::string encode_compile_request(const CompileRequest& request);
CRF_NODISCARD CRF_API Result<CompileRequest> decode_compile_request(std::string_view payload);

CRF_NODISCARD CRF_API std::string encode_session_summary(const CompilerSession& session);
CRF_NODISCARD CRF_API Result<CompilerSession> decode_session_summary(std::string_view payload);

CRF_NODISCARD CRF_API std::string encode_workspace_request(CompilerSessionId session,
                                                           CompilerSessionGeneration session_generation,
                                                           CompilerPhaseId phase,
                                                           CompilerPhaseGeneration phase_generation);
CRF_NODISCARD CRF_API Result<std::tuple<CompilerSessionId, CompilerSessionGeneration,
                                        CompilerPhaseId, CompilerPhaseGeneration>>
decode_workspace_request(std::string_view payload);

CRF_NODISCARD CRF_API std::string encode_invocation_order(const InvocationSpec& invocation,
                                                          const ProcessSpec& process,
                                                          std::string_view workspace_root,
                                                          std::string_view phase_label);
CRF_NODISCARD CRF_API Result<InvocationSpec> decode_invocation_order(std::string_view payload,
                                                                     ProcessSpec& process,
                                                                     std::string& workspace_root,
                                                                     std::string& phase_label);

CRF_NODISCARD CRF_API std::string encode_execution_report(const ExecutionReport& report);
CRF_NODISCARD CRF_API Result<ExecutionReport> decode_execution_report(std::string_view payload);

CRF_NODISCARD CRF_API std::string encode_phase_reference(CompilerSessionId session,
                                                         CompilerPhaseId phase,
                                                         CompilerPhaseGeneration phase_generation,
                                                         Ref<InvocationId> invocation);
CRF_NODISCARD CRF_API Result<std::tuple<CompilerSessionId, CompilerPhaseId,
                                        CompilerPhaseGeneration, Ref<InvocationId>>>
decode_phase_reference(std::string_view payload);

CRF_NODISCARD CRF_API std::string encode_phase_report(const PhaseRunReport& report);
CRF_NODISCARD CRF_API Result<PhaseRunReport> decode_phase_report(std::string_view payload);

CRF_NODISCARD CRF_API std::string encode_audit_report(const AuditReport& report);
CRF_NODISCARD CRF_API Result<AuditReport> decode_audit_report(std::string_view payload);

}  // namespace crf
