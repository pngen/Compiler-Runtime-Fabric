#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "crf/environment.hpp"
#include "crf/status.hpp"
#include "crf/strong_id.hpp"

namespace crf {

enum class ProcessTermination : std::uint8_t {
  exited = 0,
  /// Abnormal termination: unhandled exception, stack buffer overrun, abort.
  crashed = 1,
  /// Terminated by the runtime because of cancellation or shutdown.
  killed = 2,
  timed_out = 3,
  launch_failed = 4,
  unknown = 5,
};

CRF_NODISCARD CRF_API std::string_view to_string(ProcessTermination value) noexcept;

inline constexpr std::size_t kDefaultCaptureBytes = 1u << 20;   // 1 MiB per stream
inline constexpr std::size_t kMaxCaptureBytes = 1u << 26;       // 64 MiB hard ceiling
inline constexpr std::size_t kMaxArguments = 65536;
inline constexpr std::size_t kMaxArgumentBytes = 1u << 20;
inline constexpr std::size_t kMaxCommandLineBytes = 1u << 25;   // 32 MiB, above the OS limit
inline constexpr std::size_t kMaxEnvironmentBytes = 1u << 20;

/// A fully specified child process launch.
///
/// The argument vector is passed to the operating system through the native
/// process API with runtime-owned quoting. No shell is involved, so shell
/// metacharacters in arguments are data, never syntax.
struct CRF_API ProcessSpec {
  std::filesystem::path executable;
  /// Arguments after argv[0]. argv[0] is derived from the executable path.
  std::vector<std::string> arguments;
  /// Complete environment block. The child does not inherit the runtime
  /// process environment.
  std::vector<EnvironmentVariable> environment;
  std::filesystem::path working_directory;
  std::string standard_input;
  /// 0 disables the timeout. A non-zero timeout is an operator policy, never a
  /// substitute for test correctness.
  std::uint32_t timeout_millis = 0;
  std::size_t max_capture_bytes = kDefaultCaptureBytes;
  /// When true the child starts from the runtime's own environment and the
  /// explicit variables above are applied on top. Governed phases never set
  /// this; a toolchain probe uses it so that a vendor tool runs in the context
  /// it expects. The environment the probe observed is recorded as evidence,
  /// and it is not the environment any phase later runs under.
  bool inherit_ambient_environment = false;

  CRF_NODISCARD VoidResult validate() const;
  CRF_NODISCARD Digest canonical_digest() const;
  /// Deterministic rendering for explainability and evidence. This is the
  /// command line the operating system receives, with arguments quoted.
  CRF_NODISCARD std::string render_command_line() const;
};

/// Bounded capture of a child process's output streams.
struct CRF_API ProcessCapture {
  std::string standard_output;
  std::string standard_error;
  std::uint64_t standard_output_bytes = 0;
  std::uint64_t standard_error_bytes = 0;
  std::uint64_t dropped_standard_output_bytes = 0;
  std::uint64_t dropped_standard_error_bytes = 0;
  bool truncated = false;
};

struct CRF_API ProcessOutcome {
  ProcessId id{};
  ProcessGeneration generation{};
  Ref<InvocationId> invocation{};
  /// Diagnostic evidence only. Never an identity.
  std::uint32_t os_process_id = 0;
  ProcessTermination termination = ProcessTermination::unknown;
  std::uint32_t exit_code = 0;
  ProcessCapture capture;
  std::uint64_t started_at_nanos = 0;
  std::uint64_t finished_at_nanos = 0;
  Status status{};

  /// True only when the child exited normally with code 0. Note that this is
  /// still not phase authority: it advances a phase to Produced, not Committed.
  CRF_NODISCARD bool exited_zero() const noexcept {
    return termination == ProcessTermination::exited && exit_code == 0;
  }
  CRF_NODISCARD std::uint64_t duration_nanos() const noexcept {
    return finished_at_nanos > started_at_nanos ? finished_at_nanos - started_at_nanos : 0;
  }
};

/// Handle to one supervised child process. Safe to hold and query from several
/// threads; wait() may be called concurrently and every caller observes the same
/// outcome.
class CRF_API ProcessHandle {
 public:
  ProcessHandle();
  ~ProcessHandle();
  ProcessHandle(ProcessHandle&&) noexcept;
  ProcessHandle& operator=(ProcessHandle&&) noexcept;
  ProcessHandle(const ProcessHandle&) = delete;
  ProcessHandle& operator=(const ProcessHandle&) = delete;

  CRF_NODISCARD ProcessId id() const noexcept;
  CRF_NODISCARD ProcessGeneration generation() const noexcept;
  CRF_NODISCARD Ref<InvocationId> invocation() const noexcept;
  CRF_NODISCARD std::uint32_t os_process_id() const noexcept;
  CRF_NODISCARD bool running() const noexcept;
  CRF_NODISCARD bool valid() const noexcept;

  /// Terminate the child. Idempotent; a second call is a successful no-op.
  CRF_NODISCARD VoidResult terminate(std::string reason);
  /// Block until the child exits, then return the durable outcome.
  CRF_NODISCARD Result<ProcessOutcome> wait();
  /// Non-blocking peek; returns nullptr while the child is still running.
  CRF_NODISCARD const ProcessOutcome* try_outcome() const noexcept;

  struct Impl;

 private:
  explicit ProcessHandle(std::shared_ptr<Impl> impl);
  friend class ProcessSupervisor;
  std::shared_ptr<Impl> impl_;
};

struct CRF_API ProcessSupervisorOptions {
  std::size_t max_capture_bytes = kDefaultCaptureBytes;
  std::uint32_t default_timeout_millis = 0;
  /// Create a Windows job object that terminates every child when the runtime
  /// exits. Guarantees no orphan compiler process survives a crash.
  bool own_job_object = true;
};

/// Owns every compiler child process launched by one runtime.
///
/// Shutdown terminates all live children and closes the job object. Process
/// identity is a runtime-owned ProcessId plus ProcessGeneration; the operating
/// system process id is recorded only as diagnostic evidence.
class CRF_API ProcessSupervisor {
 public:
  explicit ProcessSupervisor(ProcessSupervisorOptions options = {});
  ~ProcessSupervisor();
  ProcessSupervisor(const ProcessSupervisor&) = delete;
  ProcessSupervisor& operator=(const ProcessSupervisor&) = delete;

  CRF_NODISCARD Result<std::shared_ptr<ProcessHandle>> spawn(const ProcessSpec& spec,
                                                            Ref<InvocationId> invocation);
  /// Spawn and wait. When cancel is non-null and becomes true the child is
  /// terminated and the outcome is classified as killed.
  CRF_NODISCARD Result<ProcessOutcome> run(const ProcessSpec& spec, Ref<InvocationId> invocation,
                                           const std::atomic<bool>* cancel = nullptr);

  CRF_NODISCARD VoidResult terminate(ProcessId id, ProcessGeneration generation, std::string reason);
  CRF_NODISCARD std::size_t terminate_all(std::string reason);
  /// Remove a finished child from the live set. Every code path that spawns a
  /// handle directly must reap it, otherwise the live count would never fall
  /// back to zero and shutdown auditing would be meaningless.
  CRF_NODISCARD VoidResult reap(ProcessId id, ProcessGeneration generation);

  CRF_NODISCARD std::size_t live_count() const noexcept;
  CRF_NODISCARD std::vector<ProcessId> live_process_ids() const;
  /// True when the given process identity is still the current generation owned
  /// by this supervisor. A recycled operating-system pid never satisfies this.
  CRF_NODISCARD bool is_current(ProcessId id, ProcessGeneration generation) const noexcept;
  /// Number of children this supervisor has ever launched. Monotonic.
  CRF_NODISCARD std::uint64_t total_spawned() const noexcept;
  /// Number of children whose outcome was never collected.
  CRF_NODISCARD std::uint64_t total_unreaped() const noexcept;

  void close();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace crf
