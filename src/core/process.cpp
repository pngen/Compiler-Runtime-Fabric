#include "crf/process.hpp"
#include "crf/canonical.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>

#if defined(_WIN32)
#  include <windows.h>
#else
#  error "Compiler Runtime Fabric 1.0.0 ships a Windows process backend only"
#endif

namespace crf {
namespace {

CRF_NODISCARD std::wstring widen(std::string_view text) {
  if (text.empty()) return {};
  const int needed = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                           nullptr, 0);
  if (needed <= 0) return {};
  std::wstring out(static_cast<std::size_t>(needed), L'\0');
  const int written = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                            out.data(), needed);
  if (written <= 0) return {};
  out.resize(static_cast<std::size_t>(written));
  return out;
}

/// Windows reports an abnormal termination as an NTSTATUS severity code.
CRF_NODISCARD bool exit_code_is_exception(DWORD code) noexcept {
  return code >= 0xC0000000u;
}

/// Environment block for CreateProcessW.
///
/// Format: "NAME=VALUE\0" per variable followed by a final "\0" terminator, so
/// N variables occupy N+1 null-terminated strings. An empty variable set must
/// still produce a well-formed block, which means two null characters: a single
/// null leaves CreateProcessW parsing past the end of the buffer, which shows up
/// as a sporadic ERROR_INVALID_PARAMETER.
CRF_NODISCARD std::vector<wchar_t> build_environment_block(
    const std::vector<EnvironmentVariable>& variables) {
  std::wstring block;
  for (const EnvironmentVariable& variable : variables) {
    block.append(widen(variable.name));
    block.push_back(L'=');
    block.append(widen(variable.value));
    block.push_back(L'\0');
  }
  block.push_back(L'\0');
  if (block.size() < 2) block.push_back(L'\0');
  return std::vector<wchar_t>(block.begin(), block.end());
}

CRF_NODISCARD std::uint32_t win32_error() noexcept {
  return static_cast<std::uint32_t>(::GetLastError());
}

}  // namespace

std::string_view to_string(ProcessTermination value) noexcept {
  switch (value) {
    case ProcessTermination::exited: return "exited";
    case ProcessTermination::crashed: return "crashed";
    case ProcessTermination::killed: return "killed";
    case ProcessTermination::timed_out: return "timed-out";
    case ProcessTermination::launch_failed: return "launch-failed";
    case ProcessTermination::unknown: return "unknown";
  }
  return "unknown";
}

struct ProcessHandle::Impl {
  ProcessId id{};
  ProcessGeneration generation = ProcessGeneration::initial();
  Ref<InvocationId> invocation{};
  std::uint32_t os_process_id = 0;

  HANDLE process = nullptr;
  HANDLE job = nullptr;

  std::thread stdout_reader;
  std::thread stderr_reader;
  std::thread stdin_writer;

  std::mutex mutex;
  std::condition_variable condition;
  bool finished = false;
  /// Exactly one caller collects the outcome and joins the reader threads.
  bool collecting = false;
  ProcessOutcome outcome;
  std::atomic<bool> terminate_requested{false};
  std::string terminate_reason;
  std::size_t max_capture_bytes = kDefaultCaptureBytes;

  Impl() = default;
  Impl(const Impl&) = delete;
  Impl& operator=(const Impl&) = delete;

  ~Impl() {
    // A handle is destroyed only after every reference is gone. If the child is
    // somehow still running, terminate it here so the runtime never leaks a
    // compiler process.
    if (!finished) {
      terminate_requested.store(true);
      if (process != nullptr) ::TerminateProcess(process, 1);
    }
    join_threads();
    if (job != nullptr) {
      // Closing the job handle with KILL_ON_JOB_CLOSE reaps any grandchild that
      // the compiler spawned and abandoned.
      ::CloseHandle(job);
      job = nullptr;
    }
    if (process != nullptr) {
      ::CloseHandle(process);
      process = nullptr;
    }
  }

  void join_threads() {
    if (stdout_reader.joinable()) stdout_reader.join();
    if (stderr_reader.joinable()) stderr_reader.join();
    if (stdin_writer.joinable()) stdin_writer.join();
  }

  void read_stream(HANDLE pipe, bool is_stdout) {
    char buffer[8192];
    std::uint64_t total = 0;
    for (;;) {
      DWORD read = 0;
      const BOOL ok = ::ReadFile(pipe, buffer, static_cast<DWORD>(sizeof(buffer)), &read, nullptr);
      if (ok == 0 || read == 0) break;
      total += read;
      std::lock_guard<std::mutex> guard(mutex);
      std::string& target = is_stdout ? outcome.capture.standard_output : outcome.capture.standard_error;
      const std::size_t room = target.size() < max_capture_bytes ? max_capture_bytes - target.size() : 0;
      const std::size_t take = std::min<std::size_t>(room, read);
      if (take > 0) target.append(buffer, take);
      if (take < read) {
        outcome.capture.truncated = true;
        if (is_stdout) {
          outcome.capture.dropped_standard_output_bytes += read - take;
        } else {
          outcome.capture.dropped_standard_error_bytes += read - take;
        }
      }
    }
    ::CloseHandle(pipe);
  }

  void write_stdin(HANDLE pipe, std::string data) {
    std::size_t written = 0;
    while (written < data.size()) {
      DWORD chunk = 0;
      const DWORD request = static_cast<DWORD>(
          std::min<std::size_t>(data.size() - written, 64u * 1024u));
      if (::WriteFile(pipe, data.data() + written, request, &chunk, nullptr) == 0) break;
      if (chunk == 0) break;
      written += chunk;
    }
    ::CloseHandle(pipe);
  }
};

ProcessHandle::ProcessHandle() = default;
ProcessHandle::ProcessHandle(std::shared_ptr<Impl> impl) : impl_(std::move(impl)) {}
ProcessHandle::~ProcessHandle() = default;
ProcessHandle::ProcessHandle(ProcessHandle&&) noexcept = default;
ProcessHandle& ProcessHandle::operator=(ProcessHandle&&) noexcept = default;

ProcessId ProcessHandle::id() const noexcept { return impl_ ? impl_->id : ProcessId{}; }

ProcessGeneration ProcessHandle::generation() const noexcept {
  return impl_ ? impl_->generation : ProcessGeneration{};
}

Ref<InvocationId> ProcessHandle::invocation() const noexcept {
  return impl_ ? impl_->invocation : Ref<InvocationId>{};
}

std::uint32_t ProcessHandle::os_process_id() const noexcept {
  return impl_ ? impl_->os_process_id : 0;
}

bool ProcessHandle::running() const noexcept {
  if (!impl_) return false;
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (impl_->finished) return false;
  if (impl_->process == nullptr) return false;
  // The outcome is only materialised by wait(); until then the kernel handle is
  // the authoritative signal, so a cancellation watcher can observe exit without
  // racing the collector.
  return ::WaitForSingleObject(impl_->process, 0) != WAIT_OBJECT_0;
}

bool ProcessHandle::valid() const noexcept { return impl_ != nullptr && impl_->process != nullptr; }

VoidResult ProcessHandle::terminate(std::string reason) {
  if (!impl_) return Status(StatusCode::not_found, "process handle is empty");
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    if (impl_->finished) return VoidResult{};
    if (impl_->terminate_requested.exchange(true)) return VoidResult{};
    impl_->terminate_reason = std::move(reason);
  }
  if (impl_->job != nullptr) {
    // Terminating the job also reaps any compiler-spawned grandchild.
    ::TerminateJobObject(impl_->job, 1);
  }
  if (impl_->process != nullptr) {
    ::TerminateProcess(impl_->process, 1);
  }
  return VoidResult{};
}

const ProcessOutcome* ProcessHandle::try_outcome() const noexcept {
  if (!impl_) return nullptr;
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (!impl_->finished) return nullptr;
  return &impl_->outcome;
}

Result<ProcessOutcome> ProcessHandle::wait() {
  if (!impl_) return Status(StatusCode::not_found, "process handle is empty");
  Impl& impl = *impl_;
  {
    const std::lock_guard<std::mutex> guard(impl.mutex);
    if (impl.finished) return impl.outcome;
  }
  if (impl.process != nullptr) {
    ::WaitForSingleObject(impl.process, INFINITE);
  }

  // Several threads may wait on one handle. Exactly one of them joins the
  // reader threads and materialises the outcome; the others observe it. Joining
  // the same std::thread twice is undefined behaviour, so this hand-off is
  // required rather than merely tidy.
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (impl.finished) return impl.outcome;
  if (impl.collecting) {
    impl.condition.wait(lock, [&impl]() { return impl.finished; });
    return impl.outcome;
  }
  impl.collecting = true;
  lock.unlock();
  impl.join_threads();
  lock.lock();

  DWORD exit_code = 0;
  if (impl.process != nullptr && ::GetExitCodeProcess(impl.process, &exit_code) == 0) {
    exit_code = 0;
  }
  if (exit_code == STILL_ACTIVE) {
    // The handle never signalled yet the process is alive. Report UNKNOWN rather
    // than guessing: the runtime fails closed on an unproven outcome.
    impl.outcome.termination = ProcessTermination::unknown;
    impl.outcome.exit_code = 0;
    impl.outcome.status = Status(StatusCode::unknown_outcome,
                                 "process outcome could not be determined");
  } else if (impl.terminate_requested.load()) {
    impl.outcome.termination = ProcessTermination::killed;
    impl.outcome.exit_code = exit_code;
    impl.outcome.status = Status(StatusCode::process_cancelled,
                                 impl.terminate_reason.empty() ? std::string("process was terminated")
                                                               : impl.terminate_reason);
  } else if (exit_code_is_exception(exit_code)) {
    impl.outcome.termination = ProcessTermination::crashed;
    impl.outcome.exit_code = exit_code;
    impl.outcome.status = Status(StatusCode::process_crashed,
                                 "compiler process terminated abnormally");
  } else {
    impl.outcome.termination = ProcessTermination::exited;
    impl.outcome.exit_code = exit_code;
    if (exit_code == 0) {
      impl.outcome.status = Status{};
    } else {
      impl.outcome.status = Status(StatusCode::process_exited_nonzero,
                                   "compiler process exited with code " + std::to_string(exit_code));
    }
  }
  impl.outcome.capture.standard_output_bytes = impl.outcome.capture.standard_output.size();
  impl.outcome.capture.standard_error_bytes = impl.outcome.capture.standard_error.size();
  impl.outcome.finished_at_nanos = monotonic_nanos();
  impl.finished = true;
  impl.collecting = false;
  impl.condition.notify_all();
  return impl.outcome;
}

struct ProcessSupervisor::Impl {
  explicit Impl(ProcessSupervisorOptions value) : options(value) {}

  ProcessSupervisorOptions options;
  mutable std::mutex mutex;
  std::unordered_map<std::uint64_t, std::shared_ptr<ProcessHandle::Impl>> live;
  IdAllocator<ProcessId> allocator;
  std::atomic<std::uint64_t> total_spawned{0};
  std::atomic<std::uint64_t> total_unreaped{0};
  bool closed = false;
};

ProcessSupervisor::ProcessSupervisor(ProcessSupervisorOptions options)
    : impl_(std::make_unique<Impl>(options)) {
  if (impl_->options.max_capture_bytes == 0 || impl_->options.max_capture_bytes > kMaxCaptureBytes) {
    impl_->options.max_capture_bytes = kDefaultCaptureBytes;
  }
}

ProcessSupervisor::~ProcessSupervisor() { close(); }

Result<std::shared_ptr<ProcessHandle>> ProcessSupervisor::spawn(const ProcessSpec& spec,
                                                               Ref<InvocationId> invocation) {
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    if (impl_->closed) {
      return Status(StatusCode::shutting_down, "process supervisor is closed");
    }
  }
  ProcessSpec effective = spec;
  if (effective.inherit_ambient_environment) {
    std::vector<EnvironmentVariable> merged = ambient_environment();
    for (const EnvironmentVariable& variable : effective.environment) {
      bool replaced = false;
      for (EnvironmentVariable& existing : merged) {
        if (equals_ascii_ci(existing.name, variable.name)) {
          existing.value = variable.value;
          replaced = true;
          break;
        }
      }
      if (!replaced) merged.push_back(variable);
    }
    std::sort(merged.begin(), merged.end(),
              [](const EnvironmentVariable& a, const EnvironmentVariable& b) {
                return less_ascii_ci(a.name, b.name);
              });
    effective.environment = std::move(merged);
  }
  if (effective.environment.empty()) {
    // A child with no environment at all cannot resolve the loader variables the
    // operating system needs, and real tools fail in confusing ways. An explicit
    // empty block is therefore upgraded to the runtime's minimal loader
    // environment; a caller that wants a specific environment supplies one.
    const Result<std::vector<EnvironmentVariable>> loader = build_process_environment(EnvironmentSpec{});
    if (loader) effective.environment = loader.value();
  }
  if (effective.max_capture_bytes == 0) effective.max_capture_bytes = impl_->options.max_capture_bytes;
  if (effective.timeout_millis == 0) effective.timeout_millis = impl_->options.default_timeout_millis;
  if (const VoidResult valid = effective.validate(); !valid) return valid.status();

  auto handle = std::make_shared<ProcessHandle::Impl>();
  handle->invocation = invocation;
  handle->max_capture_bytes = effective.max_capture_bytes;
  handle->outcome.id = impl_->allocator.next();
  handle->outcome.generation = ProcessGeneration::initial();
  handle->outcome.invocation = invocation;
  handle->id = handle->outcome.id;
  handle->generation = handle->outcome.generation;

  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;

  HANDLE stdout_read = nullptr;
  HANDLE stdout_write = nullptr;
  HANDLE stderr_read = nullptr;
  HANDLE stderr_write = nullptr;
  HANDLE stdin_read = nullptr;
  HANDLE stdin_write = nullptr;

  const auto cleanup_pipes = [&]() {
    for (HANDLE* pipe : {&stdout_read, &stdout_write, &stderr_read, &stderr_write, &stdin_read,
                         &stdin_write}) {
      if (*pipe != nullptr) {
        ::CloseHandle(*pipe);
        *pipe = nullptr;
      }
    }
  };

  if (::CreatePipe(&stdout_read, &stdout_write, &attributes, 0) == 0 ||
      ::CreatePipe(&stderr_read, &stderr_write, &attributes, 0) == 0 ||
      ::CreatePipe(&stdin_read, &stdin_write, &attributes, 0) == 0) {
    const std::uint32_t error = win32_error();
    cleanup_pipes();
    return Status(StatusCode::process_launch_failed,
                  "pipe creation failed with Win32 error " + std::to_string(error));
  }
  ::SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);
  ::SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0);
  ::SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0);
  ::SetHandleInformation(stdin_read, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

  std::wstring command_line = widen(effective.render_command_line());
  if (command_line.empty() && !effective.arguments.empty()) {
    cleanup_pipes();
    return Status(StatusCode::invalid_argument, "command line could not be encoded as UTF-16");
  }
  std::vector<wchar_t> command_buffer(command_line.begin(), command_line.end());
  command_buffer.push_back(L'\0');

  std::vector<wchar_t> environment_block = build_environment_block(effective.environment);
  const std::wstring working_directory = widen(effective.working_directory.string());

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  startup.hStdOutput = stdout_write;
  startup.hStdError = stderr_write;
  startup.hStdInput = stdin_read;

  PROCESS_INFORMATION process_info{};
  const DWORD creation_flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
  const BOOL created = ::CreateProcessW(
      nullptr, command_buffer.data(), nullptr, nullptr, TRUE, creation_flags,
      environment_block.empty() ? nullptr : static_cast<LPVOID>(environment_block.data()),
      working_directory.empty() ? nullptr : working_directory.c_str(), &startup, &process_info);
  if (created == 0) {
    const std::uint32_t error = win32_error();
    cleanup_pipes();
    return Status(StatusCode::process_launch_failed,
                  "CreateProcessW failed with Win32 error " + std::to_string(error) +
                      " for " + effective.executable.string());
  }

  // Close the child's ends in the parent so its reads observe EOF.
  ::CloseHandle(stdout_write);
  stdout_write = nullptr;
  ::CloseHandle(stderr_write);
  stderr_write = nullptr;
  ::CloseHandle(stdin_read);
  stdin_read = nullptr;

  handle->process = process_info.hProcess;
  handle->os_process_id = process_info.dwProcessId;
  handle->outcome.os_process_id = process_info.dwProcessId;
  handle->outcome.started_at_nanos = monotonic_nanos();

  if (impl_->options.own_job_object) {
    HANDLE job = ::CreateJobObjectW(nullptr, nullptr);
    if (job != nullptr) {
      JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
      limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
      if (::SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits,
                                    sizeof(limits)) != 0 &&
          ::AssignProcessToJobObject(job, process_info.hProcess) != 0) {
        handle->job = job;
      } else {
        // A hosting environment may already constrain job nesting. The runtime
        // still reaps the direct child on shutdown; it just cannot guarantee
        // grandchild reaping through the job object.
        ::CloseHandle(job);
      }
    }
  }

  if (::ResumeThread(process_info.hThread) == static_cast<DWORD>(-1)) {
    ::TerminateProcess(process_info.hProcess, 1);
    ::CloseHandle(process_info.hThread);
    cleanup_pipes();
    return Status(StatusCode::process_launch_failed, "ResumeThread failed");
  }
  ::CloseHandle(process_info.hThread);

  impl_->total_spawned.fetch_add(1);

  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    impl_->live.emplace(handle->id.value(), handle);
  }

  ProcessHandle::Impl* raw = handle.get();
  handle->stdout_reader = std::thread([raw, pipe = stdout_read]() { raw->read_stream(pipe, true); });
  handle->stderr_reader = std::thread([raw, pipe = stderr_read]() { raw->read_stream(pipe, false); });
  const std::string input = effective.standard_input;
  handle->stdin_writer = std::thread([raw, pipe = stdin_write, input]() { raw->write_stdin(pipe, input); });

  // make_shared cannot reach the private constructor; the supervisor is a
  // friend of ProcessHandle, so construct through an explicit shared_ptr.
  return std::shared_ptr<ProcessHandle>(new ProcessHandle(handle));
}

VoidResult ProcessSupervisor::terminate(ProcessId id, ProcessGeneration generation,
                                        std::string reason) {
  std::shared_ptr<ProcessHandle::Impl> handle;
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    const auto found = impl_->live.find(id.value());
    if (found == impl_->live.end()) {
      return Status(StatusCode::not_found, "process is not supervised: " + id.to_string());
    }
    if (found->second->generation != generation) {
      return Status(StatusCode::stale_phase_generation,
                    "process generation does not match the supervised process");
    }
    handle = found->second;
  }
  return ProcessHandle(handle).terminate(std::move(reason));
}

VoidResult ProcessSupervisor::reap(ProcessId id, ProcessGeneration generation) {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->live.find(id.value());
  if (found == impl_->live.end()) return VoidResult{};
  if (found->second->generation != generation) {
    return Status(StatusCode::stale_phase_generation,
                  "reap names a process generation that is not supervised");
  }
  impl_->live.erase(found);
  return VoidResult{};
}

std::size_t ProcessSupervisor::terminate_all(std::string reason) {
  std::vector<std::shared_ptr<ProcessHandle::Impl>> handles;
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    for (auto& [key, handle] : impl_->live) {
      (void)key;
      handles.push_back(handle);
    }
  }
  std::size_t terminated = 0;
  for (const std::shared_ptr<ProcessHandle::Impl>& handle : handles) {
    if (ProcessHandle(handle).terminate(reason).has_value()) ++terminated;
  }
  return terminated;
}

std::size_t ProcessSupervisor::live_count() const noexcept {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->live.size();
}

std::vector<ProcessId> ProcessSupervisor::live_process_ids() const {
  std::vector<ProcessId> out;
  std::lock_guard<std::mutex> guard(impl_->mutex);
  out.reserve(impl_->live.size());
  for (const auto& [key, handle] : impl_->live) {
    (void)handle;
    out.push_back(ProcessId::from_value(key));
  }
  std::sort(out.begin(), out.end());
  return out;
}

bool ProcessSupervisor::is_current(ProcessId id, ProcessGeneration generation) const noexcept {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->live.find(id.value());
  if (found == impl_->live.end()) return false;
  return found->second->generation == generation;
}

std::uint64_t ProcessSupervisor::total_spawned() const noexcept {
  return impl_->total_spawned.load();
}

std::uint64_t ProcessSupervisor::total_unreaped() const noexcept {
  return impl_->total_unreaped.load();
}

Result<ProcessOutcome> ProcessSupervisor::run(const ProcessSpec& spec, Ref<InvocationId> invocation,
                                              const std::atomic<bool>* cancel) {
  const Result<std::shared_ptr<ProcessHandle>> spawned = spawn(spec, invocation);
  if (!spawned) return spawned.status();
  std::shared_ptr<ProcessHandle> handle = spawned.value();
  if (cancel != nullptr) {
    while (handle->running()) {
      if (cancel->load()) {
        const VoidResult terminated =
            handle->terminate("cancellation requested while the compiler was running");
        (void)terminated;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
  }
  const Result<ProcessOutcome> outcome = handle->wait();
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    impl_->live.erase(handle->id().value());
  }
  return outcome;
}

void ProcessSupervisor::close() {
  std::vector<std::shared_ptr<ProcessHandle::Impl>> handles;
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    if (impl_->closed) return;
    impl_->closed = true;
    for (auto& [key, handle] : impl_->live) {
      (void)key;
      handles.push_back(handle);
    }
    impl_->live.clear();
  }
  for (const std::shared_ptr<ProcessHandle::Impl>& handle : handles) {
    const VoidResult terminated = ProcessHandle(handle).terminate("runtime shutdown");
    (void)terminated;
    const Result<ProcessOutcome> outcome = ProcessHandle(handle).wait();
    (void)outcome;
    impl_->total_unreaped.fetch_add(1);
  }
}

}  // namespace crf
