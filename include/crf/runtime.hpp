#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "crf/adapter.hpp"
#include "crf/artifact.hpp"
#include "crf/audit.hpp"
#include "crf/authority.hpp"
#include "crf/diagnostics.hpp"
#include "crf/environment.hpp"
#include "crf/evidence.hpp"
#include "crf/persistence.hpp"
#include "crf/policy.hpp"
#include "crf/provenance.hpp"
#include "crf/recovery.hpp"
#include "crf/retry.hpp"
#include "crf/session.hpp"
#include "crf/source.hpp"
#include "crf/workspace.hpp"

namespace crf {

struct CRF_API RuntimeOptions {
  /// Durable state directory. Created when missing.
  std::filesystem::path state_directory;
  /// Root below which every phase workspace is created.
  std::filesystem::path workspace_root;
  std::string runtime_name = "crf-runtime";
  bool enable_persistence = true;
  /// Remove durable state on clean shutdown. Intended for tests and for
  /// throwaway runtimes; a release runtime always keeps its journal.
  bool ephemeral_state = false;
  /// Load durable state at construction and fence in-flight process phases.
  bool recover_on_load = true;
  std::size_t max_sessions = 4096;
  ProcessSupervisorOptions process{};
  WorkspaceOptions workspace{};
  /// Journal and snapshot settings. The directory defaults to the state
  /// directory and the name to the runtime name.
  PersistenceOptions persistence{};
  /// Register the built-in adapters (MSVC, CUDA, synthetic).
  bool register_builtin_adapters = true;
};

/// A candidate output reported by an executor.
struct CRF_API OutputDescriptor {
  std::string logical_name;
  std::filesystem::path path;
  ObjectFormat format = ObjectFormat::unknown;
  Digest content{};
  std::uint64_t size_bytes = 0;
  bool exists = false;

  CRF_NODISCARD Digest canonical_digest() const;
};

/// Result of physically executing one invocation, whether locally or on a
/// worker. The runtime treats this as evidence, never as authority.
struct CRF_API ExecutionReport {
  bool executed = false;
  ProcessOutcome process{};
  std::vector<OutputDescriptor> outputs;
  std::vector<Diagnostic> diagnostics;
  std::filesystem::path workspace_root;
  Digest workspace_marker{};
  StatusCode status = StatusCode::ok;
  std::string detail;

  CRF_NODISCARD Digest evidence_digest() const;
};

/// Execution backend. The runtime owns authority; an executor only performs
/// physical work and reports evidence.
class CRF_API PhaseExecutor {
 public:
  virtual ~PhaseExecutor();
  PhaseExecutor(const PhaseExecutor&) = delete;
  PhaseExecutor& operator=(const PhaseExecutor&) = delete;

  /// Execute one validated invocation.
  CRF_NODISCARD virtual Result<ExecutionReport> execute(const InvocationSpec& invocation,
                                                        const ProcessSpec& process,
                                                        const Workspace& workspace,
                                                        std::string_view phase_label) = 0;
  /// Cancel an in-flight execution identified by its invocation.
  CRF_NODISCARD virtual VoidResult cancel(Ref<InvocationId> invocation, std::string reason) = 0;
  CRF_NODISCARD virtual std::string describe() const = 0;
  CRF_NODISCARD virtual bool remote() const noexcept = 0;

 protected:
  PhaseExecutor() = default;
};

/// The Compiler Runtime Fabric runtime.
///
/// One runtime owns: compiler sessions, phase authority, toolchain and target
/// registries, workspaces, child processes, diagnostics, provenance, durable
/// state, and the invariant audit. It does not own distributed placement,
/// global cache authority, or distributed artifact promotion.
class CRF_API Runtime {
 public:
  ~Runtime();
  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;

  CRF_NODISCARD static Result<std::unique_ptr<Runtime>> create(RuntimeOptions options);

  // ---- registries ---------------------------------------------------------
  CRF_NODISCARD ToolchainRegistry& toolchains() noexcept;
  CRF_NODISCARD const ToolchainRegistry& toolchains() const noexcept;
  CRF_NODISCARD TargetRegistry& targets() noexcept;
  CRF_NODISCARD const TargetRegistry& targets() const noexcept;
  CRF_NODISCARD EnvironmentRegistry& environments() noexcept;
  CRF_NODISCARD const EnvironmentRegistry& environments() const noexcept;
  CRF_NODISCARD const PolicyRegistry& policies() const noexcept;
  CRF_NODISCARD PolicyRegistry& policies() noexcept;
  CRF_NODISCARD SourceRegistry& sources() noexcept;
  CRF_NODISCARD ArtifactRegistry& artifacts() noexcept;
  CRF_NODISCARD const ArtifactRegistry& artifacts() const noexcept;
  CRF_NODISCARD DiagnosticStore& diagnostics() noexcept;
  CRF_NODISCARD const DiagnosticStore& diagnostics() const noexcept;
  CRF_NODISCARD ProvenanceLog& provenance() noexcept;
  CRF_NODISCARD const ProvenanceLog& provenance() const noexcept;
  CRF_NODISCARD LeaseTable& leases() noexcept;
  CRF_NODISCARD const LeaseTable& leases() const noexcept;
  CRF_NODISCARD ProcessSupervisor& processes() noexcept;
  CRF_NODISCARD const ProcessSupervisor& processes() const noexcept;
  CRF_NODISCARD AdapterRegistry& adapters() noexcept;
  CRF_NODISCARD const AdapterRegistry& adapters() const noexcept;
  CRF_NODISCARD EvidenceLog& evidence() noexcept;
  CRF_NODISCARD const EvidenceLog& evidence() const noexcept;
  CRF_NODISCARD PersistenceStore* persistence() noexcept;

  // ---- toolchain discovery ------------------------------------------------
  CRF_NODISCARD Result<Ref<ToolchainId>> discover_toolchain(
      ToolchainFamily family, const ToolchainProbeRequest& request = {});
  CRF_NODISCARD Result<ToolchainIdentity> probe_toolchain(
      ToolchainFamily family, const ToolchainProbeRequest& request = {}) const;
  /// Re-probe a registered toolchain and advance its generation when the
  /// evidence changed. Returns the mutation report.
  CRF_NODISCARD Result<ToolchainMutation> refresh_toolchain(ToolchainId id);
  /// Retire a toolchain generation on purpose. An operator uses this when a
  /// toolchain must be re-probed; any phase in flight under the previous
  /// generation is fenced and can never commit.
  CRF_NODISCARD Result<ToolchainMutation> invalidate_toolchain(ToolchainId id,
                                                               std::string reason);
  /// Install a caller-probed toolchain observation. Used by a worker reporting
  /// re-probed evidence and by tests that must move a toolchain generation at a
  /// precise moment. Any authority-relevant change advances the generation,
  /// which fences in-flight phases bound to the previous one.
  CRF_NODISCARD Result<ToolchainMutation> apply_toolchain_observation(
      const ToolchainIdentity& observed);
  /// Install a synthetic toolchain identity (tests and unsupported families).
  CRF_NODISCARD Result<Ref<ToolchainId>> register_synthetic_toolchain(
      ToolchainFamily family, std::string display_name, TargetSpec target);

  // ---- session lifecycle --------------------------------------------------
  CRF_NODISCARD Result<Ref<CompilerSessionId>> create_session(const CompileRequest& request);
  /// Adopt a session decoded from durable state. In-flight process state is
  /// fenced and the session is placed in RECOVERING.
  CRF_NODISCARD Result<Ref<CompilerSessionId>> adopt_session(CompilerSession session);

  CRF_NODISCARD Result<PhaseRunReport> run_phase(CompilerSessionId session, CompilerPhaseId phase);
  CRF_NODISCARD Result<PhaseRunReport> retry_phase(CompilerSessionId session, CompilerPhaseId phase);
  CRF_NODISCARD Result<CompileOutcome> run_session(CompilerSessionId session);
  CRF_NODISCARD VoidResult cancel_phase(CompilerSessionId session, CompilerPhaseId phase,
                                       std::string reason);
  CRF_NODISCARD VoidResult cancel_session(CompilerSessionId session, std::string reason);
  CRF_NODISCARD VoidResult retire_session(CompilerSessionId session, std::string reason);

  // ---- worker-reported completion -----------------------------------------
  /// Record the outcome of a physical execution without granting authority.
  CRF_NODISCARD Result<PhaseRunReport> report_output(CompilerSessionId session,
                                                     CompilerPhaseId phase,
                                                     CompilerPhaseGeneration phase_generation,
                                                     Ref<InvocationId> invocation,
                                                     std::vector<OutputDescriptor> outputs,
                                                     const ProcessOutcome& process);
  /// Attempt the authoritative commit for a phase generation. This is the only
  /// operation that can make a phase output current. Exactly one call per phase
  /// generation can succeed; a duplicate equivalent completion returns the
  /// existing authoritative result, and a divergent completion is refused.
  CRF_NODISCARD Result<PhaseRunReport> commit_phase(CompilerSessionId session,
                                                    CompilerPhaseId phase,
                                                    CompilerPhaseGeneration phase_generation,
                                                    Ref<InvocationId> invocation);
  CRF_NODISCARD Result<PhaseRunReport> fail_phase(CompilerSessionId session, CompilerPhaseId phase,
                                                  CompilerPhaseGeneration phase_generation,
                                                  FailureClass failure, StatusCode status,
                                                  std::string detail);
  CRF_NODISCARD Result<AuthorityVerdict> check_authority(CompilerSessionId session,
                                                         CompilerPhaseId phase) const;

  // ---- queries ------------------------------------------------------------
  CRF_NODISCARD std::optional<CompilerSession> find_session(CompilerSessionId session) const;
  CRF_NODISCARD std::vector<CompilerSession> list_sessions() const;
  CRF_NODISCARD Result<CompilerSession> require_session(CompilerSessionId session) const;
  CRF_NODISCARD const FinalCandidate* find_candidate(CompilerSessionId session) const;

  // ---- recovery -----------------------------------------------------------
  CRF_NODISCARD Result<RecoveryPlan> plan_recovery(CompilerSessionId session) const;
  CRF_NODISCARD Result<RecoveryPlan> apply_recovery(CompilerSessionId session);

  // ---- persistence and audit ---------------------------------------------
  CRF_NODISCARD VoidResult snapshot();
  CRF_NODISCARD Result<DurableState> durable_state() const;
  CRF_NODISCARD Result<AuditReport> audit() const;
  CRF_NODISCARD std::uint64_t epoch() const noexcept;
  /// Fence every in-flight phase, terminate every child process, flush durable
  /// state, and stop granting new authority.
  CRF_NODISCARD VoidResult shutdown();
  CRF_NODISCARD bool is_shutting_down() const noexcept;
  /// Restore the ability to grant authority (used by tests that need to prove a
  /// fenced runtime stays fenced until explicitly reopened).
  void reopen();

  // ---- executor selection -------------------------------------------------
  void set_executor(std::shared_ptr<PhaseExecutor> executor);
  CRF_NODISCARD std::shared_ptr<PhaseExecutor> executor() const noexcept;
  CRF_NODISCARD const RuntimeOptions& options() const noexcept;
  CRF_NODISCARD std::string describe() const;

  /// Cancel flag bound to a session. Executors observe it while a child runs so
  /// that cancellation reaches the compiler process rather than waiting for it.
  CRF_NODISCARD std::shared_ptr<std::atomic<bool>> session_cancel_flag(
      CompilerSessionId session) const;

  /// Total number of authoritative phase commits performed by this runtime.
  CRF_NODISCARD std::uint64_t commit_count() const noexcept;
  /// Total number of commit attempts refused because authority had moved.
  CRF_NODISCARD std::uint64_t stale_commit_count() const noexcept;

 private:
  Runtime();
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

/// Build the default local executor for a runtime.
CRF_NODISCARD CRF_API std::shared_ptr<PhaseExecutor> make_local_executor(Runtime& runtime);

}  // namespace crf
