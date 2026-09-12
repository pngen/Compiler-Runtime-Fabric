# Compiler Runtime Fabric

Open-source, vendor-neutral C++20 runtime for governing compiler-runtime
execution across toolchains, phases, workers, targets, intermediate artifacts,
diagnostics, retries, recovery, provenance, and generation-bound compilation
authority.

Copyright 2026 Summon Software Labs. Apache License 2.0. No telemetry
transmission.

---

## Systems boundary

Compiler Runtime Fabric answers one question:

> Given a compilation request already admitted for execution, what compiler work
> may execute now, under which toolchain, target, environment, phase, artifact,
> and authority generations - and how do we ensure that crashes, retries, stale
> subprocesses, invalid intermediates, nondeterministic diagnostics, or partial
> compiler execution cannot become authoritative compilation state?

Its systems boundary is the **local or worker-side compiler execution runtime**.
It begins when a compilation request has already been admitted, and it ends when
a validated candidate artifact with complete local provenance is handed back.

The central principle:

> A compiler invocation is a governed runtime, not merely a process launch.
> Process exit code is not sufficient authority.

Concretely:

* a compiler phase completing does **not** make its output current;
* an intermediate artifact existing does **not** make it valid;
* a restarted worker does **not** inherit old compiler authority;
* a toolchain executable at the same path is **not** necessarily the same
  toolchain;
* a successful subprocess that completed under stale generations must **not**
  commit;
* a retry must **not** silently duplicate authoritative phase completion;
* UNKNOWN is first-class: when toolchain identity, phase provenance, output
  integrity, compatibility, or continuation safety cannot be proven, the runtime
  **fails closed**.

## Relationship to Distributed Compilation

The boundary is sharp and deliberate.

A **Distributed Compilation** layer may decide which compilation should run,
which worker should own it, which toolchain is eligible, which request generation
is current, which attempt is authoritative, and which artifact may ultimately
commit.

Compiler Runtime Fabric then governs, locally: compiler session creation,
toolchain invocation, compiler phases, compiler subprocess lifecycle,
intermediate artifacts, phase transitions, phase-local retries, environment
construction, diagnostics capture, output validation, local execution recovery,
compiler-runtime resource discipline, compiler execution provenance, and final
candidate output handoff.

Compiler Runtime Fabric is **not** a distributed coordinator. It does not
perform cluster-level worker placement, global cache authority, or distributed
artifact promotion. The integration fixture in
`examples/distributed_handoff.cpp` shows the public boundary: a distributed
attempt identity goes in, and a candidate artifact with complete local provenance
comes back. Promoting that candidate to globally authoritative state is the
distributed layer's decision, and the runtime never claims it.

## Relationship to Compilation Fabric

A **Compilation Fabric** layer may own broader AI compilation semantics:
specialization, graph/kernel compilation policy, optimization intent, target
selection, reuse/invalidation policy, compilation-plan construction, and
deployment compatibility.

Compiler Runtime Fabric consumes an explicit compile plan or request and
executes it safely. It does not invent broad specialization policy. Where a
policy decision genuinely belongs to the selected compiler, the adapter owns it
and declares it in its phase plan and environment contract.

## Compiler session model

Every compiler-runtime execution is an explicit `CompilerSession` that binds:

* `CompilationId` and `CompilationGeneration`;
* `AttemptId` and `AttemptGeneration`;
* `ToolchainId` / `ToolchainGeneration` (plus cooperating toolchains);
* `TargetId` / `TargetGeneration`;
* `SourceId` / `SourceGeneration` and `IRGeneration`;
* `PolicyId` / `PolicyGeneration`;
* `EnvironmentId` / `EnvironmentGeneration`;
* an ordered phase plan and the current phase;
* intermediate artifact lineage;
* diagnostic state;
* process and runtime state;
* the final candidate artifact;
* authority and recovery state.

A session is **not** one compiler subprocess. A single session may involve
several tool invocations across several phases; the MSVC plan alone uses five.

Identity is strongly typed. `CompilerSessionId`, `CompilerPhaseId`,
`ToolchainId`, `IntermediateArtifactId` and the rest are distinct types over a
shared representation, so a value from one authority domain cannot be passed
where another is required. An operating-system PID is diagnostic evidence only;
an executable path is not a toolchain identity; a filename is not an artifact
identity.

## Phase model

Compiler phases are explicit. The vocabulary covers `INPUT_VALIDATE`,
`PREPROCESS`, `FRONTEND`, `PARSE`, `SEMANTIC_ANALYSIS`, `IR_GENERATE`,
`IR_OPTIMIZE`, `CODEGEN`, `ASSEMBLE`, `DEVICE_COMPILE`, `DEVICE_LINK`,
`LINK`, `POSTPROCESS`, `VALIDATE`, `FINALIZE`, and `CUSTOM`.

An adapter declares only the phases it actually implements, and a phase plan is
built from that declaration. The runtime never pretends all compilers share one
pipeline.

The MSVC adapter produces, for a one-translation-unit request:

| phase | kind | adapter phase | authority |
|---|---|---|---|
| 1 | INPUT_VALIDATE | `validate-inputs` | `cl /Zs /std:c++20` |
| 2 | CODEGEN | `compile#0` | `cl /c /std:c++20 /Brepro /Fo...` |
| 3 | LINK (fan-in) | `link` | `link /Brepro /OUT:... /MAP:...` |
| 4 | FINALIZE | `execute-candidate` | runs the produced executable |

Multiple translation units produce one CODEGEN phase per unit, and the LINK
phase fans in over all of them (`fan_in = true`, `required_inputs = N`). The
CUDA adapter produces `preprocess-device-source`, `device-compile`,
`device-link`, and `execute-candidate`.

## Phase lifecycle

```
Pending -> Ready -> Preparing -> Running -> Produced -> Validating
        -> CommitReady -> Committed
```

Off-path states are `Failed`, `Cancelled`, `Fenced`, `RecoveryRequired`, and
`Retired`. Legal transitions are explicit and enforced; the auditor rejects a
recorded transition the lifecycle forbids.

The important edges:

* **Produced is not Committed.** A process exiting with code 0 advances a phase
  to PRODUCED and no further. Commit requires output validation *and* current
  authority.
* `Committed -> Running` fails.
* `Retired -> Ready` fails.
* A `Fenced` phase can never commit.
* A `Cancelled` phase can never commit.
* A `Failed` phase may only be retried through an explicit retry, which
  advances the phase generation and creates fresh invocation authority.

## Phase authority

Every phase execution binds an explicit `PhaseAuthority`:

```
CompilerSessionGeneration, CompilationGeneration, AttemptGeneration,
CompilerPhaseGeneration, ToolchainId@Generation, TargetId@Generation,
EnvironmentId@Generation, PolicyId@Generation, SourceId@Generation,
IRGeneration, LeaseId@Generation
```

The binding is captured when the phase is reserved and is never silently
refreshed. At commit the runtime revalidates every domain in a fixed order - so
the same state always produces the same explained refusal - and re-probes the
toolchain from disk.

If the toolchain, target, input, environment, or policy moves while a phase is
executing, the phase may physically finish, but its output is fenced and can
never become current. This is proven end to end by
`msvc_toolchain_change_during_phase_refuses_commit` and
`msvc_environment_change_during_phase_refuses_commit`, and across processes by
`multiprocess_full_lifecycle_proof`.

## Toolchain and component identity

A toolchain aggregates the authoritative set of compiler components required for
the selected compile path: family, version, compiler executable identity, linker,
assembler, device compiler, SDK/toolkit roots, runtime libraries, the C++
standard library identity, plugins, target libraries, the environment contract,
a generation, and evidence provenance.

Component identity is stronger than a path:

```
path, NTFS volume serial + file index, size, last-write time,
SHA-256 content digest, version banner, capabilities, target support
```

Two executables at the same path across time are **not** automatically the same
component: replacing a binary changes its file identity and its content digest,
and the toolchain generation advances. A phase bound to the previous generation
is fenced at commit even if it physically succeeded.

The MSVC adapter probes `cl.exe`, `link.exe`, and `lib.exe`; the CUDA adapter
probes `nvcc.exe`, `ptxas.exe`, `nvlink.exe`, `cudart.lib`, and the MSVC host
compiler it drives. CUDA 12.9 and CUDA 13.1 are registered as **distinct**
toolchain generations and identities; nothing lets one silently satisfy the
other.

## Environment model

The compiler execution environment is explicit and canonical. It records the
working directory, temporary directory, variables, include paths, library paths,
SDK roots, toolkit roots, an explicit inheritance allowlist, the locale policy,
and the deterministic-build controls.

Environment identity is the digest of the canonical encoding of every one of
those fields. Variable lists are sorted by ASCII-uppercased name and duplicate
names are rejected, so two specs that differ only in insertion order have the
same identity.

Nothing is inherited from the runtime process by default. The only ambient
values that reach a child are the loader variables Windows requires
(`SystemRoot`, `windir`, `SystemDrive`), and those do not participate in
environment identity. `TEMP` and `TMP` are always redirected into the phase
workspace so two concurrent sessions cannot observe each other's scratch files.

The environment contract of the MSVC toolchain is constructed from the discovered
installation: `INCLUDE`, `LIB`, and `PATH` are built from the Visual Studio
toolset and the Windows SDK rather than inherited from a developer prompt.

## Command construction

A compiler process is never built by string concatenation. An `InvocationSpec`
carries the executable, the argument vector, the environment block, the working
directory, input bindings, expected outputs, and the quoting dialect; the runtime
renders the command line with native quoting rules and hands the operating system
a mutable UTF-16 command line through `CreateProcessW`. No shell is involved, so
shell metacharacters in arguments are data, never syntax.

Before launch, the runtime validates and refuses:

* a non-absolute, non-canonical, or missing executable;
* an executable whose on-disk bytes no longer match the bound component;
* malformed argument structure (embedded NUL, control characters, length or
  count beyond the configured ceilings);
* path traversal and workspace escape in inputs, outputs, or the working
  directory;
* forbidden options declared by policy;
* an unresolved or unsupported target architecture;
* an environment block beyond the configured ceilings.

## Workspace isolation

Every phase gets a generation-bound workspace directory containing `inputs`,
`outputs`, `temp`, and `logs`, plus a workspace marker that records the session
identity, session generation, phase identity, phase generation, creation time,
and a digest over all of it.

Workspace contents never confer authority. A file existing in a workspace is not
evidence that it is current. An existing directory at a generation-bound path is
never adopted: it is moved aside and reported as stale. Resolving a
workspace-relative path refuses traversal, absolute and drive-relative paths,
embedded NULs, and any existing component that is a reparse point.

A worker refuses to open a workspace outside its own configured root, and
revalidates the marker before it will execute inside it.

## Intermediate artifacts and lineage

Intermediates are first-class governed objects recording their identity,
generation, format, path, content digest, size, producer phase and invocation,
toolchain, target, source and IR generations, environment, policy, direct lineage
inputs, validation state, authority state, provenance, and a validation detail.

An intermediate may be `VALID`, `STALE`, `INCOMPATIBLE`, `CORRUPT`,
`SUPERSEDED`, `UNKNOWN`, or `UNSUPPORTED`. Only `VALID` **and** authoritative
artifacts are consumable, so `UNKNOWN` fails closed. A committed artifact whose
file changes on disk is re-classified as `CORRUPT` and loses its authority.

Lineage is explicit edge by edge:

```
source -> preprocessed source -> object / device object -> linked image -> candidate
```

Every edge records provenance, and lineage tracing refuses a cycle or a reference
to an unregistered artifact rather than following it. Fan-in phases require every
mandatory input to be present, current, and authoritative; a missing or stale
child blocks finalization instead of being skipped.

## Phase commit semantics

```
reserve phase execution
  -> launch compiler component
  -> observe process outcome
  -> collect candidate outputs
  -> hash outputs
  -> validate expected outputs
  -> collect diagnostics
  -> revalidate all authority generations (including a fresh toolchain re-probe)
  -> persist the committed projection and its provenance
  -> commit phase output
  -> expose it to dependent phases
```

The commit is the only operation that makes a phase output current, and it occurs
exactly once per phase generation. A duplicate *equivalent* completion returns
the existing authoritative result; a *divergent* completion is refused outright.
Ordering is mutate -> persist -> publish, so a caller that observes a successful
durable commit can restart the runtime and recover that phase as committed.

## Subprocess lifecycle

Compiler children are real operating-system processes created through
`CreateProcessW` with a runtime-rendered command line, an explicit environment
block, an explicit working directory, and anonymous pipes for all three standard
streams.

* **Process identity** is a runtime-owned `ProcessId` plus
  `ProcessGeneration`; the operating-system PID is recorded as diagnostic
  evidence only. A recycled PID never inherits phase authority, and late output
  from an old invocation can never satisfy a new one.
* **Capture is bounded.** Each stream has a ceiling; overflow is counted and
  reported as explicit truncation metadata rather than buffered without limit.
* **Children cannot be orphaned.** Each child is assigned to a Windows job object
  with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, so a crash of the worker or
  coordinator reaps the compiler tree. Shutdown terminates every live child and
  reports zero leaked processes.
* **Cancellation is first-class.** Per-invocation cancellation, session
  cancellation, and shutdown all reach the compiler child; a late completion
  after cancellation is refused at commit because the phase generation was
  fenced.

## Diagnostics

Compiler diagnostics are captured as bounded `DiagnosticSet` objects that record
the invocation, phase, toolchain and target generations, the exit status, whether
the process crashed, raw byte counts and dropped byte counts per stream, bounded
raw stream tails, normalised entries, and truncation flags.

Severities are `INFO`, `WARNING`, `ERROR`, `FATAL`, `INTERNAL`, and
`UNKNOWN`. Normalisation preserves the raw line verbatim and extracts a stable
code and source location where the compiler provides one. Normalisation never
claims cross-compiler semantic equivalence: the MSVC and nvcc dialect parsers are
separate and are labelled as such.

The runtime never infers failure from the presence of stderr, nor success from the
absence of diagnostics. Failure comes from the exit status, the termination kind,
and output validation.

## Output validation

Exit code 0 is not enough. Before commit, an adapter validates its declared
outputs. The MSVC adapter checks that a produced object is a real COFF object with
the expected machine type and at least one section; that a linked image is a real
PE image with the expected machine type and an entry point; and that the final
candidate executes and reports the expected result. The CUDA adapter additionally
requires the device object to carry an embedded device-code section, so an
"object" with no device code is refused as incompatible.

## Retry and recovery

Failures are classified, and retryability is a property of the class:

* retryable: child process crash, process interruption, transient workspace
  failure, transient storage failure, retry-safe tool invocation failure, external
  cancellation followed by fresh authority, and authority invalidation;
* not retryable: invalid source, deterministic compiler error, unsupported
  target, unsupported option, invalid toolchain, policy refusal, and invalid
  output;
* **never automatically retryable**: an UNKNOWN outcome. It requires manual
  resolution.

Both ceilings are enforced (per phase and per session), and an exhausted ceiling
is a refusal, not a silent extra attempt. A retry always creates fresh invocation
authority: a new attempt identity, a new attempt generation, a new invocation
identity, and a new lease.

Recovery outcomes are `NONE`, `RESTART_PHASE`,
`RESUME_FROM_COMMITTED_PHASE`, `REVALIDATE_INTERMEDIATE`,
`REBUILD_INTERMEDIATE`, `RESTART_SESSION`, `CANCEL`, `TERMINAL_FAILURE`,
`MANUAL_RESOLUTION_REQUIRED`, and `UNSUPPORTED`. The plan is deterministic
and conservative. The runtime **never** claims to resume a compiler subprocess
mid-process: process death means the phase restarts from the last authoritative
phase boundary.

## Reproducibility

Policy declares `REQUIRED`, `PREFERRED`, or `NOT_REQUIRED`. When
reproducibility is `REQUIRED`, the runtime performs a genuine second execution of
a deterministic phase in its own generation-bound workspace, under the same
authoritative inputs, and compares the output digests. If they differ it surfaces
the divergence and refuses to commit; it never picks a winner silently. The
runtime never rewrites compiler output after the fact to force reproducibility;
it stabilises inputs instead (temporary paths, locale, deterministic-build
controls, canonical ordering).

## Persistence

Durable state is an append-only journal with an atomically replaced snapshot. The
journal file has a checksummed header and every record carries its own record
kind, sequence, timestamp, payload length, payload CRC-32C, and header CRC-32C.
Decoding is bounded: no persisted length is trusted before it is compared against
a configured ceiling.

Integrity behaviour:

* a **torn tail** (a partially written final record) is detected, discarded, and
  the file is truncated to the last complete record;
* a record damaged in the **middle** of the journal makes the store refuse to
  open at all - no partially trusted load is permitted;
* a schema version mismatch is refused;
* a snapshot that fails its checksum or is truncated is refused.

The durable projection of a session includes the session, its phases, its
artifacts, its diagnostic sets, the authority it is bound to (toolchain, target,
environment, policy, and sources), and the provenance its authoritative artifacts
cite. That is what lets a restarted runtime revalidate committed phases instead of
trusting an empty registry.

Durability points are explicit: session creation, phase reservation, phase
commit (including its provenance), intermediate registration, candidate
registration, diagnostic metadata, and recovery decisions.

## Runtime restart behaviour

After a runtime restart the runtime loads durable state, verifies integrity,
advances the runtime epoch, marks in-flight process phases non-current, revalidates
committed intermediates, makes the toolchain and environment available again for
revalidation, and determines the legal restart phase. It does not persist OS
process handles or PIDs as resumable authority, and it does not revive dead
process authority: every phase that was in flight is fenced, and the session is
placed in `RECOVERING` until recovery decides the restart boundary.

## CLI

```
crf_cli [--state DIR] [--workspaces DIR] [--coordinator HOST:PORT] COMMAND ...

toolchain list | probe FAMILY | show ID
component show TOOLCHAIN_ID COMPONENT_ID
session list | show ID | create FAMILY SOURCE... | cancel ID REASON | retire ID REASON
phase list SESSION_ID | show S P | start S P | retry S P | cancel S P REASON | authority S P
intermediate list SESSION_ID | show ID
artifact show SESSION_ID | verify SESSION_ID
diagnostics show SET_ID
recovery explain SESSION_ID | apply SESSION_ID
provenance show ARTIFACT_ID
snapshot | verify | audit | demo [DIR] | version
explain runtime | explain session SESSION_ID
```

Output is deterministic: identical state renders identical text. `audit` exits
non-zero when the invariant auditor reports a violation.

## Control plane

`crf_coordinator` owns every compiler session, every authority generation, and
all durable state. `crf_worker` connects to it, receives fully specified
execution orders, proves each order is well formed, runs the compiler locally, and
reports evidence back. A worker holds **no** authority: killing one can never
leave authoritative compilation state behind.

The protocol is framed, versioned, bounded, request-identified, generation-aware,
and explicit about refusal. Each frame carries a magic, a protocol version, a
message type, flags, a request identity, a payload length, a payload CRC-32C, and
a header CRC-32C. Payloads are field-oriented with strictly ascending field ids.

Defences proven by `test_protocol`: malformed frames, oversized declared lengths,
truncated headers and payloads, unknown message types, corrupt checksums,
duplicate field records, reordered field records, trailing bytes, replayed request
identities, duplicate completion races, half-open peers, and reconnects. No
malformed input creates an uncontrolled allocation, and the coordinator stays
healthy after every one of them.

## Examples

```
msvc_compile_session        real MSVC session, lineage, diagnostics, audit
compile_link_and_run        two translation units, fan-in link, execution proof
failure_and_retry           real compiler child killed, classification, retry
stale_toolchain_rejection   toolchain and environment generation moved mid-phase
restart_recovery            durable commit, restart, conservative recovery
cuda_compile_and_run        real nvcc build and RTX device execution with parity
distributed_handoff         the Distributed Compilation integration fixture
consumer/                   an independent find_package consumer
```

## Benchmarks

`crf_bench` measures **runtime overhead only**, at 10, 100, 1,000, 10,000, and
100,000 records: session creation, phase authority validation, intermediate
registration, lineage lookup, diagnostics ingestion, durable journal append,
snapshot, invariant audit, and canonical hashing. Compiler wall time is not
measured there and is never reported as a runtime measurement; the MSVC and CUDA
proof suites report real compiler timings separately.

## Security

All external request, compiler output, persisted state, and protocol input is
treated as untrusted. The runtime validates identities, generations, paths,
counts, lengths, arguments, environments, executable identity, toolchain
identity, targets, intermediate references, artifact sizes, diagnostic sizes,
enum values, and integer arithmetic. It rejects path traversal and workspace
escape, and it will not launch an arbitrary peer-selected compiler executable:
an invocation executable must be a probed component of the bound toolchain, or an
authoritative artifact of the same session.

There is **no telemetry transmission** of any kind.

## CUDA adapter

The CUDA adapter drives real NVIDIA tooling: `nvcc`, `ptxas`, `nvlink`, and
`cudart.lib`, plus the MSVC host compiler nvcc itself drives. Its environment
contract is composed from the discovered toolkit and toolset (`CUDA_PATH`,
`CUDA_HOME`, `VCINSTALLDIR`, `VCToolsInstallDir`, `VSINSTALLDIR`,
`WindowsSdkDir`, `WindowsSDKVersion`, `UCRTVersion`, `INCLUDE`, `LIB`,
`PATH`), so nothing is inherited silently.

Its phase plan is `preprocess-device-source` (`nvcc -E`), `device-compile`
(`nvcc -c`), `device-link`, and `execute-candidate`. Output validation requires
the compiled object to be a real COFF object whose device-code section
(`.nv_fatbin`) is present - an object without device code is refused as
incompatible rather than accepted because the exit code was zero.

CUDA 12.9 and CUDA 13.1 are registered as distinct toolchain identities and
generations; the probe selects deterministically and a caller can pin an exact
installation, so one never silently satisfies the other.

The device architecture is either supplied by the caller
(`target.device_arch`) or probed from the driver through `nvidia-smi`; which one
happened is recorded in the toolchain identity as `cuda.device-arch-source`. The
supplied architecture is not taken on trust: the executed candidate reports its
own device and compute capability, and the proof requires that report to match.
On the RTX 5090 host used for this release the candidate reports
`CRF-CUDA-PARITY-OK device=NVIDIA GeForce RTX 5090 cc=12.0` with zero parity
error after a real host-to-device transfer, kernel launch, and device-to-host
transfer.

Two host-specific behaviours are handled explicitly rather than hidden:

* `nvidia-smi` cannot initialise NVML when it is launched as a grandchild
  process in this build environment; the adapter records the exact failure in
  `cuda.device-arch-probe` and the caller supplies the architecture, which the
  execution proof then validates.
* `nvcc` fails with no diagnostic when its temporary directory contains a space.
  When the workspace path contains one, the runtime gives the child a unique
  scratch directory under the system temporary directory instead, still per phase
  and still cleaned up.

## Real, Synthetic, and Unsupported

Evidence is labelled rigorously and the labels are asserted by tests.

* **REAL** - MSVC compiler, linker and librarian processes; nvcc device
  compilation and linking; RTX 5090 (sm_120) kernel execution with CPU parity;
  Windows process lifecycle
  including job-object reaping; TCP loopback control plane; filesystem
  workspaces; durable persistence; process kill and restart; real compiler
  diagnostics.
* **SYNTHETIC** - ROCm, Intel oneAPI, GCC and Clang toolchain identities are
  modelled for governance-path coverage only. Their identities are labelled
  `SYNTHETIC`, they declare `toolchain.real-tooling-present=false`, they expose no
  components, and every attempt to execute a phase through them is refused with
  `UNSUPPORTED`. No synthetic artifact is ever presented as compiler output.
* **UNSUPPORTED** - mid-process compiler-state migration; physical multi-node
  compiler runtime; ROCm execution without ROCm tooling; compiler daemon
  protocols that are not implemented; alternate compiler families beyond the
  implemented adapters.

## Build

Requirements: CMake 3.20 or newer, a C++20 compiler, and on Windows the Win32
APIs. There are no third-party build dependencies; SHA-256 and CRC-32C are
implemented inside the runtime.

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Options: `CRF_BUILD_TESTS`, `CRF_BUILD_EXAMPLES`, `CRF_BUILD_BENCHMARKS`,
`CRF_BUILD_TOOLS`, `CRF_WARNINGS_AS_ERRORS` (default `ON`),
`CRF_ENABLE_ASAN`, `CRF_ENABLE_IPO`.

## Test

Each suite is a standalone executable with stable, filterable case names. A case
prints a flushed `BEGIN`, explicit `PHASE` markers, and a `PASS`/`FAIL` line
with elapsed time and check count, so a hang identifies the exact case and the
last completed phase. Run one exact case with:

```
build/tests/test_msvc --filter msvc_compile_link_execute_proof
```

| suite | scope |
|---|---|
| `test_core` | identity, lifecycle, authority, plans, environments, artifacts, diagnostics, retry, persistence, audit |
| `test_property` | seeded randomised phase graphs, generation mutations, retry sequences, serialization round-trips |
| `test_concurrency` | duplicate start, cancel/complete, retry/late output, snapshot during commit, parallel sessions, shutdown races |
| `test_adversarial` | stale authority, traversal, escape, hostile streams, corrupt output, policy refusal, re-entrancy |
| `test_recovery` | durable commit, restart, recovery, integrity refusal |
| `test_protocol` | framing defence, replay, duplicate completion race |
| `test_msvc` | real MSVC compile/link/execute and real compiler-process failure proofs |
| `test_cuda` | real toolkit identity, distinct CUDA generations, device compilation, RTX 5090 execution and parity |
| `test_multiprocess` | real coordinator and worker processes end to end |

## Install

```
cmake --install build --prefix <prefix> --config Release
```

The install provides `crf::core`, `crf::adapters`, and `crf::ipc` exported
targets, a `CompilerRuntimeFabricConfig.cmake` package config, a version config,
and headers under `<prefix>/include/crf`. Use it with:

```cmake
find_package(CompilerRuntimeFabric CONFIG REQUIRED)
target_link_libraries(app PRIVATE crf::core crf::adapters)
```

`examples/consumer` is an independent project that only ever sees the installed
package; see its README.

## Limitations

These are architectural scope boundaries, not aspirations:

* **Local execution.** The runtime governs compiler execution on one host. It is
  not a physical multi-node compiler runtime; a Distributed Compilation layer owns
  placement and global promotion.
* **No mid-process compiler continuation.** Process death always means a phase
  restart from the last authoritative phase boundary. The runtime never claims to
  resume a compiler mid-process.
* **Single coordinator.** There is one coordinator process per runtime. There is
  no consensus, no leader election, and no replicated state.
* **No authentication.** The control plane binds to loopback by default and has no
  authentication or transport security. It is a local control plane; do not expose
  it to an untrusted network.
* **Two real adapter families.** MSVC (`cl.exe`, `link.exe`, `lib.exe`) and
  NVIDIA CUDA (`nvcc`, `ptxas`, `nvlink`) are implemented against real tooling.
  ROCm, Intel oneAPI, GCC, and Clang are synthetic identities only.
* **No real ROCm execution.** There is no ROCm proof in this repository because
  there is no ROCm tooling on the build host.
* **No compiler replacement.** The runtime does not parse C++, does not perform
  optimisation, and does not link. It governs the tools that do.
* **No global artifact authority.** The runtime produces a *candidate* artifact
  with complete local provenance. Distributed artifact promotion is out of scope.
* **No distributed cache ownership.** A local cache may be consulted only as a
  candidate source, and only when policy enables it; the runtime does not own a
  global cache.
* **Windows process backend.** This release ships a Windows process backend. The
  governance model is portable C++20; porting the process and file-identity layer
  is the work required for other platforms.
* **One device translation unit per CUDA session.** The CUDA adapter compiles a
  single device translation unit; multi-unit device compilation with
  `-rdc=true` device linking is not implemented.
