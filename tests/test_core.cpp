// Core governance unit proofs: identity, lifecycle, authority, plans,
// environments, artifacts, diagnostics, retry classification, persistence, audit.

#include "crf_test.hpp"
#include "crf_test_env.hpp"

#include <algorithm>
#include <atomic>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace crf;

/// Offset inside the journal used by the corruption case: past the 48-byte file
/// header and inside the first record's header, so a mid-journal defect is made.
constexpr std::streamoff kJournalProbeOffset = 56;

CRF_NODISCARD CompileRequest simple_request(const std::filesystem::path& source) {
  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {source};
  return request;
}

}  // namespace

CRF_TEST(core_process_execution_is_real_and_bounded) {
  CRF_PHASE("SETUP");
  const std::filesystem::path cl = normalize_path(
      std::filesystem::path("C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/"
                            "MSVC/14.44.35207/bin/Hostx64/x64/cl.exe"));
  CRF_REQUIRE(std::filesystem::exists(cl));

  CRF_PHASE("LAUNCH");
  ProcessSupervisor supervisor;
  ProcessSpec spec;
  spec.executable = cl;
  spec.max_capture_bytes = 64u * 1024u;
  const Result<ProcessOutcome> outcome = supervisor.run(
      spec, Ref<InvocationId>{InvocationId::from_value(1), InvocationGeneration::initial()});
  CRF_REQUIRE_OK(outcome);
  std::printf("  observed termination=%s exit=%u stdout=%llu stderr=%llu\n",
              std::string(to_string(outcome.value().termination)).c_str(),
              outcome.value().exit_code,
              static_cast<unsigned long long>(outcome.value().capture.standard_output.size()),
              static_cast<unsigned long long>(outcome.value().capture.standard_error.size()));
  std::printf("  stdout: %s\n", outcome.value().capture.standard_output.c_str());

  CRF_PHASE("VERIFY");
  CRF_EXPECT(outcome.value().termination == ProcessTermination::exited);
  CRF_EXPECT(outcome.value().os_process_id != 0);
  // The compiler banner is split across the two streams depending on the tool;
  // what matters is that both were captured, bounded, and attributed.
  const std::string combined = outcome.value().capture.standard_output +
                               outcome.value().capture.standard_error;
  CRF_EXPECT(!combined.empty());
  CRF_EXPECT(combined.find("Version") != std::string::npos);
  CRF_EXPECT(combined.size() < 64u * 1024u);
  CRF_EXPECT(outcome.value().duration_nanos() > 0);
  CRF_EXPECT_EQ(supervisor.live_count(), static_cast<std::size_t>(0));
  CRF_EXPECT(supervisor.total_spawned() == 1);

  CRF_PHASE("SHUTDOWN");
  supervisor.close();
}

CRF_TEST(core_strong_identities_are_not_interchangeable) {
  CRF_PHASE("RENDER");
  const CompilerSessionId session = CompilerSessionId::from_value(0x1234);
  const CompilerPhaseId phase = CompilerPhaseId::from_value(0x1234);
  CRF_EXPECT_EQ(session.to_string(), std::string("session-0000000000001234"));
  CRF_EXPECT_EQ(phase.to_string(), std::string("phase-0000000000001234"));
  CRF_EXPECT(session.to_string() != phase.to_string());

  CRF_PHASE("PARSE");
  CompilerSessionId parsed;
  CRF_EXPECT(CompilerSessionId::try_parse("session-0000000000001234", parsed));
  CRF_EXPECT_EQ(parsed, session);
  CRF_EXPECT(!CompilerSessionId::try_parse("phase-0000000000001234", parsed));
  CRF_EXPECT(!CompilerSessionId::try_parse("session-000000000000123", parsed));
  CRF_EXPECT(!CompilerSessionId::try_parse("session-00000000000012zz", parsed));
  CRF_EXPECT_EQ(CompilerSessionId::parse("nonsense"), CompilerSessionId{});

  CRF_PHASE("GENERATIONS");
  CompilerSessionGeneration generation = CompilerSessionGeneration::initial();
  CRF_EXPECT_EQ(generation.value(), static_cast<std::uint64_t>(1));
  generation = generation.next();
  CRF_EXPECT_EQ(generation.value(), static_cast<std::uint64_t>(2));
  CRF_EXPECT(generation > CompilerSessionGeneration::initial());
  const CompilerSessionGeneration saturated =
      CompilerSessionGeneration::from_value(CompilerSessionGeneration::kMax).next();
  CRF_EXPECT_EQ(saturated.value(), CompilerSessionGeneration::kMax);

  CRF_PHASE("ALLOCATOR");
  IdAllocator<CompilerSessionId> allocator;
  const CompilerSessionId first = allocator.next();
  const CompilerSessionId second = allocator.next();
  CRF_EXPECT(first.present());
  CRF_EXPECT(first != second);
  allocator.observe(CompilerSessionId::from_value(1000));
  CRF_EXPECT(allocator.next().value() > 1000);
}

CRF_TEST(core_phase_lifecycle_transitions_are_enforced) {
  CRF_PHASE("LEGAL");
  CRF_EXPECT(is_legal_phase_transition(PhaseState::pending, PhaseState::ready));
  CRF_EXPECT(is_legal_phase_transition(PhaseState::ready, PhaseState::preparing));
  CRF_EXPECT(is_legal_phase_transition(PhaseState::preparing, PhaseState::running));
  CRF_EXPECT(is_legal_phase_transition(PhaseState::running, PhaseState::produced));
  CRF_EXPECT(is_legal_phase_transition(PhaseState::produced, PhaseState::validating));
  CRF_EXPECT(is_legal_phase_transition(PhaseState::validating, PhaseState::commit_ready));
  CRF_EXPECT(is_legal_phase_transition(PhaseState::commit_ready, PhaseState::committed));
  CRF_EXPECT(is_legal_phase_transition(PhaseState::failed, PhaseState::ready));

  CRF_PHASE("ILLEGAL");
  CRF_EXPECT(!is_legal_phase_transition(PhaseState::committed, PhaseState::running));
  CRF_EXPECT(!is_legal_phase_transition(PhaseState::committed, PhaseState::ready));
  CRF_EXPECT(!is_legal_phase_transition(PhaseState::retired, PhaseState::ready));
  CRF_EXPECT(!is_legal_phase_transition(PhaseState::retired, PhaseState::pending));
  CRF_EXPECT(!is_legal_phase_transition(PhaseState::fenced, PhaseState::committed));
  CRF_EXPECT(!is_legal_phase_transition(PhaseState::cancelled, PhaseState::committed));
  CRF_EXPECT(!is_legal_phase_transition(PhaseState::cancelled, PhaseState::running));
  CRF_EXPECT(!is_legal_phase_transition(PhaseState::failed, PhaseState::committed));
  CRF_EXPECT(!is_legal_phase_transition(PhaseState::failed, PhaseState::running));
  CRF_EXPECT(!is_legal_phase_transition(PhaseState::produced, PhaseState::committed));

  CRF_PHASE("CLASSIFICATION");
  CRF_EXPECT(phase_state_is_terminal(PhaseState::committed));
  CRF_EXPECT(phase_state_is_terminal(PhaseState::retired));
  CRF_EXPECT(phase_state_is_terminal(PhaseState::cancelled));
  CRF_EXPECT(phase_state_is_terminal(PhaseState::fenced));
  CRF_EXPECT(!phase_state_is_terminal(PhaseState::produced));
  CRF_EXPECT(phase_state_retains_commit_authority(PhaseState::commit_ready));
  CRF_EXPECT(!phase_state_retains_commit_authority(PhaseState::fenced));
  CRF_EXPECT(phase_state_may_hold_process(PhaseState::running));
  CRF_EXPECT(!phase_state_may_hold_process(PhaseState::produced));
}

CRF_TEST(core_phase_plan_validation) {
  CRF_PHASE("VALID");
  IdAllocator<CompilerPhaseId> ids;
  const CompilerPhaseId a = ids.next();
  const CompilerPhaseId b = ids.next();
  const CompilerPhaseId c = ids.next();
  std::vector<PhaseNode> nodes(3);
  nodes[0].id = a;
  nodes[0].kind = PhaseKind::input_validate;
  nodes[1].id = b;
  nodes[1].kind = PhaseKind::codegen;
  nodes[1].depends_on = {a};
  nodes[2].id = c;
  nodes[2].kind = PhaseKind::link;
  nodes[2].depends_on = {b};
  nodes[2].fan_in = true;
  nodes[2].required_inputs = 1;
  const Result<PhasePlan> plan = PhasePlan::build(nodes);
  CRF_REQUIRE_OK(plan);
  CRF_EXPECT_EQ(plan.value().size(), static_cast<std::size_t>(3));
  CRF_EXPECT_EQ(plan.value().topological_order().size(), static_cast<std::size_t>(3));
  CRF_EXPECT_EQ(plan.value().topological_order().front(), a);
  CRF_EXPECT_EQ(plan.value().topological_order().back(), c);
  CRF_EXPECT(plan.value().is_ready(b, {a}));
  CRF_EXPECT(!plan.value().is_ready(b, {}));
  CRF_EXPECT_EQ(plan.value().dependencies(b).size(), static_cast<std::size_t>(1));
  CRF_EXPECT_EQ(plan.value().mandatory_ancestors(c).size(), static_cast<std::size_t>(2));

  CRF_PHASE("DUPLICATE");
  std::vector<PhaseNode> duplicate = nodes;
  duplicate[1].id = a;
  CRF_EXPECT_CODE(PhasePlan::build(duplicate), StatusCode::already_exists);

  CRF_PHASE("MISSING_DEPENDENCY");
  std::vector<PhaseNode> missing = nodes;
  missing[1].depends_on = {CompilerPhaseId::from_value(4242)};
  CRF_EXPECT_CODE(PhasePlan::build(missing), StatusCode::not_found);

  CRF_PHASE("CYCLE");
  std::vector<PhaseNode> cycle = nodes;
  cycle[0].depends_on = {c};
  CRF_EXPECT_CODE(PhasePlan::build(cycle), StatusCode::invalid_argument);

  CRF_PHASE("SELF_DEPENDENCY");
  std::vector<PhaseNode> self = nodes;
  self[0].depends_on = {a};
  CRF_EXPECT_CODE(PhasePlan::build(self), StatusCode::invalid_argument);

  CRF_PHASE("EMPTY");
  CRF_EXPECT_CODE(PhasePlan::build({}), StatusCode::invalid_argument);

  CRF_PHASE("BAD_FAN_IN");
  std::vector<PhaseNode> fan_in = nodes;
  fan_in[2].required_inputs = 5;
  CRF_EXPECT_CODE(PhasePlan::build(fan_in), StatusCode::invalid_argument);

  CRF_PHASE("ORPHAN");
  std::vector<PhaseNode> orphan = nodes;
  PhaseNode extra;
  extra.id = CompilerPhaseId::from_value(999);
  extra.kind = PhaseKind::postprocess;
  orphan.push_back(extra);
  CRF_EXPECT_CODE(PhasePlan::build(orphan), StatusCode::invalid_argument);
}

CRF_TEST(core_environment_identity_is_canonical) {
  CRF_PHASE("INSERTION_ORDER");
  EnvironmentSpec first;
  first.set_variable("BETA", "2");
  first.set_variable("ALPHA", "1");
  first.set_variable("gamma", "3");
  CRF_REQUIRE_OK(first.canonicalize());
  EnvironmentSpec second;
  second.set_variable("gamma", "3");
  second.set_variable("ALPHA", "1");
  second.set_variable("BETA", "2");
  CRF_REQUIRE_OK(second.canonicalize());
  CRF_EXPECT_EQ(first.canonical_digest(), second.canonical_digest());
  CRF_EXPECT_EQ(first.variables.front().name, std::string("ALPHA"));

  CRF_PHASE("DUPLICATE");
  EnvironmentSpec duplicates;
  duplicates.variables.push_back(EnvironmentVariable{"PATH", "a"});
  duplicates.variables.push_back(EnvironmentVariable{"path", "b"});
  CRF_EXPECT_CODE(duplicates.canonicalize(), StatusCode::invalid_argument);

  CRF_PHASE("PATH_NORMALISATION");
  EnvironmentSpec paths;
  paths.include_paths = {std::filesystem::path("C:/a/b/../b/c"), std::filesystem::path("C:/a/b/c")};
  CRF_REQUIRE_OK(paths.canonicalize());
  CRF_EXPECT_EQ(paths.include_paths.size(), static_cast<std::size_t>(1));

  CRF_PHASE("REGISTRY");
  EnvironmentRegistry registry;
  const Result<Ref<EnvironmentId>> interned = registry.intern(first);
  CRF_REQUIRE_OK(interned);
  const Result<Ref<EnvironmentId>> again = registry.intern(second);
  CRF_REQUIRE_OK(again);
  CRF_EXPECT_EQ(interned.value().id, again.value().id);

  CRF_PHASE("REVISION");
  EnvironmentSpec changed = first;
  changed.deterministic_controls = false;
  const Result<Ref<EnvironmentId>> revised = registry.revise(interned.value().id, changed);
  CRF_REQUIRE_OK(revised);
  CRF_EXPECT(revised.value().generation > interned.value().generation);

  CRF_PHASE("PROCESS_BLOCK");
  EnvironmentSpec block_spec;
  block_spec.temp_directory = std::filesystem::path("C:/temp/scratch");
  block_spec.set_variable("INCLUDE", "C:/inc");
  CRF_REQUIRE_OK(block_spec.canonicalize());
  const Result<std::vector<EnvironmentVariable>> block = build_process_environment(block_spec);
  CRF_REQUIRE_OK(block);
  bool saw_temp = false;
  for (const EnvironmentVariable& variable : block.value()) {
    if (variable.name == "TEMP") saw_temp = true;
  }
  CRF_EXPECT(saw_temp);
}

CRF_TEST(core_artifact_lineage_and_validity) {
  CRF_PHASE("SETUP");
  ArtifactRegistry registry;
  IntermediateArtifact source_artifact;
  source_artifact.format = ObjectFormat::preprocessed_source;
  source_artifact.state = ArtifactState::valid;
  source_artifact.content = Digest::of(std::string("preprocessed"));
  source_artifact.size_bytes = 12;
  const Result<Ref<IntermediateArtifactId>> first = registry.register_artifact(source_artifact);
  CRF_REQUIRE_OK(first);
  CRF_REQUIRE_OK(registry.set_authority(first.value().id, AuthorityState::authoritative));

  CRF_PHASE("LINEAGE");
  IntermediateArtifact object;
  object.format = ObjectFormat::coff_object;
  object.state = ArtifactState::valid;
  object.content = Digest::of(std::string("object"));
  object.lineage_inputs = {first.value()};
  const Result<Ref<IntermediateArtifactId>> second = registry.register_artifact(object);
  CRF_REQUIRE_OK(second);
  CRF_REQUIRE_OK(registry.set_authority(second.value().id, AuthorityState::authoritative));

  ProvenanceLog log;
  const Result<std::vector<Ref<IntermediateArtifactId>>> lineage =
      log.trace_lineage(registry, second.value().id);
  CRF_REQUIRE_OK(lineage);
  CRF_EXPECT_EQ(lineage.value().size(), static_cast<std::size_t>(2));
  CRF_EXPECT(log.lineage_is_authoritative(registry, second.value().id));

  CRF_PHASE("REVOCATION");
  const std::size_t revoked =
      registry.revoke_phase_outputs(CompilerPhaseId::from_value(99),
                                    CompilerPhaseGeneration::initial(), "test revocation");
  CRF_EXPECT_EQ(revoked, static_cast<std::size_t>(0));
  CRF_REQUIRE_OK(registry.set_state(first.value().id, ArtifactState::stale, "test"));
  CRF_EXPECT(registry.find(first.value().id)->authority == AuthorityState::revoked);
  CRF_EXPECT(!log.lineage_is_authoritative(registry, second.value().id));

  CRF_PHASE("UNKNOWN_IS_NOT_CONSUMABLE");
  IntermediateArtifact unknown;
  unknown.format = ObjectFormat::coff_object;
  unknown.state = ArtifactState::unknown;
  const Result<Ref<IntermediateArtifactId>> registered = registry.register_artifact(unknown);
  CRF_REQUIRE_OK(registered);
  const VoidResult promoted = registry.set_authority(registered.value().id,
                                                     AuthorityState::authoritative);
  CRF_EXPECT(!promoted.has_value());
  CRF_EXPECT(!registry.find(registered.value().id)->consumable());
}

CRF_TEST(core_diagnostics_normalisation) {
  CRF_PHASE("MSVC");
  const std::string output =
      "hello.cpp\r\n"
      "hello.cpp(5,10): error C2039: 'foo': is not a member of 'std'\r\n"
      "hello.cpp(9): warning C4101: 'x': unreferenced local variable\r\n"
      "LINK : fatal error LNK1104: cannot open file 'missing.lib'\r\n";
  const std::vector<Diagnostic> diagnostics = normalize_msvc_output(output, "cl");
  CRF_REQUIRE(diagnostics.size() >= 3);
  bool saw_error_code = false;
  bool saw_warning = false;
  bool saw_link_error = false;
  for (const Diagnostic& entry : diagnostics) {
    if (entry.code == "C2039") {
      saw_error_code = true;
      CRF_EXPECT(entry.severity == DiagnosticSeverity::error);
      CRF_EXPECT_EQ(entry.line, static_cast<std::uint32_t>(5));
      CRF_EXPECT_EQ(entry.column, static_cast<std::uint32_t>(10));
      CRF_EXPECT(entry.file.find("hello.cpp") != std::string::npos);
    }
    if (entry.code == "C4101") {
      saw_warning = true;
      CRF_EXPECT(entry.severity == DiagnosticSeverity::warning);
    }
    if (entry.code == "LNK1104") {
      saw_link_error = true;
      CRF_EXPECT(entry.severity == DiagnosticSeverity::fatal);
    }
  }
  CRF_EXPECT(saw_error_code);
  CRF_EXPECT(saw_warning);
  CRF_EXPECT(saw_link_error);

  CRF_PHASE("NVCC");
  const std::string nvcc_output =
      "kernel.cu(12): error: identifier \"x\" is undefined\n"
      "ptxas fatal   : Value 'sm_999' is not defined for option 'gpu-name'\n";
  const std::vector<Diagnostic> cuda_diagnostics = normalize_nvcc_output(nvcc_output, "nvcc");
  CRF_EXPECT(cuda_diagnostics.size() >= 2);
  bool saw_cuda_error = false;
  for (const Diagnostic& entry : cuda_diagnostics) {
    if (entry.severity == DiagnosticSeverity::error || entry.severity == DiagnosticSeverity::fatal) {
      saw_cuda_error = true;
    }
    CRF_EXPECT(!entry.raw.empty());
  }
  CRF_EXPECT(saw_cuda_error);

  CRF_PHASE("COUNTS");
  std::uint32_t errors = 0;
  std::uint32_t warnings = 0;
  count_severities(diagnostics, errors, warnings);
  CRF_EXPECT(errors >= 2);
  CRF_EXPECT(warnings >= 1);

  CRF_PHASE("BOUNDED");
  DiagnosticSet set;
  for (int i = 0; i < 100; ++i) {
    Diagnostic entry;
    entry.message = "m" + std::to_string(i);
    set.entries.push_back(entry);
  }
  CRF_EXPECT(!set.truncated);
  CRF_EXPECT(!set.normalized_digest().zero());
  CRF_EXPECT(set.normalized_digest() == set.normalized_digest());
}

CRF_TEST(core_retry_classification) {
  CRF_PHASE("RETRYABLE");
  CRF_EXPECT(is_retryable(FailureClass::process_crash));
  CRF_EXPECT(is_retryable(FailureClass::process_interrupted));
  CRF_EXPECT(is_retryable(FailureClass::transient_workspace_failure));
  CRF_EXPECT(is_retryable(FailureClass::external_cancellation));

  CRF_PHASE("NOT_RETRYABLE");
  CRF_EXPECT(!is_retryable(FailureClass::invalid_source));
  CRF_EXPECT(!is_retryable(FailureClass::deterministic_compiler_error));
  CRF_EXPECT(!is_retryable(FailureClass::unsupported_target));
  CRF_EXPECT(!is_retryable(FailureClass::policy_refusal));
  CRF_EXPECT(!is_retryable(FailureClass::unknown_outcome));

  CRF_PHASE("DECISIONS");
  PolicySpec policy;
  PhaseRecord phase;
  phase.state = PhaseState::failed;
  phase.failure = FailureClass::process_crash;
  phase.attempt_generation = AttemptGeneration::initial();
  PhaseAttempt attempt;
  attempt.id = AttemptId::from_value(1);
  phase.attempts.push_back(attempt);
  const RetryDecision legal = evaluate_retry(phase, policy, 0);
  CRF_EXPECT(legal.legal);
  CRF_EXPECT(legal.creates_new_invocation);
  CRF_EXPECT(legal.next_attempt_generation > phase.attempt_generation);

  PhaseRecord unknown;
  unknown.state = PhaseState::failed;
  unknown.failure = FailureClass::unknown_outcome;
  const RetryDecision manual = evaluate_retry(unknown, policy, 0);
  CRF_EXPECT(!manual.legal);
  CRF_EXPECT(manual.kind == RetryDecisionKind::manual_resolution_required);

  PhaseRecord committed;
  committed.state = PhaseState::committed;
  const RetryDecision refused = evaluate_retry(committed, policy, 0);
  CRF_EXPECT(!refused.legal);
  CRF_EXPECT(refused.kind == RetryDecisionKind::already_committed);

  PhaseRecord fenced;
  fenced.state = PhaseState::fenced;
  const RetryDecision withdrawn = evaluate_retry(fenced, policy, 0);
  CRF_EXPECT(!withdrawn.legal);
  CRF_EXPECT(withdrawn.kind == RetryDecisionKind::authority_withdrawn);

  PhaseRecord exhausted;
  exhausted.state = PhaseState::failed;
  exhausted.failure = FailureClass::process_crash;
  for (int i = 0; i < 6; ++i) {
    PhaseAttempt entry;
    entry.id = AttemptId::from_value(static_cast<std::uint64_t>(i + 1));
    exhausted.attempts.push_back(entry);
  }
  const RetryDecision capped = evaluate_retry(exhausted, policy, 0);
  CRF_EXPECT(!capped.legal);
  CRF_EXPECT(capped.kind == RetryDecisionKind::exhausted);

  CRF_PHASE("POLICY_OVERRIDE");
  PolicySpec strict;
  strict.retryable_classes = {FailureClass::transient_storage_failure};
  PhaseRecord crash;
  crash.state = PhaseState::failed;
  crash.failure = FailureClass::process_crash;
  const RetryDecision overridden = evaluate_retry(crash, strict, 0);
  CRF_EXPECT(!overridden.legal);
}

CRF_TEST(core_authority_comparison_orders_refusals) {
  CRF_PHASE("SETUP");
  PhaseAuthority bound;
  bound.session_generation = CompilerSessionGeneration::from_value(4);
  bound.compilation_generation = CompilationGeneration::from_value(2);
  bound.attempt_generation = AttemptGeneration::from_value(3);
  bound.phase_generation = CompilerPhaseGeneration::from_value(5);
  bound.toolchain = Ref<ToolchainId>{ToolchainId::from_value(1), ToolchainGeneration::from_value(7)};
  bound.target = Ref<TargetId>{TargetId::from_value(2), TargetGeneration::from_value(1)};
  bound.environment = Ref<EnvironmentId>{EnvironmentId::from_value(3), EnvironmentGeneration::from_value(2)};
  bound.policy = Ref<PolicyId>{PolicyId::from_value(4), PolicyGeneration::from_value(1)};
  bound.source = Ref<SourceId>{SourceId::from_value(5), SourceGeneration::from_value(1)};

  AuthorityObservation current;
  current.session_generation = bound.session_generation;
  current.compilation_generation = bound.compilation_generation;
  current.attempt_generation = bound.attempt_generation;
  current.phase_generation = bound.phase_generation;
  current.toolchain = bound.toolchain;
  current.target = bound.target;
  current.environment = bound.environment;
  current.policy = bound.policy;
  current.source = bound.source;
  CRF_EXPECT(compare_authority(bound, current) == AuthorityVerdict::valid);

  CRF_PHASE("STALE_TOOLCHAIN");
  AuthorityObservation moved_toolchain = current;
  moved_toolchain.toolchain.generation = ToolchainGeneration::from_value(8);
  CRF_EXPECT(compare_authority(bound, moved_toolchain) == AuthorityVerdict::stale_toolchain);
  CRF_EXPECT_EQ(to_status_code(AuthorityVerdict::stale_toolchain),
                StatusCode::stale_toolchain_generation);

  CRF_PHASE("STALE_ENVIRONMENT");
  AuthorityObservation moved_environment = current;
  moved_environment.environment.generation = EnvironmentGeneration::from_value(9);
  CRF_EXPECT(compare_authority(bound, moved_environment) == AuthorityVerdict::stale_environment);

  CRF_PHASE("STALE_PHASE");
  AuthorityObservation moved_phase = current;
  moved_phase.phase_generation = CompilerPhaseGeneration::from_value(6);
  CRF_EXPECT(compare_authority(bound, moved_phase) == AuthorityVerdict::stale_phase);

  CRF_PHASE("RETIRED");
  AuthorityObservation retired = current;
  retired.toolchain_current = false;
  CRF_EXPECT(compare_authority(bound, retired) == AuthorityVerdict::toolchain_retired);

  CRF_PHASE("LEASE");
  AuthorityObservation lease_lost = current;
  lease_lost.lease_held = false;
  PhaseAuthority with_lease = bound;
  with_lease.lease = Ref<LeaseId>{LeaseId::from_value(11), LeaseGeneration::from_value(1)};
  CRF_EXPECT(compare_authority(with_lease, lease_lost) == AuthorityVerdict::stale_lease);

  CRF_PHASE("LEASE_TABLE");
  LeaseTable leases;
  const Result<Ref<LeaseId>> granted =
      leases.grant(Ref<CompilerSessionId>{CompilerSessionId::from_value(1), CompilerSessionGeneration{}},
                   Ref<CompilerPhaseId>{CompilerPhaseId::from_value(2), CompilerPhaseGeneration{}}, 0,
                   "test");
  CRF_REQUIRE_OK(granted);
  CRF_EXPECT(leases.is_held(granted.value()));
  CRF_REQUIRE_OK(leases.revoke(granted.value().id, "revoked by test"));
  CRF_EXPECT(!leases.is_held(granted.value()));
}

CRF_TEST(core_persistence_roundtrip_and_integrity) {
  CRF_PHASE("SETUP");
  const std::filesystem::path directory = crftest::test_root() / "persistence-unit";
  std::error_code ec;
  std::filesystem::remove_all(directory, ec);
  crftest::ScopedTree cleanup(directory);

  CRF_PHASE("APPEND");
  PersistenceOptions options;
  options.directory = directory;
  options.name = "test";
  std::uint64_t first_sequence = 0;
  std::uint64_t second_sequence = 0;
  {
    const Result<std::unique_ptr<PersistenceStore>> store = PersistenceStore::open(options);
    CRF_REQUIRE_OK(store);
    const Result<std::uint64_t> first = store.value()->append(RecordKind::session_created, "one");
    CRF_REQUIRE_OK(first);
    const Result<std::uint64_t> second = store.value()->append(RecordKind::phase_committed, "two");
    CRF_REQUIRE_OK(second);
    CRF_EXPECT(second.value() > first.value());
    CRF_REQUIRE_OK(store.value()->record_epoch(42));
    first_sequence = first.value();
    second_sequence = second.value();
  }
  CRF_PHASE("LOAD");
  {
  const Result<std::unique_ptr<PersistenceStore>> store = PersistenceStore::open(options);
  CRF_REQUIRE_OK(store);
  const Result<DurableState> state = store.value()->load();
  CRF_REQUIRE_OK(state);
  CRF_EXPECT(state.value().trustworthy());
  CRF_EXPECT_EQ(state.value().records.size(), static_cast<std::size_t>(3));
  CRF_EXPECT_EQ(state.value().runtime_epoch, static_cast<std::uint64_t>(42));
  CRF_EXPECT_EQ(state.value().records.front().payload, std::string("one"));
  CRF_EXPECT_EQ(first_sequence, static_cast<std::uint64_t>(1));

  CRF_PHASE("SNAPSHOT");
  StateSnapshot snapshot;
  snapshot.runtime_epoch = 42;
  snapshot.last_sequence = second_sequence;
  snapshot.encoded_sessions.push_back("payload");
  const std::string encoded = snapshot.encode();
  const Result<StateSnapshot> decoded = StateSnapshot::decode(encoded);
  CRF_REQUIRE_OK(decoded);
  CRF_EXPECT_EQ(decoded.value().encoded_sessions.size(), static_cast<std::size_t>(1));
  CRF_EXPECT_EQ(decoded.value().encoded_sessions.front(), std::string("payload"));
  CRF_REQUIRE_OK(store.value()->write_snapshot(encoded, second_sequence));
  const Result<std::optional<std::string>> read_back = store.value()->read_snapshot();
  CRF_REQUIRE_OK(read_back);
  CRF_EXPECT(read_back.value().has_value());
  CRF_EXPECT_EQ(read_back.value().value(), encoded);
  }

  CRF_PHASE("TRUNCATION");
  {
    const std::filesystem::path journal = directory / "test.crfjournal";
    const std::uintmax_t size = std::filesystem::file_size(journal, ec);
    CRF_REQUIRE(!ec);
    std::filesystem::resize_file(journal, size - 3, ec);
    CRF_REQUIRE(!ec);
  }
  // Opening the journal tolerates the torn tail and repairs it in place.
  {
    const Result<std::unique_ptr<PersistenceStore>> reopened = PersistenceStore::open(options);
    CRF_REQUIRE_OK(reopened);
    const Result<DurableState> repaired = reopened.value()->load();
    CRF_REQUIRE_OK(repaired);
    CRF_EXPECT(repaired.value().trustworthy());
    CRF_EXPECT(repaired.value().records.size() >= 2);
  }

  CRF_PHASE("CORRUPTION");
  {
    // A record damaged in the middle of the journal must not be partially
    // trusted: the store refuses it outright.
    const std::filesystem::path journal = directory / "test.crfjournal";
    std::fstream stream(journal, std::ios::binary | std::ios::in | std::ios::out);
    CRF_REQUIRE(static_cast<bool>(stream));
    const std::string original = crftest::read_text(journal);
    CRF_REQUIRE(original.size() > 100);
    stream.seekp(static_cast<std::streamoff>(kJournalProbeOffset));
    const char marker[] = "\xEE\xEE";
    stream.write(marker, 2);
    stream.close();
    // A journal damaged in the middle must be refused outright: no partially
    // trusted load is permitted.
    const Result<std::unique_ptr<PersistenceStore>> damaged = PersistenceStore::open(options);
    CRF_EXPECT(!damaged.has_value());
    if (!damaged.has_value()) {
      CRF_EXPECT_EQ(damaged.code(), StatusCode::persistence_corrupt);
    }
  }

  CRF_PHASE("SCHEMA");
  const Result<StateSnapshot> bad_schema =
      StateSnapshot::decode(std::string("\x09\x00\x00\x00\x00\x00\x00\x00", 8));
  CRF_EXPECT(!bad_schema.has_value());

  CRF_PHASE("RESET");
  {
    // An operator removes damaged durable state on purpose, then the store
    // starts from a clean schema-versioned journal.
    std::filesystem::remove(directory / "test.crfjournal", ec);
    std::filesystem::remove(directory / "test.crfsnapshot", ec);
    const Result<std::unique_ptr<PersistenceStore>> fresh = PersistenceStore::open(options);
    CRF_REQUIRE_OK(fresh);
    const Result<DurableState> cleared = fresh.value()->load();
    CRF_REQUIRE_OK(cleared);
    CRF_EXPECT_EQ(cleared.value().records.size(), static_cast<std::size_t>(0));
    CRF_EXPECT(cleared.value().trustworthy());
    CRF_EXPECT_OK(fresh.value()->reset());
  }
}

CRF_TEST(core_deterministic_rng_is_reproducible) {
  CRF_PHASE("SEEDED");
  DeterministicRng first(0xDEADBEEF);
  DeterministicRng second(0xDEADBEEF);
  for (int i = 0; i < 64; ++i) {
    CRF_EXPECT_EQ(first.next_u64(), second.next_u64());
  }
  DeterministicRng different(0x1234);
  CRF_EXPECT(different.next_u64() != first.next_u64());
  DeterministicRng bounded(7);
  for (int i = 0; i < 32; ++i) {
    CRF_EXPECT(bounded.next_below(10) < 10);
  }
}
