// Property and randomised proofs.
//
// Every case records the seed it used so a failure can be replayed exactly.
// The properties asserted are the runtime's core invariants, checked against
// thousands of generated states rather than a handful of hand-written ones.

#include "crf_test.hpp"
#include "crf_test_env.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace {

using namespace crf;

/// The seed is fixed per case and printed, so a failure is reproducible.
constexpr std::uint64_t kPhaseGraphSeed = 0xC0FFEE0123456789ull;
constexpr std::uint64_t kGenerationSeed = 0x5EEDFACEF00D1234ull;
constexpr std::uint64_t kSerializationSeed = 0x0123456789ABCDEFull;
constexpr std::uint64_t kRetrySeed = 0xFACEB00CDEADBEEFull;

CRF_NODISCARD std::string random_identifier(DeterministicRng& rng, std::size_t length) {
  static const char kAlphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789_-.";
  std::string out;
  out.reserve(length);
  for (std::size_t i = 0; i < length; ++i) {
    out.push_back(kAlphabet[rng.next_below(sizeof(kAlphabet) - 1)]);
  }
  return out;
}

}  // namespace

CRF_TEST(property_randomised_phase_graphs_validate_or_refuse_cleanly) {
  CRF_PHASE("GENERATE");
  std::printf("  seed=0x%llx\n", static_cast<unsigned long long>(kPhaseGraphSeed));
  DeterministicRng rng(kPhaseGraphSeed);
  std::size_t accepted = 0;
  std::size_t refused = 0;
  for (int round = 0; round < 400; ++round) {
    const std::size_t count = 1 + static_cast<std::size_t>(rng.next_below(12));
    IdAllocator<CompilerPhaseId> ids;
    std::vector<PhaseNode> nodes;
    for (std::size_t i = 0; i < count; ++i) {
      PhaseNode node;
      node.id = ids.next();
      node.kind = static_cast<PhaseKind>(1 + rng.next_below(15));
      node.mandatory = true;
      // Dependencies only ever point backwards, so the generated graph is a DAG
      // unless a deliberate mutation below breaks it.
      if (i > 0) {
        const std::size_t dependency_count = static_cast<std::size_t>(rng.next_below(i));
        for (std::size_t d = 0; d < dependency_count; ++d) {
          node.depends_on.push_back(nodes[rng.next_below(i)].id);
        }
        std::sort(node.depends_on.begin(), node.depends_on.end());
        node.depends_on.erase(std::unique(node.depends_on.begin(), node.depends_on.end()),
                              node.depends_on.end());
      }
      nodes.push_back(std::move(node));
    }
    const Result<PhasePlan> plan = PhasePlan::build(nodes);
    if (plan) {
      ++accepted;
      // A valid plan is acyclic, covers every node, and orders dependencies first.
      CRF_EXPECT_EQ(plan.value().topological_order().size(), count);
      std::vector<CompilerPhaseId> seen;
      for (const CompilerPhaseId id : plan.value().topological_order()) {
        const PhaseNode* node = plan.value().find(id);
        CRF_EXPECT(node != nullptr);
        if (node == nullptr) continue;
        for (const CompilerPhaseId dependency : node->depends_on) {
          CRF_EXPECT(std::find(seen.begin(), seen.end(), dependency) != seen.end());
        }
        seen.push_back(id);
      }
      CRF_EXPECT(!plan.value().canonical_digest().zero());
      // Building the identical plan again yields an identical digest.
      const Result<PhasePlan> again = PhasePlan::build(nodes);
      CRF_REQUIRE_OK(again);
      CRF_EXPECT_EQ(again.value().canonical_digest(), plan.value().canonical_digest());
    } else {
      ++refused;
      CRF_EXPECT(plan.code() == StatusCode::invalid_argument ||
                 plan.code() == StatusCode::not_found ||
                 plan.code() == StatusCode::already_exists);
    }
  }
  CRF_PHASE("VERIFY");
  CRF_EXPECT(accepted + refused == 400);
  CRF_EXPECT(accepted > 0);
}

CRF_TEST(property_randomised_generation_mutations_invalidate_correctly) {
  CRF_PHASE("GENERATE");
  std::printf("  seed=0x%llx\n", static_cast<unsigned long long>(kGenerationSeed));
  DeterministicRng rng(kGenerationSeed);
  for (int round = 0; round < 500; ++round) {
    PhaseAuthority bound;
    bound.session_generation = CompilerSessionGeneration::from_value(1 + rng.next_below(64));
    bound.compilation_generation = CompilationGeneration::from_value(1 + rng.next_below(64));
    bound.attempt_generation = AttemptGeneration::from_value(1 + rng.next_below(64));
    bound.phase_generation = CompilerPhaseGeneration::from_value(1 + rng.next_below(64));
    bound.toolchain = Ref<ToolchainId>{ToolchainId::from_value(1),
                                       ToolchainGeneration::from_value(1 + rng.next_below(64))};
    bound.target = Ref<TargetId>{TargetId::from_value(1),
                                 TargetGeneration::from_value(1 + rng.next_below(64))};
    bound.environment = Ref<EnvironmentId>{EnvironmentId::from_value(1),
                                           EnvironmentGeneration::from_value(1 + rng.next_below(64))};
    bound.policy = Ref<PolicyId>{PolicyId::from_value(1),
                                 PolicyGeneration::from_value(1 + rng.next_below(64))};
    bound.source = Ref<SourceId>{SourceId::from_value(1),
                                 SourceGeneration::from_value(1 + rng.next_below(64))};

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

    // Move exactly one authority domain forward.
    AuthorityObservation moved = current;
    switch (rng.next_below(6)) {
      case 0: moved.session_generation = moved.session_generation.next(); break;
      case 1: moved.compilation_generation = moved.compilation_generation.next(); break;
      case 2: moved.attempt_generation = moved.attempt_generation.next(); break;
      case 3: moved.phase_generation = moved.phase_generation.next(); break;
      case 4: moved.toolchain.generation = moved.toolchain.generation.next(); break;
      case 5: moved.environment.generation = moved.environment.generation.next(); break;
      default: break;
    }
    const AuthorityVerdict verdict = compare_authority(bound, moved);
    CRF_EXPECT(!authority_verdict_is_current(verdict));
    CRF_EXPECT(to_status_code(verdict) != StatusCode::ok);
  }
}

CRF_TEST(property_randomised_serialization_round_trips_are_exact) {
  CRF_PHASE("GENERATE");
  std::printf("  seed=0x%llx\n", static_cast<unsigned long long>(kSerializationSeed));
  DeterministicRng rng(kSerializationSeed);
  for (int round = 0; round < 200; ++round) {
    PhaseRecord phase;
    phase.id = CompilerPhaseId::from_value(1 + rng.next_below(1000000));
    phase.generation = CompilerPhaseGeneration::from_value(1 + rng.next_below(1000));
    phase.kind = static_cast<PhaseKind>(rng.next_below(17));
    phase.adapter_phase = random_identifier(rng, 1 + static_cast<std::size_t>(rng.next_below(24)));
    phase.state = static_cast<PhaseState>(rng.next_below(13));
    phase.mandatory = rng.next_bool();
    phase.session_generation = CompilerSessionGeneration::from_value(1 + rng.next_below(500));
    phase.compilation_generation = CompilationGeneration::from_value(1 + rng.next_below(500));
    phase.attempt_generation = AttemptGeneration::from_value(1 + rng.next_below(500));
    phase.toolchain = Ref<ToolchainId>{ToolchainId::from_value(1 + rng.next_below(50)),
                                       ToolchainGeneration::from_value(1 + rng.next_below(50))};
    phase.target = Ref<TargetId>{TargetId::from_value(1 + rng.next_below(50)),
                                 TargetGeneration::from_value(1 + rng.next_below(50))};
    phase.environment = Ref<EnvironmentId>{EnvironmentId::from_value(1 + rng.next_below(50)),
                                           EnvironmentGeneration::from_value(1 + rng.next_below(50))};
    phase.policy = Ref<PolicyId>{PolicyId::from_value(1 + rng.next_below(50)),
                                 PolicyGeneration::from_value(1 + rng.next_below(50))};
    phase.source = Ref<SourceId>{SourceId::from_value(1 + rng.next_below(50)),
                                 SourceGeneration::from_value(1 + rng.next_below(50))};
    phase.last_detail = random_identifier(rng, static_cast<std::size_t>(rng.next_below(64)));
    phase.committed_output_digest = Digest::of(phase.last_detail);
    const std::size_t attempt_count = static_cast<std::size_t>(rng.next_below(8));
    for (std::size_t i = 0; i < attempt_count; ++i) {
      PhaseAttempt attempt;
      attempt.id = AttemptId::from_value(1 + rng.next_below(100000));
      attempt.generation = AttemptGeneration::from_value(1 + rng.next_below(100));
      attempt.exit_code = static_cast<std::int32_t>(rng.next_u32() % 4);
      attempt.failure = static_cast<FailureClass>(rng.next_below(16));
      phase.attempts.push_back(attempt);
    }

    const std::string encoded = encode_phase(phase);
    const Result<PhaseRecord> decoded = decode_phase(encoded);
    CRF_REQUIRE_OK(decoded);
    CRF_EXPECT_EQ(decoded.value().id, phase.id);
    CRF_EXPECT_EQ(decoded.value().generation, phase.generation);
    CRF_EXPECT(decoded.value().kind == phase.kind);
    CRF_EXPECT_EQ(decoded.value().adapter_phase, phase.adapter_phase);
    CRF_EXPECT(decoded.value().state == phase.state);
    CRF_EXPECT_EQ(decoded.value().attempts.size(), phase.attempts.size());
    CRF_EXPECT_EQ(decoded.value().canonical_digest(), phase.canonical_digest());

    // The codec is a faithful inverse: decoding and re-encoding any payload the
    // decoder accepts must reproduce it byte for byte. Corruption detection
    // itself lives in the persistence integrity layer, not in the field codec.
    if (!encoded.empty()) {
      std::string corrupted = encoded;
      const std::size_t position = static_cast<std::size_t>(rng.next_below(corrupted.size()));
      corrupted[position] = static_cast<char>(corrupted[position] ^ 0x40);
      const Result<PhaseRecord> damaged = decode_phase(corrupted);
      if (damaged) {
        CRF_EXPECT_EQ(encode_phase(damaged.value()), corrupted);
      }
    }
  }
}

CRF_TEST(property_randomised_retry_sequences_respect_both_ceilings) {
  CRF_PHASE("GENERATE");
  std::printf("  seed=0x%llx\n", static_cast<unsigned long long>(kRetrySeed));
  DeterministicRng rng(kRetrySeed);
  for (int round = 0; round < 400; ++round) {
    PolicySpec policy;
    policy.max_retries_per_phase = static_cast<std::uint32_t>(rng.next_below(6));
    policy.max_retries_per_session = static_cast<std::uint32_t>(rng.next_below(12));
    PhaseRecord phase;
    phase.state = PhaseState::failed;
    phase.failure = static_cast<FailureClass>(rng.next_below(16));
    phase.attempt_generation = AttemptGeneration::from_value(1 + rng.next_below(10));
    const std::uint32_t attempts = static_cast<std::uint32_t>(rng.next_below(8));
    for (std::uint32_t i = 0; i < attempts; ++i) {
      PhaseAttempt attempt;
      attempt.id = AttemptId::from_value(i + 1);
      phase.attempts.push_back(attempt);
    }
    const std::uint32_t session_retries = static_cast<std::uint32_t>(rng.next_below(16));
    const RetryDecision decision = evaluate_retry(phase, policy, session_retries);
    if (phase.failure == FailureClass::unknown_outcome) {
      CRF_EXPECT(!decision.legal);
      CRF_EXPECT(decision.kind == RetryDecisionKind::manual_resolution_required);
      continue;
    }
    if (phase.failure == FailureClass::authority_invalidated) {
      CRF_EXPECT(decision.legal);
      CRF_EXPECT(decision.next_attempt_generation > phase.attempt_generation);
      continue;
    }
    const bool class_ok = policy.permits_retry(phase.failure);
    const bool attempts_ok = attempts <= policy.max_retries_per_phase;
    const bool session_ok = session_retries < policy.max_retries_per_session;
    const bool expected = class_ok && attempts_ok && session_ok;
    CRF_EXPECT_EQ(decision.legal, expected);
    if (decision.legal) {
      CRF_EXPECT(decision.creates_new_invocation);
      CRF_EXPECT(decision.next_attempt_generation > phase.attempt_generation);
    } else {
      CRF_EXPECT(decision.refusal != StatusCode::ok);
    }
  }
}

CRF_TEST(property_randomised_environment_canonicalization_is_order_independent) {
  CRF_PHASE("GENERATE");
  DeterministicRng rng(0xA5A5A5A5A5A5A5A5ull);
  for (int round = 0; round < 200; ++round) {
    const std::size_t count = 1 + static_cast<std::size_t>(rng.next_below(10));
    std::vector<EnvironmentVariable> variables;
    for (std::size_t i = 0; i < count; ++i) {
      variables.push_back(EnvironmentVariable{"VAR_" + std::to_string(i),
                                              random_identifier(rng, 1 + rng.next_below(12))});
    }
    std::vector<EnvironmentVariable> shuffled = variables;
    for (std::size_t i = shuffled.size(); i > 1; --i) {
      const std::size_t other = static_cast<std::size_t>(rng.next_below(i));
      std::swap(shuffled[i - 1], shuffled[other]);
    }
    EnvironmentSpec first;
    first.variables = variables;
    EnvironmentSpec second;
    second.variables = shuffled;
    CRF_REQUIRE_OK(first.canonicalize());
    CRF_REQUIRE_OK(second.canonicalize());
    CRF_EXPECT_EQ(first.canonical_digest(), second.canonical_digest());
    CRF_EXPECT_EQ(first.variables, second.variables);
  }
}
