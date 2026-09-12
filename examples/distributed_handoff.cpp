// Example: the Distributed Compilation integration fixture.
//
// This shows the public boundary a distributed coordinator submits through. The
// distributed layer owns placement, worker selection, and global artifact
// promotion; Compiler Runtime Fabric owns local execution and produces a
// candidate artifact with complete local provenance. The fixture does not
// require the other repository: it is a single stable API call sequence.

#include "crf_example.hpp"

#include "crf/explain.hpp"

#include <string>

using namespace crf;
using namespace crf::examples;

namespace {

/// What a distributed coordinator would send into the runtime.
struct DistributedAttempt {
  std::string request_identity;
  std::string compilation_identity;
  std::string attempt_identity;
  std::uint64_t compilation_generation = 1;
  std::uint64_t attempt_generation = 1;
  std::filesystem::path source;
  std::string expected_stdout;
};

/// What the runtime hands back. The candidate is a *candidate*: promoting it to
/// a globally authoritative artifact is the distributed layer's decision.
struct HandoffResult {
  bool accepted = false;
  CompilerSessionId session{};
  FinalCandidate candidate{};
  Digest lineage_digest{};
  std::vector<Ref<IntermediateArtifactId>> intermediates;
  std::string detail;
};

}  // namespace

int main() {
  banner("Distributed compilation handoff fixture");
  Scratch scratch("distributed-handoff");
  RuntimeOptions options = runtime_options(scratch, "distributed-handoff");
  Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  if (!runtime) {
    refusal("runtime creation", runtime.status());
    return 1;
  }
  Runtime& crf = *runtime.value();
  if (!crf.discover_toolchain(ToolchainFamily::msvc)) {
    line("no MSVC toolchain is installed");
    return 1;
  }

  DistributedAttempt attempt;
  attempt.request_identity = "dist-request-7f3a";
  attempt.compilation_identity = "compilation-42";
  attempt.attempt_identity = "attempt-3";
  attempt.compilation_generation = 5;
  attempt.attempt_generation = 2;
  attempt.source = scratch.write("handoff.cpp", hello_source("CRF-HANDOFF-OK"));
  attempt.expected_stdout = "CRF-HANDOFF-OK";

  line("distributed attempt identity:");
  line("  request      " + attempt.request_identity);
  line("  compilation  " + attempt.compilation_identity + "@" +
       std::to_string(attempt.compilation_generation));
  line("  attempt      " + attempt.attempt_identity + "@" +
       std::to_string(attempt.attempt_generation));

  // ---- the single stable API boundary --------------------------------------
  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {attempt.source};
  request.run_smoke_test = true;
  request.compilation_generation = CompilationGeneration::from_value(attempt.compilation_generation);
  request.attempt_generation = AttemptGeneration::from_value(attempt.attempt_generation);
  request.adapter_options.push_back(
      EnvironmentVariable{"msvc.expected_stdout", attempt.expected_stdout});

  HandoffResult result;
  Result<Ref<CompilerSessionId>> session = crf.create_session(request);
  if (!session) {
    refusal("session creation", session.status());
    return 1;
  }
  result.session = session.value().id;
  Result<CompileOutcome> outcome = crf.run_session(session.value().id);
  if (!outcome) {
    result.detail = outcome.status().to_string();
  } else {
    result.accepted = !outcome.value().candidate.path.empty();
    result.candidate = outcome.value().candidate;
    result.lineage_digest = outcome.value().lineage_digest;
    result.intermediates = outcome.value().intermediates;
    result.detail = outcome.value().detail;
  }

  line("");
  line("handoff result:");
  line("  accepted     " + std::string(result.accepted ? "yes" : "no"));
  line("  session      " + result.session.to_string());
  if (result.accepted) {
    line("  candidate    " + result.candidate.path.string());
    line("  sha256       " + result.candidate.content.to_hex());
    line("  size         " + std::to_string(result.candidate.size_bytes));
    line("  toolchain    " + result.candidate.toolchain.to_string());
    line("  target       " + result.candidate.target.to_string());
    line("  environment  " + result.candidate.environment.to_string());
    line("  policy       " + result.candidate.policy.to_string());
    line("  lineage      " + std::to_string(result.candidate.lineage.size()) + " artifact(s)");
    line("  lineage-sha  " + result.lineage_digest.to_hex());
    line("  provenance   " + result.candidate.provenance.to_string());
    line("  complete     " + std::string(result.candidate.complete_lineage ? "yes" : "no"));
  } else {
    line("  detail       " + result.detail);
  }
  line("");
  line("the runtime produced a candidate with local provenance. It did not claim");
  line("global artifact authority: promoting this candidate is the distributed");
  line("compilation layer's decision.");

  const VoidResult stopped = crf.shutdown();
  (void)stopped;
  return result.accepted ? 0 : 1;
}
