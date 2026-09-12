#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "crf/artifact.hpp"
#include "crf/authority.hpp"
#include "crf/retry.hpp"
#include "crf/runtime.hpp"
#include "crf/session.hpp"

namespace crf {

struct CRF_API ExplainOptions {
  bool include_evidence = true;
  bool include_history = true;
  bool verbose = false;
};

/// Deterministic explanation output. The same runtime state always renders the
/// same lines in the same order: no hash iteration, pointer values, or timing
/// influence the result.
struct CRF_API Explanation {
  std::string title;
  std::vector<std::string> lines;

  CRF_NODISCARD std::string render() const;
  void add(std::string line);
  CRF_NODISCARD bool empty() const noexcept { return lines.empty(); }
};

CRF_NODISCARD CRF_API Explanation explain_runtime(const Runtime& runtime,
                                                  const ExplainOptions& options = {});
CRF_NODISCARD CRF_API Explanation explain_session(const Runtime& runtime, CompilerSessionId session,
                                                  const ExplainOptions& options = {});
CRF_NODISCARD CRF_API Explanation explain_phase(const Runtime& runtime, CompilerSessionId session,
                                                CompilerPhaseId phase,
                                                const ExplainOptions& options = {});
CRF_NODISCARD CRF_API Explanation explain_authority(const Runtime& runtime, CompilerSessionId session,
                                                    CompilerPhaseId phase);
CRF_NODISCARD CRF_API Explanation explain_toolchain(const Runtime& runtime, ToolchainId toolchain,
                                                    const ExplainOptions& options = {});
CRF_NODISCARD CRF_API Explanation explain_component(const Runtime& runtime, ToolchainId toolchain,
                                                    CompilerComponentId component);
CRF_NODISCARD CRF_API Explanation explain_artifact(const Runtime& runtime,
                                                   IntermediateArtifactId artifact,
                                                   const ExplainOptions& options = {});
CRF_NODISCARD CRF_API Explanation explain_candidate(const Runtime& runtime, CompilerSessionId session);
CRF_NODISCARD CRF_API Explanation explain_diagnostics(const Runtime& runtime, DiagnosticSetId set,
                                                      const ExplainOptions& options = {});
CRF_NODISCARD CRF_API Explanation explain_retry(const Runtime& runtime, CompilerSessionId session,
                                                CompilerPhaseId phase);
CRF_NODISCARD CRF_API Explanation explain_recovery(const Runtime& runtime, CompilerSessionId session);
CRF_NODISCARD CRF_API Explanation explain_provenance(const Runtime& runtime,
                                                     IntermediateArtifactId artifact);
CRF_NODISCARD CRF_API Explanation explain_refusal(StatusCode code, std::string_view context);
CRF_NODISCARD CRF_API Explanation explain_plan(const PhasePlan& plan);

}  // namespace crf
