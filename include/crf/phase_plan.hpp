#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "crf/digest.hpp"
#include "crf/phase.hpp"
#include "crf/status.hpp"
#include "crf/target.hpp"

namespace crf {

/// One node of an adapter-declared phase plan.
struct CRF_API PhaseNode {
  CompilerPhaseId id{};
  PhaseKind kind = PhaseKind::unknown;
  std::string adapter_phase;
  std::vector<CompilerPhaseId> depends_on;
  bool mandatory = true;
  /// Formats this phase is expected to emit. Empty means the adapter declares
  /// no static expectation and validation is driven by the invocation's
  /// declared expected outputs instead.
  std::vector<ObjectFormat> expected_outputs;
  /// True when this phase consumes the outputs of several independent producer
  /// phases and must fan in before it may commit.
  bool fan_in = false;
  /// Minimum number of authoritative inputs required before fan-in may commit.
  std::size_t required_inputs = 0;

  CRF_NODISCARD Digest canonical_digest() const;
};

enum class PlanDefect : std::uint8_t {
  none = 0,
  empty_plan = 1,
  duplicate_phase_id = 2,
  missing_dependency = 3,
  cycle = 4,
  self_dependency = 5,
  phase_consumes_future_output = 6,
  mandatory_sink_missing = 7,
  fan_in_arity_invalid = 8,
  too_many_phases = 9,
  /// A declared phase contributes to no sink, so its output could never become
  /// authoritative.
  orphan_phase = 10,
};

CRF_NODISCARD CRF_API std::string_view to_string(PlanDefect value) noexcept;

/// A validated, immutable phase plan.
///
/// The plan is a DAG. Construction validates every structural property up
/// front, so phase reservation later never has to re-derive legality.
class CRF_API PhasePlan {
 public:
  static constexpr std::size_t kMaxPhases = 4096;

  static Result<PhasePlan> build(std::vector<PhaseNode> nodes);

  CRF_NODISCARD const std::vector<PhaseNode>& nodes() const noexcept { return nodes_; }
  CRF_NODISCARD std::size_t size() const noexcept { return nodes_.size(); }
  CRF_NODISCARD const PhaseNode* find(CompilerPhaseId id) const noexcept;
  CRF_NODISCARD const PhaseNode* find_by_kind(PhaseKind kind) const noexcept;

  /// Deterministic topological order. Ties are broken by the phase's position
  /// in the declared node list, never by container iteration order.
  CRF_NODISCARD const std::vector<CompilerPhaseId>& topological_order() const noexcept {
    return order_;
  }
  CRF_NODISCARD std::vector<CompilerPhaseId> roots() const;
  CRF_NODISCARD std::vector<CompilerPhaseId> dependents(CompilerPhaseId id) const;
  CRF_NODISCARD const std::vector<CompilerPhaseId>& dependencies(CompilerPhaseId id) const;
  /// Phases that must be authoritative before the given phase may commit.
  CRF_NODISCARD std::vector<CompilerPhaseId> transitive_dependencies(CompilerPhaseId id) const;
  CRF_NODISCARD std::vector<CompilerPhaseId> mandatory_ancestors(CompilerPhaseId id) const;
  CRF_NODISCARD bool is_ready(CompilerPhaseId id,
                              const std::vector<CompilerPhaseId>& committed) const;

  CRF_NODISCARD Digest canonical_digest() const;
  CRF_NODISCARD std::string describe() const;

 private:
  std::vector<PhaseNode> nodes_;
  std::unordered_map<std::uint64_t, std::size_t> index_;
  std::vector<std::vector<CompilerPhaseId>> dependents_;
  std::vector<CompilerPhaseId> order_;
};

}  // namespace crf
