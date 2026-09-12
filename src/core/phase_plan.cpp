#include "crf/phase_plan.hpp"
#include "crf/canonical.hpp"

#include <algorithm>
#include <deque>
#include <unordered_set>

namespace crf {

std::string_view to_string(PlanDefect value) noexcept {
  switch (value) {
    case PlanDefect::none: return "none";
    case PlanDefect::empty_plan: return "empty-plan";
    case PlanDefect::duplicate_phase_id: return "duplicate-phase-id";
    case PlanDefect::missing_dependency: return "missing-dependency";
    case PlanDefect::cycle: return "cycle";
    case PlanDefect::self_dependency: return "self-dependency";
    case PlanDefect::phase_consumes_future_output: return "phase-consumes-future-output";
    case PlanDefect::mandatory_sink_missing: return "mandatory-sink-missing";
    case PlanDefect::fan_in_arity_invalid: return "fan-in-arity-invalid";
    case PlanDefect::too_many_phases: return "too-many-phases";
    case PlanDefect::orphan_phase: return "orphan-phase";
  }
  return "unknown";
}

Digest PhaseNode::canonical_digest() const {
  CanonicalWriter writer;
  writer.text(id.to_string());
  writer.text(to_string(kind));
  writer.text(adapter_phase);
  writer.boolean(mandatory);
  writer.boolean(fan_in);
  writer.u64(required_inputs);
  std::vector<std::string> deps;
  deps.reserve(depends_on.size());
  for (CompilerPhaseId dependency : depends_on) deps.push_back(dependency.to_string());
  std::sort(deps.begin(), deps.end());
  for (const std::string& dep : deps) writer.text(dep);
  std::vector<std::string> formats;
  formats.reserve(expected_outputs.size());
  for (ObjectFormat format : expected_outputs) formats.emplace_back(to_string(format));
  std::sort(formats.begin(), formats.end());
  for (const std::string& format : formats) writer.text(format);
  return Digest::of(writer.bytes());
}

Result<PhasePlan> PhasePlan::build(std::vector<PhaseNode> nodes) {
  if (nodes.empty()) {
    return Status(StatusCode::invalid_argument, "phase plan is empty");
  }
  if (nodes.size() > kMaxPhases) {
    return Status(StatusCode::capacity_exceeded, "phase plan exceeds the phase ceiling");
  }

  PhasePlan plan;
  plan.nodes_ = std::move(nodes);
  plan.dependents_.resize(plan.nodes_.size());
  plan.index_.reserve(plan.nodes_.size());

  // Duplicate identity check plus index construction.
  for (std::size_t i = 0; i < plan.nodes_.size(); ++i) {
    const CompilerPhaseId id = plan.nodes_[i].id;
    if (!id.present()) {
      return Status(StatusCode::invalid_identity, "phase plan contains an absent phase identity");
    }
    const auto inserted = plan.index_.emplace(id.value(), i);
    if (!inserted.second) {
      return Status(StatusCode::already_exists,
                    "duplicate phase identity in phase plan: " + id.to_string());
    }
  }

  // Dependency existence and self-dependency checks.
  for (std::size_t i = 0; i < plan.nodes_.size(); ++i) {
    for (const CompilerPhaseId dependency : plan.nodes_[i].depends_on) {
      if (dependency == plan.nodes_[i].id) {
        return Status(StatusCode::invalid_argument,
                      "phase depends on itself: " + dependency.to_string());
      }
      const auto found = plan.index_.find(dependency.value());
      if (found == plan.index_.end()) {
        return Status(StatusCode::not_found,
                      "phase dependency is not part of the plan: " + dependency.to_string());
      }
      plan.dependents_[found->second].push_back(plan.nodes_[i].id);
    }
  }

  // Fan-in arity: a fan-in node must require at least one input and must declare
  // at least that many dependencies.
  for (const PhaseNode& node : plan.nodes_) {
    if (!node.fan_in) continue;
    if (node.required_inputs == 0 || node.required_inputs > node.depends_on.size()) {
      return Status(StatusCode::invalid_argument,
                    "fan-in phase declares an impossible input arity: " + node.id.to_string());
    }
  }

  // Deterministic Kahn topological sort. Ready nodes are released in ascending
  // declaration index so the order never depends on container iteration.
  std::vector<std::size_t> indegree(plan.nodes_.size(), 0);
  for (std::size_t i = 0; i < plan.nodes_.size(); ++i) {
    indegree[i] = plan.nodes_[i].depends_on.size();
  }
  std::deque<std::size_t> ready;
  for (std::size_t i = 0; i < plan.nodes_.size(); ++i) {
    if (indegree[i] == 0) ready.push_back(i);
  }
  while (!ready.empty()) {
    const std::size_t current = ready.front();
    ready.pop_front();
    plan.order_.push_back(plan.nodes_[current].id);
    std::vector<std::size_t> released;
    for (const CompilerPhaseId dependent : plan.dependents_[current]) {
      const std::size_t index = plan.index_.at(dependent.value());
      if (--indegree[index] == 0) released.push_back(index);
    }
    std::sort(released.begin(), released.end());
    for (const std::size_t index : released) ready.push_back(index);
  }
  if (plan.order_.size() != plan.nodes_.size()) {
    return Status(StatusCode::invalid_argument, "phase plan contains a dependency cycle");
  }

  // A plan whose sink is not mandatory could complete without producing the
  // final artifact the caller asked for.
  std::vector<bool> has_dependent(plan.nodes_.size(), false);
  for (std::size_t i = 0; i < plan.nodes_.size(); ++i) {
    if (!plan.dependents_[i].empty()) has_dependent[i] = true;
  }
  bool any_sink_mandatory = false;
  for (std::size_t i = 0; i < plan.nodes_.size(); ++i) {
    if (!has_dependent[i] && plan.nodes_[i].mandatory) any_sink_mandatory = true;
  }
  if (!any_sink_mandatory) {
    return Status(StatusCode::invalid_argument,
                  "phase plan has no mandatory sink phase to produce the final artifact");
  }

  // Orphan detection: every node must reach at least one mandatory sink.
  {
    const CompilerPhaseId primary = plan.order_.back();
    std::unordered_set<std::uint64_t> reaches_primary;
    for (auto it = plan.order_.rbegin(); it != plan.order_.rend(); ++it) {
      bool reaches = (*it == primary);
      for (const CompilerPhaseId dependent : plan.dependents_[plan.index_.at(it->value())]) {
        if (reaches_primary.count(dependent.value()) != 0) reaches = true;
      }
      if (reaches) reaches_primary.insert(it->value());
    }
    for (const PhaseNode& node : plan.nodes_) {
      if (reaches_primary.count(node.id.value()) == 0) {
        return Status(StatusCode::invalid_argument,
                      "phase contributes to no final artifact: " + node.id.to_string());
      }
    }
  }

  return plan;
}

const PhaseNode* PhasePlan::find(CompilerPhaseId id) const noexcept {
  const auto found = index_.find(id.value());
  if (found == index_.end()) return nullptr;
  return &nodes_[found->second];
}

const PhaseNode* PhasePlan::find_by_kind(PhaseKind kind) const noexcept {
  for (const PhaseNode& node : nodes_) {
    if (node.kind == kind) return &node;
  }
  return nullptr;
}

std::vector<CompilerPhaseId> PhasePlan::roots() const {
  std::vector<CompilerPhaseId> out;
  for (const PhaseNode& node : nodes_) {
    if (node.depends_on.empty()) out.push_back(node.id);
  }
  return out;
}

std::vector<CompilerPhaseId> PhasePlan::dependents(CompilerPhaseId id) const {
  const auto found = index_.find(id.value());
  if (found == index_.end()) return {};
  std::vector<CompilerPhaseId> out = dependents_[found->second];
  std::sort(out.begin(), out.end());
  return out;
}

const std::vector<CompilerPhaseId>& PhasePlan::dependencies(CompilerPhaseId id) const {
  static const std::vector<CompilerPhaseId> kEmpty;
  const PhaseNode* node = find(id);
  return node != nullptr ? node->depends_on : kEmpty;
}

std::vector<CompilerPhaseId> PhasePlan::transitive_dependencies(CompilerPhaseId id) const {
  std::vector<CompilerPhaseId> out;
  std::unordered_set<std::uint64_t> visited;
  std::deque<CompilerPhaseId> pending;
  for (const CompilerPhaseId dependency : dependencies(id)) pending.push_back(dependency);
  while (!pending.empty()) {
    const CompilerPhaseId current = pending.front();
    pending.pop_front();
    if (!visited.insert(current.value()).second) continue;
    out.push_back(current);
    for (const CompilerPhaseId dependency : dependencies(current)) pending.push_back(dependency);
  }
  std::sort(out.begin(), out.end());
  return out;
}

std::vector<CompilerPhaseId> PhasePlan::mandatory_ancestors(CompilerPhaseId id) const {
  std::vector<CompilerPhaseId> out;
  for (const CompilerPhaseId candidate : transitive_dependencies(id)) {
    const PhaseNode* node = find(candidate);
    if (node != nullptr && node->mandatory) out.push_back(candidate);
  }
  return out;
}

bool PhasePlan::is_ready(CompilerPhaseId id, const std::vector<CompilerPhaseId>& committed) const {
  const PhaseNode* node = find(id);
  if (node == nullptr) return false;
  for (const CompilerPhaseId dependency : node->depends_on) {
    if (std::find(committed.begin(), committed.end(), dependency) == committed.end()) return false;
  }
  return true;
}

Digest PhasePlan::canonical_digest() const {
  CanonicalWriter writer;
  writer.u64(nodes_.size());
  for (const PhaseNode& node : nodes_) writer.text(node.canonical_digest().to_hex());
  return Digest::of(writer.bytes());
}

std::string PhasePlan::describe() const {
  std::string out;
  for (const CompilerPhaseId id : order_) {
    const PhaseNode* node = find(id);
    if (node == nullptr) continue;
    out.append(id.to_string());
    out.append(" ");
    out.append(to_string(node->kind));
    if (!node->adapter_phase.empty()) {
      out.append(" [");
      out.append(node->adapter_phase);
      out.append("]");
    }
    if (!node->mandatory) out.append(" (optional)");
    if (node->fan_in) {
      out.append(" (fan-in>=");
      out.append(std::to_string(node->required_inputs));
      out.append(")");
    }
    if (!node->depends_on.empty()) {
      out.append(" <- ");
      bool first = true;
      for (const CompilerPhaseId dependency : node->depends_on) {
        if (!first) out.append(",");
        first = false;
        out.append(dependency.to_string());
      }
    }
    out.append("\n");
  }
  return out;
}

}  // namespace crf
