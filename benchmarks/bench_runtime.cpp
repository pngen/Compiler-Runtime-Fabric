// Benchmarks: runtime overhead, measured separately from compiler wall time.
//
// Nothing here reports a compiler launch as a runtime measurement. The compiler
// numbers are printed separately and labelled as such.

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include "crf/canonical.hpp"
#include "crf/runtime.hpp"
#include "crf/version.hpp"

namespace {

using namespace crf;

using Clock = std::chrono::steady_clock;

struct Measurement {
  std::string name;
  std::size_t records = 0;
  double total_micros = 0.0;
  double per_record_nanos = 0.0;
};

std::vector<Measurement> g_measurements;

template <class Operation>
void measure(const char* name, std::size_t records, std::size_t iterations, Operation operation) {
  const auto start = Clock::now();
  for (std::size_t i = 0; i < iterations; ++i) operation(i);
  const auto finish = Clock::now();
  const double micros =
      std::chrono::duration<double, std::micro>(finish - start).count();
  Measurement measurement;
  measurement.name = name;
  measurement.records = records;
  measurement.total_micros = micros;
  const double operations = static_cast<double>(iterations);
  measurement.per_record_nanos =
      records == 0 ? 0.0 : (micros * 1000.0) / (operations * static_cast<double>(records));
  g_measurements.push_back(measurement);
}

void report() {
  std::printf("\n%-38s %10s %14s %16s\n", "operation", "records", "total (us)", "ns per record");
  std::printf("%-38s %10s %14s %16s\n", "--------------------------------------", "----------",
              "--------------", "----------------");
  for (const Measurement& measurement : g_measurements) {
    std::printf("%-38s %10llu %14.1f %16.1f\n", measurement.name.c_str(),
                static_cast<unsigned long long>(measurement.records), measurement.total_micros,
                measurement.per_record_nanos);
  }
  std::fflush(stdout);
}

}  // namespace

int main() {
  std::printf("Compiler Runtime Fabric %s runtime-overhead benchmarks\n", version_string);
  std::printf("(all figures are runtime work only; no compiler process is measured here)\n");

  const std::vector<std::size_t> scales = {10, 100, 1000, 10000, 100000};

  for (const std::size_t scale : scales) {
    // Session creation and phase-plan validation.
    {
      std::vector<std::unique_ptr<Runtime>> runtimes;
      const std::size_t iterations = std::max<std::size_t>(1, 200000 / scale);
      measure("session creation (with toolchain probe)", scale, iterations, [&](std::size_t i) {
        RuntimeOptions options;
        options.state_directory =
            std::filesystem::temp_directory_path() / ("crf-bench-" + std::to_string(scale) + "-" +
                                                      std::to_string(i));
        options.workspace_root = options.state_directory / "work";
        options.enable_persistence = false;
        options.register_builtin_adapters = false;
        Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
        if (runtime) runtimes.push_back(std::move(runtime.value()));
      });
      runtimes.clear();
    }

    // Phase authority validation.
    {
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
      AuthorityObservation observation;
      observation.session_generation = bound.session_generation;
      observation.compilation_generation = bound.compilation_generation;
      observation.attempt_generation = bound.attempt_generation;
      observation.phase_generation = bound.phase_generation;
      observation.toolchain = bound.toolchain;
      observation.target = bound.target;
      observation.environment = bound.environment;
      observation.policy = bound.policy;
      observation.source = bound.source;
      measure("phase authority validation", scale, 200000, [&](std::size_t) {
        volatile int valid = compare_authority(bound, observation) == AuthorityVerdict::valid ? 1 : 0;
        (void)valid;
      });
    }

    // Intermediate registration and lineage lookup.
    {
      ArtifactRegistry registry;
      std::vector<Ref<IntermediateArtifactId>> registered;
      measure("intermediate registration", scale, 1, [&](std::size_t) {
        for (std::size_t i = 0; i < scale; ++i) {
          IntermediateArtifact artifact;
          artifact.format = ObjectFormat::coff_object;
          artifact.state = ArtifactState::valid;
          artifact.content = Digest::of(std::to_string(i));
          if (!registered.empty()) artifact.lineage_inputs = {registered.back()};
          Result<Ref<IntermediateArtifactId>> added = registry.register_artifact(std::move(artifact));
          if (added) registered.push_back(added.value());
        }
      });
      measure("lineage lookup (depth 1)", scale, 1, [&](std::size_t) {
        for (const Ref<IntermediateArtifactId>& reference : registered) {
          volatile const IntermediateArtifact* found = registry.find(reference.id);
          (void)found;
        }
      });
    }

    // Diagnostics ingestion.
    {
      std::string output;
      for (std::size_t i = 0; i < scale; ++i) {
        output += "bench.cpp(" + std::to_string(i) + ",3): warning C4101: 'x': unreferenced local "
                  "variable\n";
      }
      measure("diagnostics ingestion", scale, std::max<std::size_t>(1, 20000 / scale),
              [&](std::size_t) {
                const std::vector<Diagnostic> diagnostics = normalize_msvc_output(output, "cl");
                volatile std::size_t count = diagnostics.size();
                (void)count;
              });
    }

    // Persistence append and snapshot.
    {
      const std::filesystem::path directory =
          std::filesystem::temp_directory_path() / ("crf-bench-journal-" + std::to_string(scale));
      std::error_code ec;
      std::filesystem::remove_all(directory, ec);
      PersistenceOptions options;
      options.directory = directory;
      options.name = "bench";
      Result<std::unique_ptr<PersistenceStore>> store = PersistenceStore::open(options);
      if (store) {
        std::string payload(256, 'p');
        measure("persistence append (durable)", scale, std::max<std::size_t>(1, 2000 / std::min<std::size_t>(scale, 1000)),
                [&](std::size_t) {
                  for (std::size_t i = 0; i < std::min<std::size_t>(scale, 1000); ++i) {
                    const Result<std::uint64_t> sequence =
                        store.value()->append(RecordKind::phase_state_changed, payload);
                    (void)sequence;
                  }
                });
      }
      std::filesystem::remove_all(directory, ec);
    }

    // Invariant audit over a synthetic session population.
    {
      std::vector<CompilerSession> sessions;
      const std::size_t count = std::min<std::size_t>(scale, 2000);
      for (std::size_t i = 0; i < count; ++i) {
        CompilerSession session;
        session.id = CompilerSessionId::from_value(i + 1);
        session.state = SessionState::active;
        IdAllocator<CompilerPhaseId> ids;
        std::vector<PhaseNode> nodes;
        PhaseNode node;
        node.id = ids.next();
        node.kind = PhaseKind::codegen;
        node.mandatory = true;
        nodes.push_back(node);
        Result<PhasePlan> plan = PhasePlan::build(std::move(nodes));
        if (!plan) continue;
        session.plan = plan.value();
        PhaseRecord record;
        record.id = session.plan.nodes().front().id;
        record.state = PhaseState::pending;
        session.phases.emplace(record.id.value(), record);
        sessions.push_back(std::move(session));
      }
      AuditSubject subject;
      subject.sessions = &sessions;
      InvariantAuditor auditor;
      measure("invariant audit", sessions.size(), 1, [&](std::size_t) {
        volatile std::size_t violations = auditor.audit(subject).violations.size();
        (void)violations;
      });
    }
  }

  // Canonical hashing throughput, which underpins every identity computation.
  {
    const std::string payload(4096, 'h');
    measure("sha256 of 4 KiB payload", 1, 20000, [&](std::size_t) {
      volatile Digest digest = Digest::of(payload);
      (void)digest;
    });
  }

  report();
  std::printf("\ncompiler wall time is not measured here; see the examples and the\n");
  std::printf("MSVC proof suite for real compiler-process timings.\n");
  return 0;
}
