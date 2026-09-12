// crf_cli - the Compiler Runtime Fabric command line interface.
//
// Every command explains what the runtime decided and why. Output is
// deterministic: identical state renders identical text.

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#include "crf/explain.hpp"
#include "crf/ipc.hpp"
#include "crf/version.hpp"
#include "ipc/service.hpp"

namespace {

using namespace crf;

struct Globals {
  std::filesystem::path state_directory;
  std::filesystem::path workspace_root;
  std::string coordinator;
  std::string runtime_name = "crf-cli";
  bool json = false;
};

/// Scratch directory for the demo command. It lives outside the repository so
/// that running the CLI never leaves files in the source tree.
CRF_NODISCARD std::filesystem::path cli_scratch_directory() {
  std::error_code ec;
  const std::filesystem::path path = std::filesystem::temp_directory_path(ec) / "crf-cli-demo";
  std::filesystem::create_directories(path, ec);
  return path;
}

int usage() {
  std::printf(
      "crf_cli " CRF_VERSION_STRING " - Compiler Runtime Fabric\n"
      "\n"
      "usage: crf_cli [global options] COMMAND [arguments]\n"
      "\n"
      "global options:\n"
      "  --state DIR             durable state directory (default ./crf-state)\n"
      "  --workspaces DIR        workspace root (default <state>/workspaces)\n"
      "  --coordinator HOST:PORT operate against a running crf_coordinator\n"
      "  --name NAME             runtime name\n"
      "\n"
      "commands:\n"
      "  toolchain list                          list registered toolchains\n"
      "  toolchain probe FAMILY                  discover a toolchain for real\n"
      "  toolchain show ID                       explain one toolchain\n"
      "  component show TOOLCHAIN_ID COMPONENT_ID explain one compiler component\n"
      "  session list                            list compiler sessions\n"
      "  session show ID                         explain one session\n"
      "  session create FAMILY SOURCE...         create and run a compile session\n"
      "  session cancel ID REASON                cancel a session\n"
      "  session retire ID REASON                retire a session\n"
      "  phase list SESSION_ID                   list the phase plan\n"
      "  phase show SESSION_ID PHASE_ID          explain one phase\n"
      "  phase start SESSION_ID PHASE_ID         run one phase\n"
      "  phase retry SESSION_ID PHASE_ID         retry a failed phase\n"
      "  phase cancel SESSION_ID PHASE_ID REASON cancel a phase\n"
      "  phase authority SESSION_ID PHASE_ID     report the authority verdict\n"
      "  intermediate list SESSION_ID            list intermediates\n"
      "  intermediate show ID                    explain one intermediate\n"
      "  artifact show SESSION_ID                show the final candidate\n"
      "  artifact verify SESSION_ID              re-hash the candidate and its lineage\n"
      "  diagnostics show SET_ID                 show a diagnostic set\n"
      "  recovery explain SESSION_ID             explain the recovery plan\n"
      "  recovery apply SESSION_ID               apply the recovery plan\n"
      "  provenance show ARTIFACT_ID             trace artifact lineage\n"
      "  snapshot                                write a durable snapshot\n"
      "  verify                                  verify durable state integrity\n"
      "  audit                                   run the invariant auditor\n"
      "  explain session SESSION_ID              full session explanation\n"
      "  demo [output-dir]                       real MSVC compile, link and execute\n"
      "  version                                 print the version\n");
  return 2;
}

CRF_NODISCARD std::string join_from(int argc, char** argv, int first) {
  std::string out;
  for (int index = first; index < argc; ++index) {
    if (!out.empty()) out.push_back(' ');
    out.append(argv[index]);
  }
  return out;
}

/// A CLI session runtime. In local mode it owns a runtime; in remote mode it
/// talks to a coordinator over the framed control plane.
class Cli {
 public:
  explicit Cli(Globals globals) : globals_(std::move(globals)) {}

  ~Cli() {
    if (runtime_ != nullptr) {
      const VoidResult stopped = runtime_->shutdown();
      (void)stopped;
    }
  }

  CRF_NODISCARD bool remote() const { return !globals_.coordinator.empty(); }

  CRF_NODISCARD Result<Runtime*> runtime() {
    if (remote()) {
      return Status(StatusCode::unsupported,
                    "this command must be run against a local runtime; pass no --coordinator");
    }
    if (runtime_ != nullptr) return runtime_.get();
    RuntimeOptions options;
    options.state_directory = globals_.state_directory;
    options.workspace_root = globals_.workspace_root;
    options.runtime_name = globals_.runtime_name;
    Result<std::unique_ptr<Runtime>> created = Runtime::create(options);
    if (!created) return created.status();
    runtime_ = std::move(created.value());
    return runtime_.get();
  }

  CRF_NODISCARD Result<Message> call(MessageType type, std::string payload) {
    const std::size_t colon = globals_.coordinator.rfind(':');
    if (colon == std::string::npos) {
      return Status(StatusCode::invalid_argument, "--coordinator expects HOST:PORT");
    }
    const std::string host = globals_.coordinator.substr(0, colon);
    const std::uint16_t port =
        static_cast<std::uint16_t>(std::stoi(globals_.coordinator.substr(colon + 1)));
    Result<std::unique_ptr<FramedConnection>> connection =
        FramedConnection::connect(host, port, ConnectionOptions{});
    if (!connection) return connection.status();
    Message hello;
    hello.type = MessageType::hello;
    hello.payload = encode_hello(globals_.runtime_name, "cli", 0, "cli");
    const Result<Message> acknowledged = connection.value()->transact(hello);
    if (!acknowledged) return acknowledged.status();
    Message request;
    request.type = type;
    request.payload = std::move(payload);
    const Result<Message> reply = connection.value()->transact(request);
    connection.value()->close();
    if (!reply) return reply.status();
    if (reply.value().type == MessageType::error) {
      const Result<std::pair<StatusCode, std::string>> decoded = decode_error(reply.value().payload);
      if (!decoded) return decoded.status();
      return Status(decoded.value().first, decoded.value().second);
    }
    return reply.value();
  }

 private:
  Globals globals_;
  std::unique_ptr<Runtime> runtime_;
};

void print_explanation(const Explanation& explanation) { std::printf("%s", explanation.render().c_str()); }

CRF_NODISCARD std::uint64_t parse_u64(const std::string& text) {
  return std::strtoull(text.c_str(), nullptr, 10);
}

CRF_NODISCARD bool parse_family(const std::string& text, ToolchainFamily& out) {
  return parse_toolchain_family(text, out);
}

int command_toolchain(Cli& cli, int argc, char** argv, int index) {
  if (index >= argc) return usage();
  const std::string action = argv[index];
  if (action == "probe") {
    if (index + 1 >= argc) return usage();
    ToolchainFamily family = ToolchainFamily::unknown;
    if (!parse_family(argv[index + 1], family)) {
      std::fprintf(stderr, "crf_cli: unknown toolchain family '%s'\n", argv[index + 1]);
      return 2;
    }
    Result<Runtime*> runtime = cli.runtime();
    if (!runtime) {
      std::fprintf(stderr, "crf_cli: %s\n", runtime.status().to_string().c_str());
      return 1;
    }
    const Result<Ref<ToolchainId>> registered =
        runtime.value()->discover_toolchain(family);
    if (!registered) {
      std::printf("REFUSED %s\n", registered.status().to_string().c_str());
      return 1;
    }
    const ToolchainIdentity* identity = runtime.value()->toolchains().find(registered.value().id);
    if (identity == nullptr) return 1;
    print_explanation(explain_toolchain(*runtime.value(), identity->id));
    return 0;
  }
  if (action == "show") {
    if (index + 1 >= argc) return usage();
    Result<Runtime*> runtime = cli.runtime();
    if (!runtime) {
      std::fprintf(stderr, "crf_cli: %s\n", runtime.status().to_string().c_str());
      return 1;
    }
    const ToolchainId id = ToolchainId::parse(argv[index + 1]);
    print_explanation(explain_toolchain(*runtime.value(), id));
    return 0;
  }
  // list
  if (cli.remote()) {
    return usage();
  }
  Result<Runtime*> runtime = cli.runtime();
  if (!runtime) {
    std::fprintf(stderr, "crf_cli: %s\n", runtime.status().to_string().c_str());
    return 1;
  }
  for (const ToolchainIdentity& identity : runtime.value()->toolchains().list()) {
    std::printf("%s %-14s %-24s %s evidence=%s\n", identity.id.to_string().c_str(),
                std::string(to_string(identity.family)).c_str(), identity.version.c_str(),
                identity.display_name.c_str(),
                std::string(to_string(identity.evidence_class)).c_str());
  }
  return 0;
}

int command_component(Cli& cli, int argc, char** argv, int index) {
  if (index + 2 >= argc) return usage();
  Result<Runtime*> runtime = cli.runtime();
  if (!runtime) {
    std::fprintf(stderr, "crf_cli: %s\n", runtime.status().to_string().c_str());
    return 1;
  }
  print_explanation(explain_component(*runtime.value(), ToolchainId::parse(argv[index + 1]),
                                      CompilerComponentId::parse(argv[index + 2])));
  return 0;
}

int command_session(Cli& cli, int argc, char** argv, int index) {
  if (index >= argc) return usage();
  const std::string action = argv[index];
  if (action == "list") {
    if (cli.remote()) {
      const Result<Message> reply = cli.call(MessageType::session_list, std::string{});
      if (!reply) {
        std::fprintf(stderr, "crf_cli: %s\n", reply.status().to_string().c_str());
        return 1;
      }
      CanonicalReader reader(reply.value().payload);
      std::string blob;
      (void)reader.text(blob, 1u << 24);
      CanonicalReader list(blob);
      std::uint64_t count = 0;
      (void)list.u64(count);
      for (std::uint64_t i = 0; i < count; ++i) {
        std::string encoded;
        if (!list.text(encoded, 1u << 24)) break;
        const Result<CompilerSession> session = decode_session(encoded);
        if (!session) break;
        std::printf("%s state=%s phases=%llu adapter=%s\n",
                    session.value().id.to_string().c_str(),
                    std::string(to_string(session.value().state)).c_str(),
                    static_cast<unsigned long long>(session.value().phases.size()),
                    session.value().adapter_name.c_str());
      }
      return 0;
    }
    Result<Runtime*> runtime = cli.runtime();
    if (!runtime) return 1;
    for (const CompilerSession& session : runtime.value()->list_sessions()) {
      std::printf("%s state=%s generation=%s phases=%llu adapter=%s\n",
                  session.id.to_string().c_str(), std::string(to_string(session.state)).c_str(),
                  session.generation.to_string().c_str(),
                  static_cast<unsigned long long>(session.phases.size()),
                  session.adapter_name.c_str());
    }
    return 0;
  }
  if (action == "show") {
    if (index + 1 >= argc) return usage();
    const CompilerSessionId id = CompilerSessionId::parse(argv[index + 1]);
    if (cli.remote()) {
      FieldWriter writer;
      writer.u64(1, id.value());
      const Result<Message> reply = cli.call(MessageType::query_session, writer.take());
      if (!reply) {
        std::fprintf(stderr, "crf_cli: %s\n", reply.status().to_string().c_str());
        return 1;
      }
      const Result<CompilerSession> session = decode_session_summary(reply.value().payload);
      if (!session) {
        std::fprintf(stderr, "crf_cli: %s\n", session.status().to_string().c_str());
        return 1;
      }
      std::printf("session          %s\nstate            %s\ngeneration       %s\nadapter          %s\n",
                  session.value().id.to_string().c_str(),
                  std::string(to_string(session.value().state)).c_str(),
                  session.value().generation.to_string().c_str(),
                  session.value().adapter_name.c_str());
      return 0;
    }
    Result<Runtime*> runtime = cli.runtime();
    if (!runtime) return 1;
    print_explanation(explain_session(*runtime.value(), id));
    return 0;
  }
  if (action == "create") {
    if (index + 2 >= argc) return usage();
    ToolchainFamily family = ToolchainFamily::unknown;
    if (!parse_family(argv[index + 1], family)) {
      std::fprintf(stderr, "crf_cli: unknown toolchain family '%s'\n", argv[index + 1]);
      return 2;
    }
    CompileRequest request;
    request.toolchain_family = family;
    for (int source = index + 2; source < argc; ++source) {
      request.sources.emplace_back(argv[source]);
    }
    request.run_smoke_test = true;
    if (cli.remote()) {
      const Result<Message> reply =
          cli.call(MessageType::create_session, encode_compile_request(request));
      if (!reply) {
        std::printf("REFUSED %s\n", reply.status().to_string().c_str());
        return 1;
      }
      const Result<CompilerSession> initial = decode_session_summary(reply.value().payload);
      if (!initial) {
        std::fprintf(stderr, "crf_cli: %s\n", initial.status().to_string().c_str());
        return 1;
      }
      FieldWriter run_writer;
      run_writer.u64(1, initial.value().id.value());
      const Result<Message> ran = cli.call(MessageType::run_session, run_writer.take());
      if (!ran) {
        std::printf("REFUSED %s\n", ran.status().to_string().c_str());
        return 1;
      }
      const Result<CompilerSession> session = decode_session_summary(ran.value().payload);
      if (!session) {
        std::fprintf(stderr, "crf_cli: %s\n", session.status().to_string().c_str());
        return 1;
      }
      std::printf("session %s state=%s\n", session.value().id.to_string().c_str(),
                  std::string(to_string(session.value().state)).c_str());
      if (session.value().candidate_present) {
        std::printf("candidate %s sha256=%s\n", session.value().candidate.path.string().c_str(),
                    session.value().candidate.content.to_hex().c_str());
      }
      return 0;
    }
    Result<Runtime*> runtime = cli.runtime();
    if (!runtime) return 1;
    const Result<Ref<ToolchainId>> toolchain = runtime.value()->discover_toolchain(family);
    if (!toolchain) {
      std::printf("REFUSED %s\n", toolchain.status().to_string().c_str());
      return 1;
    }
    const Result<Ref<CompilerSessionId>> created = runtime.value()->create_session(request);
    if (!created) {
      std::printf("REFUSED %s\n", created.status().to_string().c_str());
      return 1;
    }
    const Result<CompileOutcome> outcome = runtime.value()->run_session(created.value().id);
    if (!outcome) {
      std::printf("REFUSED %s\n", outcome.status().to_string().c_str());
      return 1;
    }
    std::printf("session %s\n", created.value().id.to_string().c_str());
    for (const PhaseRunReport& report : outcome.value().phases) {
      std::printf("  %s %-16s %s\n", report.phase.id.to_string().c_str(),
                  std::string(to_string(report.state)).c_str(),
                  std::string(to_string(report.status)).c_str());
    }
    if (outcome.value().candidate.path.empty()) {
      std::printf("status %s detail=%s\n", std::string(to_string(outcome.value().status)).c_str(),
                  outcome.value().detail.c_str());
      return 1;
    }
    std::printf("candidate %s sha256=%s size=%llu\n",
                outcome.value().candidate.path.string().c_str(),
                outcome.value().candidate.content.to_hex().c_str(),
                static_cast<unsigned long long>(outcome.value().candidate.size_bytes));
    const Result<AuditReport> audit = runtime.value()->audit();
    if (audit) {
      std::printf("audit violations=%llu\n",
                  static_cast<unsigned long long>(audit.value().violations.size()));
    }
    return 0;
  }
  if (action == "cancel" || action == "retire") {
    if (index + 2 >= argc) return usage();
    Result<Runtime*> runtime = cli.runtime();
    if (!runtime) return 1;
    const CompilerSessionId id = CompilerSessionId::parse(argv[index + 1]);
    const std::string reason = join_from(argc, argv, index + 2);
    const VoidResult outcome = action == "cancel" ? runtime.value()->cancel_session(id, reason)
                                                  : runtime.value()->retire_session(id, reason);
    if (!outcome) {
      std::printf("REFUSED %s\n", outcome.status().to_string().c_str());
      return 1;
    }
    std::printf("%s %s\n", action == "cancel" ? "cancelled" : "retired", id.to_string().c_str());
    return 0;
  }
  return usage();
}

int command_phase(Cli& cli, int argc, char** argv, int index) {
  if (index >= argc) return usage();
  const std::string action = argv[index];
  if (action == "list") {
    if (index + 1 >= argc) return usage();
    Result<Runtime*> runtime = cli.runtime();
    if (!runtime) return 1;
    const Result<CompilerSession> session =
        runtime.value()->require_session(CompilerSessionId::parse(argv[index + 1]));
    if (!session) {
      std::printf("REFUSED %s\n", session.status().to_string().c_str());
      return 1;
    }
    print_explanation(explain_plan(session.value().plan));
    for (const CompilerPhaseId id : session.value().plan.topological_order()) {
      const PhaseRecord* phase = session.value().find_phase(id);
      if (phase == nullptr) continue;
      std::printf("  %s state=%s generation=%s attempts=%u outputs=%llu\n",
                  id.to_string().c_str(), std::string(to_string(phase->state)).c_str(),
                  phase->generation.to_string().c_str(), phase->attempt_count(),
                  static_cast<unsigned long long>(phase->outputs.size()));
    }
    return 0;
  }
  if (index + 2 >= argc) return usage();
  const CompilerSessionId session = CompilerSessionId::parse(argv[index + 1]);
  const CompilerPhaseId phase = CompilerPhaseId::parse(argv[index + 2]);
  if (action == "show") {
    Result<Runtime*> runtime = cli.runtime();
    if (!runtime) return 1;
    print_explanation(explain_phase(*runtime.value(), session, phase));
    return 0;
  }
  if (action == "authority") {
    Result<Runtime*> runtime = cli.runtime();
    if (!runtime) return 1;
    print_explanation(explain_authority(*runtime.value(), session, phase));
    return 0;
  }
  if (action == "start" || action == "retry") {
    if (cli.remote()) {
      FieldWriter writer;
      writer.u64(1, session.value());
      writer.u64(2, phase.value());
      const Result<Message> reply = cli.call(
          action == "start" ? MessageType::start_phase : MessageType::retry_phase, writer.take());
      if (!reply) {
        std::printf("REFUSED %s\n", reply.status().to_string().c_str());
        return 1;
      }
      const Result<PhaseRunReport> report = decode_phase_report(reply.value().payload);
      if (!report) {
        std::fprintf(stderr, "crf_cli: %s\n", report.status().to_string().c_str());
        return 1;
      }
      std::printf("phase %s state=%s status=%s\n", report.value().phase.id.to_string().c_str(),
                  std::string(to_string(report.value().state)).c_str(),
                  std::string(to_string(report.value().status)).c_str());
      return report.value().committed() ? 0 : 1;
    }
    Result<Runtime*> runtime = cli.runtime();
    if (!runtime) return 1;
    const Result<PhaseRunReport> report = action == "start"
                                              ? runtime.value()->run_phase(session, phase)
                                              : runtime.value()->retry_phase(session, phase);
    if (!report) {
      std::printf("REFUSED %s\n", report.status().to_string().c_str());
      return 1;
    }
    std::printf("phase %s state=%s status=%s failure=%s\n",
                report.value().phase.id.to_string().c_str(),
                std::string(to_string(report.value().state)).c_str(),
                std::string(to_string(report.value().status)).c_str(),
                std::string(to_string(report.value().failure)).c_str());
    if (!report.value().detail.empty()) std::printf("detail %s\n", report.value().detail.c_str());
    return report.value().committed() ? 0 : 1;
  }
  if (action == "cancel") {
    if (index + 3 >= argc) return usage();
    Result<Runtime*> runtime = cli.runtime();
    if (!runtime) return 1;
    const VoidResult cancelled =
        runtime.value()->cancel_phase(session, phase, join_from(argc, argv, index + 3));
    if (!cancelled) {
      std::printf("REFUSED %s\n", cancelled.status().to_string().c_str());
      return 1;
    }
    std::printf("cancelled %s\n", phase.to_string().c_str());
    return 0;
  }
  return usage();
}

int command_intermediate(Cli& cli, int argc, char** argv, int index) {
  if (index >= argc) return usage();
  const std::string action = argv[index];
  Result<Runtime*> runtime = cli.runtime();
  if (!runtime) {
    std::fprintf(stderr, "crf_cli: %s\n", runtime.status().to_string().c_str());
    return 1;
  }
  if (action == "list") {
    if (index + 1 >= argc) return usage();
    const Result<CompilerSession> session =
        runtime.value()->require_session(CompilerSessionId::parse(argv[index + 1]));
    if (!session) {
      std::printf("REFUSED %s\n", session.status().to_string().c_str());
      return 1;
    }
    for (const Ref<IntermediateArtifactId>& reference : session.value().intermediates) {
      const IntermediateArtifact* artifact = runtime.value()->artifacts().find(reference.id);
      if (artifact == nullptr) continue;
      std::printf("%s %-20s %-9s %-14s %s\n", artifact->id.to_string().c_str(),
                  std::string(to_string(artifact->format)).c_str(),
                  std::string(to_string(artifact->state)).c_str(),
                  std::string(to_string(artifact->authority)).c_str(),
                  artifact->content.to_short_hex().c_str());
    }
    return 0;
  }
  if (action == "show") {
    if (index + 1 >= argc) return usage();
    print_explanation(
        explain_artifact(*runtime.value(), IntermediateArtifactId::parse(argv[index + 1])));
    return 0;
  }
  return usage();
}

int command_artifact(Cli& cli, int argc, char** argv, int index) {
  if (index + 1 >= argc) return usage();
  const std::string action = argv[index];
  Result<Runtime*> runtime = cli.runtime();
  if (!runtime) {
    std::fprintf(stderr, "crf_cli: %s\n", runtime.status().to_string().c_str());
    return 1;
  }
  const CompilerSessionId session = CompilerSessionId::parse(argv[index + 1]);
  if (action == "show") {
    print_explanation(explain_candidate(*runtime.value(), session));
    return 0;
  }
  if (action == "verify") {
    const FinalCandidate* candidate = runtime.value()->find_candidate(session);
    if (candidate == nullptr) {
      std::printf("REFUSED no candidate is registered for this session\n");
      return 1;
    }
    std::size_t mismatches = 0;
    Digest observed;
    if (!Digest::of_file(candidate->path, observed)) {
      std::printf("MISSING %s\n", candidate->path.string().c_str());
      return 1;
    }
    if (observed != candidate->content) {
      std::printf("MISMATCH candidate content changed on disk\n");
      ++mismatches;
    }
    for (const Ref<IntermediateArtifactId>& reference : candidate->lineage) {
      const Result<ArtifactState> state = runtime.value()->artifacts().revalidate(reference.id);
      if (!state) {
        std::printf("REFUSED %s\n", state.status().to_string().c_str());
        return 1;
      }
      if (state.value() != ArtifactState::valid) {
        std::printf("STALE %s state=%s\n", reference.id.to_string().c_str(),
                    std::string(to_string(state.value())).c_str());
        ++mismatches;
      }
    }
    std::printf("verified candidate=%s artifacts=%llu mismatches=%llu\n",
                candidate->content.to_hex().c_str(),
                static_cast<unsigned long long>(candidate->lineage.size()),
                static_cast<unsigned long long>(mismatches));
    return mismatches == 0 ? 0 : 1;
  }
  return usage();
}

int command_diagnostics(Cli& cli, int argc, char** argv, int index) {
  if (index + 1 >= argc) return usage();
  Result<Runtime*> runtime = cli.runtime();
  if (!runtime) return 1;
  print_explanation(
      explain_diagnostics(*runtime.value(), DiagnosticSetId::parse(argv[index + 1])));
  return 0;
}

int command_recovery(Cli& cli, int argc, char** argv, int index) {
  if (index + 1 >= argc) return usage();
  const std::string action = argv[index];
  if (index + 2 >= argc) return usage();
  Result<Runtime*> runtime = cli.runtime();
  if (!runtime) return 1;
  const CompilerSessionId session = CompilerSessionId::parse(argv[index + 2]);
  if (action == "explain") {
    print_explanation(explain_recovery(*runtime.value(), session));
    return 0;
  }
  if (action == "apply") {
    const Result<RecoveryPlan> applied = runtime.value()->apply_recovery(session);
    if (!applied) {
      std::printf("REFUSED %s\n", applied.status().to_string().c_str());
      return 1;
    }
    std::printf("recovery %s legal=%s operator=%s\n",
                std::string(to_string(applied.value().headline)).c_str(),
                applied.value().legal ? "yes" : "no",
                applied.value().requires_operator ? "yes" : "no");
    return applied.value().requires_operator ? 1 : 0;
  }
  return usage();
}

int command_provenance(Cli& cli, int argc, char** argv, int index) {
  if (index + 1 >= argc) return usage();
  Result<Runtime*> runtime = cli.runtime();
  if (!runtime) return 1;
  print_explanation(
      explain_provenance(*runtime.value(), IntermediateArtifactId::parse(argv[index + 1])));
  return 0;
}

int command_audit(Cli& cli) {
  if (cli.remote()) {
    const Result<Message> reply = cli.call(MessageType::audit, std::string{});
    if (!reply) {
      std::fprintf(stderr, "crf_cli: %s\n", reply.status().to_string().c_str());
      return 1;
    }
    const Result<AuditReport> report = decode_audit_report(reply.value().payload);
    if (!report) {
      std::fprintf(stderr, "crf_cli: %s\n", report.status().to_string().c_str());
      return 1;
    }
    std::printf("%s", report.value().render().c_str());
    return report.value().zero_violations() ? 0 : 1;
  }
  Result<Runtime*> runtime = cli.runtime();
  if (!runtime) return 1;
  const Result<AuditReport> report = runtime.value()->audit();
  if (!report) {
    std::fprintf(stderr, "crf_cli: %s\n", report.status().to_string().c_str());
    return 1;
  }
  std::printf("%s", report.value().render().c_str());
  return report.value().zero_violations() ? 0 : 1;
}

int command_snapshot(Cli& cli) {
  if (cli.remote()) {
    const Result<Message> reply = cli.call(MessageType::snapshot, std::string{});
    if (!reply) {
      std::fprintf(stderr, "crf_cli: %s\n", reply.status().to_string().c_str());
      return 1;
    }
    std::printf("snapshot written\n");
    return 0;
  }
  Result<Runtime*> runtime = cli.runtime();
  if (!runtime) return 1;
  const VoidResult written = runtime.value()->snapshot();
  if (!written) {
    std::printf("REFUSED %s\n", written.status().to_string().c_str());
    return 1;
  }
  std::printf("snapshot written\n");
  return 0;
}

int command_verify(Cli& cli) {
  Result<Runtime*> runtime = cli.runtime();
  if (!runtime) return 1;
  const Result<DurableState> state = runtime.value()->durable_state();
  if (!state) {
    std::printf("REFUSED %s\n", state.status().to_string().c_str());
    return 1;
  }
  std::printf("durable outcome=%s trustworthy=%s records=%llu epoch=%llu repaired_bytes=%llu\n",
              std::string(to_string(state.value().outcome)).c_str(),
              state.value().trustworthy() ? "yes" : "no",
              static_cast<unsigned long long>(state.value().records.size()),
              static_cast<unsigned long long>(state.value().runtime_epoch),
              static_cast<unsigned long long>(state.value().repaired_bytes));
  if (!state.value().detail.empty()) std::printf("detail %s\n", state.value().detail.c_str());
  return state.value().trustworthy() ? 0 : 1;
}

int command_demo(Cli& cli, int argc, char** argv, int index) {
  Result<Runtime*> runtime = cli.runtime();
  if (!runtime) {
    std::fprintf(stderr, "crf_cli: %s\n", runtime.status().to_string().c_str());
    return 1;
  }
  const std::filesystem::path output =
      index + 1 < argc ? std::filesystem::path(argv[index + 1])
                       : cli_scratch_directory();
  std::error_code ec;
  std::filesystem::create_directories(output, ec);
  const std::filesystem::path source = output / "crf_demo.cpp";
  {
    std::FILE* file = std::fopen(source.string().c_str(), "wb");
    if (file == nullptr) {
      std::fprintf(stderr, "crf_cli: could not write the demo source\n");
      return 1;
    }
    const char* text =
        "#include <cstdio>\n"
        "int main() { std::printf(\"CRF-DEMO-OK\\n\"); return 0; }\n";
    std::fwrite(text, 1, std::strlen(text), file);
    std::fclose(file);
  }
  const Result<Ref<ToolchainId>> toolchain =
      runtime.value()->discover_toolchain(ToolchainFamily::msvc);
  if (!toolchain) {
    std::printf("REFUSED %s\n", toolchain.status().to_string().c_str());
    return 1;
  }
  CompileRequest request;
  request.toolchain_family = ToolchainFamily::msvc;
  request.sources = {source};
  request.run_smoke_test = true;
  request.adapter_options.push_back(
      EnvironmentVariable{"msvc.expected_stdout", "CRF-DEMO-OK"});
  const Result<Ref<CompilerSessionId>> created = runtime.value()->create_session(request);
  if (!created) {
    std::printf("REFUSED %s\n", created.status().to_string().c_str());
    return 1;
  }
  const Result<CompileOutcome> outcome = runtime.value()->run_session(created.value().id);
  if (!outcome) {
    std::printf("REFUSED %s\n", outcome.status().to_string().c_str());
    return 1;
  }
  print_explanation(explain_session(*runtime.value(), created.value().id));
  print_explanation(explain_candidate(*runtime.value(), created.value().id));
  const Result<AuditReport> audit = runtime.value()->audit();
  if (audit) std::printf("%s", audit.value().render().c_str());
  return outcome.value().candidate.path.empty() ? 1 : 0;
}

}  // namespace

int main(int argc, char** argv) {
  Globals globals;
  int index = 1;
  for (; index < argc; ++index) {
    const std::string argument = argv[index];
    const auto value = [&argc, &argv, &index]() -> std::string {
      return index + 1 < argc ? std::string(argv[++index]) : std::string{};
    };
    if (argument == "--state") {
      globals.state_directory = value();
      continue;
    }
    if (argument == "--workspaces") {
      globals.workspace_root = value();
      continue;
    }
    if (argument == "--coordinator") {
      globals.coordinator = value();
      continue;
    }
    if (argument == "--name") {
      globals.runtime_name = value();
      continue;
    }
    if (argument == "--help" || argument == "-h") return usage();
    if (argument == "version") {
      std::printf("Compiler Runtime Fabric %s (protocol %u.%u)\n", version_string,
                  protocol_version_major, protocol_version_minor);
      return 0;
    }
    break;
  }
  if (index >= argc) return usage();
  if (globals.state_directory.empty()) {
    globals.state_directory = std::filesystem::current_path() / "crf-state";
  }
  if (globals.workspace_root.empty()) {
    globals.workspace_root = globals.state_directory / "workspaces";
  }

  Cli cli(globals);
  const std::string command = argv[index];
  if (command == "toolchain") return command_toolchain(cli, argc, argv, index + 1);
  if (command == "component") return command_component(cli, argc, argv, index + 1);
  if (command == "session") return command_session(cli, argc, argv, index + 1);
  if (command == "phase") return command_phase(cli, argc, argv, index + 1);
  if (command == "intermediate") return command_intermediate(cli, argc, argv, index + 1);
  if (command == "artifact") return command_artifact(cli, argc, argv, index + 1);
  if (command == "diagnostics") return command_diagnostics(cli, argc, argv, index + 1);
  if (command == "recovery") return command_recovery(cli, argc, argv, index + 1);
  if (command == "provenance") return command_provenance(cli, argc, argv, index + 1);
  if (command == "audit") return command_audit(cli);
  if (command == "snapshot") return command_snapshot(cli);
  if (command == "verify") return command_verify(cli);
  if (command == "demo") return command_demo(cli, argc, argv, index + 1);
  if (command == "explain") {
    if (index + 2 < argc && std::string(argv[index + 1]) == "session") {
      Result<Runtime*> runtime = cli.runtime();
      if (!runtime) return 1;
      print_explanation(
          explain_session(*runtime.value(), CompilerSessionId::parse(argv[index + 2])));
      return 0;
    }
    if (index + 1 < argc && std::string(argv[index + 1]) == "runtime") {
      Result<Runtime*> runtime = cli.runtime();
      if (!runtime) return 1;
      print_explanation(explain_runtime(*runtime.value()));
      return 0;
    }
    return usage();
  }
  return usage();
}
