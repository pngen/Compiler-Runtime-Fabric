// crf_worker - the compiler worker.
//
// A worker holds no compiler authority. It connects to a coordinator, receives
// fully specified execution orders, proves each order is well formed, runs the
// compiler locally, and reports evidence back. Killing a worker can therefore
// never leave authoritative compilation state behind.

#include <cstdio>
#include <cstring>
#include <string>

#include "crf/version.hpp"
#include "ipc/service.hpp"

namespace {

void print_usage() {
  std::printf(
      "crf_worker " CRF_VERSION_STRING " - Compiler Runtime Fabric compiler worker\n"
      "\n"
      "usage: crf_worker --coordinator HOST:PORT --workspace-root DIR [options]\n"
      "\n"
      "  --coordinator H:P     coordinator endpoint (required)\n"
      "  --workspace-root DIR  root below which the worker may execute (required)\n"
      "  --name NAME           worker name (default crf-worker)\n"
      "  --max-requests N      exit after N orders (0 = unlimited)\n"
      "  --help                show this message\n");
}

}  // namespace

int main(int argc, char** argv) {
  crf::WorkerOptions options;
  bool have_coordinator = false;
  bool have_workspace = false;

  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    const auto value = [&argc, &argv, &index]() -> std::string {
      return index + 1 < argc ? std::string(argv[++index]) : std::string{};
    };
    if (argument == "--help" || argument == "-h") {
      print_usage();
      return 0;
    }
    if (argument == "--coordinator") {
      const std::string endpoint = value();
      const std::size_t colon = endpoint.rfind(':');
      if (colon == std::string::npos) {
        std::fprintf(stderr, "crf_worker: --coordinator expects HOST:PORT\n");
        return 2;
      }
      options.coordinator_host = endpoint.substr(0, colon);
      options.coordinator_port =
          static_cast<std::uint16_t>(std::stoi(endpoint.substr(colon + 1)));
      have_coordinator = true;
      continue;
    }
    if (argument == "--workspace-root") {
      options.workspace_root = value();
      have_workspace = true;
      continue;
    }
    if (argument == "--name") {
      options.name = value();
      continue;
    }
    if (argument == "--max-requests") {
      options.max_requests = static_cast<std::size_t>(std::stoul(value()));
      continue;
    }
    std::fprintf(stderr, "crf_worker: unrecognised argument '%s'\n", argument.c_str());
    print_usage();
    return 2;
  }

  if (!have_coordinator || !have_workspace) {
    std::fprintf(stderr, "crf_worker: --coordinator and --workspace-root are required\n");
    return 2;
  }

  crf::WorkerService worker;
  const crf::VoidResult connected = worker.connect(options);
  if (!connected) {
    std::fprintf(stderr, "crf_worker: %s\n", connected.status().to_string().c_str());
    return 1;
  }
  std::printf("CRF_WORKER_READY %s %s:%u\n", options.name.c_str(),
              options.coordinator_host.c_str(), static_cast<unsigned>(options.coordinator_port));
  std::fflush(stdout);

  const crf::VoidResult served = worker.serve();
  if (!served) {
    std::fprintf(stderr, "crf_worker: %s\n", served.status().to_string().c_str());
    return 1;
  }
  std::printf("CRF_WORKER_EXECUTED %llu\n",
              static_cast<unsigned long long>(worker.executed_phases()));
  std::fflush(stdout);
  return 0;
}
