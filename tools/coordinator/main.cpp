// crf_coordinator - the Compiler Runtime Fabric control plane.
//
// The coordinator owns every compiler session, every authority generation, and
// all durable state. Compiler workers connect to it and execute the orders it
// authorises; they hold no authority of their own.

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include "crf/version.hpp"
#include "ipc/service.hpp"

namespace {

void print_usage() {
  std::printf(
      "crf_coordinator " CRF_VERSION_STRING " - Compiler Runtime Fabric control plane\n"
      "\n"
      "usage: crf_coordinator [options]\n"
      "\n"
      "  --bind ADDRESS        bind address (default 127.0.0.1)\n"
      "  --port PORT           listen port; 0 selects an ephemeral port\n"
      "  --state DIR           durable state directory (required)\n"
      "  --workspaces DIR      workspace root (default <state>/workspaces)\n"
      "  --name NAME           runtime name (default crf-coordinator)\n"
      "  --no-persistence      run without a durable journal\n"
      "  --quiet               print only the endpoint line\n"
      "  --help                show this message\n");
}

CRF_NODISCARD bool next_value(int argc, char** argv, int& index, std::string& out) {
  if (index + 1 >= argc) return false;
  out = argv[++index];
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  crf::CoordinatorOptions options;
  options.server.bind_address = "127.0.0.1";
  options.runtime.runtime_name = "crf-coordinator";
  bool quiet = false;
  bool have_state = false;

  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    std::string value;
    if (argument == "--help" || argument == "-h") {
      print_usage();
      return 0;
    }
    if (argument == "--bind" && next_value(argc, argv, index, value)) {
      options.server.bind_address = value;
      continue;
    }
    if (argument == "--port" && next_value(argc, argv, index, value)) {
      options.server.port = static_cast<std::uint16_t>(std::stoi(value));
      continue;
    }
    if (argument == "--state" && next_value(argc, argv, index, value)) {
      options.runtime.state_directory = value;
      have_state = true;
      continue;
    }
    if (argument == "--workspaces" && next_value(argc, argv, index, value)) {
      options.runtime.workspace_root = value;
      continue;
    }
    if (argument == "--name" && next_value(argc, argv, index, value)) {
      options.runtime.runtime_name = value;
      continue;
    }
    if (argument == "--no-persistence") {
      options.runtime.enable_persistence = false;
      continue;
    }
    if (argument == "--quiet") {
      quiet = true;
      continue;
    }
    std::fprintf(stderr, "crf_coordinator: unrecognised argument '%s'\n", argument.c_str());
    print_usage();
    return 2;
  }

  if (!have_state) {
    std::fprintf(stderr, "crf_coordinator: --state DIR is required\n");
    return 2;
  }

  crf::CoordinatorService service;
  const crf::VoidResult started = service.start(options);
  if (!started) {
    std::fprintf(stderr, "crf_coordinator: %s\n", started.status().to_string().c_str());
    return 1;
  }
  std::printf("CRF_ENDPOINT %s\n", service.endpoint().c_str());
  if (!quiet) {
    std::printf("CRF_EPOCH %llu\n", static_cast<unsigned long long>(service.runtime().epoch()));
    std::printf("CRF_READY\n");
  }
  std::fflush(stdout);

  const crf::VoidResult served = service.serve_forever();
  if (!served) {
    std::fprintf(stderr, "crf_coordinator: serve failed: %s\n",
                 served.status().to_string().c_str());
    return 1;
  }
  const crf::VoidResult stopped = service.runtime().shutdown();
  (void)stopped;
  std::printf("CRF_STOPPED\n");
  std::fflush(stdout);
  return 0;
}
