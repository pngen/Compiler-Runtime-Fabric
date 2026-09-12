// Real CUDA hardware proof.
//
// The device source performs host-to-device transfer, a kernel launch,
// device-to-host transfer, and a CPU parity check. If no CUDA toolkit or no
// device is available the case reports UNSUPPORTED explicitly and never claims
// a result it did not produce.

#include "crf_test.hpp"
#include "crf_test_env.hpp"

#include <string>

namespace {

using namespace crf;

CRF_NODISCARD std::string cuda_source() {
  return R"CUDA(// Compiler Runtime Fabric CUDA parity kernel.
#include <cstdio>
#include <cuda_runtime.h>

__global__ void crf_scale(const float* input, float* output, int count, float factor) {
  const int index = blockIdx.x * blockDim.x + threadIdx.x;
  if (index < count) {
    output[index] = input[index] * factor;
  }
}

int main() {
  const int count = 4096;
  const float factor = 2.5f;
  float host_in[count];
  float host_out[count];
  float reference[count];
  for (int i = 0; i < count; ++i) {
    host_in[i] = static_cast<float>(i) * 0.5f;
    reference[i] = host_in[i] * factor;
    host_out[i] = -1.0f;
  }

  int devices = 0;
  if (cudaGetDeviceCount(&devices) != cudaSuccess || devices == 0) {
    std::printf("CRF-CUDA-NO-DEVICE\n");
    return 3;
  }
  cudaDeviceProp properties{};
  if (cudaGetDeviceProperties(&properties, 0) != cudaSuccess) {
    std::printf("CRF-CUDA-NO-PROPERTIES\n");
    return 3;
  }

  float* device_in = nullptr;
  float* device_out = nullptr;
  const std::size_t bytes = sizeof(float) * static_cast<std::size_t>(count);
  if (cudaMalloc(&device_in, bytes) != cudaSuccess) { std::printf("CRF-CUDA-ALLOC-FAILED\n"); return 4; }
  if (cudaMalloc(&device_out, bytes) != cudaSuccess) { std::printf("CRF-CUDA-ALLOC-FAILED\n"); return 4; }

  if (cudaMemcpy(device_in, host_in, bytes, cudaMemcpyHostToDevice) != cudaSuccess) {
    std::printf("CRF-CUDA-H2D-FAILED\n");
    return 5;
  }
  crf_scale<<<(count + 255) / 256, 256>>>(device_in, device_out, count, factor);
  const cudaError_t launched = cudaGetLastError();
  if (launched != cudaSuccess) {
    std::printf("CRF-CUDA-LAUNCH-FAILED\n");
    return 6;
  }
  if (cudaDeviceSynchronize() != cudaSuccess) {
    std::printf("CRF-CUDA-SYNC-FAILED\n");
    return 6;
  }
  if (cudaMemcpy(host_out, device_out, bytes, cudaMemcpyDeviceToHost) != cudaSuccess) {
    std::printf("CRF-CUDA-D2H-FAILED\n");
    return 7;
  }

  double worst = 0.0;
  for (int i = 0; i < count; ++i) {
    const double difference = static_cast<double>(host_out[i]) - static_cast<double>(reference[i]);
    const double magnitude = difference < 0 ? -difference : difference;
    if (magnitude > worst) worst = magnitude;
  }
  cudaFree(device_in);
  cudaFree(device_out);

  if (worst > 1e-4) {
    std::printf("CRF-CUDA-PARITY-FAILED worst=%.9f\n", worst);
    return 8;
  }
  std::printf("CRF-CUDA-PARITY-OK device=%s cc=%d.%d worst=%.9f\n", properties.name,
              properties.major, properties.minor, worst);
  return 0;
}
)CUDA";
}

}  // namespace

CRF_TEST(cuda_compiler_launch_context_is_diagnosed) {
  CRF_PHASE("SETUP");
  const std::filesystem::path nvcc = normalize_path(std::filesystem::path(
      "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v13.1/bin/nvcc.exe"));
  if (!std::filesystem::exists(nvcc)) {
    std::printf("  SKIPPED nvcc is not installed at the expected location\n");
    return;
  }
  const std::filesystem::path work = crftest::test_root() / "cuda-launch-context";
  std::error_code ec;
  std::filesystem::create_directories(work, ec);
  const std::filesystem::path source = work / "ctx.cu";
  CRF_REQUIRE(crftest::write_text(source, "#include <cstdio>\n__global__ void k(){}\nint main(){return 0;}\n"));

  const auto attempt = [&](const char* label, const EnvironmentSpec& environment,
                           bool inherit, const std::vector<std::string>& arguments) {
    ProcessSpec spec;
    spec.executable = nvcc;
    spec.arguments = arguments;
    spec.working_directory = work;
    spec.inherit_ambient_environment = inherit;
    if (!inherit) {
      const Result<std::vector<EnvironmentVariable>> block = build_process_environment(environment);
      if (block) spec.environment = block.value();
    }
    ProcessSupervisor supervisor;
    const Result<ProcessOutcome> outcome = supervisor.run(
        spec, Ref<InvocationId>{InvocationId::from_value(1), InvocationGeneration::initial()});
    supervisor.close();
    if (!outcome) {
      std::printf("  %s: refused %s\n", label, outcome.status().to_string().c_str());
      return;
    }
    std::string output = outcome.value().capture.standard_output;
    if (output.size() > 240) output.resize(240);
    std::string error = outcome.value().capture.standard_error;
    if (error.size() > 240) error.resize(240);
    std::printf("  %s: exit=%u stdout=%llu stderr=%llu\n    out=\"%s\"\n    err=\"%s\"\n", label,
                outcome.value().exit_code,
                static_cast<unsigned long long>(outcome.value().capture.standard_output_bytes),
                static_cast<unsigned long long>(outcome.value().capture.standard_error_bytes),
                output.c_str(), error.c_str());
  };

  CRF_PHASE("VERSION");
  attempt("version-minimal", EnvironmentSpec{}, false, {"--version"});
  attempt("version-ambient", EnvironmentSpec{}, true, {"--version"});

  CRF_PHASE("PREPROCESS");
  attempt("preprocess-minimal", EnvironmentSpec{}, false,
          {"-std=c++20", "-arch=sm_120", "-E", source.string(), "-o", (work / "out.cpp").string()});

  // The governed toolchain contract is what a phase actually runs under.
  std::shared_ptr<const CompilerAdapter> adapter = make_cuda_adapter();
  CRF_REQUIRE(adapter != nullptr);
  ToolchainProbeRequest probe;
  probe.family = ToolchainFamily::nvcc;
  probe.target.architecture = Architecture::x64;
  probe.target.os = OperatingSystem::windows;
  probe.target.device_arch = "sm_120";
  const Result<ToolchainIdentity> identity = adapter->probe_toolchain(probe);
  CRF_REQUIRE_OK(identity);
  TargetSpec target;
  target.architecture = Architecture::x64;
  target.os = OperatingSystem::windows;
  target.device_arch = "sm_120";
  const Result<EnvironmentSpec> governed =
      adapter->compose_environment(identity.value(), target, EnvironmentSpec{});
  CRF_REQUIRE_OK(governed);
  for (const EnvironmentVariable& variable : governed.value().variables) {
    if (variable.name == "PATH") {
      std::string shown = variable.value;
      if (shown.size() > 300) shown.resize(300);
      std::printf("  governed PATH=%s\n", shown.c_str());
    }
  }
  attempt("preprocess-governed", governed.value(), false,
          {"-std=c++20", "-arch=sm_120", "-E", source.string(), "-o", (work / "out2.cpp").string()});

  // The same governed contract, but with the temporary directory inside a path
  // that contains spaces, which is what a workspace under a spaced root gives.
  {
    EnvironmentSpec spaced = governed.value();
    spaced.temp_directory = work;   // test_root() contains spaces on this host
    attempt("preprocess-spaced-temp", spaced, false,
            {"-std=c++20", "-arch=sm_120", "-E", source.string(), "-o",
             (work / "out3.cpp").string()});
  }
}

CRF_TEST(cuda_driver_query_tool_runs_under_the_runtime_supervisor) {
  CRF_PHASE("SETUP");
  const std::filesystem::path tool = normalize_path(std::filesystem::path("C:/Windows/System32/nvidia-smi.exe"));
  if (!std::filesystem::exists(tool)) {
    std::printf("  SKIPPED nvidia-smi is not installed\n");
    return;
  }
  const auto attempt = [&tool](const char* label, const ProcessSupervisorOptions& options,
                               const std::vector<std::string>& arguments) {
    ProcessSupervisor supervisor(options);
    ProcessSpec spec;
    spec.executable = tool;
    spec.arguments = arguments;
    spec.max_capture_bytes = 64u * 1024u;
    const Result<ProcessOutcome> outcome = supervisor.run(
        spec, Ref<InvocationId>{InvocationId::from_value(1), InvocationGeneration::initial()});
    supervisor.close();
    if (!outcome) {
      std::printf("  %s: refused %s\n", label, outcome.status().to_string().c_str());
      return;
    }
    std::string output = outcome.value().capture.standard_output;
    if (output.size() > 80) output.resize(80);
    std::string error = outcome.value().capture.standard_error;
    if (error.size() > 120) error.resize(120);
    std::printf("  %s: exit=%u termination=%s stdout=\"%s\" stderr=\"%s\"\n", label,
                outcome.value().exit_code,
                std::string(to_string(outcome.value().termination)).c_str(), output.c_str(),
                error.c_str());
  };
  CRF_PHASE("QUERY");
  attempt("default", ProcessSupervisorOptions{}, {"--query-gpu=compute_cap", "--format=csv,noheader"});
  ProcessSupervisorOptions no_job;
  no_job.own_job_object = false;
  attempt("no-job-object", no_job, {"--query-gpu=compute_cap", "--format=csv,noheader"});
  attempt("plain", ProcessSupervisorOptions{}, {});
}

CRF_TEST(cuda_toolkit_identity_is_exact_and_distinct) {
  CRF_PHASE("SETUP");
  RuntimeOptions options = crftest::test_runtime_options("cuda-identity");
  crftest::ScopedTree cleanup(options.state_directory.parent_path());
  const Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  CRF_REQUIRE_OK(runtime);

  CRF_PHASE("PROBE");
  // The device architecture is supplied explicitly. Auto-detection through
  // nvidia-smi is attempted first when it is not supplied and its outcome is
  // recorded either way; the execution proof below validates the architecture.
  ToolchainProbeRequest probe_request;
  probe_request.family = ToolchainFamily::nvcc;
  probe_request.target.architecture = Architecture::x64;
  probe_request.target.os = OperatingSystem::windows;
  probe_request.target.device_arch = "sm_120";
  const Result<ToolchainIdentity> probed =
      runtime.value()->probe_toolchain(ToolchainFamily::nvcc, probe_request);
  if (!probed) {
    if (probed.code() == StatusCode::toolchain_not_found) {
      std::printf("  SKIPPED no CUDA toolkit is installed on this machine\n");
      return;
    }
    CRF_FAIL(probed.status().to_string());
    return;
  }
  const ToolchainIdentity& identity = probed.value();
  CRF_EXPECT(identity.family == ToolchainFamily::nvcc);
  CRF_EXPECT(identity.evidence_class == EvidenceClass::real);
  std::printf("  detected %s version=%s root=%s\n", identity.display_name.c_str(),
              identity.version.c_str(), identity.toolkit_root.string().c_str());
  const ComponentIdentity* nvcc = identity.find_component(ComponentKind::device_compiler);
  const ComponentIdentity* host = identity.find_component(ComponentKind::host_cxx_compiler);
  CRF_REQUIRE(nvcc != nullptr);
  CRF_EXPECT(host != nullptr);
  CRF_EXPECT(nvcc->file.content_hashed);
  CRF_EXPECT(!nvcc->file.content.zero());
  bool detected_device = false;
  for (const EnvironmentVariable& attribute : identity.attributes) {
    if (attribute.name == "cuda.detected_device_arch") {
      detected_device = attribute.value.rfind("sm_", 0) == 0;
      std::printf("  device architecture %s\n", attribute.value.c_str());
    }
    if (attribute.name == "cuda.device-arch-source") {
      std::printf("  device architecture source: %s\n", attribute.value.c_str());
    }
    if (attribute.name == "cuda.device-arch-probe") {
      std::printf("  architecture probe detail: %s\n", attribute.value.c_str());
    }
  }
  CRF_EXPECT(detected_device);

  CRF_PHASE("DISTINCT_TOOLCHAINS");
  // Two installations are two identities. Discovering them separately must not
  // let one silently satisfy the other.
  ToolchainProbeRequest pinned;
  pinned.family = ToolchainFamily::nvcc;
  pinned.toolkit_preference = "12.9";
  const Result<ToolchainIdentity> older = runtime.value()->probe_toolchain(
      ToolchainFamily::nvcc, pinned);
  if (older) {
    const Result<Ref<ToolchainId>> registered_older =
        runtime.value()->discover_toolchain(ToolchainFamily::nvcc, pinned);
    CRF_REQUIRE_OK(registered_older);
    const Result<Ref<ToolchainId>> registered_current =
        runtime.value()->discover_toolchain(ToolchainFamily::nvcc);
    CRF_REQUIRE_OK(registered_current);
    CRF_EXPECT(registered_older.value().id != registered_current.value().id);
    const ToolchainIdentity* older_identity =
        runtime.value()->toolchains().find(registered_older.value().id);
    const ToolchainIdentity* current_identity =
        runtime.value()->toolchains().find(registered_current.value().id);
    CRF_REQUIRE(older_identity != nullptr);
    CRF_REQUIRE(current_identity != nullptr);
    CRF_EXPECT(older_identity->version != current_identity->version ||
               canonical_path_key(older_identity->toolkit_root) !=
                   canonical_path_key(current_identity->toolkit_root));
    CRF_EXPECT(older_identity->canonical_digest() != current_identity->canonical_digest());
  } else {
    std::printf("  only one CUDA toolkit version is installed; distinct-generation proof limited\n");
  }
  CRF_EXPECT_OK(runtime.value()->shutdown());
}

CRF_TEST(cuda_compile_link_and_device_parity_execution) {
  CRF_PHASE("SETUP");
  RuntimeOptions options = crftest::test_runtime_options("cuda-parity");
  crftest::ScopedTree cleanup(options.state_directory.parent_path());
  const Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  CRF_REQUIRE_OK(runtime);

  CRF_PHASE("DISCOVER_TOOLCHAIN");
  ToolchainProbeRequest probe_request;
  probe_request.family = ToolchainFamily::nvcc;
  probe_request.target.architecture = Architecture::x64;
  probe_request.target.os = OperatingSystem::windows;
  probe_request.target.device_arch = "sm_120";
  const Result<Ref<ToolchainId>> toolchain =
      runtime.value()->discover_toolchain(ToolchainFamily::nvcc, probe_request);
  if (!toolchain) {
    std::printf("  SKIPPED no usable CUDA toolchain: %s\n",
                toolchain.status().to_string().c_str());
    return;
  }
  const ToolchainIdentity* identity = runtime.value()->toolchains().find(toolchain.value().id);
  CRF_REQUIRE(identity != nullptr);
  std::string device_arch;
  for (const EnvironmentVariable& attribute : identity->attributes) {
    if (attribute.name == "cuda.detected_device_arch") device_arch = attribute.value;
  }
  CRF_REQUIRE(!device_arch.empty());

  CRF_PHASE("CREATE_SESSION");
  const std::filesystem::path source = crftest::test_root() / "sources" / "crf_parity.cu";
  CRF_REQUIRE(crftest::write_text(source, cuda_source()));
  CompileRequest request;
  request.toolchain_family = ToolchainFamily::nvcc;
  request.sources = {source};
  request.run_smoke_test = true;
  request.target.architecture = Architecture::x64;
  request.target.os = OperatingSystem::windows;
  request.target.device_arch = device_arch;
  request.adapter_options.push_back(
      EnvironmentVariable{"cuda.expected_stdout", "CRF-CUDA-PARITY-OK"});
  const Result<Ref<CompilerSessionId>> created = runtime.value()->create_session(request);
  if (!created) {
    CRF_FAIL(created.status().to_string());
    return;
  }

  CRF_PHASE("COMPILE");
  const Result<CompileOutcome> outcome = runtime.value()->run_session(created.value().id);
  CRF_REQUIRE_OK(outcome);
  if (outcome.value().candidate.path.empty()) {
    const Result<CompilerSession> session = runtime.value()->require_session(created.value().id);
    std::printf("  outcome phases=%llu detail=%s\n",
                static_cast<unsigned long long>(outcome.value().phases.size()),
                outcome.value().detail.c_str());
    if (session) {
      for (const CompilerPhaseId id : session.value().plan.topological_order()) {
        const PhaseRecord* phase = session.value().find_phase(id);
        if (phase == nullptr) continue;
        std::printf("  phase %s state=%s status=%s detail=%s diagnostics=%s\n",
                    id.to_string().c_str(), std::string(to_string(phase->state)).c_str(),
                    std::string(to_string(phase->last_status)).c_str(), phase->last_detail.c_str(),
                    phase->diagnostics.id.to_string().c_str());
        const DiagnosticSet* captured =
            phase->diagnostics.id.present()
                ? runtime.value()->diagnostics().find(phase->diagnostics.id)
                : nullptr;
        if (captured == nullptr) continue;
        std::printf("    exit=%d errors=%u warnings=%u entries=%llu stdout=%llu stderr=%llu\n",
                    captured->exit_code, captured->error_count, captured->warning_count,
                    static_cast<unsigned long long>(captured->entries.size()),
                    static_cast<unsigned long long>(captured->raw_stdout_bytes),
                    static_cast<unsigned long long>(captured->raw_stderr_bytes));
        if (!captured->raw_stderr_tail.empty()) {
          std::printf("    stderr: %s\n", captured->raw_stderr_tail.c_str());
        }
        if (!captured->raw_stdout_tail.empty()) {
          std::printf("    stdout: %s\n", captured->raw_stdout_tail.c_str());
        }
      }
    }
    // A machine without a usable device must not be reported as a pass.
    bool device_missing = false;
    for (const PhaseRunReport& report : outcome.value().phases) {
      const DiagnosticSet* set = report.diagnostics.present()
                                     ? runtime.value()->diagnostics().find(report.diagnostics.id)
                                     : nullptr;
      if (set == nullptr) continue;
      if (!set->raw_stderr_tail.empty()) {
        std::printf("  raw stderr tail (%llu bytes): %s\n",
                    static_cast<unsigned long long>(set->raw_stderr_bytes),
                    set->raw_stderr_tail.c_str());
      }
      if (!set->raw_stdout_tail.empty()) {
        std::printf("  raw stdout tail (%llu bytes): %s\n",
                    static_cast<unsigned long long>(set->raw_stdout_bytes),
                    set->raw_stdout_tail.c_str());
      }
      for (const Diagnostic& entry : set->entries) {
        if (entry.message.find("no CUDA-capable device") != std::string::npos ||
            entry.message.find("NO-DEVICE") != std::string::npos) {
          device_missing = true;
        }
        std::printf("  %s %s\n", std::string(to_string(entry.severity)).c_str(),
                    entry.message.c_str());
      }
    }
    if (device_missing) {
      std::printf("  UNSUPPORTED no CUDA device is available on this machine\n");
      CRF_EXPECT_OK(runtime.value()->shutdown());
      return;
    }
    CRF_FAIL("CUDA session produced no candidate");
    return;
  }

  CRF_PHASE("VALIDATE");
  // The executed candidate reported its own device and compute capability, so
  // the supplied architecture is validated by real device execution rather than
  // asserted.
  bool reported_device = false;
  for (const PhaseRunReport& report : outcome.value().phases) {
    const DiagnosticSet* set = report.diagnostics.present()
                                   ? runtime.value()->diagnostics().find(report.diagnostics.id)
                                   : nullptr;
    if (set == nullptr) continue;
    if (set->raw_stdout_tail.find("CRF-CUDA-PARITY-OK") != std::string::npos) {
      reported_device = true;
      std::string captured = set->raw_stdout_tail;
      while (!captured.empty() && (captured.back() == '\n' || captured.back() == '\r')) {
        captured.pop_back();
      }
      std::printf("  candidate reported: %s\n", captured.c_str());
      CRF_EXPECT(captured.find("cc=12.") != std::string::npos);
    }
  }
  CRF_EXPECT(reported_device);
  CRF_EXPECT(outcome.value().candidate.format == ObjectFormat::coff_image);
  CRF_EXPECT(std::filesystem::exists(outcome.value().candidate.path));
  CRF_EXPECT(!outcome.value().candidate.content.zero());
  CRF_EXPECT(outcome.value().candidate.complete_lineage);
  CRF_EXPECT(outcome.value().evidence == EvidenceClass::real);
  bool device_code = false;
  for (const IntermediateArtifact& artifact : runtime.value()->artifacts().list()) {
    if (artifact.format != ObjectFormat::coff_object) continue;
    if (artifact.validation_detail.find("device") != std::string::npos) device_code = true;
  }
  CRF_EXPECT(device_code);

  CRF_PHASE("AUDIT");
  const Result<AuditReport> audit = runtime.value()->audit();
  CRF_REQUIRE_OK(audit);
  if (!audit.value().zero_violations()) std::printf("%s", audit.value().render().c_str());
  CRF_EXPECT(audit.value().zero_violations());
  CRF_EXPECT_OK(runtime.value()->shutdown());
  CRF_EXPECT_EQ(runtime.value()->processes().live_count(), static_cast<std::size_t>(0));
}
