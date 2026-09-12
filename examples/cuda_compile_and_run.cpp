// Example: a real CUDA compile and device execution.
//
// The example detects the installed toolkit and device architecture, compiles a
// kernel with nvcc, links it with the host compiler, validates that the object
// actually carries device code, and executes the candidate. The candidate itself
// performs host-to-device transfer, a kernel launch, device-to-host transfer and
// a CPU parity check, so the parity result is produced by the device, not by the
// runtime.

#include "crf_example.hpp"

using namespace crf;
using namespace crf::examples;

namespace {

const char* kCudaSource = R"CUDA(
#include <cstdio>
#include <cuda_runtime.h>

__global__ void crf_example_scale(const float* in, float* out, int n, float factor) {
  const int index = blockIdx.x * blockDim.x + threadIdx.x;
  if (index < n) out[index] = in[index] * factor;
}

int main() {
  const int n = 2048;
  const float factor = 1.5f;
  float in[n];
  float out[n];
  for (int i = 0; i < n; ++i) { in[i] = static_cast<float>(i); out[i] = -1.0f; }
  int devices = 0;
  if (cudaGetDeviceCount(&devices) != cudaSuccess || devices == 0) {
    std::printf("CRF-EXAMPLE-NO-DEVICE\n");
    return 3;
  }
  cudaDeviceProp properties{};
  cudaGetDeviceProperties(&properties, 0);
  float* device_in = nullptr;
  float* device_out = nullptr;
  const std::size_t bytes = sizeof(float) * static_cast<std::size_t>(n);
  if (cudaMalloc(&device_in, bytes) != cudaSuccess) return 4;
  if (cudaMalloc(&device_out, bytes) != cudaSuccess) return 4;
  if (cudaMemcpy(device_in, in, bytes, cudaMemcpyHostToDevice) != cudaSuccess) return 5;
  crf_example_scale<<<(n + 255) / 256, 256>>>(device_in, device_out, n, factor);
  if (cudaGetLastError() != cudaSuccess) return 6;
  if (cudaDeviceSynchronize() != cudaSuccess) return 6;
  if (cudaMemcpy(out, device_out, bytes, cudaMemcpyDeviceToHost) != cudaSuccess) return 7;
  cudaFree(device_in);
  cudaFree(device_out);
  double worst = 0.0;
  for (int i = 0; i < n; ++i) {
    const double expected = static_cast<double>(i) * factor;
    const double difference = static_cast<double>(out[i]) - expected;
    const double magnitude = difference < 0 ? -difference : difference;
    if (magnitude > worst) worst = magnitude;
  }
  if (worst > 1e-4) { std::printf("CRF-EXAMPLE-PARITY-FAILED\n"); return 8; }
  std::printf("CRF-EXAMPLE-PARITY-OK device=%s cc=%d.%d\n", properties.name, properties.major,
              properties.minor);
  return 0;
}
)CUDA";

}  // namespace

int main() {
  banner("CUDA compile and device execution");
  Scratch scratch("cuda-compile-and-run");
  RuntimeOptions options = runtime_options(scratch, "cuda-example");
  Result<std::unique_ptr<Runtime>> runtime = Runtime::create(options);
  if (!runtime) {
    refusal("runtime creation", runtime.status());
    return 1;
  }
  Runtime& crf = *runtime.value();
  // The device architecture is supplied explicitly. The adapter records whether
  // it was supplied or probed, and the executed candidate reports its own device
  // and compute capability, which is what validates the architecture.
  ToolchainProbeRequest probe;
  probe.family = ToolchainFamily::nvcc;
  probe.target.architecture = Architecture::x64;
  probe.target.os = OperatingSystem::windows;
  probe.target.device_arch = "sm_120";
  Result<Ref<ToolchainId>> toolchain =
      crf.discover_toolchain(ToolchainFamily::nvcc, probe);
  if (!toolchain) {
    line("UNSUPPORTED: " + toolchain.status().to_string());
    line("no CUDA toolkit was found; this example does not model CUDA execution");
    const VoidResult stopped = crf.shutdown();
    (void)stopped;
    return 0;
  }
  const ToolchainIdentity* identity = crf.toolchains().find(toolchain.value().id);
  if (identity == nullptr) return 1;
  line("toolkit: " + identity->display_name + " version=" + identity->version);
  std::string device_arch;
  for (const EnvironmentVariable& attribute : identity->attributes) {
    line("  " + attribute.name + "=" + attribute.value);
    if (attribute.name == "cuda.detected_device_arch") device_arch = attribute.value;
  }

  const std::filesystem::path source = scratch.write("scale.cu", kCudaSource);
  CompileRequest request;
  request.toolchain_family = ToolchainFamily::nvcc;
  request.sources = {source};
  request.run_smoke_test = true;
  request.target.architecture = Architecture::x64;
  request.target.os = OperatingSystem::windows;
  request.target.device_arch = device_arch;
  request.adapter_options.push_back(
      EnvironmentVariable{"cuda.expected_stdout", "CRF-EXAMPLE-PARITY-OK"});

  Result<Ref<CompilerSessionId>> session = crf.create_session(request);
  if (!session) {
    refusal("session creation", session.status());
    return 1;
  }
  line("session: " + session.value().id.to_string());
  line("target device architecture: " + device_arch);

  Result<CompileOutcome> outcome = crf.run_session(session.value().id);
  if (!outcome) {
    refusal("session execution", outcome.status());
    return 1;
  }
  for (const PhaseRunReport& report : outcome.value().phases) {
    line("  " + std::string(to_string(report.state)) + " " + report.phase.id.to_string() +
         " status=" + std::string(to_string(report.status)));
  }
  if (outcome.value().candidate.path.empty()) {
    line("no candidate was produced; the diagnostics above explain why");
    const VoidResult stopped = crf.shutdown();
    (void)stopped;
    return 1;
  }
  line("candidate: " + outcome.value().candidate.path.string());
  line("  sha256 " + outcome.value().candidate.content.to_hex());
  line("the device reported CPU parity for the kernel result");

  Result<AuditReport> audit = crf.audit();
  if (audit) line(audit.value().render());
  const VoidResult stopped = crf.shutdown();
  (void)stopped;
  return 0;
}
