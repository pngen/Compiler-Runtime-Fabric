#include "msvc_env.hpp"

#include <algorithm>
#include <cstdlib>
#include <system_error>

#include "crf/canonical.hpp"
#include "crf/process.hpp"

namespace crf::adapters {
namespace {

CRF_NODISCARD std::vector<std::filesystem::path> candidate_vs_roots() {
  std::vector<std::filesystem::path> roots;
  const auto push = [&roots](const char* root) {
    std::error_code ec;
    // Paths are canonicalised on the way in: the runtime never lets a
    // mixed-separator path reach a child process command line.
    const std::filesystem::path path = normalize_path(std::filesystem::path(root));
    if (std::filesystem::is_directory(path, ec) && !ec) roots.push_back(path);
  };
  push("C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools");
  push("C:/Program Files (x86)/Microsoft Visual Studio/2022/Community");
  push("C:/Program Files (x86)/Microsoft Visual Studio/2022/Professional");
  push("C:/Program Files (x86)/Microsoft Visual Studio/2022/Enterprise");
  push("C:/Program Files/Microsoft Visual Studio/2022/BuildTools");
  push("C:/Program Files/Microsoft Visual Studio/2022/Community");
  push("C:/Program Files/Microsoft Visual Studio/2022/Professional");
  push("C:/Program Files/Microsoft Visual Studio/2022/Enterprise");
  return roots;
}

CRF_NODISCARD std::vector<std::string> list_versions(const std::filesystem::path& parent) {
  std::vector<std::string> versions;
  std::error_code ec;
  if (!std::filesystem::is_directory(parent, ec) || ec) return versions;
  for (const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator(parent, ec)) {
    if (ec) break;
    if (!entry.is_directory(ec) || ec) continue;
    versions.push_back(entry.path().filename().string());
  }
  std::sort(versions.begin(), versions.end());
  return versions;
}

CRF_NODISCARD bool has_file(const std::filesystem::path& path) {
  std::error_code ec;
  return std::filesystem::is_regular_file(path, ec) && !ec;
}

}  // namespace

std::string MsvcToolset::include_value() const {
  std::string out;
  for (const std::filesystem::path& path : include_dirs) {
    if (!out.empty()) out.push_back(';');
    out.append(path.string());
  }
  return out;
}

std::string MsvcToolset::lib_value() const {
  std::string out;
  for (const std::filesystem::path& path : lib_dirs) {
    if (!out.empty()) out.push_back(';');
    out.append(path.string());
  }
  return out;
}

std::string MsvcToolset::path_value() const {
  std::string out;
  for (const std::filesystem::path& path : path_dirs) {
    if (!out.empty()) out.push_back(';');
    out.append(path.string());
  }
  return out;
}

Result<std::string> probe_component_banner(const std::filesystem::path& executable,
                                           std::vector<std::string> arguments) {
  ProcessSpec spec;
  spec.executable = executable;
  spec.arguments = std::move(arguments);
  spec.max_capture_bytes = 64u * 1024u;
  // A tool banner probe still runs a real process, so it gets a real, explicit
  // environment rather than an empty block. The probe inherits the ambient
  // environment because vendor tools legitimately depend on it; the environment
  // a governed phase runs under is composed separately and never inherits.
  EnvironmentSpec environment;
  const Result<std::vector<EnvironmentVariable>> block = build_process_environment(environment);
  if (block) spec.environment = block.value();
  spec.inherit_ambient_environment = true;
  ProcessSupervisor supervisor;
  const Result<ProcessOutcome> outcome =
      supervisor.run(spec, Ref<InvocationId>{InvocationId::from_value(1), InvocationGeneration::initial()});
  supervisor.close();
  if (!outcome) return outcome.status();
  std::string banner = outcome.value().capture.standard_output;
  banner.append(outcome.value().capture.standard_error);
  if (banner.empty() && !outcome.value().exited_zero()) {
    // A version banner is emitted even when the tool refuses the arguments;
    // an empty capture with a failed launch is the only real failure.
    return Status(StatusCode::probe_failed,
                  "component produced no banner output: " + executable.string());
  }
  return banner;
}

std::string extract_version(std::string_view text, std::string_view keyword) {
  std::size_t search = 0;
  while (search < text.size()) {
    const std::size_t position = text.find(keyword, search);
    if (position == std::string_view::npos) break;
    std::size_t cursor = position + keyword.size();
    while (cursor < text.size() && (text[cursor] == ' ' || text[cursor] == ':')) ++cursor;
    std::string version;
    while (cursor < text.size()) {
      const char c = text[cursor];
      const bool is_version_char = (c >= '0' && c <= '9') || c == '.';
      if (!is_version_char) break;
      version.push_back(c);
      ++cursor;
    }
    while (!version.empty() && version.back() == '.') version.pop_back();
    if (!version.empty()) return version;
    search = position + keyword.size();
  }
  return {};
}

Result<MsvcToolset> discover_msvc_toolset() {
  MsvcToolset toolset;
  for (const std::filesystem::path& root : candidate_vs_roots()) {
    const std::vector<std::string> versions = list_versions(root / "VC" / "Tools" / "MSVC");
    for (auto it = versions.rbegin(); it != versions.rend(); ++it) {
      const std::filesystem::path tools = root / "VC" / "Tools" / "MSVC" / *it;
      const std::filesystem::path bin = tools / "bin" / "Hostx64" / "x64";
      if (!has_file(bin / "cl.exe") || !has_file(bin / "link.exe")) continue;
      toolset.vs_root = normalize_path(root);
      toolset.vc_tools_root = normalize_path(tools);
      toolset.host_bin_dir = normalize_path(bin);
      toolset.toolset_version = *it;
      break;
    }
    if (!toolset.host_bin_dir.empty()) break;
  }
  if (toolset.host_bin_dir.empty()) {
    return Status(StatusCode::toolchain_not_found,
                  "no MSVC toolset with cl.exe and link.exe was found in the standard roots");
  }
  toolset.cl = normalize_path(toolset.host_bin_dir / "cl.exe");
  toolset.link = normalize_path(toolset.host_bin_dir / "link.exe");
  toolset.lib = normalize_path(toolset.host_bin_dir / "lib.exe");
  toolset.path_dirs.push_back(toolset.host_bin_dir);
  if (has_file(toolset.lib)) {
    // lib.exe sits beside cl.exe; nothing else to add.
  }

  // Windows SDK.
  const std::vector<std::filesystem::path> sdk_roots = {
      std::filesystem::path("C:/Program Files (x86)/Windows Kits/10"),
      std::filesystem::path("C:/Program Files/Windows Kits/10")};
  for (const std::filesystem::path& sdk : sdk_roots) {
    const std::vector<std::string> includes = list_versions(sdk / "Include");
    for (auto it = includes.rbegin(); it != includes.rend(); ++it) {
      const std::filesystem::path include_root = sdk / "Include" / *it;
      const std::filesystem::path lib_root = sdk / "Lib" / *it;
      std::error_code ec;
      if (!std::filesystem::is_directory(include_root / "um", ec) || ec) continue;
      if (!std::filesystem::is_directory(lib_root / "um" / "x64", ec) || ec) continue;
      toolset.sdk_root = normalize_path(sdk);
      toolset.sdk_version = *it;
      for (const char* name : {"ucrt", "shared", "um", "winrt", "cppwinrt"}) {
        const std::filesystem::path directory = include_root / name;
        if (std::filesystem::is_directory(directory, ec) && !ec) {
          toolset.include_dirs.push_back(directory);
        }
      }
      for (const char* name : {"ucrt", "um"}) {
        const std::filesystem::path directory = lib_root / name / "x64";
        if (std::filesystem::is_directory(directory, ec) && !ec) {
          toolset.lib_dirs.push_back(directory);
        }
      }
      const std::filesystem::path sdk_bin = sdk / "bin" / *it / "x64";
      if (std::filesystem::is_directory(sdk_bin, ec) && !ec) toolset.path_dirs.push_back(sdk_bin);
      break;
    }
    if (!toolset.sdk_version.empty()) break;
  }

  toolset.include_dirs.insert(toolset.include_dirs.begin(), toolset.vc_tools_root / "include");
  toolset.lib_dirs.insert(toolset.lib_dirs.begin(), toolset.vc_tools_root / "lib" / "x64");
  toolset.standard_library = toolset.vc_tools_root / "lib" / "x64" / "msvcprt.lib";

  const Result<std::string> cl_banner = probe_component_banner(toolset.cl);
  if (cl_banner) {
    toolset.compiler_version = extract_version(cl_banner.value(), "Version");
  } else {
    return Status(StatusCode::probe_failed,
                  "cl.exe banner probe failed: " + cl_banner.status().to_string());
  }
  const Result<std::string> link_banner = probe_component_banner(toolset.link);
  if (link_banner) toolset.linker_version = extract_version(link_banner.value(), "Linker");
  if (toolset.compiler_version.empty()) {
    return Status(StatusCode::probe_failed,
                  "cl.exe did not report a compiler version; banner bytes=" +
                      std::to_string(cl_banner.value().size()) + " banner=\"" +
                      cl_banner.value().substr(0, 160) + "\"");
  }
  if (toolset.sdk_version.empty()) {
    return Status(StatusCode::probe_failed, "no Windows SDK include and library set was found");
  }
  return toolset;
}

}  // namespace crf::adapters
