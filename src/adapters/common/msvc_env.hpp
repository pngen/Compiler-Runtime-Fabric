#pragma once

// Discovery of an installed MSVC toolchain. Shared by the MSVC adapter and by
// the CUDA adapter, which needs an MSVC host compiler to link device code.

#include <filesystem>
#include <string>
#include <vector>

#include "crf/environment.hpp"
#include "crf/status.hpp"

namespace crf::adapters {

struct MsvcToolset {
  std::filesystem::path vs_root;
  std::filesystem::path vc_tools_root;
  std::filesystem::path host_bin_dir;
  std::filesystem::path cl;
  std::filesystem::path link;
  std::filesystem::path lib;
  std::string toolset_version;
  std::string compiler_version;
  std::string linker_version;
  std::filesystem::path sdk_root;
  std::string sdk_version;
  std::vector<std::filesystem::path> include_dirs;
  std::vector<std::filesystem::path> lib_dirs;
  std::vector<std::filesystem::path> path_dirs;
  std::filesystem::path standard_library;

  CRF_NODISCARD std::string include_value() const;
  CRF_NODISCARD std::string lib_value() const;
  CRF_NODISCARD std::string path_value() const;
};

/// Locate the installed toolset by scanning the standard Visual Studio roots and
/// the Windows SDK. Never relies on an ambient developer prompt.
CRF_NODISCARD Result<MsvcToolset> discover_msvc_toolset();

/// Run a component and return its combined banner output. The default argument
/// list is empty because cl.exe and link.exe print their version banner only
/// when they are invoked without options.
CRF_NODISCARD Result<std::string> probe_component_banner(
    const std::filesystem::path& executable, std::vector<std::string> arguments = {});

/// Extract a dotted version number from a banner line containing the keyword.
CRF_NODISCARD std::string extract_version(std::string_view text, std::string_view keyword);

}  // namespace crf::adapters
