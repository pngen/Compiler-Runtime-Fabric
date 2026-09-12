#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "crf/digest.hpp"
#include "crf/status.hpp"
#include "crf/strong_id.hpp"

namespace crf {

/// A generation-bound directory tree owned by one session phase.
///
/// Workspace contents never confer authority. A file existing in a workspace is
/// not evidence that it is current: only a committed phase makes its output
/// authoritative.
struct CRF_API Workspace {
  std::filesystem::path root;
  CompilerSessionId session{};
  CompilerSessionGeneration session_generation{};
  CompilerPhaseId phase{};
  CompilerPhaseGeneration phase_generation{};
  Digest marker_digest{};
  bool valid = false;

  CRF_NODISCARD std::filesystem::path inputs_directory() const;
  CRF_NODISCARD std::filesystem::path outputs_directory() const;
  CRF_NODISCARD std::filesystem::path temp_directory() const;
  CRF_NODISCARD std::filesystem::path logs_directory() const;

  /// Resolve a relative path inside the workspace. Refuses traversal, absolute
  /// paths, drive-relative paths, embedded NULs, and any existing component
  /// that is a reparse point.
  CRF_NODISCARD Result<std::filesystem::path> resolve(std::string_view relative) const;
  /// True when an existing path is inside this workspace after resolving
  /// reparse points.
  CRF_NODISCARD bool contains(const std::filesystem::path& candidate) const;
};

/// Why a workspace was rejected.
enum class WorkspaceDefect : std::uint8_t {
  none = 0,
  missing = 1,
  marker_missing = 2,
  marker_corrupt = 3,
  session_mismatch = 4,
  generation_mismatch = 5,
  phase_mismatch = 6,
  reparse_point = 7,
  escape = 8,
  too_deep = 9,
};

CRF_NODISCARD CRF_API std::string_view to_string(WorkspaceDefect value) noexcept;

struct CRF_API WorkspaceInspection {
  WorkspaceDefect defect = WorkspaceDefect::none;
  std::filesystem::path root;
  CompilerSessionId session{};
  CompilerSessionGeneration session_generation{};
  CompilerPhaseId phase{};
  CompilerPhaseGeneration phase_generation{};
  std::uint64_t created_at_nanos = 0;
  /// Digest over the marker body that the workspace was created with.
  Digest marker_digest{};
  bool stale = false;
  std::string detail;

  CRF_NODISCARD bool acceptable() const noexcept { return defect == WorkspaceDefect::none; }
};

struct CRF_API WorkspaceOptions {
  std::filesystem::path base_directory;
  std::size_t max_relative_depth = 32;
  /// Refuse to descend into reparse points when resolving paths.
  bool reject_reparse_points = true;
  /// Delete a workspace when its phase is retired. Off by default so that
  /// post-mortem evidence survives a failed phase.
  bool cleanup_on_retire = false;
};

/// Creates, validates, and tears down workspaces.
class CRF_API WorkspaceManager {
 public:
  explicit WorkspaceManager(WorkspaceOptions options);
  ~WorkspaceManager();
  WorkspaceManager(const WorkspaceManager&) = delete;
  WorkspaceManager& operator=(const WorkspaceManager&) = delete;

  CRF_NODISCARD const WorkspaceOptions& options() const noexcept;

  /// Create a fresh generation-bound workspace. An existing directory at the
  /// same path is never adopted: it is renamed aside and reported as stale.
  CRF_NODISCARD Result<Workspace> create(CompilerSessionId session,
                                         CompilerSessionGeneration session_generation,
                                         CompilerPhaseId phase,
                                         CompilerPhaseGeneration phase_generation,
                                         std::string_view label = {});

  /// Open an existing workspace and verify its marker against the expected
  /// identity. A mismatch yields a defect and marks the workspace invalid.
  CRF_NODISCARD Result<Workspace> open(const std::filesystem::path& root,
                                       CompilerSessionId session,
                                       CompilerSessionGeneration session_generation,
                                       CompilerPhaseId phase,
                                       CompilerPhaseGeneration phase_generation) const;

  /// Inspect any directory for a workspace marker without prior expectations.
  CRF_NODISCARD WorkspaceInspection inspect(const std::filesystem::path& root) const;

  /// Remove a workspace tree. Refuses to remove anything that is not contained
  /// in the configured base directory.
  CRF_NODISCARD VoidResult cleanup(const Workspace& workspace);

  /// Stage an input file into the workspace and verify its digest.
  CRF_NODISCARD Result<std::filesystem::path> stage_input(const Workspace& workspace,
                                                          const std::filesystem::path& source,
                                                          std::string_view logical_name = {});

  CRF_NODISCARD std::size_t live_workspace_count() const noexcept;
  CRF_NODISCARD std::vector<std::filesystem::path> live_workspaces() const;
  CRF_NODISCARD const std::filesystem::path& base_directory() const noexcept;

  /// Remove every workspace tree below the base directory that this manager
  /// created in this process. Used by tests and clean shutdown.
  CRF_NODISCARD std::size_t cleanup_all();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace crf
