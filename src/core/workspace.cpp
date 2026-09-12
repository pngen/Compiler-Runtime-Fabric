#include "crf/workspace.hpp"
#include "crf/canonical.hpp"

#include <algorithm>
#include <fstream>
#include <mutex>
#include <system_error>

#if defined(_WIN32)
#  include <windows.h>
#endif

namespace crf {
namespace {

constexpr const char* kMarkerName = ".crf-workspace.marker";
constexpr const char* kMarkerMagic = "crf-workspace/1";

CRF_NODISCARD bool is_reparse_point(const std::filesystem::path& path) {
#if defined(_WIN32)
  const DWORD attributes = ::GetFileAttributesW(path.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES) return false;
  return (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
  std::error_code ec;
  return std::filesystem::is_symlink(std::filesystem::symlink_status(path, ec));
#endif
}

CRF_NODISCARD std::string marker_body(CompilerSessionId session,
                                      CompilerSessionGeneration session_generation,
                                      CompilerPhaseId phase,
                                      CompilerPhaseGeneration phase_generation,
                                      std::uint64_t created_at_nanos) {
  std::string body;
  body.append(kMarkerMagic);
  body.push_back('\n');
  body.append("session=" + session.to_string() + "\n");
  body.append("session-generation=" + session_generation.to_string() + "\n");
  body.append("phase=" + phase.to_string() + "\n");
  body.append("phase-generation=" + phase_generation.to_string() + "\n");
  body.append("created=" + std::to_string(created_at_nanos) + "\n");
  return body;
}

CRF_NODISCARD std::string marker_contents(const std::string& body) {
  return body + "digest=" + Digest::of(body).to_hex() + "\n";
}

CRF_NODISCARD bool write_file_atomic(const std::filesystem::path& path, std::string_view contents) {
  const std::filesystem::path temporary = path.string() + ".tmp";
  {
    std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
    if (!stream) return false;
    stream.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    stream.flush();
    if (!stream) return false;
  }
#if defined(_WIN32)
  if (::MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING) == 0) {
    std::error_code ec;
    std::filesystem::remove(temporary, ec);
    return false;
  }
#else
  std::error_code ec;
  std::filesystem::rename(temporary, path, ec);
  if (ec) {
    std::filesystem::remove(temporary, ec);
    return false;
  }
#endif
  return true;
}

CRF_NODISCARD std::string read_file(const std::filesystem::path& path, std::size_t max_bytes) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) return {};
  std::string out;
  out.resize(max_bytes);
  stream.read(out.data(), static_cast<std::streamsize>(out.size()));
  out.resize(static_cast<std::size_t>(stream.gcount()));
  return out;
}

CRF_NODISCARD std::string marker_field(const std::string& contents, std::string_view key) {
  const std::string needle = std::string(key) + "=";
  std::size_t start = 0;
  while (start < contents.size()) {
    std::size_t end = contents.find('\n', start);
    if (end == std::string::npos) end = contents.size();
    const std::string_view line(contents.data() + start, end - start);
    if (line.size() > needle.size() && line.substr(0, needle.size()) == needle) {
      return std::string(line.substr(needle.size()));
    }
    start = end + 1;
  }
  return {};
}

}  // namespace

std::string_view to_string(WorkspaceDefect value) noexcept {
  switch (value) {
    case WorkspaceDefect::none: return "none";
    case WorkspaceDefect::missing: return "missing";
    case WorkspaceDefect::marker_missing: return "marker-missing";
    case WorkspaceDefect::marker_corrupt: return "marker-corrupt";
    case WorkspaceDefect::session_mismatch: return "session-mismatch";
    case WorkspaceDefect::generation_mismatch: return "generation-mismatch";
    case WorkspaceDefect::phase_mismatch: return "phase-mismatch";
    case WorkspaceDefect::reparse_point: return "reparse-point";
    case WorkspaceDefect::escape: return "escape";
    case WorkspaceDefect::too_deep: return "too-deep";
  }
  return "unknown";
}

std::filesystem::path Workspace::inputs_directory() const { return root / "inputs"; }
std::filesystem::path Workspace::outputs_directory() const { return root / "outputs"; }
std::filesystem::path Workspace::temp_directory() const { return root / "temp"; }
std::filesystem::path Workspace::logs_directory() const { return root / "logs"; }

Result<std::filesystem::path> Workspace::resolve(std::string_view relative) const {
  if (!valid) {
    return Status(StatusCode::invalid_argument, "workspace is not valid");
  }
  if (relative.empty()) {
    return Status(StatusCode::invalid_argument, "workspace-relative path is empty");
  }
  if (relative.size() > 4096) {
    return Status(StatusCode::invalid_argument, "workspace-relative path is too long");
  }
  if (relative.find('\0') != std::string_view::npos) {
    return Status(StatusCode::path_traversal, "workspace-relative path contains a NUL byte");
  }
  const std::filesystem::path candidate(relative);
  if (candidate.is_absolute() || candidate.has_root_name() || candidate.has_root_directory()) {
    return Status(StatusCode::path_traversal,
                  "workspace-relative path must not be absolute or drive-relative");
  }
  if (path_has_traversal(candidate)) {
    return Status(StatusCode::path_traversal,
                  "workspace-relative path escapes with a parent component: " + std::string(relative));
  }
  const std::filesystem::path resolved = normalize_path(root / candidate);
  if (!path_is_within(resolved, root)) {
    return Status(StatusCode::workspace_escape,
                  "resolved path escapes the workspace: " + resolved.string());
  }
  // Refuse to traverse an existing reparse point: a junction inside the
  // workspace would silently redirect writes outside it.
  std::filesystem::path walk = root;
  for (const std::filesystem::path& component : candidate) {
    walk /= component;
    std::error_code ec;
    if (!std::filesystem::exists(walk, ec) || ec) break;
    if (is_reparse_point(walk)) {
      return Status(StatusCode::reparse_point_rejected,
                    "workspace path crosses a reparse point: " + walk.string());
    }
  }
  return resolved;
}

bool Workspace::contains(const std::filesystem::path& candidate) const {
  if (!valid) return false;
  return path_is_within(normalize_path(candidate), root);
}

struct WorkspaceManager::Impl {
  explicit Impl(WorkspaceOptions value) : options(std::move(value)) {}

  WorkspaceOptions options;
  mutable std::mutex mutex;
  std::vector<std::filesystem::path> live;
};

WorkspaceManager::WorkspaceManager(WorkspaceOptions options)
    : impl_(std::make_unique<Impl>(std::move(options))) {
  if (!impl_->options.base_directory.empty()) {
    impl_->options.base_directory = normalize_path(impl_->options.base_directory);
  }
}

WorkspaceManager::~WorkspaceManager() = default;

const WorkspaceOptions& WorkspaceManager::options() const noexcept { return impl_->options; }

const std::filesystem::path& WorkspaceManager::base_directory() const noexcept {
  return impl_->options.base_directory;
}

Result<Workspace> WorkspaceManager::create(CompilerSessionId session,
                                           CompilerSessionGeneration session_generation,
                                           CompilerPhaseId phase,
                                           CompilerPhaseGeneration phase_generation,
                                           std::string_view label) {
  if (!session.present() || !phase.present()) {
    return Status(StatusCode::invalid_identity, "workspace requires a session and phase identity");
  }
  if (impl_->options.base_directory.empty()) {
    return Status(StatusCode::invalid_argument, "workspace base directory is not configured");
  }

  std::filesystem::path root = impl_->options.base_directory / session.to_string() /
                               (phase.to_string() + "-g" + phase_generation.to_string());
  if (!label.empty()) {
    std::string suffix(label);
    suffix.erase(std::remove_if(suffix.begin(), suffix.end(),
                                [](char c) {
                                  return !(std::isalnum(static_cast<unsigned char>(c)) != 0 ||
                                           c == '-' || c == '_');
                                }),
                 suffix.end());
    if (suffix.size() > 64) suffix.resize(64);
    if (!suffix.empty()) root += "-" + suffix;
  }
  root = normalize_path(root);
  if (!path_is_within(root, impl_->options.base_directory)) {
    return Status(StatusCode::workspace_escape, "workspace root escapes the configured base");
  }

  std::error_code ec;
  std::filesystem::create_directories(impl_->options.base_directory, ec);
  if (ec) {
    return Status(StatusCode::permission_denied,
                  "workspace base directory could not be created: " + ec.message());
  }

  // An existing directory at this exact generation-bound path is never adopted:
  // it is moved aside so that stale content can never be mistaken for current.
  if (std::filesystem::exists(root, ec) && !ec) {
    std::filesystem::path stale = root;
    stale += ".stale";
    for (int attempt = 0; attempt < 1000 && std::filesystem::exists(stale, ec); ++attempt) {
      stale = root;
      stale += ".stale-" + std::to_string(attempt + 1);
    }
    std::filesystem::rename(root, stale, ec);
    if (ec) {
      return Status(StatusCode::already_exists,
                    "a stale workspace exists and could not be moved aside: " + ec.message());
    }
  }

  std::filesystem::create_directories(root, ec);
  if (ec) {
    return Status(StatusCode::permission_denied, "workspace could not be created: " + ec.message());
  }
  Workspace workspace;
  workspace.root = root;
  workspace.session = session;
  workspace.session_generation = session_generation;
  workspace.phase = phase;
  workspace.phase_generation = phase_generation;

  for (const std::filesystem::path& directory :
       {workspace.inputs_directory(), workspace.outputs_directory(), workspace.temp_directory(),
        workspace.logs_directory()}) {
    std::filesystem::create_directories(directory, ec);
    if (ec) {
      return Status(StatusCode::permission_denied,
                    "workspace subdirectory could not be created: " + ec.message());
    }
  }

  const std::string body =
      marker_body(session, session_generation, phase, phase_generation, wall_nanos());
  const std::string contents = marker_contents(body);
  if (!write_file_atomic(root / kMarkerName, contents)) {
    return Status(StatusCode::persistence_io, "workspace marker could not be written");
  }
  workspace.marker_digest = Digest::of(body);
  workspace.valid = true;

  {
    const std::lock_guard<std::mutex> guard(impl_->mutex);
    impl_->live.push_back(root);
  }
  return workspace;
}

Result<Workspace> WorkspaceManager::open(const std::filesystem::path& root,
                                         CompilerSessionId session,
                                         CompilerSessionGeneration session_generation,
                                         CompilerPhaseId phase,
                                         CompilerPhaseGeneration phase_generation) const {
  const WorkspaceInspection inspection = inspect(root);
  Workspace workspace;
  workspace.root = normalize_path(root);
  workspace.session = inspection.session;
  workspace.session_generation = inspection.session_generation;
  workspace.phase = inspection.phase;
  workspace.phase_generation = inspection.phase_generation;
  if (!inspection.acceptable()) {
    workspace.valid = false;
    return Status(StatusCode::invalid_argument,
                  std::string("workspace rejected: ") + std::string(to_string(inspection.defect)) +
                      " " + inspection.detail);
  }
  if (inspection.session != session || inspection.session_generation != session_generation) {
    workspace.valid = false;
    return Status(StatusCode::stale_session_generation,
                  "workspace belongs to a different session generation");
  }
  if (inspection.phase != phase || inspection.phase_generation != phase_generation) {
    workspace.valid = false;
    return Status(StatusCode::stale_phase_generation,
                  "workspace belongs to a different phase generation");
  }
  workspace.marker_digest = inspection.marker_digest;
  workspace.valid = true;
  return workspace;
}

WorkspaceInspection WorkspaceManager::inspect(const std::filesystem::path& root) const {
  WorkspaceInspection inspection;
  inspection.root = normalize_path(root);
  std::error_code ec;
  if (!std::filesystem::exists(inspection.root, ec) || ec) {
    inspection.defect = WorkspaceDefect::missing;
    inspection.detail = "workspace directory does not exist";
    return inspection;
  }
  if (is_reparse_point(inspection.root)) {
    inspection.defect = WorkspaceDefect::reparse_point;
    inspection.detail = "workspace root is a reparse point";
    return inspection;
  }
  const std::filesystem::path marker = inspection.root / kMarkerName;
  if (!std::filesystem::exists(marker, ec) || ec) {
    inspection.defect = WorkspaceDefect::marker_missing;
    inspection.detail = "workspace marker is missing";
    inspection.stale = true;
    return inspection;
  }
  const std::string contents = read_file(marker, 4096);
  if (contents.empty()) {
    inspection.defect = WorkspaceDefect::marker_corrupt;
    inspection.detail = "workspace marker is empty or unreadable";
    inspection.stale = true;
    return inspection;
  }
  const std::size_t digest_at = contents.find("digest=");
  if (digest_at == std::string::npos) {
    inspection.defect = WorkspaceDefect::marker_corrupt;
    inspection.detail = "workspace marker has no digest";
    inspection.stale = true;
    return inspection;
  }
  const std::string body = contents.substr(0, digest_at);
  if (!starts_with_ci(body, kMarkerMagic)) {
    inspection.defect = WorkspaceDefect::marker_corrupt;
    inspection.detail = "workspace marker has an unknown schema";
    inspection.stale = true;
    return inspection;
  }
  std::string recorded = marker_field(contents, "digest");
  recorded = std::string(trim_ascii(recorded));
  Digest recorded_digest;
  if (!Digest::from_hex(recorded, recorded_digest) || recorded_digest != Digest::of(body)) {
    inspection.defect = WorkspaceDefect::marker_corrupt;
    inspection.detail = "workspace marker digest does not match its contents";
    inspection.stale = true;
    return inspection;
  }
  inspection.session = CompilerSessionId::parse(marker_field(contents, "session"));
  inspection.session_generation =
      CompilerSessionGeneration::from_value(std::strtoull(marker_field(contents, "session-generation").c_str(), nullptr, 10));
  inspection.phase = CompilerPhaseId::parse(marker_field(contents, "phase"));
  inspection.phase_generation =
      CompilerPhaseGeneration::from_value(std::strtoull(marker_field(contents, "phase-generation").c_str(), nullptr, 10));
  inspection.created_at_nanos =
      std::strtoull(marker_field(contents, "created").c_str(), nullptr, 10);
  if (!inspection.session.present() || !inspection.phase.present()) {
    inspection.defect = WorkspaceDefect::marker_corrupt;
    inspection.detail = "workspace marker carries absent identities";
    inspection.stale = true;
    return inspection;
  }
  inspection.marker_digest = recorded_digest;
  inspection.defect = WorkspaceDefect::none;
  inspection.detail = "workspace marker verified";
  return inspection;
}

VoidResult WorkspaceManager::cleanup(const Workspace& workspace) {
  if (impl_->options.base_directory.empty()) {
    return Status(StatusCode::invalid_argument, "workspace base directory is not configured");
  }
  if (!path_is_within(workspace.root, impl_->options.base_directory)) {
    return Status(StatusCode::workspace_escape,
                  "refusing to remove a directory outside the workspace base");
  }
  if (normalize_path(workspace.root) == normalize_path(impl_->options.base_directory)) {
    return Status(StatusCode::workspace_escape, "refusing to remove the workspace base itself");
  }
  std::error_code ec;
  std::filesystem::remove_all(workspace.root, ec);
  if (ec) {
    return Status(StatusCode::permission_denied, "workspace removal failed: " + ec.message());
  }
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = std::find(impl_->live.begin(), impl_->live.end(), normalize_path(workspace.root));
  if (found != impl_->live.end()) impl_->live.erase(found);
  return VoidResult{};
}

Result<std::filesystem::path> WorkspaceManager::stage_input(const Workspace& workspace,
                                                            const std::filesystem::path& source,
                                                            std::string_view logical_name) {
  if (!workspace.valid) {
    return Status(StatusCode::invalid_argument, "workspace is not valid");
  }
  Digest content;
  if (!Digest::of_file(source, content)) {
    return Status(StatusCode::not_found, "input could not be hashed: " + source.string());
  }
  std::string name = logical_name.empty() ? source.filename().string() : std::string(logical_name);
  for (char& c : name) {
    if (c == '/' || c == '\\' || c == ':' || c == '\0') {
      return Status(StatusCode::path_traversal, "staged input name contains a path separator");
    }
  }
  if (name.empty() || name == "." || name == "..") {
    return Status(StatusCode::invalid_argument, "staged input name is invalid");
  }
  const Result<std::filesystem::path> destination = workspace.resolve("inputs/" + name);
  if (!destination) return destination.status();
  std::error_code ec;
  std::filesystem::copy_file(source, destination.value(),
                             std::filesystem::copy_options::overwrite_existing, ec);
  if (ec) {
    return Status(StatusCode::permission_denied, "input staging failed: " + ec.message());
  }
  Digest staged;
  if (!Digest::of_file(destination.value(), staged) || staged != content) {
    return Status(StatusCode::output_corrupt, "staged input digest does not match the source");
  }
  return destination.value();
}

std::size_t WorkspaceManager::live_workspace_count() const noexcept {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->live.size();
}

std::vector<std::filesystem::path> WorkspaceManager::live_workspaces() const {
  const std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->live;
}

std::size_t WorkspaceManager::cleanup_all() {
  std::vector<std::filesystem::path> roots;
  {
    const std::lock_guard<std::mutex> guard(impl_->mutex);
    roots = impl_->live;
    impl_->live.clear();
  }
  std::size_t removed = 0;
  for (const std::filesystem::path& root : roots) {
    if (!path_is_within(root, impl_->options.base_directory)) continue;
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    if (!ec) ++removed;
  }
  return removed;
}

}  // namespace crf
