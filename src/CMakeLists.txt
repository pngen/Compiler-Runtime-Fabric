# Compiler Runtime Fabric core library.
#
# Everything vendor-neutral lives here: identity, authority, toolchain and
# environment models, phase lifecycle, workspaces, subprocess supervision,
# persistence, recovery, and the invariant audit. Adapters live in
# src/adapters and depend on this library, never the other way round.

set(CRF_CORE_SOURCES
  core/adapter.cpp
  core/artifact.cpp
  core/audit.cpp
  core/authority.cpp
  core/canonical.cpp
  core/component.cpp
  core/diagnostics.cpp
  core/digest.cpp
  core/environment.cpp
  core/evidence.cpp
  core/explain.cpp
  core/invocation.cpp
  core/persistence.cpp
  core/phase.cpp
  core/phase_plan.cpp
  core/policy.cpp
  core/process.cpp
  core/provenance.cpp
  core/recovery.cpp
  core/retry.cpp
  core/runtime.cpp
  core/session.cpp
  core/source.cpp
  core/status.cpp
  core/target.cpp
  core/toolchain.cpp
  core/workspace.cpp
)

# The configured source list is filtered against the files that exist so the
# build stays usable while a module is being written.
set(CRF_CORE_PRESENT "")
foreach(source IN LISTS CRF_CORE_SOURCES)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${source}")
    list(APPEND CRF_CORE_PRESENT "${source}")
  endif()
endforeach()

add_library(crf_core STATIC ${CRF_CORE_PRESENT})
add_library(crf::core ALIAS crf_core)
target_link_libraries(crf_core PUBLIC crf_headers)
target_compile_definitions(crf_core PRIVATE CRF_BUILDING_LIBRARY)
set_target_properties(crf_core PROPERTIES
  OUTPUT_NAME "compiler_runtime_fabric"
  EXPORT_NAME "core"
  POSITION_INDEPENDENT_CODE ON)
crf_apply_strict_options(crf_core)
crf_enable_asan(crf_core)

if(WIN32)
  target_link_libraries(crf_core PUBLIC ws2_32)
endif()

add_subdirectory(adapters)

# Protocol and control-plane helpers built on top of the core.
set(CRF_IPC_SOURCES
  ipc/protocol.cpp
  ipc/messages.cpp
  ipc/service.cpp
  ipc/client.cpp
)
set(CRF_IPC_PRESENT "")
foreach(source IN LISTS CRF_IPC_SOURCES)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${source}")
    list(APPEND CRF_IPC_PRESENT "${source}")
  endif()
endforeach()

set(CRF_INSTALL_TARGETS crf_core)
if(CRF_IPC_PRESENT)
  add_library(crf_ipc STATIC ${CRF_IPC_PRESENT})
  add_library(crf::ipc ALIAS crf_ipc)
  target_link_libraries(crf_ipc PUBLIC crf_core)
  # Internal headers (ipc/service.hpp) are exported for the tools and the
  # multiprocess proof, which embed the same services the daemons run.
  target_include_directories(crf_ipc PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")
  target_compile_definitions(crf_ipc PRIVATE CRF_BUILDING_LIBRARY)
  set_target_properties(crf_ipc PROPERTIES
    OUTPUT_NAME "compiler_runtime_fabric_ipc"
    EXPORT_NAME "ipc")
  crf_apply_strict_options(crf_ipc)
  crf_enable_asan(crf_ipc)
  list(APPEND CRF_INSTALL_TARGETS crf_ipc)
endif()

if(TARGET crf_adapters)
  list(APPEND CRF_INSTALL_TARGETS crf_adapters)
endif()

install(TARGETS ${CRF_INSTALL_TARGETS}
        EXPORT CompilerRuntimeFabricTargets
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
