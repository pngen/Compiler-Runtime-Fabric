cmake_minimum_required(VERSION 3.20)

project(CompilerRuntimeFabric
        VERSION 1.0.0
        DESCRIPTION "Vendor-neutral C++20 runtime for governing compiler-runtime execution"
        HOMEPAGE_URL "https://github.com/pngen/Compiler-Runtime-Fabric"
        LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CRFCompilerOptions)

# ---------------------------------------------------------------------------
# Global language level. C++20 is a hard requirement of the runtime core.
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(CRF_BUILD_TESTS "Build the Compiler Runtime Fabric test suites" ON)
option(CRF_BUILD_EXAMPLES "Build the Compiler Runtime Fabric examples" ON)
option(CRF_BUILD_BENCHMARKS "Build the Compiler Runtime Fabric benchmarks" ON)
option(CRF_BUILD_TOOLS "Build coordinator, worker and CLI executables" ON)
option(CRF_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
option(CRF_ENABLE_ASAN "Instrument first-party targets with AddressSanitizer" OFF)
option(CRF_ENABLE_IPO "Enable interprocedural optimization for Release builds" OFF)

# When consumed through add_subdirectory() or FetchContent, default to building
# only the library so downstream projects are not surprised by extra targets.
if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(CRF_IS_TOP_LEVEL OFF)
  option(CRF_AS_SUBPROJECT_BUILD_TOOLS "Build tools when used as a subproject" OFF)
  set(CRF_BUILD_TESTS OFF CACHE BOOL "Build the Compiler Runtime Fabric test suites" FORCE)
  set(CRF_BUILD_EXAMPLES OFF CACHE BOOL "Build the Compiler Runtime Fabric examples" FORCE)
  set(CRF_BUILD_BENCHMARKS OFF CACHE BOOL "Build the Compiler Runtime Fabric benchmarks" FORCE)
  set(CRF_BUILD_TOOLS ${CRF_AS_SUBPROJECT_BUILD_TOOLS} CACHE BOOL "Build tools" FORCE)
else()
  set(CRF_IS_TOP_LEVEL ON)
endif()

if(MSVC)
  # /Zc:__cplusplus is required for correct __cplusplus values under MSVC.
  add_compile_options(/Zc:__cplusplus /utf-8 /EHsc /MP)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
  if(CRF_ENABLE_IPO AND CMAKE_BUILD_TYPE STREQUAL "Release")
    include(CheckIPOSupported)
    check_ipo_supported(RESULT CRF_IPO_OK OUTPUT CRF_IPO_ERR)
    if(CRF_IPO_OK)
      set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    else()
      message(STATUS "IPO not supported: ${CRF_IPO_ERR}")
    endif()
  endif()
endif()

add_subdirectory(include)
add_subdirectory(src)
if(CRF_BUILD_TOOLS)
  add_subdirectory(tools)
endif()
if(CRF_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
if(CRF_BUILD_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()
if(CRF_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Installation: exported targets, package config, version config.
# ---------------------------------------------------------------------------
install(EXPORT CompilerRuntimeFabricTargets
        FILE CompilerRuntimeFabricTargets.cmake
        NAMESPACE crf::
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/CompilerRuntimeFabric")

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CompilerRuntimeFabricConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/CompilerRuntimeFabricConfig.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/CompilerRuntimeFabric")

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/CompilerRuntimeFabricConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/CompilerRuntimeFabricConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/CompilerRuntimeFabricConfigVersion.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/CompilerRuntimeFabric")

install(FILES LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/CompilerRuntimeFabric")
install(FILES README.md DESTINATION "${CMAKE_INSTALL_DATADIR}/CompilerRuntimeFabric")

message(STATUS "Compiler Runtime Fabric ${PROJECT_VERSION} | top-level=${CRF_IS_TOP_LEVEL} | build=${CMAKE_BUILD_TYPE}${CMAKE_CONFIGURATION_TYPES}")
