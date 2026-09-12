# Compiler adapters. Vendor-specific knowledge is confined to this directory.

set(CRF_ADAPTER_FILES
  msvc/msvc_adapter.cpp
  cuda/cuda_adapter.cpp
  synthetic/synthetic_adapter.cpp
  common/pe_coff.cpp
  common/msvc_env.cpp
)
set(CRF_ADAPTER_PRESENT "")
foreach(source IN LISTS CRF_ADAPTER_FILES)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${source}")
    list(APPEND CRF_ADAPTER_PRESENT "${source}")
  endif()
endforeach()

if(NOT CRF_ADAPTER_PRESENT)
  message(STATUS "No adapter sources present yet")
  return()
endif()

add_library(crf_adapters STATIC ${CRF_ADAPTER_PRESENT})
add_library(crf::adapters ALIAS crf_adapters)
target_link_libraries(crf_adapters PUBLIC crf_core)
target_compile_definitions(crf_adapters PRIVATE CRF_BUILDING_LIBRARY)
target_include_directories(crf_adapters PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
set_target_properties(crf_adapters PROPERTIES
  OUTPUT_NAME "compiler_runtime_fabric_adapters"
  EXPORT_NAME "adapters")
crf_apply_strict_options(crf_adapters)
crf_enable_asan(crf_adapters)
