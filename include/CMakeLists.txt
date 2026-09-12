# Generated public header: version.hpp.
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/crf/version.hpp.in"
  "${CMAKE_CURRENT_BINARY_DIR}/crf/version.hpp"
  @ONLY)

# Header-only interface target. Exported so that downstream consumers get the
# installed include directory through the same namespaced target they link.
add_library(crf_headers INTERFACE)
add_library(crf::headers ALIAS crf_headers)
target_include_directories(crf_headers INTERFACE
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>"
  "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")
target_compile_features(crf_headers INTERFACE cxx_std_20)

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/crf"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        PATTERN "*.in" EXCLUDE)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/crf/version.hpp"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/crf")

install(TARGETS crf_headers EXPORT CompilerRuntimeFabricTargets)
