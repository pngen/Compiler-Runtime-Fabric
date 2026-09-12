# Compiler Runtime Fabric test suites.
#
# Each suite is a standalone executable with a stable, filterable case name set.
# A suite prints a flushed BEGIN line per case and a PASS/FAIL line with elapsed
# time and check count, so a hang identifies the exact case and the last phase.

set(CRF_TEST_SUITES
  test_core
  test_persistence
  test_protocol
  test_msvc
  test_cuda
  test_property
  test_concurrency
  test_adversarial
  test_recovery
  test_multiprocess
)

set(CRF_TEST_PRESENT "")
foreach(suite IN LISTS CRF_TEST_SUITES)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${suite}.cpp")
    list(APPEND CRF_TEST_PRESENT "${suite}")
  endif()
endforeach()

set(CRF_TEST_LIBS crf_core crf_adapters)
if(TARGET crf_ipc)
  list(APPEND CRF_TEST_LIBS crf_ipc)
endif()

foreach(suite IN LISTS CRF_TEST_PRESENT)
  add_executable(${suite} ${suite}.cpp test_main.cpp)
  target_link_libraries(${suite} PRIVATE ${CRF_TEST_LIBS})
  target_include_directories(${suite} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_compile_definitions(${suite} PRIVATE
    CRF_TEST_WORKSPACE_ROOT="${CMAKE_CURRENT_BINARY_DIR}/crf-test-work"
    CRF_TEST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
  crf_apply_strict_options(${suite})
  crf_enable_asan(${suite})
  add_test(NAME ${suite} COMMAND ${suite})
  set_tests_properties(${suite} PROPERTIES TIMEOUT 3600)
endforeach()

# The multiprocess proof drives the real coordinator and worker executables.
if(TARGET crf_coordinator AND TARGET test_multiprocess)
  add_dependencies(test_multiprocess crf_coordinator crf_worker)
  target_compile_definitions(test_multiprocess PRIVATE
    CRF_TOOL_DIR="$<TARGET_FILE_DIR:crf_coordinator>")
endif()
