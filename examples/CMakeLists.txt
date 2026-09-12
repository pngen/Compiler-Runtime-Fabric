# Runnable examples. Each example uses only the public API.

set(CRF_EXAMPLES
  msvc_compile_session
  compile_link_and_run
  failure_and_retry
  stale_toolchain_rejection
  restart_recovery
  cuda_compile_and_run
  distributed_handoff
)

foreach(example IN LISTS CRF_EXAMPLES)
  add_executable(crf_example_${example} ${example}.cpp)
  target_link_libraries(crf_example_${example} PRIVATE crf_core crf_adapters)
  target_include_directories(crf_example_${example} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  crf_apply_strict_options(crf_example_${example})
  crf_enable_asan(crf_example_${example})
endforeach()

if(TARGET crf_ipc)
  target_link_libraries(crf_example_distributed_handoff PRIVATE crf_ipc)
endif()

# The downstream consumer is built and installed separately: see
# examples/consumer/README.md.
