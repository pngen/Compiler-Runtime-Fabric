# Control-plane executables.

add_executable(crf_coordinator coordinator/main.cpp)
target_link_libraries(crf_coordinator PRIVATE crf_core crf_adapters crf_ipc)
crf_apply_strict_options(crf_coordinator)
crf_enable_asan(crf_coordinator)

add_executable(crf_worker worker/main.cpp)
target_link_libraries(crf_worker PRIVATE crf_core crf_adapters crf_ipc)
crf_apply_strict_options(crf_worker)
crf_enable_asan(crf_worker)

add_executable(crf_cli cli/main.cpp)
target_link_libraries(crf_cli PRIVATE crf_core crf_adapters crf_ipc)
crf_apply_strict_options(crf_cli)
crf_enable_asan(crf_cli)

install(TARGETS crf_coordinator crf_worker crf_cli
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
