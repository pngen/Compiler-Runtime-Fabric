cmake_minimum_required(VERSION 3.20)
project(CrfInstalledConsumer LANGUAGES CXX)

# The consumer only ever sees the installed package. It must not reach into the
# Compiler Runtime Fabric source tree.
find_package(CompilerRuntimeFabric CONFIG REQUIRED)

add_executable(crf_consumer main.cpp)
target_link_libraries(crf_consumer PRIVATE crf::core crf::adapters)
target_compile_features(crf_consumer PRIVATE cxx_std_20)

message(STATUS "Consumer using CompilerRuntimeFabric ${CompilerRuntimeFabric_VERSION} "
               "from ${CompilerRuntimeFabric_DIR}")
