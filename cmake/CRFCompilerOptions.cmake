# Strict, reproducible first-party compile options for Compiler Runtime Fabric.
#
# Every first-party target is expected to build clean at /W4 /WX /permissive- on
# MSVC and -Wall -Wextra -Werror elsewhere. Warnings are fixed at the root cause;
# suppression pragmas are not permitted in first-party sources.
include_guard(GLOBAL)

function(crf_apply_strict_options target)
  if(MSVC)
    target_compile_options(${target} PRIVATE
      /W4
      /permissive-
      /w14242 /w14254 /w14263 /w14265 /w14287 /w14296 /w14311 /w14545 /w14546
      /w14547 /w14549 /w14555 /w14619 /w14640 /w14826 /w14905 /w14906 /w14928)
    if(CRF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    # Deterministic debug information improves reproducible packaging.
    target_compile_options(${target} PRIVATE $<$<CONFIG:Release>:/Gy>)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion)
    if(CRF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()

function(crf_enable_asan target)
  if(NOT CRF_ENABLE_ASAN)
    return()
  endif()
  if(MSVC)
    target_compile_options(${target} PRIVATE /fsanitize=address /Zi)
    target_link_options(${target} PRIVATE /INCREMENTAL:NO)
    # An instrumented executable loads the ASan runtime DLL. Processes started
    # through the runtime's supervisor get a minimal PATH, so the DLL is placed
    # next to every instrumented executable.
    get_target_property(_crf_type ${target} TYPE)
    get_filename_component(_crf_cl_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
    set(_crf_asan_dll "${_crf_cl_dir}/clang_rt.asan_dynamic-x86_64.dll")
    if(_crf_type STREQUAL "EXECUTABLE" AND EXISTS "${_crf_asan_dll}")
      add_custom_command(TARGET ${target} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_crf_asan_dll}" "$<TARGET_FILE_DIR:${target}>")
    endif()
  else()
    target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(${target} PRIVATE -fsanitize=address)
  endif()
endfunction()
