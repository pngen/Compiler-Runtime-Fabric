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
    # ASan needs debug info at runtime; keep the PDB next to the binary.
    target_compile_options(${target} PRIVATE $<IF:$<CONFIG:Debug>,/Od,/O1>)
  else()
    target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(${target} PRIVATE -fsanitize=address)
  endif()
endfunction()
