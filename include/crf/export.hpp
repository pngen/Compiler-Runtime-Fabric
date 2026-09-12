#pragma once

// Compiler Runtime Fabric - shared library export control.
//
// The library builds as a static archive by default. Defining
// CRF_BUILD_SHARED_LIBRARY switches the annotations to DLL semantics on
// Windows so the same sources serve both packaging modes.

#if defined(_WIN32) && defined(CRF_BUILD_SHARED_LIBRARY)
#  if defined(CRF_BUILDING_LIBRARY)
#    define CRF_API __declspec(dllexport)
#  else
#    define CRF_API __declspec(dllimport)
#  endif
#  define CRF_LOCAL
#else
#  define CRF_API
#  define CRF_LOCAL
#endif

#if defined(__GNUC__) || defined(__clang__)
#  define CRF_MAYBE_UNUSED [[maybe_unused]]
#else
#  define CRF_MAYBE_UNUSED [[maybe_unused]]
#endif

#define CRF_NODISCARD [[nodiscard]]
