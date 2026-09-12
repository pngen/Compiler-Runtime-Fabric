# Installed consumer

This directory is deliberately *not* part of the Compiler Runtime Fabric build.
It is a separate CMake project that consumes an installed package exactly the way
a downstream user would.

```
cmake -S examples/consumer -B <build-dir> -DCMAKE_PREFIX_PATH=<install-prefix>
cmake --build <build-dir> --config Release
<build-dir>/crf_consumer
```

The consumer:

1. calls `find_package(CompilerRuntimeFabric CONFIG REQUIRED)`;
2. includes only installed headers under `<prefix>/include/crf`;
3. links the exported namespaced targets `crf::core` and `crf::adapters`;
4. creates a compiler-session model with strongly typed identities;
5. validates a toolchain contract (components, target support, INCLUDE/LIB);
6. compiles, links and executes a real program through the installed runtime;
7. validates a phase plan built against the installed API;
8. runs the invariant audit and requires zero violations.

It never references the source tree, so it proves the exported package is
self-contained.
