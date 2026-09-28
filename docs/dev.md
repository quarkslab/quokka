# Devs Tips & Tricks

## Debug the Plugin

First, generate a debug build using the option `CMAKE_BUILD_TYPE=Debug`. This will 
decrease the performances but allow to debug the plugin easily.

### Setup for CLion

It is possible to perform a `step-by-step` debug of the plugin while running with IDA.
The following steps are using [CLion](https://www.jetbrains.com/clion/) but are 
adaptable for other IDEs.

1. First, configure the Profiles for the project. The two most important options 
   are the SDK Root directory and the IDA bin directory.
   ![Profile Window](img/Profile.png)
2. Create a Run/Debug configuration
   ![Debug](img/Debug.png)
   - Set the target to `quokka_plugin`
   - Set the executable to be your `idat` file
   - Set arguments (the same you would use on the command line)
   - Add some environment variables:
     - IDALOG=/path/to/file Save the IDA's output in a file
     - TVHEADLESS=1 - Improve the speed
   - Set Build and Install as action before launch.

If you set a breakpoint in the code, you can now debug your plugin by simply 
running `Debug` in CLion interface.

### Use Sanitizers

By using the `ENABLE_SANITIZER` option in `CMake`, you enable
[ASan](https://github.com/google/sanitizers/wiki/AddressSanitizer).

Of note, to run with IDA, you need to specify the path to Asan using `LD_PRELOAD`.

## Running Tests

All suites (C++, Python offline, IDA / Ghidra / Binary Ninja integration, Ghidra JUnit,
Binary Ninja extension), their requirements and the CI workflows are described in
[`tests/README.md`](https://github.com/quarkslab/quokka/blob/main/tests/README.md).
