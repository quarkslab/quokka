include_guard()

# Standalone tests (no IDA SDK needed) - always built
add_subdirectory(standalone)

# IDA-dependent tests - only when explicitly enabled.
# Currently broken: IDA SDK kernel symbols (msg(), error(),
# replace_wait_box()) are not available outside the plugin runtime.
# Enable with -DBUILD_IDA_TESTS=On once fixed.
option(BUILD_IDA_TESTS "Build tests that require IDA SDK runtime" OFF)
if(BUILD_IDA_TESTS)
    add_subdirectory(ida)
endif()
