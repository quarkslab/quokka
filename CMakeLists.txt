cmake_minimum_required(VERSION 3.13)

find_program(CCACHE_PROGRAM ccache
        PATHS /opt/ccache)

if (CCACHE_PROGRAM)
    message(STATUS "Enable ccache")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif ()

set(CMAKE_OSX_DEPLOYMENT_TARGET "11.0" CACHE STRING "Targeting MacOS Version" FORCE)

project(quokka
        DESCRIPTION "Quokka: A Fast and Accurate Binary Exporter"
        VERSION 0.6.0
        LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

include(FetchContent)
include(CheckLinkerFlag)
include(GoogleTest)

if (PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
    cmake_print_variables(PROJECT_SOURCE_DIR PROJECT_BINARY_DIR)
    message(FATAL_ERROR "In source builds are not allowed")
endif ()


if (NOT CMAKE_BUILD_TYPE)
    # Set a default build type if none was specified.
    # Warning: does work only for single configurations generators
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif ()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_INSTALL_PREFIX ${quokka_BINARY_DIR})

option(BUILD_TEST "Build C++ test binaries (need gtest)" OFF)
option(NO_BUILD "Don't build plugin" OFF)
option(NO_DEPRECATED "Don't use deprecated functions from IDA SDK" OFF)
option(ENABLE_SANITIZER "Enable address sanitizer" OFF)

if (UNIX)
    if(APPLE)
        add_compile_options(
            -gfull
            -Wno-nullability-completeness
        )

        # Originates from google/binexport
        # https://github.com/google/binexport/blob/85c89a4ab96febcccc4cdc01ca5fc6c005e9a2cf/cmake/CompileOptions.cmake#L71-L74
        check_linker_flag(CXX "LINKER:-ld_classic" _ld_classic_supported)
        if(_ld_classic_supported)
          add_link_options(LINKER:-ld_classic)
        endif()

        add_link_options(
            -dead_strip
        )        
    else()
    endif()
elseif(WIN32)
endif()

if (NOT NO_BUILD)

    if (ENABLE_SANITIZER)
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls)
        add_link_options(-fsanitize=address)

    endif ()

    set(ABSL_PROPAGATE_CXX_STD ON)

    FetchContent_Declare(
            abseil
            GIT_REPOSITORY https://github.com/abseil/abseil-cpp.git
            GIT_TAG 20220623.1
    )
    FetchContent_MakeAvailable(abseil)

    FetchContent_Declare(
            protobuf
            GIT_REPOSITORY https://github.com/protocolbuffers/protobuf.git
            SOURCE_SUBDIR cmake
            GIT_TAG v30.2
    )
    set(protobuf_BUILD_TESTS OFF CACHE INTERNAL "")
    set(protobuf_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    set(protobuf_BUILD_EXPORT OFF)
    set(protobuf_WITH_ZLIB_DEFAULT OFF CACHE BOOL "" FORCE)
    set(protobuf_USE_STATIC_LIBS ON CACHE BOOL "" FORCE)
    set(protobuf_MSVC_STATIC_RUNTIME OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(protobuf)

    # Find protoc
    set(_PROTOBUF_PROTOC $<TARGET_FILE:protoc>)

    # Include protobuf functions
    include(cmake/protobuf.cmake)

    find_package(IdaSdk REQUIRED)

    add_subdirectory(proto)

    add_subdirectory(src)

endif ()

if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TEST)
    FetchContent_Declare(
            googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            GIT_TAG release-1.12.1
    )
    FetchContent_MakeAvailable(googletest)

    enable_testing()
    add_subdirectory(tests)
endif ()
