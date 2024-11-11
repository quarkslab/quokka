# Copyright 2011-2019 Google LLC. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# FindIdaSdk
# ----------
#
# This module is derived from FindIdaSdk.cmake from BinExport
# https://github.com/google/binexport/blob/main/cmake/FindIdaSdk.cmake
#
# Locates and configures the IDA Pro SDK. Only support version 7.0 or higher.
#
# Use this module by invoking find_package with the form:
#
#   find_package(IdaSdk
#                [REQUIRED]  # Fail with an error if IDA SDK is not found
#               )
#
# Defines the following variables:
#
#   IdaSdk_INCLUDE_DIRS - Include directories for the IDA Pro SDK.
#   IdaSdk_PLATFORM     - IDA SDK platform, one of __LINUX__, __NT__ or
#                         __MAC__.
#   IDA_ROOT_DIR        - IDA Binary
#   IdaSdk_LIB          - Windows: path to ida.lib for 64-bit address sizes
#   IdaSdk_LIB32        - Windows: full path to a suitable ida.lib for 32-bit
#                                  address aware IDA.
#
# This module reads hints about search locations from variables:
#
#   IdaSdk_ROOT_DIR  - SDK root dir
#   Ida_BIN_DIR      - IDA binary root dir

include(CMakeParseArguments)
include(FindPackageHandleStandardArgs)

find_path(IdaSdk_DIR NAMES include/pro.h
        HINTS ${IdaSdk_ROOT_DIR} ENV IDASDK_ROOT
        PATHS ${CMAKE_CURRENT_LIST_DIR}/../third_party/idasdk
        DOC "Location of the IDA SDK"
        NO_DEFAULT_PATH)
set(IdaSdk_INCLUDE_DIRS ${IdaSdk_DIR}/include)
set(IdaSdk_MODULE_DIRS ${IdaSdk_DIR}/module)

find_package_handle_standard_args(
        IdaSdk FOUND_VAR IdaSdk_FOUND
        REQUIRED_VARS IdaSdk_DIR
        IdaSdk_INCLUDE_DIRS
        FAIL_MESSAGE "IDA SDK not found, try setting IdaSdk_ROOT_DIR")

find_path(IDA_ROOT_DIR
        NAMES ida64
        PATHS /opt/
        HINTS ${Ida_BIN_DIR} ENV IDA_BIN
        DOC "Location of IDA root dir")

if (NOT IDA_ROOT_DIR)
    message(STATUS "Did not find IDA binary. Try to set Ida_BIN_DIR or env variable IDA_BIN")
else ()
    message(STATUS "Found IDA binary in ${IDA_ROOT_DIR}")
endif ()

if (UNIX)
    if (APPLE)
        set(IdaSdk_PLATFORM __MAC__)
        set(IdaLib ${IdaSdk_DIR}/lib/arm64_mac_clang_64_pro/libida64.dylib)
    else ()
        set(IdaSdk_PLATFORM __LINUX__)
        set(IdaLib ${IdaSdk_DIR}/lib/x64_linux_gcc_64/libida64.so)
    endif ()
elseif (WIN32)
    set(IdaSdk_PLATFORM __NT__)
    find_library(IdaSdk_LIB ida
      PATHS ${IdaSdk_DIR}/lib
      PATH_SUFFIXES x64_win_vc_64
                    # IDA SDK 8.2 and later
                    x64_win_vc_64_teams
                    x64_win_vc_64_pro
                    x64_win_vc_64_home
      NO_DEFAULT_PATH
    )
    find_library(IdaSdk_LIB32 ida
      PATHS ${IdaSdk_DIR}/lib
      PATH_SUFFIXES x64_win_vc_32
                    # IDA SDK 8.2 and later
                    x64_win_vc_32_teams
                    x64_win_vc_32_pro
                    x64_win_vc_32_home
      NO_DEFAULT_PATH
    )
    if(NOT IdaSdk_LIB OR NOT IdaSdk_LIB32)
      message(FATAL_ERROR "Missing ida.lib from SDK lib dir")
    endif()
    set(IdaLib ${IdaSdk_LIB})
else ()
    message(FATAL_ERROR "Unsupported system type: ${CMAKE_SYSTEM_NAME}")
endif ()

function(ida_common_target_settings t)
    # Add the necessary __IDP__ define and allow to use "dangerous" and standard
    # file functions.
    target_compile_definitions(${t} PUBLIC
            ${IdaSdk_PLATFORM} __X64__ __IDP__ USE_DANGEROUS_FUNCTIONS
            USE_STANDARD_FILE_FUNCTIONS __EA64__)

    target_include_directories(${t} PUBLIC ${IdaSdk_INCLUDE_DIRS})
endfunction()

function(_ida_plugin name link_script)  # ARGN contains sources
    # Define a module with the specified sources.
    add_library(${name} SHARED ${ARGN})
    ida_common_target_settings(${name})

    # Rename the plugin to have the proper naming scheme for IDA
    set_target_properties(${name} PROPERTIES
            PREFIX ""
            OUTPUT_NAME ${name}${PROJECT_VERSION_MAJOR}${PROJECT_VERSION_MINOR}64)

    if (UNIX)
        if (APPLE)
            target_link_libraries(${name}
                    -Wl,-flat_namespace
                    -Wl,-undefined,warning
                    -Wl,-exported_symbol,_PLUGIN
                    ${IdaLib})
        else ()
            # Always use the linker script needed for IDA.
            target_link_libraries(${name}
                    -Wl,--version-script ${IdaSdk_DIR}/${link_script})
        endif ()

        # For qrefcnt_obj_t in ida.hpp
        # TODO(cblichmann): This belongs in an interface library instead.
        target_compile_options(${name} PUBLIC -Wno-non-virtual-dtor)
    elseif (WIN32)
        target_link_libraries(${name} ${IdaSdk_LIB})
    endif ()
endfunction()

function(add_ida_library name)
    # Define the actual library.
    add_library(${name} ${ARGN})
    ida_common_target_settings(${name})
endfunction()

function(add_ida_plugin name)
    _ida_plugin(${name} plugins/exports.def ${ARGN})
endfunction()

function(add_ida_loader name)
    _ida_plugin(${name} ldr/exports.def ${ARGN})
endfunction()
