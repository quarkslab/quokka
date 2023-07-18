include_guard()

configure_file(Version.cpp.in Version.cpp @ONLY)

add_library(quokka_version STATIC
        "${CMAKE_CURRENT_BINARY_DIR}/Version.cpp")

target_include_directories(quokka_version
        PRIVATE "${quokka_SOURCE_DIR}/include")


# Prevent usage of deprecated IDA SDK Functions
if (NO_DEPRECATED)
    add_compile_definitions(NO_OBSOLETE_FUNCS)
endif ()

add_library(quokka_shared STATIC
        "Block.cpp"
        "Comment.cpp"
        "Data.cpp"
        "FileMetadata.cpp"
        "Function.cpp"
        "Imports.cpp"
        "Instruction.cpp"
        "Layout.cpp"
        "Reference.cpp"
        "Segment.cpp"
        "Util.cpp"
        "Writer.cpp"
        "${quokka_BINARY_DIR}/proto/quokka.pb.cc")

protobuf_set_generated(quokka_proto)

add_dependencies(quokka_shared quokka_proto)

target_include_directories(quokka_shared PRIVATE
        "${quokka_SOURCE_DIR}/include"
        "${quokka_BINARY_DIR}/proto")

ida_common_target_settings(quokka_shared)

target_link_libraries(quokka_shared PUBLIC
        quokka_version
        protobuf::libprotobuf
        absl::strings
        absl::str_format
        absl::time
        absl::flat_hash_map
        absl::hash)

add_ida_plugin(quokka_plugin
        "Quokka.cpp")

target_include_directories(quokka_plugin
        PUBLIC "${quokka_SOURCE_DIR}/include"
        "${quokka_BINARY_DIR}/proto")

set_target_properties(quokka_plugin
        PROPERTIES POSITION_INDEPENDENT_CODE ON)

if (NOT ${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
    target_link_libraries(
            quokka_plugin
            quokka_shared
            absl::strings
            absl::str_format
            stdc++fs
            protobuf::libprotobuf
    )
else ()
    target_link_libraries(
            quokka_plugin
            quokka_shared
            absl::strings
            absl::str_format
            protobuf::libprotobuf
    )
endif ()


install(TARGETS quokka_plugin
        LIBRARY DESTINATION $ENV{HOME}/.idapro/plugins)


if (IDA_ROOT_DIR)
    install(TARGETS quokka_plugin
            LIBRARY DESTINATION ${IDA_ROOT_DIR}/plugins)

endif ()

install(TARGETS quokka_plugin
        ARCHIVE DESTINATION quokka-install
        RUNTIME DESTINATION quokka-install
        LIBRARY DESTINATION quokka-install)