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

add_ida_library(quokka_shared STATIC
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
        "Writer.cpp")

ida_target_include_directories(quokka_shared 
        PRIVATE "${quokka_SOURCE_DIR}/include"
                "${quokka_BINARY_DIR}/proto"
)

ida_target_link_libraries(quokka_shared PUBLIC
        quokka_version
        quokka_proto
        protobuf::libprotobuf
        absl::strings
        absl::str_format
        absl::time
        absl::flat_hash_map
        absl::hash)

add_ida_plugin(quokka_plugin
        "Quokka.cpp")

ida_target_include_directories(quokka_plugin 
        PRIVATE "${quokka_SOURCE_DIR}/include"
                "${quokka_BINARY_DIR}/proto"
)

set_ida_target_properties(quokka_plugin
         PROPERTIES POSITION_INDEPENDENT_CODE ON)

ida_target_link_libraries(
        quokka_plugin
        quokka_shared
        absl::strings
        absl::str_format
        protobuf::libprotobuf
)

ida_install(TARGETS quokka_plugin
        LIBRARY DESTINATION $ENV{HOME}/.idapro/plugins)


if (IDA_ROOT_DIR)
    ida_install(TARGETS quokka_plugin
            LIBRARY DESTINATION ${IDA_ROOT_DIR}/plugins)

endif ()

ida_install(TARGETS quokka_plugin
        ARCHIVE DESTINATION quokka-install
        RUNTIME DESTINATION quokka-install
        LIBRARY DESTINATION quokka-install)