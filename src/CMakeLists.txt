include_guard()

# Prevent usage of deprecated IDA SDK Functions
if (NO_DEPRECATED)
    add_compile_definitions(NO_OBSOLETE_FUNCS)
endif ()

ida_get_version(IDA_SDK_VERSION)
message(STATUS "Compiling against IDA SDK ${IDA_SDK_VERSION}.")

if(IDA_SDK_VERSION VERSION_GREATER "850" OR IDA_SDK_VERSION VERSION_EQUAL "850")
        # No 32 bit version in IDA >= 8.5
        set(VAR_NOEA32 NOEA32)
endif()

add_ida_library(quokka_shared STATIC ${VAR_NOEA32}
        "Block.cpp"
        # "Comment.cpp"
        "Data.cpp"
        "DataType.cpp"
        "FileMetadata.cpp"
        "Function.cpp"
        "Imports.cpp"
        # "Instruction.cpp"
        "Layout.cpp"
        # "Reference.cpp"
        "Segment.cpp"
        "Util.cpp"
        "Writer.cpp")

ida_target_include_directories(quokka_shared 
        PRIVATE "${quokka_SOURCE_DIR}/include"
                "${GENERATED_INCLUDE_DIR}"
                "${quokka_BINARY_DIR}/proto"
)

ida_target_link_libraries(quokka_shared PUBLIC
        quokka_proto
        protobuf::libprotobuf
        absl::strings
        absl::str_format
        absl::time
        absl::flat_hash_map
        absl::hash)

add_ida_plugin(quokka_plugin ${VAR_NOEA32} "Quokka.cpp")

ida_target_include_directories(quokka_plugin 
        PRIVATE "${quokka_SOURCE_DIR}/include"
                "${GENERATED_INCLUDE_DIR}"
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