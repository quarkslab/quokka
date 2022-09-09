include_guard()

get_filename_component(hw_proto "quokka.proto" ABSOLUTE)

protobuf_generate_python(PROTO_PY "${hw_proto}")
protobuf_generate_cpp(PROTO_SRC PROTO_HDRS "${hw_proto}")

add_custom_target(quokka_python ALL
        DEPENDS "${PROTO_PY}")

add_custom_target(quokka_proto
        DEPENDS ${PROTO_SRC} ${PROTO_HDRS})

set_target_properties(quokka_proto PROPERTIES
        GENERATED_FILES "${PROTO_SRC};${PROTO_HDRS}")

set_target_properties(quokka_python PROPERTIES
        GENERATED_FILES ${PROTO_PY})