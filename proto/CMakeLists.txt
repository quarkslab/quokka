include_guard()

set(PROTO_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}")

add_library(quokka_proto OBJECT "${CMAKE_CURRENT_LIST_DIR}/quokka.proto")

protobuf_generate(
        TARGET quokka_proto
        LANGUAGE cpp)

target_link_libraries(quokka_proto PUBLIC protobuf::libprotobuf)

protobuf_generate(
        TARGET quokka_proto
        LANGUAGE python)
