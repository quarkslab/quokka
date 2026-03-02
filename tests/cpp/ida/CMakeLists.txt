protobuf_set_generated(quokka_proto)

add_executable(QuokkaTest_UnitTesting
        Quokka_test.cpp
        Bucket_test.cpp
        # Block_test.cpp
        "${quokka_BINARY_DIR}/proto/quokka.pb.cc")

add_dependencies(QuokkaTest_UnitTesting quokka_proto)

target_link_libraries(QuokkaTest_UnitTesting
        PUBLIC ida64)

target_include_directories(QuokkaTest_UnitTesting
        PRIVATE "${quokka_SOURCE_DIR}/include"
        "${quokka_BINARY_DIR}/proto"
        "${IdaSdk_INCLUDE_DIRS}")

target_compile_definitions(QuokkaTest_UnitTesting
        PUBLIC __EA64__ ${IdaSdk_PLATFORM} __X64__ __IDP__
               USE_DANGEROUS_FUNCTIONS USE_STANDARD_FILE_FUNCTIONS)

target_link_libraries(QuokkaTest_UnitTesting
        PRIVATE gtest gtest_main quokka_shared protobuf::libprotobuf)

gtest_discover_tests(QuokkaTest_UnitTesting)
