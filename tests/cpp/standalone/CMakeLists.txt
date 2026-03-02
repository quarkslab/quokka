add_executable(QuokkaTest_DataType
        DataType_test.cpp)

target_link_libraries(QuokkaTest_DataType
        PRIVATE gtest gtest_main absl::flat_hash_map)

gtest_discover_tests(QuokkaTest_DataType)
