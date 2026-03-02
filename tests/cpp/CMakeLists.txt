# Standalone tests (no IDA SDK needed) - always built
include_guard()

add_executable(QuokkaTest_DataType
        DataType_test.cpp)

target_link_libraries(QuokkaTest_DataType
        PRIVATE gtest gtest_main absl::flat_hash_map)

gtest_discover_tests(QuokkaTest_DataType)

# Util tests (standalone copies of utility logic)
add_executable(QuokkaTest_Util
        Util_test.cpp)

target_link_libraries(QuokkaTest_Util
        PRIVATE gtest gtest_main absl::time absl::strings)

gtest_discover_tests(QuokkaTest_Util)

# Bucket tests (uses actual Bucket.h/ProtoHelper.h headers, no IDA needed)
add_executable(QuokkaTest_Bucket
        Bucket_test.cpp)

target_include_directories(QuokkaTest_Bucket
        PRIVATE ${PROJECT_SOURCE_DIR}/include/quokka)

target_link_libraries(QuokkaTest_Bucket
        PRIVATE gtest gtest_main absl::flat_hash_set absl::btree absl::hash)

gtest_discover_tests(QuokkaTest_Bucket)
