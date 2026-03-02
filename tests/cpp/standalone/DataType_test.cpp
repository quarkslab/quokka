// Unit test for the key-snapshot iteration pattern used in
// ExportCompositeDataTypes().
//
// Verifies that snapshotting keys before iterating over an
// absl::flat_hash_map allows safe insertion of new entries during the
// loop without iterator invalidation.
//
// This is a standalone test that mirrors the DataTypes collection layout
// without depending on IDA SDK types.

#include <cstddef>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "gtest/gtest.h"

#include "absl/container/flat_hash_map.h"

namespace {

// Minimal type stubs mirroring quokka::StructureType, UnionType, etc.
struct StructStub {
  std::string name;
};
struct UnionStub {
  std::string name;
};
struct PointerStub {
  std::string name;
};
struct ArrayStub {
  std::string name;
};

using TypeVariant =
    std::variant<StructStub, UnionStub, PointerStub, ArrayStub>;

using MapT = absl::flat_hash_map<int, std::unique_ptr<TypeVariant>>;

// Helper: snapshot keys whose variant holds one of the requested types.
template <typename... Ts>
std::vector<int> SnapshotKeys(const MapT& map) {
  std::vector<int> keys;
  for (const auto& [k, v] : map) {
    if ((std::holds_alternative<Ts>(*v) || ...))
      keys.push_back(k);
  }
  return keys;
}

// Verify that the key-snapshot pattern survives insertions that would
// invalidate a live iterator over the underlying flat_hash_map.
TEST(KeySnapshotIteration, InsertDuringIteration) {
  MapT map;

  // Seed with StructStub and UnionStub entries (like ExportStructOrUnion)
  constexpr int kStructCount = 100;
  constexpr int kUnionCount = 100;
  for (int i = 0; i < kStructCount; ++i) {
    map.emplace(
        i,
        std::make_unique<TypeVariant>(StructStub{"s" + std::to_string(i)}));
  }
  for (int i = 0; i < kUnionCount; ++i) {
    map.emplace(
        kStructCount + i,
        std::make_unique<TypeVariant>(UnionStub{"u" + std::to_string(i)}));
  }

  ASSERT_EQ(map.size(), static_cast<size_t>(kStructCount + kUnionCount));

  // 1. Snapshot composite keys (the fix pattern)
  auto composite_keys = SnapshotKeys<StructStub, UnionStub>(map);
  ASSERT_EQ(composite_keys.size(),
            static_cast<size_t>(kStructCount + kUnionCount));

  // 2. Iterate over the snapshot and insert new PointerStub / ArrayStub
  //    entries — this simulates ExportCompositeMembers calling
  //    ExportPointer/ExportArray which emplace into the same map.
  size_t visited = 0;
  int next_key = kStructCount + kUnionCount;
  for (int key : composite_keys) {
    auto it = map.find(key);
    ASSERT_NE(it, map.end()) << "Original key " << key << " disappeared";
    ++visited;

    // Insert a PointerStub (triggers potential rehash)
    map.emplace(
        next_key++,
        std::make_unique<TypeVariant>(
            PointerStub{"ptr" + std::to_string(visited)}));

    // Insert an ArrayStub too for good measure
    map.emplace(
        next_key++,
        std::make_unique<TypeVariant>(
            ArrayStub{"arr" + std::to_string(visited)}));
  }

  EXPECT_EQ(visited, static_cast<size_t>(kStructCount + kUnionCount));

  // Original composites + 2 new entries per composite
  size_t expected = static_cast<size_t>(kStructCount + kUnionCount) +
                    2 * static_cast<size_t>(kStructCount + kUnionCount);
  EXPECT_EQ(map.size(), expected);

  // 3. Verify the original entries are still accessible after all insertions
  for (int key : composite_keys) {
    auto it = map.find(key);
    EXPECT_NE(it, map.end()) << "Original key " << key << " lost after inserts";
    EXPECT_TRUE(std::holds_alternative<StructStub>(*it->second) ||
                std::holds_alternative<UnionStub>(*it->second));
  }
}

// Verify that SnapshotKeys only collects the requested types.
TEST(KeySnapshotIteration, FiltersCorrectly) {
  MapT map;
  map.emplace(1, std::make_unique<TypeVariant>(StructStub{"s1"}));
  map.emplace(2, std::make_unique<TypeVariant>(UnionStub{"u1"}));
  map.emplace(3, std::make_unique<TypeVariant>(PointerStub{"p1"}));
  map.emplace(4, std::make_unique<TypeVariant>(ArrayStub{"a1"}));

  auto composite = SnapshotKeys<StructStub, UnionStub>(map);
  EXPECT_EQ(composite.size(), 2u);

  auto pointers = SnapshotKeys<PointerStub>(map);
  EXPECT_EQ(pointers.size(), 1u);

  auto all = SnapshotKeys<StructStub, UnionStub, PointerStub, ArrayStub>(map);
  EXPECT_EQ(all.size(), 4u);
}

// Stress test: many insertions to force multiple rehashes.
TEST(KeySnapshotIteration, StressRehash) {
  MapT map;

  constexpr int kInitial = 500;
  for (int i = 0; i < kInitial; ++i) {
    map.emplace(
        i,
        std::make_unique<TypeVariant>(StructStub{"s" + std::to_string(i)}));
  }

  auto keys = SnapshotKeys<StructStub>(map);
  ASSERT_EQ(keys.size(), static_cast<size_t>(kInitial));

  int next = kInitial;
  for (int key : keys) {
    ASSERT_NE(map.find(key), map.end());

    // Insert 3 entries per original (forces multiple rehashes)
    for (int j = 0; j < 3; ++j) {
      map.emplace(
          next++,
          std::make_unique<TypeVariant>(
              PointerStub{"ptr" + std::to_string(next)}));
    }
  }

  EXPECT_EQ(map.size(), static_cast<size_t>(kInitial + kInitial * 3));
}

}  // namespace
