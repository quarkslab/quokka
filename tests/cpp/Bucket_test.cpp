// Unit tests for quokka Bucket containers (SetBucket, MapBucket,
// MultiMapBucket, SortedView).
//
// These tests use the actual Bucket.h and ProtoHelper.h headers, which have
// no IDA SDK dependencies.

#include "Bucket.h"

#include <stdexcept>
#include <string>
#include <utility>

#include "gtest/gtest.h"

namespace {

// A simple ProtoHelper-derived type for testing buckets.
struct TestItem : public quokka::ProtoHelper {
  int id;
  std::string name;

  TestItem(int id_, std::string name_) : id(id_), name(std::move(name_)) {}

  bool operator==(const TestItem& other) const {
    return id == other.id && name == other.name;
  }

  template <typename H>
  friend H AbslHashValue(H h, const TestItem& m) {
    return H::combine(std::move(h), m.id, m.name);
  }
};

// ---------------------------------------------------------------------------
// SetBucket tests
// ---------------------------------------------------------------------------

TEST(SetBucket, EmplaceBasic) {
  quokka::SetBucket<TestItem> bucket;
  const auto& item = bucket.emplace(1, "alpha");
  EXPECT_EQ(item.id, 1);
  EXPECT_EQ(item.name, "alpha");
  EXPECT_EQ(bucket.size(), 1u);
}

TEST(SetBucket, EmplaceDeduplicates) {
  quokka::SetBucket<TestItem> bucket;
  const auto& first = bucket.emplace(1, "alpha");
  const auto& second = bucket.emplace(1, "alpha");
  EXPECT_EQ(bucket.size(), 1u);
  EXPECT_EQ(&first, &second);
  EXPECT_EQ(first.ref_count, 2u);
}

TEST(SetBucket, InsertBasic) {
  quokka::SetBucket<TestItem> bucket;
  TestItem item(2, "beta");
  const auto& ref = bucket.insert(std::move(item));
  EXPECT_EQ(ref.id, 2);
  EXPECT_EQ(ref.name, "beta");
  EXPECT_EQ(bucket.size(), 1u);
}

TEST(SetBucket, InsertDeduplicates) {
  quokka::SetBucket<TestItem> bucket;
  const auto& first = bucket.insert(TestItem(1, "alpha"));
  const auto& second = bucket.insert(TestItem(1, "alpha"));
  EXPECT_EQ(bucket.size(), 1u);
  EXPECT_EQ(&first, &second);
  EXPECT_EQ(first.ref_count, 2u);
}

TEST(SetBucket, MultipleDistinctItems) {
  quokka::SetBucket<TestItem> bucket;
  bucket.emplace(1, "alpha");
  bucket.emplace(2, "beta");
  bucket.emplace(3, "gamma");
  EXPECT_EQ(bucket.size(), 3u);
}

TEST(SetBucket, RefCountTracking) {
  quokka::SetBucket<TestItem> bucket;
  const auto& item = bucket.emplace(1, "alpha");
  EXPECT_EQ(item.ref_count, 1u);
  bucket.emplace(1, "alpha");
  EXPECT_EQ(item.ref_count, 2u);
  bucket.emplace(1, "alpha");
  EXPECT_EQ(item.ref_count, 3u);
}

TEST(SetBucket, FreezeAndSort) {
  quokka::SetBucket<TestItem> bucket;
  // Insert items with different ref counts
  bucket.emplace(1, "alpha");
  bucket.emplace(1, "alpha");
  bucket.emplace(1, "alpha");  // ref_count = 3
  bucket.emplace(2, "beta");   // ref_count = 1
  bucket.emplace(3, "gamma");
  bucket.emplace(3, "gamma");  // ref_count = 2

  bucket.Sort();
  auto view = bucket.GetSortedView();
  EXPECT_EQ(view.size(), 3u);
  // Sorted by ref_count descending: alpha(3), gamma(2), beta(1)
  EXPECT_EQ(view[0].name, "alpha");
  EXPECT_EQ(view[1].name, "gamma");
  EXPECT_EQ(view[2].name, "beta");
}

TEST(SetBucket, ThrowsOnInsertAfterFreeze) {
  quokka::SetBucket<TestItem> bucket;
  bucket.emplace(1, "alpha");
  bucket.Freeze();
  EXPECT_THROW(bucket.emplace(2, "beta"), std::logic_error);
  EXPECT_THROW(bucket.insert(TestItem(3, "gamma")), std::logic_error);
}

TEST(SetBucket, ThrowsOnReserveAfterFreeze) {
  quokka::SetBucket<TestItem> bucket;
  bucket.Freeze();
  EXPECT_THROW(bucket.reserve(100), std::logic_error);
}

TEST(SetBucket, GetSortedViewRequiresFreezeAndSort) {
  quokka::SetBucket<TestItem> bucket;
  bucket.emplace(1, "alpha");
  EXPECT_THROW(bucket.GetSortedView(), std::logic_error);
  bucket.Freeze();
  EXPECT_THROW(bucket.GetSortedView(), std::logic_error);
  bucket.Sort();
  EXPECT_NO_THROW(bucket.GetSortedView());
}

TEST(SetBucket, SortedViewIteration) {
  quokka::SetBucket<TestItem> bucket;
  bucket.emplace(1, "alpha");
  bucket.emplace(2, "beta");
  bucket.Sort();
  auto view = bucket.GetSortedView();

  int count = 0;
  for (const auto& item : view) {
    EXPECT_FALSE(item.name.empty());
    ++count;
  }
  EXPECT_EQ(count, 2);
}

TEST(SetBucket, SortedViewOutOfBounds) {
  quokka::SetBucket<TestItem> bucket;
  bucket.emplace(1, "alpha");
  bucket.Sort();
  auto view = bucket.GetSortedView();
  EXPECT_THROW(view[1], std::out_of_range);
  EXPECT_THROW(view[100], std::out_of_range);
}

TEST(SetBucket, Reserve) {
  quokka::SetBucket<TestItem> bucket;
  EXPECT_NO_THROW(bucket.reserve(100));
  bucket.emplace(1, "alpha");
  EXPECT_EQ(bucket.size(), 1u);
}

TEST(SetBucket, SortImplicitlyFreezes) {
  quokka::SetBucket<TestItem> bucket;
  bucket.emplace(1, "alpha");
  // Sort without explicit Freeze -> should freeze internally
  bucket.Sort();
  EXPECT_THROW(bucket.emplace(2, "beta"), std::logic_error);
  EXPECT_NO_THROW(bucket.GetSortedView());
}

TEST(SetBucket, EmptyBucketSortAndView) {
  quokka::SetBucket<TestItem> bucket;
  bucket.Sort();
  auto view = bucket.GetSortedView();
  EXPECT_EQ(view.size(), 0u);
}

// ---------------------------------------------------------------------------
// MapBucket tests
// ---------------------------------------------------------------------------

TEST(MapBucket, EmplaceAndLookup) {
  quokka::MapBucket<int, TestItem> bucket;
  const auto& item = bucket.emplace(10, 1, "alpha");
  EXPECT_EQ(item.id, 1);
  EXPECT_EQ(item.name, "alpha");
  EXPECT_EQ(bucket.size(), 1u);
}

TEST(MapBucket, ContainsKey) {
  quokka::MapBucket<int, TestItem> bucket;
  bucket.emplace(10, 1, "alpha");
  EXPECT_TRUE(bucket.contains(10));
  EXPECT_FALSE(bucket.contains(20));
}

TEST(MapBucket, OperatorBracket) {
  quokka::MapBucket<int, TestItem> bucket;
  bucket.emplace(10, 1, "alpha");
  const auto& item = bucket[10];
  EXPECT_EQ(item.id, 1);
  EXPECT_EQ(item.name, "alpha");
}

TEST(MapBucket, ThrowsOnMissingKey) {
  quokka::MapBucket<int, TestItem> bucket;
  EXPECT_THROW(bucket[42], std::out_of_range);
}

TEST(MapBucket, DeduplicatesExistingKey) {
  quokka::MapBucket<int, TestItem> bucket;
  const auto& first = bucket.emplace(10, 1, "alpha");
  const auto& second = bucket.emplace(10, 2, "beta");
  EXPECT_EQ(bucket.size(), 1u);
  // Returns the original item, not the new one
  EXPECT_EQ(first.id, 1);
  EXPECT_EQ(second.id, 1);
  EXPECT_EQ(&first, &second);
  EXPECT_EQ(first.ref_count, 2u);
}

TEST(MapBucket, MultipleKeys) {
  quokka::MapBucket<int, TestItem> bucket;
  bucket.emplace(1, 1, "alpha");
  bucket.emplace(2, 2, "beta");
  bucket.emplace(3, 3, "gamma");
  EXPECT_EQ(bucket.size(), 3u);
  EXPECT_TRUE(bucket.contains(1));
  EXPECT_TRUE(bucket.contains(2));
  EXPECT_TRUE(bucket.contains(3));
}

TEST(MapBucket, FreezeAndSort) {
  quokka::MapBucket<int, TestItem> bucket;
  bucket.emplace(1, 1, "alpha");
  bucket.emplace(1, 1, "alpha");  // ref_count = 2
  bucket.emplace(2, 2, "beta");   // ref_count = 1

  bucket.Sort();
  auto view = bucket.GetSortedView();
  EXPECT_EQ(view.size(), 2u);
  // alpha has higher ref_count
  EXPECT_EQ(view[0].name, "alpha");
  EXPECT_EQ(view[1].name, "beta");
}

TEST(MapBucket, ThrowsOnInsertAfterFreeze) {
  quokka::MapBucket<int, TestItem> bucket;
  bucket.Freeze();
  EXPECT_THROW(bucket.emplace(1, 1, "alpha"), std::logic_error);
}

TEST(MapBucket, StringKeys) {
  quokka::MapBucket<std::string, TestItem> bucket;
  bucket.emplace("key1", 1, "alpha");
  bucket.emplace("key2", 2, "beta");
  EXPECT_TRUE(bucket.contains("key1"));
  EXPECT_TRUE(bucket.contains("key2"));
  EXPECT_FALSE(bucket.contains("key3"));
  EXPECT_EQ(bucket["key1"].id, 1);
}

// ---------------------------------------------------------------------------
// MultiMapBucket tests
// ---------------------------------------------------------------------------

TEST(MultiMapBucket, EmplaceBasic) {
  quokka::MultiMapBucket<int, TestItem> bucket;
  const auto& item = bucket.emplace(10, 1, "alpha");
  EXPECT_EQ(item.id, 1);
  EXPECT_EQ(item.name, "alpha");
  EXPECT_EQ(bucket.size(), 1u);
}

TEST(MultiMapBucket, SameKeyDifferentValues) {
  quokka::MultiMapBucket<int, TestItem> bucket;
  const auto& a = bucket.emplace(10, 1, "alpha");
  const auto& b = bucket.emplace(10, 2, "beta");
  EXPECT_EQ(bucket.size(), 2u);
  EXPECT_NE(&a, &b);
  EXPECT_EQ(a.id, 1);
  EXPECT_EQ(b.id, 2);
}

TEST(MultiMapBucket, DeduplicatesSameKeyAndValue) {
  quokka::MultiMapBucket<int, TestItem> bucket;
  const auto& first = bucket.emplace(10, 1, "alpha");
  const auto& second = bucket.emplace(10, 1, "alpha");
  EXPECT_EQ(bucket.size(), 1u);
  EXPECT_EQ(&first, &second);
  EXPECT_EQ(first.ref_count, 2u);
}

TEST(MultiMapBucket, ContainsKey) {
  quokka::MultiMapBucket<int, TestItem> bucket;
  bucket.emplace(10, 1, "alpha");
  EXPECT_TRUE(bucket.contains(10));
  EXPECT_FALSE(bucket.contains(20));
}

TEST(MultiMapBucket, DifferentKeys) {
  quokka::MultiMapBucket<int, TestItem> bucket;
  bucket.emplace(1, 1, "alpha");
  bucket.emplace(2, 2, "beta");
  EXPECT_EQ(bucket.size(), 2u);
  EXPECT_TRUE(bucket.contains(1));
  EXPECT_TRUE(bucket.contains(2));
}

TEST(MultiMapBucket, FreezeAndSort) {
  quokka::MultiMapBucket<int, TestItem> bucket;
  bucket.emplace(1, 1, "alpha");
  bucket.emplace(1, 1, "alpha");
  bucket.emplace(1, 1, "alpha");  // ref_count = 3
  bucket.emplace(2, 2, "beta");   // ref_count = 1

  bucket.Sort();
  auto view = bucket.GetSortedView();
  EXPECT_EQ(view.size(), 2u);
  EXPECT_EQ(view[0].name, "alpha");  // higher ref_count
  EXPECT_EQ(view[1].name, "beta");
}

TEST(MultiMapBucket, ThrowsOnInsertAfterFreeze) {
  quokka::MultiMapBucket<int, TestItem> bucket;
  bucket.Freeze();
  EXPECT_THROW(bucket.emplace(1, 1, "alpha"), std::logic_error);
}

TEST(MultiMapBucket, ManyEntriesSameKey) {
  quokka::MultiMapBucket<int, TestItem> bucket;
  bucket.emplace(1, 1, "a");
  bucket.emplace(1, 2, "b");
  bucket.emplace(1, 3, "c");
  bucket.emplace(1, 4, "d");
  EXPECT_EQ(bucket.size(), 4u);
}

TEST(MultiMapBucket, DeduplicatesAcrossManyEntries) {
  quokka::MultiMapBucket<int, TestItem> bucket;
  bucket.emplace(1, 1, "a");
  bucket.emplace(1, 2, "b");
  bucket.emplace(1, 3, "c");
  // Re-insert existing value -> dedup
  const auto& ref = bucket.emplace(1, 2, "b");
  EXPECT_EQ(bucket.size(), 3u);
  EXPECT_EQ(ref.ref_count, 2u);
}

// ---------------------------------------------------------------------------
// SortedView tests
// ---------------------------------------------------------------------------

TEST(SortedView, RandomAccessMatchesIteration) {
  quokka::SetBucket<TestItem> bucket;
  bucket.emplace(1, "alpha");
  bucket.emplace(2, "beta");
  bucket.emplace(3, "gamma");
  bucket.Sort();
  auto view = bucket.GetSortedView();

  size_t idx = 0;
  for (const auto& item : view) {
    EXPECT_EQ(item.id, view[idx].id);
    EXPECT_EQ(item.name, view[idx].name);
    ++idx;
  }
  EXPECT_EQ(idx, view.size());
}

TEST(SortedView, RefCountOrder) {
  quokka::SetBucket<TestItem> bucket;
  // beta: 5 refs, alpha: 1 ref, gamma: 3 refs
  for (int i = 0; i < 5; ++i)
    bucket.emplace(2, "beta");
  bucket.emplace(1, "alpha");
  for (int i = 0; i < 3; ++i)
    bucket.emplace(3, "gamma");

  bucket.Sort();
  auto view = bucket.GetSortedView();
  ASSERT_EQ(view.size(), 3u);
  EXPECT_EQ(view[0].ref_count, 5u);
  EXPECT_EQ(view[1].ref_count, 3u);
  EXPECT_EQ(view[2].ref_count, 1u);
}

TEST(SortedView, EmptyView) {
  quokka::SetBucket<TestItem> bucket;
  bucket.Sort();
  auto view = bucket.GetSortedView();
  EXPECT_EQ(view.size(), 0u);
  int count = 0;
  for ([[maybe_unused]] const auto& item : view)
    ++count;
  EXPECT_EQ(count, 0);
}

}  // namespace
