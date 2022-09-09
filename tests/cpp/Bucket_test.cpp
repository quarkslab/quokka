//
// Created by alexis on 07/05/2020.
//

#include <vector>

#include "gtest/gtest.h"

#include "quokka/ProtoHelper.h"
#include "quokka/Util.h"

struct Element : quokka::ProtoHelper {
  int val_;
  explicit Element(int value) : val_(value) {}

  bool operator==(const Element& rhs) const { return val_ == rhs.val_; }

  bool operator!=(const Element& rhs) const { return !(rhs == *this); }

  /* Make type hashable */
  template <typename H>
  friend H AbslHashValue(H h, const Element& m) {
    return H::combine(std::move(h), m.val_);
  }
};

class BucketTest : public ::testing::Test {
 protected:
  void SetUp() override {
    bucket1_.emplace(7);
    bucket1_.emplace(5);
    bucket1_.emplace(9);
    bucket1_.emplace(5);
  }

  // void TearDown() override {}
  quokka::BucketNew<Element> bucket1_;
  quokka::BucketNew<Element> bucket2_;
};

TEST_F(BucketTest, BucketAdd) {
  bucket2_.emplace(5);
  EXPECT_EQ(bucket2_.size(), 1);

  bucket2_.emplace(1);
  EXPECT_EQ(bucket2_.size(), 2);

  bucket2_.emplace(5);  // Not a typo
  EXPECT_EQ(bucket2_.size(), 2);
}

TEST_F(BucketTest, BucketDel) {
  EXPECT_EQ(bucket1_.size(), 3);

  const std::shared_ptr<Element> element = *(bucket1_.begin());
  bucket1_.erase(element);

  EXPECT_EQ(bucket1_.size(), 2);

  bucket1_.clear();
  EXPECT_EQ(bucket1_.size(), 0);
}

TEST_F(BucketTest, BucketFrequency) {
  auto freq_map = bucket1_.SortByFrequency();

  EXPECT_EQ(freq_map.begin()->first, 2);
  EXPECT_EQ(freq_map.begin()->second->val_, 5);
}
