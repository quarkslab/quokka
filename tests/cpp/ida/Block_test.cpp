//
// Created by alexis on 07/05/2020.
//

#include "gtest/gtest.h"

#include "quokka/Block.h"
#include "quokka/Instruction.h"

class BlockTest : public ::testing::Test {
 protected:
  quokka::Block* block_ = nullptr;
  quokka::Block* fake_block_ = nullptr;

  void SetUp() override {
    block_ = new quokka::Block(0x400000, 0x400800, quokka::BTYPE_NORMAL);
    fake_block_ = new quokka::Block(0x40100);
  }

  void TearDown() override {
    free(block_);
    free(fake_block_);
  }
};

TEST_F(BlockTest, FakeBlock) {
  ASSERT_EQ(fake_block_->is_fake, true);
  ASSERT_EQ(fake_block_->end_addr, BADADDR);

  // Should resize
  fake_block_->Resize(0x401400, true);
  ASSERT_EQ(fake_block_->end_addr, 0x401400);

  // Should also resize
  fake_block_->Resize(fake_block_->end_addr - 0x400);
  ASSERT_EQ(fake_block_->end_addr, 0x401000);
}

TEST_F(BlockTest, RegularBlock) {
  EXPECT_FALSE(block_->is_fake);
  ASSERT_LT(block_->end_addr, BADADDR);

  /* Should resize */
  block_->Resize(block_->end_addr - 0x400, true);
  ASSERT_EQ(block_->end_addr, 0x400400);

  /* Should not resize */
  block_->Resize(block_->end_addr - 0x400);
  ASSERT_EQ(block_->end_addr, 0x400400);
}

TEST_F(BlockTest, InBlock) {
  EXPECT_TRUE(block_->IsBetween(0x400100));

  /* Edge case: limit values */
  EXPECT_TRUE(block_->IsBetween(block_->start_addr));
  EXPECT_FALSE(block_->IsBetween(block_->end_addr));
}
