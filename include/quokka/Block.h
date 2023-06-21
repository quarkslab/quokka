// Copyright 2022-2023 Quarkslab
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * @file Block.h
 * A `Block` represents a Basic Block: a sequence of consecutive instructions
 * with no incoming flow.
 *
 * The difference between Block and Fake Block is explained more in the
 * FakeChunk (Function.h) file.
 */

#ifndef QUOKKA_BLOCK_H
#define QUOKKA_BLOCK_H

#include <cassert>
#include <vector>

#include <pro.h>

#include <gdl.hpp>
#include <ida.hpp>

#include "absl/container/flat_hash_map.h"

#include "Logger.h"
#include "Windows.h"

namespace quokka {

class Instruction;

enum BlockType : short {
  BTYPE_NORMAL = 0,
  BTYPE_INDJUMP,
  BTYPE_RET,
  BTYPE_CNDRET,
  BTYPE_NORET,
  BTYPE_ENORET,
  BTYPE_EXTERN,
  BTYPE_ERROR,
  BTYPE_FAKE,
};

/**
 * Convert the block type from IDA to the internal enum
 * @param block_type Type of block (IDA)
 * @return Block type
 */
BlockType RetrieveBlockType(fc_block_type_t block_type);

/**
 * -----------------------------------------------------------------------------
 * quokka::Block
 * -----------------------------------------------------------------------------
 * Representation of a basic block.
 */
class Block {
 public:
  ea_t start_addr;  ///< Start address
  ea_t end_addr;    ///< End address (may be equal to `BADADDR`)
  BlockType block_type;

  /**
   * List of instructions. Container of all instructions referenced in
   * the block. The ordering is important here, because the address are
   * computed by looking at the size of the previous instructions.
   */
  std::vector<std::shared_ptr<Instruction>> instructions;

  bool is_fake = false;  ///< Boolean for fake blocks

  /**
   * Construct Block
   *
   * @param addr Start address of the block
   * @param eaddr End address of the block
   */
  Block(ea_t addr, ea_t eaddr, BlockType block_type)
      : start_addr(addr), end_addr(eaddr), block_type(block_type) {
    current_address = start_addr;
  }

  /**
   * Construct a fake block
   * @param addr Start address
   */
  explicit Block(ea_t addr)
      : start_addr(addr),
        end_addr(BADADDR),
        block_type(BTYPE_FAKE),
        is_fake(true) {
    current_address = start_addr;
  }

  /**
   * Check if `addr` belongs to the block
   * @param addr Address to check
   * @return Boolean for success
   */
  [[nodiscard]] bool IsBetween(ea_t addr) const;

  /**
   * Retrieve the index of the instruction at `addr`
   * @param addr Address of the instruction
   * @return Instruction index
   */
  [[nodiscard]] std::optional<int> GetInstIndex(ea_t addr) const;

  /**
   * Reset the end address of the block to `endaddr`.
   *
   * For fake blocks, no check is performed, otherwise, must be forced.
   *
   * @param endaddr New end address
   * @param force Overwrite the current end address ?
   */
  void Resize(ea_t endaddr, bool force = false);

  /**
   * Add an instruction to the list of instruction in the block.
   *
   * @param instruction New instruction
   */
  void AppendInstruction(const std::shared_ptr<Instruction>& instruction);

 private:
  ea_t current_address;  ///< Internal representation of the current address

  /**
   * Map of address associated to index of the instruction. Kept for fast
   * lookup but must be updated each time a new instruction is appended in
   * the block.
   */
  absl::flat_hash_map<ea_t, int> address_to_index;
};

}  // namespace quokka

#endif  // QUOKKA_BLOCK_H
