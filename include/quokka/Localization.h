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
 * @file Localization.h
 * Management of localizations
 *
 * A localization is attached to Comment or Reference to understand where
 * they point.
 */

#ifndef QUOKKA_LOCALIZATION_H
#define QUOKKA_LOCALIZATION_H

#include <memory>
#include <variant>

#include "Compatibility.h"
#include <pro.h>

#include "Windows.h"

namespace quokka {

class Structure;
struct StructureMember;
class FuncChunk;
class Block;
class Instruction;
class Data;
class Function;

/**
 * ---------------------------------------------
 * quokka::InstructionInstance
 * ---------------------------------------------
 * Localization for an instruction instance
 *
 * An instance of an instruction is associated to a tuple (chunk, block,
 * instruction index). Remember that instructions are deduplicated so no
 * address field is available but we still need to attach some elements to a
 * specific instance of an instruction (e.g. a comment).
 */
struct InstructionInstance {
  std::shared_ptr<FuncChunk> chunk_;  ///< Chunk
  std::shared_ptr<Block> block_;      ///< Block
  int instruction_index;              ///< Index inside the block

  /**
   * Constructor
   *
   * @param chunk Chunk
   * @param block Block
   * @param index Instruction index
   */
  InstructionInstance(std::shared_ptr<FuncChunk> chunk,
                      std::shared_ptr<Block> block, int index)
      : chunk_(std::move(chunk)),
        block_(std::move(block)),
        instruction_index(index) {}

  /**
   * Hash implementation of the object using absl::Hash
   * @tparam H Hash
   * @param h Hash value
   * @param m InstructionInstance object
   * @return An hash value for the object
   */
  template <typename H>
  friend H AbslHashValue(H h, const InstructionInstance& m) {
    return H::combine(std::move(h), m.chunk_, m.block_, m.instruction_index);
  }
};

/*
 * Location possibility
 *
 * The two last (Instruction, InstructionInstance) are used for :
 * - Instruction : used if the reference is bound to the instruction itself
 * (e.g. lea rsi, _string_)
 * - InstructionInstance: used if the reference is bound to the instance of the
 * instruction (e.g. call eax)
 *
 * */
using Location =
    std::variant<ea_t,                              ///< IDA unique identifier
                 std::shared_ptr<Data>,             ///< Data
                 std::shared_ptr<Structure>,        ///< Structure
                 std::shared_ptr<StructureMember>,  ///< Structure member
                 std::shared_ptr<Instruction>,      ///< Instruction
                 InstructionInstance,        ///< Instance of an instruction
                 std::shared_ptr<Function>,  ///< Function
                 std::shared_ptr<FuncChunk>  //< Chunks
                 >;

}  // namespace quokka
#endif  // QUOKKA_LOCALIZATION_H
