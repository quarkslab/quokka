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
 * @file Layout.h
 * Layout management
 *
 * This is the most important part of the exporter. It uses a state machine
 * to iterate through every heads of IDA disassembly. The objective is to do
 * a linear pass on every heads to be as efficient as possible.
 */

#ifndef QUOKKA_LAYOUT_H
#define QUOKKA_LAYOUT_H

#include <cassert>
#include <cstdint>
#include <optional>
#include <string_view>
#include <unordered_set>

// clang-format off: Compatibility.h must come before ida headers
#include "Compatibility.h"
// clang-format on
#include <pro.h>
#include <bytes.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <graph.hpp>
#include <ida.hpp>
#include <kernwin.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <ua.hpp>
#include <utility>
#include <vector>
#include <xref.hpp>

#include "absl/container/btree_set.h"
#include "absl/hash/hash.h"
#include "absl/time/clock.h"

#include "Bucket.h"
#include "Data.h"
#include "Function.h"
#include "Imports.h"
#include "Logger.h"
#include "ProtoWrapper.h"
#include "Segment.h"
#include "Windows.h"

namespace quokka {

class FuncChunk;
class Block;
class Instruction;
class Data;
class Operand;
class OperandString;
class Mnemonic;
class Comments;
class FuncChunkCollection;
class Function;

/**
 * Machine state and layout state
 */
enum State : short {
  START = 0,  ///< Not used for layout type
  CODE,
  DATA,
  UNK,
  UNK_WITH_XREF,
  GAP,
  FINISH,  ///< Not used for layout type
  TBD,     ///< Not used for layout type
};

constexpr std::string_view to_string(const State& s) noexcept {
  using namespace std::string_view_literals;
  switch (s) {
    case State::START:
      return "START"sv;
    case State::CODE:
      return "CODE"sv;
    case State::DATA:
      return "DATA"sv;
    case State::UNK:
      return "UNK"sv;
    case State::UNK_WITH_XREF:
      return "UNK_WITH_XREF"sv;
    case State::GAP:
      return "GAP"sv;
    case State::FINISH:
      return "FINISH"sv;
    case State::TBD:
      return "TBD"sv;
  }
  return "Invalid value"sv;
}

/**
 * ---------------------------------------------
 * quokka::Layout
 * ---------------------------------------------
 * Layout representation
 *
 * Store the information about a layout.
 * You may picture layout as a representation of IDA Navigator toolbar. Every
 * color block is a layout.
 */
struct Layout {
  State type;  ///< Type of layout (use the state machine)
  ea_t start;  ///< Start address
  ea_t size;   ///< Size of the layout

  /**
   * Constructor
   * @param type Layout type
   * @param start Start of the layout
   * @param size Size of the layout
   */
  Layout(State type, ea_t start, ea_t size)
      : type(type), start(start), size(size) {}

  explicit Layout() : type(UNK), start(BADADDR), size(0) {}
};

/**
 * ---------------------------------------------
 * quokka::HeadIterator
 * ---------------------------------------------
 * Head iterator
 *
 * This class is the bread and butter of the exporter. It maintain every
 * information about the current state of the iterator, the next addresses to
 * analyze.
 */
class HeadIterator {
 private:
  ea_t max_ea;          ///< Max address in the program (`inf.max_ea`)
  ea_t current_ea;      ///< Current address
  uint64_t item_size;   ///< Size of the object at `current_ea`
  ea_t next_ea;         ///< Next address to analyze
  State state = START;  ///< Current state

  /* Information about futures address */
  ea_t next_unk_addr = BADADDR;       ///< Next unknown address
  ea_t next_head_addr = BADADDR;      ///< Next head address
  ea_t next_chunk_addr = BADADDR;     ///< Next chunk head address
  func_t* next_func_chunk = nullptr;  ///< Next function chunk pointer

  /* Pointers on current element */
  std::shared_ptr<Block> current_block = nullptr;  ///< Current block

  Layout current_layout;                   ///< Current layout
  std::optional<FuncChunk> current_chunk;  ///< Current chunk

  /**
   * Has the decoding of an instruction failed ?
   *
   * If is set to true, the next instruction will be searched aggressively
   * (it will try every next address until a valid one is found).
   */
  bool false_decoding = false;

  /**
   * Is the `current_ea` an instruction head ?
   * @return Bool for success
   */
  bool IsInstHead() const;

  /**
   * Is the `current_ea` a block head ?
   * @return Bool for success
   */
  bool IsBlockHead() const;

  /**
   * Create a new block at `current_ea`
   * @return Block
   */
  std::shared_ptr<Block> CreateNewBlock();

  /**
   * Is the `current_ea` a chunk tail ?
   * @return Bool for success
   */
  bool IsChunkTail() const;

  /**
   * Updates the next_ea attribute.
   */
  void UpdateNextEa();

  /**
   * Add the current layout to the layouts collection and start a new layout
   *
   * @param state Current state
   * @param addr Starting address of the layout
   * @param size Size of the layout
   * @return
   */
  void RotateLayout(State state, ea_t addr, ea_t size);

 public:
  /**
   * Current instruction
   */
  std::shared_ptr<Instruction> current_instruction = nullptr;

  std::deque<Layout> layouts;  ///< List of layouts

  // BucketNew<Instruction> instruction_bucket;         ///< Bucket of
  // instruction BucketNew<Operand> operand_bucket;                 ///< Bucket
  // of operands BucketNew<OperandString> operand_string_bucket;    ///< Bucket
  // of op strings BucketNew<Mnemonic> mnemonic_bucket;               ///<
  // Bucket of mnemonic
  SetBucket<Data> data_list;  ///< Bucket of data

  std::forward_list<std::shared_ptr<Block>> blocks;  ///< List of blocks

  /**
   * Constructor
   * Set the address boundaries, and initialize the first address for the
   * iteration.
   *
   * @param start_ea Starting address
   * @param max_ea Maximum address
   */
  HeadIterator(ea_t start_ea, ea_t max_ea);

  /**
   * Is the `current_ea` a chunk head ?
   * @return Bool for success
   */
  [[nodiscard]] bool IsChunkHead() const;

  /**
   * Create a new chunk at `current_ea`
   * @return
   */
  void CreateNewChunk();

  /**
   * Create a fake chunk
   * For a fake chunk, we don't have any information on potential blocks
   * (expect the one starting at the chunk start) so it will be retrieved
   * on the fly
   * @return FuncChunk object
   */
  // std::shared_ptr<FuncChunk> CreateFakeChunk();

  /**
   * Is the `current_ea` a block tail ?
   * @return Bool for success
   */
  [[nodiscard]] bool IsBlockTail() const;

  /**
   * Create a fake block at `current_ea`
   * Sometimes, we may already have had the intuition that this address
   * would have been a block head (because of an edge pointing towards).
   * @return Block
   */
  std::shared_ptr<Block> CreateFakeBlock();

  /**
   * Create a instruction
   *
   * Most of the time it creates a instruction. However sometime, the
   * decoding may fail (even if we are only trying to disassemble CODE
   * layout). In this case, we set false_decoding to true and delete the
   * instruction in the database.
   *
   * If the instruction does not belong to a block and/or a function we
   * create a FakeBlock (FakeChunk) as parents.
   * @note There are no "fake" instruction because they always exists. If
   * IDA does not find an instruction, we don't export it.
   *
   * Finally, since IDA provide `is_basic_block_end`, we use it here to see
   * if this is the end of the current block.
   *
   * @warning This function modify the database in case of false decoding
   *
   * @return An instruction (or a nullptr)
   */
  std::shared_ptr<Instruction> CreateNewInst();

  /**
   * Reset the next addresses to be the first after `address`
   *
   * This method is used at the beginning of the export (when address ==
   * min_ea) and every time after a false decoding
   *
   * @param address Address to start from
   */
  void InitAddresses(ea_t address);

  /**
   * Retrieve the next chunk address if any are found
   * @param address Address to start from
   * @param skip_current Do not consider the chunk starting at the current
   * address
   */
  void SetNextChunk(ea_t address, bool skip_current = true);

  /**
   * Create a new layout and set it to current_layout
   * @param start_addr Start address
   * @param current_state Layout state
   * @param size Size of the layout
   */
  void StartLayout(ea_t start_addr, State current_state, ea_t size = 0);

  /**
   * Augment the size of the current layout
   * Most of the item, it's only the size of the current item but for GAP,
   * we take a shortcut.
   *
   * @param size Optional size. If it is zero then it is automatically deduced
   */
  void AddLayoutSize(size_t size = 0);

  /**
   * Move forward by computing the next address, state and layout.
   * Updates state, current_ea, next_ea, item_size, layout.
   *
   * @note The code of the method is documented to understand how to process
   */
  void Iterate();

  /**
   * Scans the whole binary, loading all the relevant data structures,
   * instructions, operands, etc. that are not part of the excluded ranges
   *
   * @param export_instructions whether to export instructions or not
   * @param excluded_ranges The ranges of addresses that should be skipped
   * during the analysis
   */
  void Scan(bool export_instructions,
            const std::vector<std::pair<ea_t, ea_t>>& excluded_ranges);

  void DebugPrint() const;
};

/**
 * Compute the state at address
 *
 * @param address Address
 * @return State type
 */
State GetState(ea_t address);

/**
 * This will be responsible for iterating through every head that is not part of
 * the provided ranges, exporting blocks, instructions and data. Normally the
 * excluded ranges are the function chunks that have been already exported
 *
 * @param proto Main protobuf
 * @param excluded_ranges The ranges of addresses that should be skipped during
 * the analysis
 * @return Int for success
 */
int ExportLinearScan(quokka::Quokka* proto,
                     const std::vector<std::pair<ea_t, ea_t>>& exclude_ranges);

}  // namespace quokka
#endif  // QUOKKA_LAYOUT_H
