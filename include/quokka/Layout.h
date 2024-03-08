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
#include <unordered_set>

#include "Compatibility.h"
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
#include <xref.hpp>

#include "absl/container/btree_set.h"
#include "absl/hash/hash.h"
#include "absl/time/clock.h"

#include "Logger.h"
#include "ProtoWrapper.h"
#include "Util.h"
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
  ea_t max_ea;  ///< Max address in the program (`inf.max_ea`)

  /* Information about futures address */
  ea_t next_unk_addr = BADADDR;       ///< Next unknown address
  ea_t next_head_addr = BADADDR;      ///< Next head address
  ea_t next_chunk_addr = BADADDR;     ///< Next chunk head address
  func_t* next_func_chunk = nullptr;  ///< Next function chunk pointer

  /**
   * Has the decoding of an instruction failed ?
   *
   * If is set to true, the next instruction will be searched aggressively
   * (it will try every next address until a valid one is found).
   */
  bool false_decoding = false;

 public:
  ea_t current_ea;     ///< Current address
  uint64_t item_size;  ///< Size of the object at `current_ea`

  ea_t next_ea;  ///< Next address to analyze

  State state = START;     ///< Current state
  State next_state = TBD;  ///< Next state

  /* Pointers on current element */
  std::shared_ptr<FuncChunk> current_chunk = nullptr;  ///< Current chunk
  std::shared_ptr<Block> current_block = nullptr;      ///< Current block

  /**
   * Current instruction
   */
  std::shared_ptr<Instruction> current_instruction = nullptr;

  std::deque<Layout> layouts;  ///< List of layouts
  Layout current_layout;       ///< Current layout

  /* Main containers */
  FuncChunkCollection& func_chunks;  ///< Collection of chunks

  BucketNew<Instruction> instruction_bucket;       ///< Bucket of instruction
  BucketNew<Operand> operand_bucket;               ///< Bucket of operands
  BucketNew<OperandString> operand_string_bucket;  ///< Bucket of op strings
  BucketNew<Mnemonic> mnemonic_bucket;             ///< Bucket of mnemonic
  BucketNew<Data> data_list;                       ///< Bucket of data

  std::forward_list<std::shared_ptr<Block>> blocks;  ///< List of blocks

  Comments* comments;  ///< Collection for comments

  /**
   * Constructor
   * Set the address boundaries, and initialize the first address for the
   * iteration.
   *
   * @param start_ea Starting address
   * @param max_ea Maximum address
   * @param func_chunks Chunk collection
   */
  HeadIterator(ea_t start_ea, ea_t max_ea, FuncChunkCollection& func_chunks);

  /**
   * Is the `current_ea` a chunk head ?
   * @return Bool for success
   */
  [[nodiscard]] bool IsChunkHead() const;

  /**
   * Is the `current_ea` a chunk tail ?
   * @return Bool for success
   */
  [[nodiscard]] bool IsChunkTail() const;

  /**
   * Create a new chunk at `current_ea`
   * @return FuncChunk object
   */
  std::shared_ptr<FuncChunk> CreateNewChunk();

  /**
   * Create a fake chunk
   * For a fake chunk, we don't have any information on potential blocks
   * (expect the one starting at the chunk start) so it will be retrieved
   * on the fly
   * @return FuncChunk object
   */
  std::shared_ptr<FuncChunk> CreateFakeChunk();

  /**
   * Is the `current_ea` a block head ?
   * @return Bool for success
   */
  [[nodiscard]] bool IsBlockHead() const;

  /**
   * Is the `current_ea` a block tail ?
   * @return Bool for success
   */
  [[nodiscard]] bool IsBlockTail() const;

  /**
   * Create a new block at `current_ea`
   * @return Block
   */
  std::shared_ptr<Block> CreateNewBlock();

  /**
   * Create a fake block at `current_ea`
   * Sometimes, we may already have had the intuition that this address
   * would have been a block head (because of an edge pointing towards).
   * @return Block
   */
  std::shared_ptr<Block> CreateFakeBlock();

  /**
   * Is the `current_ea` an instruction head ?
   * @return Bool for success
   */
  [[nodiscard]] bool IsInstHead() const;

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
   * Compute the next address and state
   * @note The code of the method is documented to understand how to process
   */
  void NextAddressAndState();

  /**
   * Create a new layout and set it to current_layout
   * @param start_addr Start address
   * @param current_state Layout state
   * @param size Size of the layout
   */
  void StartLayout(ea_t start_addr, State current_state, ea_t size = 0);

  /**
   * Add the current layout to the layouts collection
   */
  void SaveLayout();

  /**
   * Augment the size of the current layout
   * Most of the item, it's only the size of the current item but for GAP,
   * we take a shortcut.
   */
  void AddLayoutSize();

  /**
   * Move forward
   * Set the {next_state, next_ea} to {state,current_ea} and compute new
   * values associated to this address.
   */
  void Iterate();
};

/**
 * Compute the state at address
 *
 * @param address Address
 * @return State type
 */
State GetState(ea_t address);

/**
 * Main exporter function
 *
 * This will be responsible for iterating through every head and thus
 * exporting Instruction, Data, Blocks and Functions.
 *
 * @param proto Main protobuf
 * @return Int for success
 */
int ExportLayout(quokka::Quokka* proto);

}  // namespace quokka
#endif  // QUOKKA_LAYOUT_H
