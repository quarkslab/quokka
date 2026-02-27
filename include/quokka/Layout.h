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

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string_view>
#include <utility>
#include <vector>

// clang-format off: Compatibility.h must come before ida headers
#include "Compatibility.h"
// clang-format on
#include <pro.h>

#include "Bucket.h"
#include "Data.h"
#include "ProtoWrapper.h"

namespace quokka {

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
  ea_t next_unk_addr = BADADDR;    ///< Next unknown address
  ea_t next_head_addr = BADADDR;   ///< Next head address

  Layout current_layout;  ///< Current layout

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
  std::deque<Layout> layouts;  ///< List of layouts

  // BucketNew<Instruction> instruction_bucket;         ///< Bucket of
  // instruction BucketNew<Operand> operand_bucket;                 ///< Bucket
  // of operands BucketNew<OperandString> operand_string_bucket;    ///< Bucket
  // of op strings BucketNew<Mnemonic> mnemonic_bucket;               ///<
  // Bucket of mnemonic
  SetBucket<Data> data_list;  ///< Bucket of data

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
  // std::shared_ptr<Instruction> CreateNewInst();

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
 * This will be responsible for iterating through every head that is not part of
 * the provided ranges, exporting blocks, instructions and data. Normally the
 * excluded ranges are the function chunks that have been already exported
 *
 * @param proto Main protobuf
 * @param excluded_ranges The ranges of addresses that should be skipped during
 * the analysis
 * @return Int for success
 */
int ExportLinearScan(Quokka* proto,
                     const std::vector<std::pair<ea_t, ea_t>>& exclude_ranges);

}  // namespace quokka
#endif  // QUOKKA_LAYOUT_H
