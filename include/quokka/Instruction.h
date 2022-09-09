// Copyright 2022 Quarkslab
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
 * @file Instruction.h
 * Instruction management
 */

#ifndef QUOKKA_INSTRUCTION_H
#define QUOKKA_INSTRUCTION_H

#include <sstream>
#include <unordered_set>
#include <utility>
#include <vector>

#include <ida.hpp>
#include <idp.hpp>
#include <lines.hpp>
#include <segregs.hpp>
#include <ua.hpp>

#include "absl/container/btree_set.h"
#include "absl/container/flat_hash_set.h"
#include "absl/hash/hash.h"
#include "absl/strings/str_format.h"

#include "Logger.h"
#include "ProtoHelper.h"
#include "Util.h"
#include "Windows.h"

namespace quokka {

/**
 * ---------------------------------------------
 * quokka::Operand
 * ---------------------------------------------
 * Operand representation
 *
 * This mostly replicate every field found in `op_t` class. The operands are
 * deduplicated so only one instance will be stored (e.g only one "eax").
 *
 * @note We could go further and analyze expression inside the operand to
 * deduplicate all of them (e.g [eax+0x5] and [eax+0x7] could be refactored)
 * but it's not done yet.
 *
 * @see ua.hpp (IDA SDK)
 */
class Operand : public ProtoHelper {
 public:
  uint32_t type = 0;   ///< Type of operand (@see optype_t)
  uint32_t flags = 0;  ///< Operand flags

  uint32_t op_value_type = 0;  ///< Type of operand value (op_dtype_t)
  uint64_t value = 0;          ///< Value of the operand

  uint32_t register_id = 0;  ///< Number of the register
  uint32_t phrase_id = 0;    ///< Number of register phrase

  int64 addr = 0;  ///< Virtual address pointed or used by the operand

  uint64_t specval = 0;                 ///< Custom field
  std::array<char, 4> specflags = {0};  ///< Custom fields (used in idp)

  /**
   * Default constructor
   * @param operand IDA-operand
   */
  explicit Operand(op_t operand);

  /**
   * Operator overloading
   */
  bool operator==(const Operand& rhs) const;
  bool operator!=(const Operand& rhs) const;
  bool operator<(const Operand& rhs) const;

  /**
   * Hash implementation of the object using absl::Hash
   * @tparam H Hash
   * @param h Hash value
   * @param m Operand object
   * @return An hash value for the object
   */
  template <typename H>
  friend H AbslHashValue(H h, const Operand& m);
};

class OperandString : public ProtoHelper {
 public:
  std::string representation;  ///< Operand String

  /**
   * Hash implementation of the object using absl::Hash
   * @tparam H Hash
   * @param h Hash value
   * @param m OperandString object
   * @return An hash value for the object
   */
  template <typename H>
  friend H AbslHashValue(H h, const OperandString& m);

  explicit OperandString(std::string m_) : representation(std::move(m_)){};

  /**
   * Operator overloading
   */
  bool operator==(const OperandString& rhs) const {
    return representation == rhs.representation;
  }

  bool operator!=(const OperandString& rhs) const { return !(rhs == *this); }
};

/**
 * ---------------------------------------------
 * quokka::Mnemonic
 * ---------------------------------------------
 * Storage of a mnemonic
 *
 * Mnemonics are deduplicated so only one occurrence of them will be stored.
 * @see ProtoHelper
 */
class Mnemonic : public ProtoHelper {
 public:
  std::string mnemonic;  ///< Mnemonic value

  /**
   * Hash implementation of the object using absl::Hash
   * @tparam H Hash
   * @param h Hash value
   * @param m Mnemonic object
   * @return An hash value for the object
   */
  template <typename H>
  friend H AbslHashValue(H h, const Mnemonic& m);

  /**
   * Constructor
   * @param m_ Value of the mnemonic
   */
  explicit Mnemonic(std::string m_) : mnemonic(std::move(m_)){};

  /**
   * Operator overloading
   */
  bool operator==(const Mnemonic& rhs) const {
    return mnemonic == rhs.mnemonic;
  }

  bool operator!=(const Mnemonic& rhs) const { return !(rhs == *this); }
};

/**
 * ---------------------------------------------
 * quokka::Instruction
 * ---------------------------------------------
 * Representation of an instruction
 *
 * The instruction is responsible for creating every operands it use. The
 * instruction are also deduplicated, so no address field is present (so
 * ``push ebp`` will be only stored once)
 */
class Instruction : public ProtoHelper {
 public:
  int inst_size;  ///< Size of the instruction (as decoded by IDA)
  std::shared_ptr<Mnemonic> mnemonic = nullptr;  ///< Instruction mnemonic
  bool thumb = false;                            ///< Is it a thumb instruction
  std::vector<std::shared_ptr<OperandString>> operand_strings;

  /**
   * Does the current decoded instance of the instruction denote the end of
   * a block.
   * IDA has a nice function to help delimit block boundaries (
   * `is_basic_block_end`) but need a `insn_t` object. We need to store it
   * there and it will be recomputed every time the instruction is used
   */
  bool is_block_end = false;

  std::vector<std::shared_ptr<Operand>> operands;  ///< List of operands

  /**
   * Constructor
   * @param instruction Decoded instruction (IDA object)
   * @param operand_bucket Operands bucket
   * @param mnemonic_bucket Mnemonic bucket
   * @param operand_string_bucket Operand string bucket
   */
  Instruction(const insn_t& instruction, BucketNew<Operand>& operand_bucket,
              BucketNew<Mnemonic>& mnemonic_bucket,
              BucketNew<OperandString>& operand_string_bucket);

  /**
   * Hash implementation of the object using absl::Hash
   * @tparam H Hash
   * @param h Hash value
   * @param m Instruction object
   * @return An hash value for the object
   */
  template <typename H>
  friend H AbslHashValue(H h, const Instruction& m) {
    return H::combine(std::move(h), m.inst_size, m.mnemonic, m.operands);
  }

  /**
   * Operator overloading
   */
  bool operator==(const Instruction& rhs) const;
  bool operator!=(const Instruction& rhs) const;
};

/**
 * Check if the address is a thumb one
 *
 * @param ea Address to check
 * @return Boolean for success
 */
bool is_thumb_ea(ea_t ea);

}  // namespace quokka

#endif  // QUOKKA_INSTRUCTION_H
