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

#include "quokka/Instruction.h"

#include "quokka/Compatibility.h"
#include "quokka/Settings.h"

namespace quokka {

Operand::Operand(op_t operand) {
  this->type = operand.type;

  /* Remove the shown flags */
  this->flags = operand.flags;
  this->flags &= ~OF_SHOW;

  /* Set value & value type */
  this->op_value_type = operand.dtype;
  this->value = operand.value;

  this->register_id = operand.reg;
  this->phrase_id = operand.phrase;

  // 0xfffffffffff9d84d
  this->addr = static_cast<int64>(operand.addr);

  /*  Special values */
  this->specval = operand.specval;
  this->specflags = {operand.specflag1, operand.specflag2, operand.specflag3,
                     operand.specflag4};
}

template <typename H>
H AbslHashValue(H h, const Operand& m) {
  return H::combine(std::move(h), m.type, m.flags, m.op_value_type, m.value,
                    m.register_id, m.phrase_id, m.addr, m.specflags, m.specval);
}

bool Operand::operator<(const Operand& rhs) const {
  return absl::Hash<Operand>()(rhs) < absl::Hash<Operand>()(*this);
}

bool Operand::operator==(const Operand& rhs) const {
  return type == rhs.type && flags == rhs.flags &&
         op_value_type == rhs.op_value_type && value == rhs.value &&
         register_id == rhs.register_id && phrase_id == rhs.phrase_id &&
         addr == rhs.addr && specval == rhs.specval &&
         specflags == rhs.specflags;
}

bool Operand::operator!=(const Operand& rhs) const { return !(rhs == *this); }

template <typename H>
H AbslHashValue(H h, const Mnemonic& m) {
  return H::combine(std::move(h), m.mnemonic);
}

Instruction::Instruction(const insn_t& instruction,
                         BucketNew<Operand>& operand_bucket,
                         BucketNew<Mnemonic>& mnemonic_bucket,
                         BucketNew<OperandString>& operand_string_bucket) {
  this->inst_size = instruction.size;
  this->thumb = is_thumb_ea(instruction.ea);

  this->mnemonic = mnemonic_bucket.emplace(GetMnemonic(instruction));

  qstring name;
  for (auto operand : instruction.ops) {
    if (operand.type == o_void) {
      break;
    }

    this->operands.push_back(operand_bucket.emplace(operand));

    // Export also the operand string if needed
    if (Settings::GetInstance().ExportInstructionStrings()) {
      print_operand(&name, instruction.ea,
                    static_cast<int>(this->operands.size()) - 1);
      tag_remove(&name, name);
      if (!name.empty()) {
        this->operand_strings.push_back(
            operand_string_bucket.emplace(ConvertIdaString(name)));
      }
    }
  }
}

bool Instruction::operator==(const Instruction& rhs) const {
  return inst_size == rhs.inst_size && mnemonic == rhs.mnemonic &&
         operands == rhs.operands;
}

bool Instruction::operator!=(const Instruction& rhs) const {
  return !(rhs == *this);
}

inline bool is_thumb_ea(ea_t ea) {
  if (GetProcessor()->id != PLFM_ARM) {
    return false;
  }

  // 20 is the segment used for ARM to store thumb mode
  sel_t t = get_sreg(ea, 20);
  return t != BADSEL && t != 0;
}

template <typename H>
H AbslHashValue(H h, const OperandString& m) {
  return H::combine(std::move(h), m.representation);
}

}  // namespace quokka