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

// clang-format off: Compatibility.h must come before ida headers
#include "quokka/Compatibility.h"
// clang-format on
#include <idp.hpp>
#include <segregs.hpp>
#include <ua.hpp>

#include "absl/strings/str_format.h"

#include "quokka/Block.h"
#include "quokka/Instruction.h"
#include "quokka/Reference.h"
#include "quokka/Settings.h"
#include "quokka/Util.h"

namespace quokka {

static bool is_thumb_ea(ea_t ea) {
  if (GetProcessor()->id != PLFM_ARM) {
    return false;
  }

  // 20 is the segment used for ARM to store thumb mode
  sel_t t = get_sreg(ea, 20);
  return t != BADSEL && t != 0;
}

BlockType RetrieveBlockType(fc_block_type_t block_type) {
  switch (block_type) {
    case fcb_normal:
      return BTYPE_NORMAL;
    case fcb_indjump:
      return BTYPE_INDJUMP;
    case fcb_ret:
      return BTYPE_RET;
    case fcb_cndret:
      return BTYPE_CNDRET;
    case fcb_noret:
      return BTYPE_NORET;
    case fcb_enoret:
      return BTYPE_ENORET;
    case fcb_extern:
      return BTYPE_EXTERN;
    case fcb_error:
      return BTYPE_ERROR;
  }
  assert(false && "Invalid block type");
}

Block::Block(ea_t addr, ea_t eaddr, BlockType block_type)
    : start_addr(addr), end_addr(eaddr), block_type(block_type) {
  current_address = start_addr;

  try {
    this->segment = &GetSegment(this->start_addr);
  } catch (const std::out_of_range& e) {
    std::throw_with_nested(std::runtime_error(
        absl::StrFormat("Block at address 0x%x doesn't belong to any segment",
                        this->start_addr)));
  }

  this->file_offset = get_fileregion_offset(this->start_addr);
  this->is_thumb = is_thumb_ea(this->start_addr);

  this->ExportInstructions();
}

void Block::ExportInstructions() {
  Instructions& instructions = Instructions::GetInstance();
  ea_t current_ea = this->start_addr;
  bool export_instructions = Settings::GetInstance().ExportInstructions();

  while (current_ea < this->end_addr) {
    insn_t ida_instruction;
    int decoded_size = decode_insn(&ida_instruction, current_ea);
    if (decoded_size == 0) {
      // TODO. HUGE PROBLEM. WHAT TO DO HERE? HOW TO RECOVER?
      // this->current_instruction = nullptr;
      // this->false_decoding = true;

      // if (not del_items(this->current_ea, DELIT_SIMPLE, this->item_size)) {
      //   QLOGE << "Unable to delete falsy instruction, layout may be
      //       incomplete ";
      // }

      // return nullptr;
      assert(false);
    }

    // Export only if required
    if (export_instructions) {
      // Instruction instruction = instructions.emplace(
      //     ida_instruction, this->operand_bucket, this->mnemonic_bucket,
      //     this->operand_string_bucket);

      // // Orphaned instructions : create a fake chunk and a fake block
      // if (this->current_chunk == nullptr) {
      //   this->CreateFakeChunk();
      // }

      // if (this->current_block == nullptr) {
      //   this->CreateFakeBlock();
      // } else {
      //   this->current_instruction->is_block_end =
      //       is_basic_block_end(instruction, false);
      // }

      // address_to_index.try_emplace(current_ea,
      //                              static_cast<int>(instructions.size()));
      // this->instructions.push_back(instruction);
    }

    ExportCodeReference(current_ea);

    ++this->instr_count;
    current_ea += static_cast<ea_t>(decoded_size);
  }
}

// std::optional<int> Block::GetInstIndex(ea_t addr) const {
//   auto iterator = address_to_index.find(addr);
//   if (iterator != address_to_index.end()) {
//     return iterator->second;
//   }

//   return std::nullopt;
// }

// void Block::Resize(ea_t endaddr, bool force) {
//   if (this->is_fake or force) {
//     this->end_addr = endaddr;
//   }

//   if (this->end_addr != endaddr) {
//     QLOGE << "Error while computing end address for a block";
//   }
// }

// bool Block::IsBetween(ea_t addr) const {
//   return addr >= start_addr && addr < end_addr;
// }

}  // namespace quokka