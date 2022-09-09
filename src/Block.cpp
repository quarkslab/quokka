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

#include "quokka/Block.h"

#include "quokka/Instruction.h"

namespace quokka {

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

std::optional<int> Block::GetInstIndex(ea_t addr) const {
  auto iterator = address_to_index.find(addr);
  if (iterator != address_to_index.end()) {
    return iterator->second;
  }

  return std::nullopt;
}

void Block::Resize(ea_t endaddr, bool force) {
  if (this->is_fake or force) {
    this->end_addr = endaddr;
  }

  if (this->end_addr != endaddr) {
    QLOGE << "Error while computing end address for a block";
  }
}

bool Block::IsBetween(ea_t addr) const {
  return addr >= start_addr && addr < end_addr;
}

void Block::AppendInstruction(const std::shared_ptr<Instruction>& instruction) {
  address_to_index.try_emplace(current_address,
                               static_cast<int>(instructions.size()));
  this->instructions.push_back(instruction);
  current_address += static_cast<ea_t>(instruction->inst_size);
}

}  // namespace quokka