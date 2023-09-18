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

#include "quokka/Layout.h"

#include "quokka/Block.h"
#include "quokka/Comment.h"
#include "quokka/Data.h"
#include "quokka/Function.h"
#include "quokka/Imports.h"
#include "quokka/Instruction.h"
#include "quokka/Reference.h"
#include "quokka/Settings.h"
#include "quokka/Writer.h"

namespace quokka {

State GetState(ea_t address) {
  flags_t flags = get_flags(address);
  if (is_code(flags)) {
    return CODE;
  } else if (is_data(flags)) {
    return DATA;
  } else if (has_xref(flags)) {
    return UNK_WITH_XREF;
  }

  return UNK;
}

HeadIterator::HeadIterator(ea_t start_ea, ea_t max_ea,
                           FuncChunkCollection& func_chunks)
    : func_chunks(func_chunks), next_ea(BADADDR) {
  this->current_ea = start_ea;
  this->max_ea = max_ea;

  /* Initialize the next heads */
  InitAddresses(start_ea);

  /* Init item size*/
  this->item_size = uint64_t(get_item_size(this->current_ea));

  this->comments = &Comments::GetInstance();

  this->state = GetState(this->current_ea);
  this->StartLayout(this->current_ea, this->state);
}

void HeadIterator::InitAddresses(ea_t address) {
  this->next_unk_addr = next_unknown(address, this->max_ea);
  this->next_head_addr = next_head(address, this->max_ea);

  this->SetNextChunk(address);
}

void HeadIterator::SetNextChunk(ea_t address) {
  func_t* func = get_next_fchunk(address);
  if (func != nullptr) {
    this->next_chunk_addr = func->start_ea;
    this->next_func_chunk = func;
  } else {
    this->next_chunk_addr = BADADDR;
    this->next_func_chunk = nullptr;
  }
}

void HeadIterator::StartLayout(ea_t start_addr, State current_state,
                               ea_t size) {
  this->current_layout = Layout(current_state, start_addr, size);
}

void HeadIterator::NextAddressAndState() {
  this->next_state = TBD;

  // Get the next head
  this->next_ea = std::min(this->next_head_addr, this->next_unk_addr);

  /* Warning:  Order of the tests matters ! */

  // First, we test if it's the end
  if (this->state == FINISH || this->next_ea == BADADDR) {
    this->next_state = FINISH;

    // Second, we test if we have a GAP
  } else if (this->current_layout.start + this->current_layout.size !=
             this->next_ea) {
    this->next_state = GAP;

    // Reset next_ea to the start of the "GAP"
    this->next_ea = this->current_layout.start + this->current_layout.size;

    // We don't want to update the next_head_addr or next_unk_addr !

    // Third, we test if the next addr is a head
  } else if (this->next_ea == this->next_head_addr) {
    this->next_head_addr = next_head(this->next_head_addr, this->max_ea);

    // Then, we test if it's an "unknown" address
  } else if (this->next_ea == this->next_unk_addr) {
    this->next_unk_addr = next_unknown(this->next_ea, this->max_ea);

    // In the case of false decoding, we want to restart code as soon as
    // possible
    if (this->false_decoding) {
      size_t ins_size = create_insn(this->next_ea);
      if (ins_size > 0) {
        this->next_state = CODE;
        this->false_decoding = false;
        this->next_unk_addr =
            next_unknown(this->next_ea + ins_size, this->max_ea);
      } else {
        this->next_state = UNK;
      }
    }

    // An error somewhere ?
  } else {
    static_assert("We should not reach this part");
  }

  // If we did not determine the type of the next state yet, compute it.
  if (this->next_state == TBD) {
    this->next_state = GetState(this->next_ea);
  }
  assert(this->next_state != TBD && "Error during computation of next state");
}

void HeadIterator::AddLayoutSize() {
  if (this->current_ea != BADADDR) {
    if (this->state == GAP) {
      assert(this->current_layout.size == 0 && "Problem with gap size");

      // The size of "gap" head is always 1, so to go faster, we skip through
      // these useless heads
      ea_t next_head = std::min(this->next_head_addr, this->next_unk_addr);
      if (next_head ==
          BADADDR) {  // Check we did not reached the end of the program
        next_head = this->max_ea;
      }

      this->current_layout.size = next_head - this->current_ea;
    } else {
      this->current_layout.size += this->item_size;
    }
  }
}

void HeadIterator::SaveLayout() {
  this->layouts.push_back(this->current_layout);
}

void HeadIterator::Iterate() {
  this->state = this->next_state;
  this->current_ea = this->next_ea;

  this->item_size = uint64_t(get_item_size(this->current_ea));

  /* Reset instruction */
  if (this->state != CODE) {
    this->current_instruction = nullptr;
  }
}

bool HeadIterator::IsChunkHead() const {
  return this->state == CODE && this->current_ea == this->next_chunk_addr;
}

bool HeadIterator::IsChunkTail() const {
  if (this->state == CODE && this->current_chunk != nullptr) {
    return this->next_ea == this->next_chunk_addr ||
           // The next addr is already a known chunk
           // We know the end of the chunk
           (!this->current_chunk->fake_chunk &&
            this->current_chunk->end_addr ==
                this->current_ea + this->item_size);
  }
  return false;
}

std::shared_ptr<FuncChunk> HeadIterator::CreateNewChunk() {
  if (this->current_chunk != nullptr) {
    this->current_chunk->Resize(BADADDR);
  }

  this->current_chunk =
      this->func_chunks.Insert(this->current_ea, this->next_func_chunk);

  // Finally, prepare the next chunk head
  this->SetNextChunk(this->current_ea);

  return this->current_chunk;
}

bool HeadIterator::IsBlockHead() const {
  return this->state == CODE &&               // We need to be in code state
         this->current_chunk != nullptr &&    // To have a chunk
         !this->current_chunk->fake_chunk &&  // But to *not* have a fake chunk
         this->current_chunk->block_heads.find(this->current_ea) !=
             this->current_chunk->block_heads
                 .end();  // And to check if the head is in the head list
}

bool HeadIterator::IsBlockTail() const {
  if (this->state == CODE && this->current_block != nullptr &&
      this->current_instruction != nullptr) {
    /* Most of the time, we trust IDA to give block boundaries. However, for
     * alignment directives IDA considers either DATA or NOP instructions
     * and is not consistent */
    return this->next_state != CODE ||
           this->current_instruction->is_block_end || IsChunkTail();
  }
  return false;
}

std::shared_ptr<Block> HeadIterator::CreateNewBlock() {
  // size_t block_idx = this->current_chunk->block_heads.at(this->current_ea);
  ea_t end_ea = this->current_chunk->block_ends[this->current_ea];

  assert(end_ea != 0x0 && end_ea != BADADDR && "Problem with end address");
  assert(end_ea > this->current_ea && "Block misformed");

  BlockType block_type =
      RetrieveBlockType(this->current_chunk->block_types[this->current_ea]);
  this->blocks.emplace_front(
      std::make_shared<Block>(this->current_ea, end_ea, block_type));
  this->current_block = this->blocks.front();

  this->current_chunk->blocks.push_back(this->current_block);

  return this->current_block;
}

std::shared_ptr<Block> HeadIterator::CreateFakeBlock() {
  this->blocks.emplace_front(std::make_shared<Block>(this->current_ea));
  this->current_block = this->blocks.front();

  auto result = this->current_chunk->block_heads.find(this->current_ea);
  if (result == this->current_chunk->block_heads.end()) {
    this->current_chunk->block_heads.emplace(this->current_ea);
  }

  this->current_chunk->blocks.push_back(this->current_block);

  return this->current_block;
}

std::shared_ptr<FuncChunk> HeadIterator::CreateFakeChunk() {
  this->current_chunk = this->func_chunks.Insert(this->current_ea);

  if (get_fileregion_offset(this->current_ea) == -1) {
    this->current_chunk->in_file = false;
  }

  return this->current_chunk;
}

std::shared_ptr<Instruction> HeadIterator::CreateNewInst() {
  insn_t instruction;
  int decoded_size = decode_insn(&instruction, this->current_ea);
  if (decoded_size != 0) {
    this->current_instruction = this->instruction_bucket.emplace(
        instruction, this->operand_bucket, this->mnemonic_bucket,
        this->operand_string_bucket);

  } else {
    this->current_instruction = nullptr;
    this->false_decoding = true;

    if (not del_items(this->current_ea, DELIT_SIMPLE, this->item_size)) {
      QLOGE << "Unable to delete falsy instruction, layout may be incomplete";
    }

    return nullptr;
  }

  // Orphaned instructions : create a fake chunk and a fake block
  if (this->current_chunk == nullptr) {
    this->CreateFakeChunk();
  }

  if (this->current_block == nullptr) {
    this->CreateFakeBlock();
  } else {
    this->current_instruction->is_block_end =
        is_basic_block_end(instruction, false);
  }

  this->current_block->AppendInstruction(this->current_instruction);
  return this->current_instruction;
}
bool HeadIterator::IsInstHead() const { return this->state == CODE; }

void MergeLayouts(std::deque<Layout>& layouts) {
  std::deque<Layout> merged_layouts;
  auto should_merge = [](const Layout& left, const Layout& right) -> bool {
    return left.type == right.type and
           (right.start + right.size == left.start or
            left.start + left.size == right.start);
  };

  auto merge_layout = [](const Layout& left, const Layout& right) -> Layout {
    return {left.type, std::min(left.start, right.start),
            left.size + right.size};
  };

  // TODO(dm) Check if useful (hint: probably not) -> should be improved for
  //  UNK_WITH_REF
  MergeAdjacent(begin(layouts), end(layouts),
                std::back_inserter(merged_layouts), should_merge, merge_layout);

  QLOGD << absl::StrFormat("Previous size: %d", layouts.size());
  QLOGD << absl::StrFormat("Merged size: %d", merged_layouts.size());

  layouts = merged_layouts;
}

int ExportLayout(quokka::Quokka* proto) {
  FuncChunkCollection func_chunks;
  HeadIterator head_iterator(inf_get_min_ea(), inf_get_max_ea(), func_chunks);

  Timer timer(absl::Now());
  QLOGI << "Start to export Layout";

  int inst_count = 0;

  /* Get the import range */
  ImportManager import_manager = ImportManager();

  bool export_instructions = Settings::GetInstance().ExportInstructions();

  while (true) {
    /* We need to compute this now because next_state is used later*/
    head_iterator.AddLayoutSize();
    head_iterator.NextAddressAndState();

    if (head_iterator.state == FINISH) {
      if (head_iterator.current_chunk != nullptr)
        head_iterator.current_chunk->Resize(BADADDR);
      QLOGI << absl::StrFormat("End export layout in %.2fs",
                               timer.ElapsedSeconds(absl::Now()));
      break;
    } else if (head_iterator.state == CODE) {
      if (head_iterator.IsChunkHead()) {
        head_iterator.CreateNewChunk();
      }

      if (head_iterator.IsBlockHead() and
          not import_manager.InImport(head_iterator.current_ea)) {
        head_iterator.CreateNewBlock();
      }

      if (head_iterator.IsInstHead()) {
        /* We want to only export instructions when not in the import table
         * This behavior change between PE and ELF but we want consistency.
         * */
        if (export_instructions &&
            !import_manager.InImport(head_iterator.current_ea)) {
          head_iterator.CreateNewInst();

          if (head_iterator.current_instruction != nullptr) {
            ++inst_count;

            int instruction_index =
                int(head_iterator.current_block->instructions.size()) - 1;

            GetComments(head_iterator.current_ea,
                        head_iterator.current_block->instructions.back());

            ExportCodeReference(head_iterator.current_ea,
                                head_iterator.current_chunk,
                                head_iterator.current_block, instruction_index,
                                head_iterator.data_list);
          } else {
            // We failed the decoding of the instruction, so it's probably not
            // code

            // Resize block + chunk
            head_iterator.current_block->Resize(head_iterator.current_ea, true);
            head_iterator.current_chunk->Resize(head_iterator.current_ea);

            head_iterator.current_block = nullptr;
            head_iterator.current_chunk = nullptr;

            head_iterator.current_layout.size -= head_iterator.item_size;
            head_iterator.SaveLayout();

            head_iterator.state = UNK;
            head_iterator.item_size = get_item_size(head_iterator.current_ea);
            head_iterator.StartLayout(head_iterator.current_ea,
                                      head_iterator.state,
                                      head_iterator.item_size);

            head_iterator.InitAddresses(head_iterator.current_ea);
            head_iterator.NextAddressAndState();
          }
          // We don't want to create Fake* when dealing with imports
        } else if (not import_manager.InImport(head_iterator.current_ea)) {
          if (head_iterator.current_chunk == nullptr) {
            head_iterator.CreateFakeChunk();
          }
          if (head_iterator.current_block == nullptr) {
            head_iterator.CreateFakeBlock();
          }
        }
      }

    } else if (head_iterator.state == DATA) {
      if (not import_manager.InImport(head_iterator.current_ea)) {
        /*
         * In PE, the imports are listed as DATA.
         * We want instead to have them as empty chunks (and funcs)
         * */

        DataType data_type = GetDataType(get_flags(head_iterator.current_ea));

        std::shared_ptr<Data> data = head_iterator.data_list.emplace(
            head_iterator.current_ea, data_type, head_iterator.item_size);
        uint32_t ref_count =
            ExportDataReferences(head_iterator.current_ea, data);
        data->ref_count += ref_count;
      }

    } else if (head_iterator.state == UNK_WITH_XREF) {
      /* IDA being IDA, some unknown part in the code have data ref attached
       * to them.
       *
       * This tries to deal with this case but also attaching "data" ref to
       * unknown part of the code.
       * */

      ExportUnkReferences(head_iterator.current_ea, head_iterator.data_list);
    }

    if (head_iterator.IsBlockTail()) {
      head_iterator.current_block->Resize(head_iterator.current_ea +
                                          head_iterator.item_size);
      head_iterator.current_block = nullptr;
    }

    if (head_iterator.IsChunkTail()) {
      head_iterator.current_chunk->Resize(head_iterator.current_ea +
                                          head_iterator.item_size);
      head_iterator.current_chunk = nullptr;
    }

    if (head_iterator.state != head_iterator.next_state) {
      head_iterator.SaveLayout();
      if (head_iterator.next_state != FINISH) {
        head_iterator.StartLayout(head_iterator.next_ea,
                                  head_iterator.next_state);
      }
    }

    head_iterator.Iterate();
  }

  QLOGD << absl::StrFormat("Found %d instructions", inst_count);

  timer.Reset();

  QLOGI << "Start to write layout.";
  MergeLayouts(head_iterator.layouts);
  WriteLayout(proto, head_iterator.layouts);
  head_iterator.layouts = {};

  if (export_instructions) {
    QLOGI << "Start to write mnemonic.";
    WriteMnemonic(proto, head_iterator.mnemonic_bucket);
    QLOGI << absl::StrFormat("Finished to write mnemonics (took: %.2fs)",
                             timer.ElapsedSeconds(absl::Now()));

    timer.Reset();
    QLOGI << "Start to write operand strings.";
    WriteOperandStrings(proto, head_iterator.operand_string_bucket);
    QLOGI << absl::StrFormat("Finished to write operand_strings (took: %.2fs)",
                             timer.ElapsedSeconds(absl::Now()));

    timer.Reset();
    QLOGI << "Start to write operands";
    WriteOperands(proto, head_iterator.operand_bucket);
    QLOGI << absl::StrFormat("Finished to write operands (took: %.2fs)",
                             timer.ElapsedSeconds(absl::Now()));

    timer.Reset();
    QLOGI << "Start to write instructions";
    WriteInstructions(proto, head_iterator.instruction_bucket);
    QLOGI << absl::StrFormat("Finished to write instructions (took: %.2fs)",
                             timer.ElapsedSeconds(absl::Now()));

    head_iterator.mnemonic_bucket.clear();
    head_iterator.operand_bucket.clear();
  }

  {
    QLOGD << "Start to sort chunks";
    ResolveEdges(head_iterator.func_chunks, ReferenceHolder::GetInstance());
    Timer sort_timer(absl::Now());
    head_iterator.func_chunks.Sort();
    QLOGD << absl::StrFormat("Chunks sorted (took %.2fs)",
                             sort_timer.ElapsedSeconds(absl::Now()));
  }

  QLOGI << "Start to write func chunks";
  timer.Reset();
  import_manager.AddMissingChunks(head_iterator.func_chunks);
  WriteFuncChunk(proto, head_iterator.func_chunks);

  QLOGI << absl::StrFormat("Finished to write func_chunks (took: %.2fs)",
                           timer.ElapsedSeconds(absl::Now()));

  {
    QLOGI << "Start to export and write functions";
    Timer func_timer(absl::Now());
    std::vector<Function> func_list;

    ExportFunctions(func_list, head_iterator.func_chunks, import_manager);
    WriteFunctions(proto, func_list, head_iterator.func_chunks);

    QLOGI << absl::StrFormat(
        "Finished to export/write functions (took : %.2fs)",
        func_timer.ElapsedSeconds(absl::Now()));
  }

  {
    QLOGI << "Start to transform references";
    Timer sort_timer(absl::Now());

    ReferenceHolder::GetInstance().RemoveMissingAddr(
        head_iterator.func_chunks, head_iterator.instruction_bucket,
        head_iterator.data_list, Structures::GetInstance());

    QLOGD << absl::StrFormat("Removing took %.2fs",
                             sort_timer.ElapsedSeconds(absl::Now()));
  }

  QLOGI << "Start to write data, comments and references";
  timer.Reset();
  WriteData(proto, head_iterator.data_list);

  WriteComments(proto, head_iterator.comments);

  /* WRITE AFTER FUNCTIONS */
  WriteReferences(proto, ReferenceHolder::GetInstance());

  QLOGI << absl::StrFormat(
      "Finished to write data comments and references (took : %.2fs)",
      timer.ElapsedSeconds(absl::Now()));

  return eOk;
}

}  // namespace quokka
