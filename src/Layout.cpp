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
#include <cstddef>
#include <stdexcept>
#include <utility>

#include "absl/container/btree_map.h"
#include "absl/strings/str_format.h"
#include "absl/time/clock.h"
#include "pro.h"
#include "quokka/Block.h"
#include "quokka/Comment.h"
#include "quokka/Data.h"
#include "quokka/DataType.h"
// #include "quokka/Function.h"
#include "quokka/Function.h"
#include "quokka/Imports.h"
#include "quokka/Instruction.h"
// #include "quokka/Reference.h"
#include "quokka/Segment.h"
#include "quokka/Settings.h"
#include "quokka/Writer.h"

namespace quokka {

constexpr const bool LOCAL_TRACE = false;

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

HeadIterator::HeadIterator(ea_t start_ea, ea_t max_ea)
    : current_ea(start_ea), max_ea(max_ea) {
  /* Initialize the next heads */
  InitAddresses(start_ea);

  /* Init item size*/
  this->item_size = uint64_t(get_item_size(this->current_ea));

  this->comments = &Comments::GetInstance();

  this->state = GetState(this->current_ea);
  this->StartLayout(this->current_ea, this->state);
}

void HeadIterator::UpdateNextEa() {
  this->next_ea = std::min(this->next_head_addr, this->next_unk_addr);

  // Check we did not reached the end of the program
  if (this->next_ea == BADADDR)
    this->next_ea = this->max_ea;
}

void HeadIterator::InitAddresses(ea_t address) {
  this->next_unk_addr = next_unknown(address, this->max_ea);
  this->next_head_addr = next_head(address, this->max_ea);
  this->UpdateNextEa();
}

void HeadIterator::StartLayout(ea_t start_addr, State current_state,
                               ea_t size) {
  this->current_layout = Layout(current_state, start_addr, size);
}

void HeadIterator::AddLayoutSize(size_t size /* = 0 */) {
  assert(this->current_ea != BADADDR);  // should never happen

  if (this->state == GAP) {
    assert(this->current_layout.size == 0 && "Problem with gap size");

    // The size of "gap" head is always 1, so to go faster, we skip through
    // these useless heads
    this->current_layout.size =
        (size ? size : this->next_ea - this->current_ea);
  } else {
    this->current_layout.size += (size ? size : this->item_size);
  }
}

void HeadIterator::RotateLayout(State state, ea_t addr, ea_t size) {
  this->layouts.push_back(
      std::exchange(this->current_layout, Layout(state, addr, size)));
}

void HeadIterator::Iterate() {
  State next_state = TBD;

  /* Warning:  Order of the tests matters ! */

  // First, we test if it's the end
  if (this->state == FINISH || this->next_ea == this->max_ea) {
    next_state = FINISH;

    // Second, we test if we have a GAP
  } else if (this->current_layout.start + this->current_layout.size !=
             this->next_ea) {
    assert(this->current_layout.start + this->current_layout.size <
           this->next_ea);
    next_state = GAP;

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
    // TODO check
    // if (this->false_decoding) {
    //   size_t ins_size = create_insn(this->next_ea);
    //   if (ins_size > 0) {
    //     this->next_state = CODE;
    //     this->false_decoding = false;
    //     this->next_unk_addr =
    //         next_unknown(this->next_ea + ins_size, this->max_ea);
    //   } else {
    //     this->next_state = UNK;
    //   }
    // }

    // An error somewhere ?
  } else {
    static_assert("We should not reach this part");
  }

  // If we did not determine the type of the next state yet, compute it.
  if (next_state == TBD)
    next_state = GetState(this->next_ea);
  assert(next_state != TBD && "Error during computation of next state");

  // Save layout and start a new one unless the state is preserved
  if (this->state != next_state) {
    this->RotateLayout(next_state, this->next_ea, 0);
  }

  // Update the state
  this->state = next_state;
  this->current_ea = this->next_ea;
  this->UpdateNextEa();
  this->item_size = uint64_t(get_item_size(this->current_ea));

  /* Reset instruction */
  if (this->state != CODE) {
    this->current_instruction = nullptr;
  }
}

bool HeadIterator::IsChunkTail() const {
  return this->state == CODE &&              // Must be in the code section
         this->current_chunk.has_value() &&  // Chunk is valid
         (this->next_ea == this->next_chunk_addr ||  // Next ea is a valid chunk
          this->current_chunk->end_addr ==
              this->current_ea +
                  this->item_size  // We are at the advertised end of the chunk
         );
}

void HeadIterator::CreateNewChunk() {
  if (this->current_chunk.has_value())
    throw std::runtime_error(
        "Trying to create a new chunk while there is still an active one");

  this->current_chunk.emplace(this->next_func_chunk);
}

bool HeadIterator::IsBlockTail() const {
  /* Most of the time, we trust IDA to give block boundaries. However, for
   * alignment directives IDA considers either DATA or NOP instructions
   * and is not consistent */
  return this->state == CODE &&             // Must be in the code section
         this->current_block != nullptr &&  // There is an active current block
         (GetState(this->current_ea + this->item_size) !=
              CODE ||             // Next address is not code
          this->IsChunkTail() ||  // This is a chunk tail
          true                    // TODO add end of block
         );
}

std::shared_ptr<Block> HeadIterator::CreateNewBlock() {
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
  // this->blocks.emplace_front(std::make_shared<Block>(this->current_ea));
  // this->current_block = this->blocks.front();

  // auto result = this->current_chunk->block_heads.find(this->current_ea);
  // if (result == this->current_chunk->block_heads.end()) {
  //   this->current_chunk->block_heads.emplace(this->current_ea);
  // }

  // this->current_chunk->blocks.push_back(this->current_block);

  // return this->current_block;
}

// std::shared_ptr<FuncChunk> HeadIterator::CreateFakeChunk() {
//   this->current_chunk = this->func_chunks.Insert(this->current_ea);

//   if (get_fileregion_offset(this->current_ea) == -1) {
//     this->current_chunk->in_file = false;
//   }

//   return this->current_chunk;
// }

std::shared_ptr<Instruction> HeadIterator::CreateNewInst() {
  // insn_t instruction;
  // int decoded_size = decode_insn(&instruction, this->current_ea);
  // if (decoded_size != 0) {
  //   this->current_instruction = this->instruction_bucket.emplace(
  //       instruction, this->operand_bucket, this->mnemonic_bucket,
  //       this->operand_string_bucket);

  // } else {
  //   this->current_instruction = nullptr;
  //   this->false_decoding = true;

  //   if (not del_items(this->current_ea, DELIT_SIMPLE, this->item_size)) {
  //     QLOGE << "Unable to delete falsy instruction, layout may be
  //     incomplete";
  //   }

  //   return nullptr;
  // }

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

  // this->current_block->AppendInstruction(this->current_instruction);
  return this->current_instruction;
}

void HeadIterator::DebugPrint() const {
  QLOGD << "HeadIterator";
  QLOGD << absl::StrFormat("\tstate: %s", to_string(this->state));
  QLOGD << absl::StrFormat("\tcurrent_ea: 0x%08x", this->current_ea);
  QLOGD << absl::StrFormat("\tmax_ea: 0x%08x", this->max_ea);
  QLOGD << absl::StrFormat("\titem_size: 0x%x", this->item_size);
  QLOGD << absl::StrFormat("\tnext_head_addr: 0x%08x", this->next_head_addr);
  QLOGD << absl::StrFormat("\tnext_unk_addr: 0x%08x", this->next_unk_addr);
  QLOGD << absl::StrFormat("\tnext_chunk_addr: 0x%08x", this->next_chunk_addr);
  QLOGD << absl::StrFormat("\tnext_ea: 0x%08x\n", this->next_ea);
}

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

void HeadIterator::Scan(
    bool export_instructions,
    const std::vector<std::pair<ea_t, ea_t>>& exclude_ranges) {
  const ImportManager& import_manager = ImportManager::GetInstance();
  int inst_count = 0;

  Timer timer(absl::Now());
  QLOGI << "Starting the linear scan";

  auto range_it = exclude_ranges.cbegin();
  auto is_excluded = [&](ea_t addr) -> bool {
    while (range_it != exclude_ranges.end() && range_it->second <= addr)
      ++range_it;
    return (range_it != exclude_ranges.end() && range_it->first <= addr &&
            addr < range_it->second);
  };

  if constexpr (LOCAL_TRACE) {
    QLOGD << "Excluded ranges";
    for (const auto& r : exclude_ranges)
      QLOGD << absl::StrFormat("0x%08x - 0x%08x", r.first, r.second);
  }

  while (true) {
    if constexpr (LOCAL_TRACE)
      this->DebugPrint();

    // Skip addresses in the excluded ranges (they have been already exported).
    // We still have to take into account the skipped range for the layout
    if (is_excluded(this->current_ea)) {
      this->AddLayoutSize(range_it->second - range_it->first);
      this->InitAddresses(range_it->second);
      this->next_ea = range_it->second;
      goto iterate;
    }

    this->AddLayoutSize();

    if (this->state == FINISH) {
      // Last chunk should have already been finalized
      QLOGI << absl::StrFormat("Linear scan terminated in %.2fs",
                               timer.ElapsedSeconds(absl::Now()));
      break;

    } else if (this->state == CODE) {
      assert(!import_manager.InImport(this->current_ea) &&
             "Imported functions should have already been exported and be part "
             "of the excluded ranges");

      // Export the orphaned instructions
      if (export_instructions) {
        // this->CreateNewInst();

        //     if (head_iterator.current_instruction != nullptr) {
        //       ++inst_count;

        //       int instruction_index =
        //           int(head_iterator.current_block->instructions.size()) -
        //           1;

        //       GetComments(head_iterator.current_ea,
        //                   head_iterator.current_block->instructions.back());

        //       ExportCodeReference(head_iterator.current_ea,
        //                           head_iterator.current_chunk,
        //                           head_iterator.current_block,
        //                           instruction_index,
        //                           head_iterator.data_list);
        //     } else {
        //       // We failed the decoding of the instruction, so it's
        //       probably not
        //           // code

        //           // Resize block + chunk
        //           head_iterator.current_block->Resize(head_iterator.current_ea,
        //                                               true);
        //       head_iterator.current_chunk->Resize(head_iterator.current_ea);

        //       head_iterator.current_block = nullptr;
        //       head_iterator.current_chunk = nullptr;

        //       head_iterator.current_layout.size -= head_iterator.item_size;
        //       head_iterator.SaveLayout();

        //       head_iterator.state = UNK;
        //       head_iterator.item_size =
        //       get_item_size(head_iterator.current_ea);
        //       head_iterator.StartLayout(head_iterator.current_ea,
        //                                 head_iterator.state,
        //                                 head_iterator.item_size);

        //       head_iterator.InitAddresses(head_iterator.current_ea);
        //       head_iterator.NextAddressAndState();
        //     }
        //     // We don't want to create Fake* when dealing with imports
      }

    } else if (this->state == DATA) {
      // In PE, the imports are listed as DATA
      assert(!import_manager.InImport(this->current_ea) &&
             "Found an imported function in the DATA section that is not part "
             "of the excluded ranges");

      const Data& data =
          this->data_list.insert(Data::Make(this->current_ea, this->item_size));

      // uint32_t ref_count =
      //     ExportDataReferences(head_iterator.current_ea, data);
      // data.ref_count += ref_count;

    } else if (this->state == UNK_WITH_XREF) {
      /* IDA being IDA, some unknown part in the code have data ref attached
       * to them.
       *
       * This tries to deal with this case but also attaching "data" ref to
       * unknown part of the code.
       * */

      // ExportUnkReferences(head_iterator.current_ea, head_iterator.data_list);
    }

  iterate:  // Iterate on the next head
    this->Iterate();
  }

  QLOGD << absl::StrFormat("Found %d instructions", inst_count);
}

int ExportLinearScan(quokka::Quokka* proto,
                     const std::vector<std::pair<ea_t, ea_t>>& exclude_ranges) {
  bool export_instructions = Settings::GetInstance().ExportInstructions();

  HeadIterator head_iterator(inf_get_min_ea(), inf_get_max_ea());

  head_iterator.Scan(export_instructions, std::move(exclude_ranges));

  Timer timer(absl::Now());

  QLOGI << "Starting to write segments...";
  WriteSegments(proto);
  QLOGI << absl::StrFormat("Segments written successfully (took: %.2fs)",
                           timer.ElapsedSeconds(absl::Now()));

  QLOGI << "Start to write layout.";
  MergeLayouts(head_iterator.layouts);
  WriteLayout(proto, head_iterator.layouts);
  head_iterator.layouts = {};

  // if (export_instructions) {
  //   QLOGI << "Start to write mnemonic.";
  //   WriteMnemonic(proto, head_iterator.mnemonic_bucket);
  //   QLOGI << absl::StrFormat("Finished to write mnemonics (took: %.2fs)",
  //                            timer.ElapsedSeconds(absl::Now()));

  //   timer.Reset();
  //   QLOGI << "Start to write operand strings.";
  //   WriteOperandStrings(proto, head_iterator.operand_string_bucket);
  //   QLOGI << absl::StrFormat("Finished to write operand_strings (took:
  //   %.2fs)",
  //                            timer.ElapsedSeconds(absl::Now()));

  //   timer.Reset();
  //   QLOGI << "Start to write operands";
  //   WriteOperands(proto, head_iterator.operand_bucket);
  //   QLOGI << absl::StrFormat("Finished to write operands (took: %.2fs)",
  //                            timer.ElapsedSeconds(absl::Now()));

  //   timer.Reset();
  //   QLOGI << "Start to write instructions";
  //   WriteInstructions(proto, head_iterator.instruction_bucket);
  //   QLOGI << absl::StrFormat("Finished to write instructions (took:
  //   %.2fs)",
  //                            timer.ElapsedSeconds(absl::Now()));

  //   head_iterator.mnemonic_bucket.clear();
  //   head_iterator.operand_bucket.clear();
  // }

  // {
  //   QLOGD << "Start to sort chunks";
  //   ResolveEdges(head_iterator.func_chunks,
  //   ReferenceHolder::GetInstance()); Timer sort_timer(absl::Now());
  //   head_iterator.func_chunks.Sort();
  //   QLOGD << absl::StrFormat("Chunks sorted (took %.2fs)",
  //                            sort_timer.ElapsedSeconds(absl::Now()));
  // }

  // QLOGI << "Start to write func chunks";
  // timer.Reset();
  // import_manager.AddMissingChunks(head_iterator.func_chunks);
  // WriteFuncChunk(proto, head_iterator.func_chunks);

  // QLOGI << absl::StrFormat("Finished to write func_chunks (took: %.2fs)",
  //                          timer.ElapsedSeconds(absl::Now()));

  // {
  //   QLOGI << "Start to export and write functions";
  //   Timer func_timer(absl::Now());
  //   std::vector<Function> func_list;

  //   ExportFunctions(func_list, head_iterator.func_chunks, import_manager);
  //   WriteFunctions(proto, func_list, head_iterator.func_chunks);

  //   QLOGI << absl::StrFormat(
  //       "Finished to export/write functions (took : %.2fs)",
  //       func_timer.ElapsedSeconds(absl::Now()));
  // }

  // {
  //   QLOGI << "Start to transform references";
  //   Timer sort_timer(absl::Now());

  //   ReferenceHolder::GetInstance().RemoveMissingAddr(
  //       head_iterator.func_chunks, head_iterator.instruction_bucket,
  //       head_iterator.data_list, Structures::GetInstance());

  //   QLOGD << absl::StrFormat("Removing took %.2fs",
  //                            sort_timer.ElapsedSeconds(absl::Now()));
  // }

  // QLOGI << "Start to write data, comments and references";
  // timer.Reset();
  // WriteData(proto, head_iterator.data_list);

  // WriteComments(proto, head_iterator.comments);

  // /* WRITE AFTER FUNCTIONS */
  // WriteReferences(proto, ReferenceHolder::GetInstance());

  // QLOGI << absl::StrFormat(
  //     "Finished to write data comments and references (took : %.2fs)",
  //     timer.ElapsedSeconds(absl::Now()));

  return eOk;
}

}  // namespace quokka
