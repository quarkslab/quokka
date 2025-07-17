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

#include "quokka/Reference.h"

#include "quokka/Compatibility.h"

#include "quokka/Block.h"
#include "quokka/Data.h"
#include "quokka/Function.h"

#if IDA_SDK_VERSION < 850
#include "api_v8/Reference.cpp"
#else
#include "api_v9/Reference.cpp"
#endif

namespace quokka {

ReferenceType GetDataRefType(uchar ref_type, ea_t target) {
  if (ref_type == dr_S) {
    return REF_ENUM;
  } else if (target > inf_get_max_ea()) {
    return REF_STRUC;
  } else {
    return REF_DATA;
  }
}

ReferenceType GetCodeRefType(uchar ref_type, ea_t target,
                             const std::shared_ptr<FuncChunk>& chunk) {
  assert(chunk != nullptr);
  if (ref_type == fl_JN || ref_type == fl_JF || ref_type == fl_F) {
    // FIX: IDA may get confused with references, double check that both side
    // reference code
    flags_t flags = get_flags(target);
    if (not is_code(flags)) {
      return REF_INVALID;
    }

    // For the moment, we want to keep every flow in fake chunk as flows. It
    // will be sorted a bit later to see if it's indeed flow or calls.
    if (chunk->fake_chunk || chunk->InChunk(target)) {
      return REF_FLOW;
    } else {
      // FIX: IDA has an invalid behavior where there may be a flow towards
      // the head of a function (and that should not be possible)
      if (ref_type == fl_F and is_func(flags)) {
        return REF_INVALID;
      }

      return REF_CALL;
    }
  } else if (ref_type == fl_CF || ref_type == fl_CN) {
    return REF_CALL;
  }

  return REF_INVALID;
}

void GetCodeRefFrom(std::vector<ea_t>& code_refs, ea_t start_addr) {
  xrefblk_t xref{};
  for (bool ok = xref.first_to(start_addr, XREF_ALL); ok && xref.iscode;
       ok = xref.next_to()) {
    if (xref.type == fl_JN || xref.type == fl_JF || xref.type == fl_F) {
      code_refs.push_back(xref.from);
    }
  }
}

Location ResolveAddr(ea_t addr, const FuncChunkCollection& chunks,
                     const BucketNew<Instruction>& instructions) {
  std::shared_ptr<FuncChunk> chunk = chunks.GetElement(addr, false);
  if (chunk == nullptr) {
    return BADADDR;
  }

  std::shared_ptr<Block> block = chunk->GetBlockContainingAddress(addr);
  if (block == nullptr) {
    // TODO Check here if we are in imports ... otherwise it's bad
    return chunk;
  }

  auto instruction_index = block->GetInstIndex(addr);
  if (instruction_index == std::nullopt) {
    return BADADDR;
  }

  /* FIXME(dm): For some architecture, namely arm64, instructions are serialized
   * but the reference is wrongly attached to the deduplicated instruction. Due
   * to this problem, the protobuf at the end attach "every" string to one
   * instruction. A temp fix here is to never attach the reference to the
   * instruction itself but always to an instance */
  return InstructionInstance(chunk, block, instruction_index.value());
}

Location ReferenceHolder::ResolveData(ea_t addr,
                                      const BucketNew<Data>& data_bucket) {
  auto it = data_addresses.find(addr);
  if (it != data_addresses.end()) {
    return it->second;
  }

  return BADADDR;
}

Location ReferenceHolder::ResolveLocation(
    Location location, const BucketNew<Instruction>& instructions, ea_t max_ea,
    const Structures& structures, const FuncChunkCollection& chunks,
    const BucketNew<Data>& data_bucket) {
  if (std::holds_alternative<ea_t>(location)) {
    auto addr = std::get<ea_t>(location);

    if (addr > max_ea) {
      location = ResolveStructure(addr, structures);
    } else {
      location = ResolveAddr(addr, chunks, instructions);
      if (std::holds_alternative<ea_t>(location)) {
        location = ResolveData(addr, data_bucket);
      }
    }
  }

  return location;
}

void ReferenceHolder::RemoveMissingAddr(
    const FuncChunkCollection& chunks,
    const BucketNew<Instruction>& instructions,
    const BucketNew<Data>& data_bucket, const Structures& structures) {
  ea_t max_ea = inf_get_max_ea();

  QLOGD << absl::StrFormat("Size: %d", references.size());

  /* Create the mapping for the addresses of data */
  data_addresses.reserve(data_bucket.size());
  for (const auto& data_p : data_bucket) {
    data_addresses[data_p->addr] = data_p;
  }

  absl::flat_hash_set<long> references_hashes;
  references.erase(
      std::remove_if(references.begin(), references.end(),
                     [&](Reference& ref) -> bool {
                       if (std::holds_alternative<ea_t>(ref.source_)) {
                         QLOGE << "Invalid source reference type";
                         return true;
                       }

                       Location new_loc = this->ResolveLocation(
                           ref.destination_, instructions, max_ea, structures,
                           chunks, data_bucket);

                       if (std::holds_alternative<ea_t>(new_loc)) {
                         return true;
                       } else {
                         ref.destination_ = new_loc;
                       }

                       /* Check if the reference already exists by its hash and
                        * if it does remove it */
                       auto [it, result] = references_hashes.insert(
                           absl::Hash<Reference>()(ref));
                       return not result;
                     }),
      references.end());

  QLOGD << absl::StrFormat("Size: %d", references.size());
}

void ResolveEdges(const FuncChunkCollection& chunks,
                  ReferenceHolder& reference_holder) {
  // TODO(dm) Sort chunk blocks by start address

  for (const std::shared_ptr<FuncChunk>& chunk : chunks) {
    for (const PendingEdge& pending_edge : chunk->pending_edges) {
      std::shared_ptr<Block> source_block =
          chunk->GetBlockContainingAddress(pending_edge.source);

      auto source_block_index = chunk->GetBlockIdx(source_block);
      if (source_block_index == std::nullopt) {
        QLOGE << "Unable to find source block";
        continue;
      }

      auto destination_block_index =
          chunk->BlockIdxFromAddr(pending_edge.destination);

      if (destination_block_index == std::nullopt) {
        // Sometimes, IDA misses the points with references towards non-head so
        // double check
        flags_t f = get_flags(pending_edge.destination);
        auto instruction_index =
            source_block->GetInstIndex(pending_edge.source);
        if (is_head(f) && is_code(f) && instruction_index.has_value()) {
          // Reference is correct but block does not exist : this is a call
          ReferenceHolder::GetInstance().emplace_back(
              InstructionInstance(chunk, source_block,
                                  instruction_index.value()),
              pending_edge.destination, REF_CALL);
        } else {
          QLOGD << "IDA reference is wrong, does not point towards an head.";
        }
        continue;
      }

      chunk->edge_list.emplace_back(pending_edge.edge_type,
                                    source_block_index.value(),
                                    destination_block_index.value());
    }

    chunk->pending_edges = {};
  }
}

void ExportFlowGraph(ea_t current_ea,
                     const std::shared_ptr<FuncChunk>& current_chunk,
                     const std::vector<ea_t>& flow_refs) {
  // Case 1 : no outgoing edges (end of function)
  if (flow_refs.empty()) {
    return;
  }

  ea_t next_addr = current_ea + get_item_size(current_ea);

  // Case 2 : 1 outgoing edge : either normal flow or unconditional jump
  if (flow_refs.size() == 1) {
    // Normal flow
    if (flow_refs[0] == next_addr and
        current_chunk->block_heads.find(next_addr) ==
            current_chunk->block_heads.end()) {
      return;
      // Unconditional jump
    } else {
      current_chunk->AddEdge(current_ea, flow_refs[0], TYPE_UNCONDITIONAL);
    }
    // Case 3: 2 edges -> condition
  } else if (flow_refs.size() == 2) {
    for (const auto dst_addr : flow_refs) {
      if (next_addr == dst_addr) {
        current_chunk->AddEdge(current_ea, dst_addr, TYPE_FALSE);
      } else {
        current_chunk->AddEdge(current_ea, dst_addr, TYPE_TRUE);
      }
    }
    // Case 4 : 2+ edges -> switch
  } else {
    for (const auto dst_addr : flow_refs) {
      current_chunk->AddEdge(current_ea, dst_addr, TYPE_SWITCH);
    }
  }
}

void ExportCodeReference(ea_t current_ea,
                         const std::shared_ptr<FuncChunk>& current_chunk,
                         const std::shared_ptr<Block>& block_p, int inst_idx,
                         BucketNew<Data>& data_bucket) {
  ReferenceHolder& reference_holder = ReferenceHolder::GetInstance();

  std::vector<ea_t> flow_refs;

  xrefblk_t xref{};
  ReferenceType ref_type;
  for (bool ok = xref.first_from(current_ea, XREF_ALL); ok && xref.iscode;
       ok = xref.next_from()) {
    ref_type = GetCodeRefType(xref.type, xref.to, current_chunk);
    if (ref_type == REF_CALL) {
      /* In case of calls, we want to have an instruction position towards an
       * instruction position We do not attach the call to the instruction
       * because instructions like call eax will be deduplicated */
      reference_holder.emplace_back(
          InstructionInstance(current_chunk, block_p, inst_idx), xref.to,
          ref_type);
    } else if (ref_type == REF_FLOW) {
      flow_refs.emplace_back(xref.to);
    }
  }

  for (bool ok = xref.first_to(current_ea, XREF_DATA); ok;
       ok = xref.next_to()) {
    /* In some cases, we have an instruction that has a data-ref to another
     * code line (e.g. adrp x2, #0x12345). The type of the operand is still a
     * constant but the constant represents an address.
     * <!> The reference is added *BACKWARDS*, i.e. from the DATA to the
     * Instruction.
     * In the previous example, it means the reference is added at the
     * instruction #0x12345
     */
    ref_type = GetDataRefType(xref.type, xref.from);
    if (ref_type == REF_DATA) {
      std::shared_ptr<Data> data =
          data_bucket.emplace(xref.from, GetDataType(get_flags(xref.from)),
                              get_item_size(xref.from));

      reference_holder.emplace_back(
          InstructionInstance(current_chunk, block_p, inst_idx),
          xref.from,  // This is on purpose : a data ref is from the data
                      // towards the target.
          REF_DATA);
    }
  }

  // Try to understand the outgoing flow from this instruction
  ExportFlowGraph(current_ea, current_chunk, flow_refs);
}

uint32_t ExportDataReferences(ea_t current_ea,
                              const std::shared_ptr<Data>& data) {
  ReferenceHolder& reference_holder = ReferenceHolder::GetInstance();
  std::unordered_map<ReferenceType, std::vector<ea_t>> dest_ref;

  xrefblk_t xref{};

  for (bool ok = xref.first_to(current_ea, XREF_DATA); ok;
       ok = xref.next_to()) {
    dest_ref[GetDataRefType(xref.type, xref.from)].push_back(xref.from);
  }

  uint32_t ref_count = 0;
  for (const auto& ref : dest_ref[REF_DATA]) {
    reference_holder.emplace_back(data, ea_t(ref), REF_DATA);
    ++ref_count;
  }

  return ref_count;
}

void ExportUnkReferences(ea_t current_ea, BucketNew<Data>& data_bucket) {
  ReferenceHolder& reference_holder = ReferenceHolder::GetInstance();

  xrefblk_t xref{};
  uint32_t ref_count = 0;
  std::shared_ptr<Data> data;

  for (bool ok = xref.first_to(current_ea, XREF_DATA); ok;
       ok = xref.next_to()) {
    if (ref_count == 0) {
      data = data_bucket.emplace(current_ea, DataType::TYPE_UNK, 1);
    }

    reference_holder.emplace_back(data, ea_t(xref.from), REF_DATA);
    ++ref_count;
  }

  if (ref_count > 0) {
    data->ref_count += (ref_count - 1);
  }
}

void ExportStructureReference(ea_t sid,
                              const std::shared_ptr<Structure>& structure,
                              StructureType struct_type) {
  ReferenceHolder& ref_holder = ReferenceHolder::GetInstance();

  ReferenceType ref_type;
  if (struct_type == STRUCT_ENUM) {
    ref_type = REF_ENUM;
  } else {
    ref_type = REF_STRUC;
  }

  xrefblk_t xref{};
  for (bool ok = xref.first_to(sid, XREF_DATA); ok; ok = xref.next_to()) {
    // Note: We "reverse" the reference here, saying its from the structure
    // towards the instruction and note the opposite like IDA
    ref_holder.emplace_back(structure, xref.from, ref_type);
  }
}

void ExportStructureMemberReference(
    ea_t sid, const std::shared_ptr<StructureMember>& member,
    StructureType struct_type) {
  ReferenceHolder& ref_holder = ReferenceHolder::GetInstance();

  ReferenceType ref_type;
  if (struct_type == STRUCT_ENUM) {
    ref_type = REF_ENUM;
  } else {
    ref_type = REF_STRUC;
  }

  xrefblk_t xref{};
  for (bool ok = xref.first_to(sid, XREF_DATA); ok; ok = xref.next_to()) {
    // Note: We "reverse" the reference here, saying its from the structure
    // towards the instruction and note the opposite like IDA
    ref_holder.emplace_back(member, xref.from, ref_type);
  }
}

}  // namespace quokka