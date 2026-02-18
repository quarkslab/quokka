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

#include "quokka/Writer.h"
#include <cassert>
#include <type_traits>
#include <variant>

#include "quokka.pb.h"
#include "quokka/Block.h"
// #include "quokka/Comment.h"
// #include "quokka/Data.h"
#include "quokka/DataType.h"
#include "quokka/FileMetadata.h"
// #include "quokka/Function.h"
// #include "quokka/Instruction.h"
#include "quokka/Function.h"
#include "quokka/Layout.h"
// #include "quokka/Localization.h"
// #include "quokka/Reference.h"
#include "quokka/Segment.h"
#include "quokka/Settings.h"
#include "quokka/Util.h"
#include "quokka/Version.h"

namespace quokka {

/**
 * Convert a function type to the proto associated type
 * @param func_type Type to convert
 * @return Converted type
 */
static quokka::Quokka::Function::FunctionType ToProtoFuncType(
    FunctionType func_type) {
  switch (func_type) {
    case TYPE_NORMAL:
      return quokka::Quokka::Function::TYPE_NORMAL;
    case TYPE_IMPORTED:
      return quokka::Quokka::Function::TYPE_IMPORTED;
    case TYPE_LIBRARY:
      return quokka::Quokka::Function::TYPE_LIBRARY;
    case TYPE_THUNK:
      return quokka::Quokka::Function::TYPE_THUNK;
    default:
      return quokka::Quokka::Function::TYPE_INVALID;
  }
}

static quokka::Quokka::Function::Edge::EdgeType ToProtoEdgeType(
    EdgeType edge_type) {
  switch (edge_type) {
    case TYPE_TRUE:
      return quokka::Quokka::Function::Edge::TYPE_TRUE;
    case TYPE_FALSE:
      return quokka::Quokka::Function::Edge::TYPE_FALSE;
    case TYPE_SWITCH:
      return quokka::Quokka::Function::Edge::TYPE_DYNAMIC;
    case TYPE_UNCONDITIONAL:
      return quokka::Quokka::Function::Edge::TYPE_UNCONDITIONAL;
    default:
      QLOGE << "Edge type is not correct";
      return quokka::Quokka::Function::Edge::TYPE_UNCONDITIONAL;
  }
}

/**
 * Convert a block type type to the proto associated type
 * @param block_type Type to convert
 * @return the protobuf converted BlockType
 */
static quokka::Quokka::Block::BlockType ToProtoBlockType(BlockType block_type) {
  switch (block_type) {
    case BTYPE_NORMAL:
      return quokka::Quokka::Block::BLOCK_TYPE_NORMAL;
    case BTYPE_INDJUMP:
      return quokka::Quokka::Block::BLOCK_TYPE_INDJUMP;
    case BTYPE_RET:
      return quokka::Quokka::Block::BLOCK_TYPE_RET;
    case BTYPE_NORET:
      return quokka::Quokka::Block::BLOCK_TYPE_NORET;
    case BTYPE_CNDRET:
      return quokka::Quokka::Block::BLOCK_TYPE_CNDRET;
    case BTYPE_ENORET:
      return quokka::Quokka::Block::BLOCK_TYPE_ENORET;
    case BTYPE_EXTERN:
      return quokka::Quokka::Block::BLOCK_TYPE_EXTERN;
    case BTYPE_ERROR:
      return quokka::Quokka::Block::BLOCK_TYPE_ERROR;
    default:
      assert(false && "Mismatch between BlockType enum");
  }
}

static quokka::Quokka::DataType ToProtoDataType(DataType data_type) {
  switch (data_type) {
    case TYPE_B:
      return quokka::Quokka::TYPE_B;
    case TYPE_W:
      return quokka::Quokka::TYPE_W;
    case TYPE_DW:
      return quokka::Quokka::TYPE_DW;
    case TYPE_QW:
      return quokka::Quokka::TYPE_QW;
    case TYPE_OW:
      return quokka::Quokka::TYPE_OW;
    case TYPE_FLOAT:
      return quokka::Quokka::TYPE_FLOAT;
    case TYPE_DOUBLE:
      return quokka::Quokka::TYPE_DOUBLE;
    case TYPE_ASCII:
      return quokka::Quokka::TYPE_ASCII;
    case TYPE_STRUCT:
      return quokka::Quokka::TYPE_STRUCT;
    case TYPE_ALIGN:
      return quokka::Quokka::TYPE_ALIGN;
    case TYPE_POINTER:
      return quokka::Quokka::TYPE_POINTER;
    default:
      return quokka::Quokka::TYPE_UNK;
  }
}

/**
 * Write a block
 *
 * @param proto_func Current protobuf object for Function
 * @param block Block to write
 * @param position Optional position of the block
 * @param idx Index (in the function) of the block
 */
static void WriteBlock(Quokka::Function* proto_func, const Block& block,
                       const std::optional<Position>& position, size_t idx) {
  // Get it once and forget it. It will not change throughout the execution
  static bool is_light_mode = Settings::GetInstance().GetMode() == MODE_LIGHT;

  assert(block.segment != nullptr &&
         block.segment->start_addr <= block.start_addr &&
         block.start_addr < block.segment->end_addr &&
         block.end_addr <= block.segment->end_addr);

  quokka::Quokka::Block* proto_block = proto_func->add_blocks();
  proto_block->set_segment_index(block.segment->proto_index);
  proto_block->set_segment_offset(block.start_addr - block.segment->start_addr);
  proto_block->set_file_offset(block.file_offset);
  proto_block->set_block_type(ToProtoBlockType(block.block_type));
  proto_block->set_size(block.end_addr - block.start_addr);
  proto_block->set_is_thumb(block.is_thumb);

  if (is_light_mode) {
    proto_block->set_n_instr(block.instr_count);
  } else {
    assert(false && "Not implemented yet. TODO");
    // proto_block->mutable_instructions_index()->Reserve(
    //     static_cast<int>(block->instructions.size()));
    // for (auto const& instruction : block->instructions) {
    //   proto_block->add_instructions_index(instruction->proto_index);
    // }
  }

  if (position.has_value()) {
    auto* proto_blockpos = proto_func->add_block_positions();
    proto_blockpos->set_block_id(idx);
    auto* proto_pos = proto_blockpos->mutable_position();
    proto_pos->set_x(position->x);
    proto_pos->set_y(position->y);
    proto_pos->set_position_type(position->pos_type);
  }
}

// void WriteMnemonic(quokka::Quokka* proto, BucketNew<Mnemonic>& mnemonics) {
//   proto->mutable_mnemonics()->Reserve(static_cast<int>(mnemonics.size()));
//   for (const auto& [ref_count, mnemonic] : mnemonics.SortByFrequency()) {
//     mnemonic->proto_index = proto->mnemonics_size();
//     proto->add_mnemonics(mnemonic->mnemonic);
//   }
// }

// void WriteOperandStrings(quokka::Quokka* proto,
//                          BucketNew<OperandString>& operand_strings) {
//   proto->mutable_operand_table()->Reserve(
//       static_cast<int>(operand_strings.size()));

//   for (const auto& [ref_count, operand_str] :
//        operand_strings.SortByFrequency()) {
//     operand_str->proto_index = proto->operand_table_size();
//     proto->add_operand_table(operand_str->representation);
//   }
// }

// void WriteOperands(quokka::Quokka* proto, BucketNew<Operand>& operands) {
//   proto->mutable_operands()->Reserve(static_cast<int>(operands.size()));
//   quokka::Quokka::Operand* proto_operand;
//   for (const auto& [ref_count, operand] : operands.SortByFrequency()) {
//     operand->proto_index = proto->operands_size();

//     proto_operand = proto->add_operands();
//     proto_operand->set_type(operand->type);
//     proto_operand->set_flags(operand->flags);
//     proto_operand->set_value_type(operand->op_value_type);
//     proto_operand->set_value(operand->value);
//     proto_operand->set_register_id(operand->register_id);
//     proto_operand->set_phrase_id(operand->phrase_id);
//     proto_operand->set_address(operand->addr);
//     proto_operand->set_specval(operand->specval);

//     for (char specflag : operand->specflags) {
//       proto_operand->add_specflags(specflag);
//     }
//   }
// }

// void WriteInstructions(quokka::Quokka* proto,
//                        BucketNew<Instruction>& instructions) {
//   // Operands and mnemonics must be written first !
//   proto->mutable_instructions()->Reserve(static_cast<int>(instructions.size()));
//   for (const auto& [ref_count, instruction] : instructions.SortByFrequency())
//   {
//     instruction->proto_index = proto->instructions_size();

//     quokka::Quokka::Instruction* proto_inst = proto->add_instructions();
//     proto_inst->set_size(instruction->inst_size);
//     proto_inst->set_mnemonic_index(instruction->mnemonic->proto_index);

//     proto_inst->set_is_thumb(instruction->thumb);

//     for (auto& operand : instruction->operands) {
//       proto_inst->add_operand_index(operand->proto_index);
//     }

//     for (auto& operand_string : instruction->operand_strings) {
//       proto_inst->add_operand_strings(operand_string->proto_index);
//     }
//   }
// }

// void WriteBlockIdentifier(quokka::Quokka::BlockIdentifier* proto_block_id,
//                           int block_idx, int chunk_idx) {
//   proto_block_id->set_block_id(uint32_t(block_idx));

//   if (chunk_idx < 0) {
//     proto_block_id->set_no_chunk(true);
//   } else {
//     proto_block_id->set_chunk_id(uint32_t(chunk_idx));
//   }
// }

// void WriteInnerEdges(quokka::Quokka::FunctionChunk* proto_chunk,
//                      const std::vector<Edge>& edge_list) {
//   proto_chunk->mutable_edges()->Reserve(static_cast<int>(edge_list.size()));
//   for (auto edge : edge_list) {
//     quokka::Quokka::Edge* proto_edge = proto_chunk->add_edges();
//     WriteBlockIdentifier(proto_edge->mutable_source(), edge.source_idx, -1);
//     WriteBlockIdentifier(proto_edge->mutable_destination(),
//                          edge.destination_idx, -1);
//     proto_edge->set_edge_type(ToProtoEdgeType(edge.edge_type));
//   }
// }

// void WriteFuncChunk(quokka::Quokka* proto, FuncChunkCollection& chunks) {
//   ea_t base_addr = get_imagebase();
//   assert(base_addr != BADADDR && "Problem with the base address");

//   quokka::Quokka::FunctionChunk* proto_chunk;

//   uint64_t fake_chunks = 0;

//   proto->mutable_function_chunks()->Reserve(static_cast<int>(chunks.size()));
//   for (const std::shared_ptr<FuncChunk>& chunk : chunks) {
//     if (chunk->fake_chunk) {
//       fake_chunks++;
//     }

//     chunk->proto_index = proto->function_chunks().size();

//     proto_chunk = proto->add_function_chunks();
//     proto_chunk->set_offset_start(uint64_t(chunk->start_addr - base_addr));
//     proto_chunk->set_is_fake(chunk->fake_chunk);
//     proto_chunk->set_is_infile(chunk->in_file);

//     proto_chunk->mutable_blocks()->Reserve(
//         static_cast<int>(chunk->blocks.size()));
//     for (const auto& block_p : chunk->blocks) {
//       WriteBlock(proto_chunk, block_p, base_addr);
//     }

//     WriteInnerEdges(proto_chunk, chunk->edge_list);
//   }

//   QLOGD << absl::StrFormat("Written %d fake chunks", fake_chunks);
// }

// quokka::Quokka::Function::Position::PositionType ToProtoPositionType(
//     PositionType position_type) {
//   switch (position_type) {
//     case CENTER:
//       return quokka::Quokka::Function::Position::CENTER;
//     case TOP_LEFT:
//       return quokka::Quokka::Function::Position::TOP_LEFT;
//   }

//   return quokka::Quokka::Function::Position::CENTER;
// }

// void WritePosition(quokka::Quokka::Function::Position* proto_position,
//                    const Position& position) {
//   proto_position->set_position_type(ToProtoPositionType(position.pos_type));
//   proto_position->set_x(position.x);
//   proto_position->set_y(position.y);
// }

void WriteFunctions(quokka::Quokka* proto,
                    const std::vector<Function>& functions) {
  proto->mutable_functions()->Reserve(static_cast<int>(functions.size()));
  for (const auto& function : functions) {
    quokka::Quokka::Function* proto_func = proto->add_functions();
    proto_func->set_name(function.name);
    if (!function.mangled_name.empty())
      proto_func->set_mangled_name(function.mangled_name);

    if (!function.decompiled_code.empty())
      proto_func->set_decompiled_code(function.decompiled_code);

    assert(function.segment != nullptr);
    assert(function.segment->start_addr <= function.start_addr &&
           function.start_addr < function.segment->end_addr);
    proto_func->set_segment_index(function.segment->proto_index);
    proto_func->set_segment_offset(function.start_addr -
                                   function.segment->start_addr);

    proto_func->set_file_offset(function.file_offset);
    proto_func->set_function_type(ToProtoFuncType(function.func_type));

    // Reserve capacity
    int blocks_size = static_cast<int>(function.blocks.size());
    proto_func->mutable_blocks()->Reserve(blocks_size);
    proto_func->mutable_block_positions()->Reserve(blocks_size);
    proto_func->mutable_edges()->Reserve(function.edges.size());

    // Add blocks and positions
    int i = 0;
    for (const auto& [block, position] : function.blocks) {
      WriteBlock(proto_func, block, position, i);
      ++i;
    }

    // Add edges
    for (const auto& edge : function.edges) {
      auto* proto_edge = proto_func->add_edges();
      proto_edge->set_edge_type(ToProtoEdgeType(edge.edge_type));
      proto_edge->set_source(edge.source_idx);
      proto_edge->set_destination(edge.destination_idx);
      proto_edge->set_user_defined(false);
    }
  }
}

// quokka::Quokka::Reference::ReferenceType ToProtoReferenceType(
//     ReferenceType ref_type) {
//   switch (ref_type) {
//     case REF_CALL:
//       return quokka::Quokka::Reference::REF_CALL;
//     case REF_ENUM:
//       return quokka::Quokka::Reference::REF_ENUM;
//     case REF_STRUC:
//       return quokka::Quokka::Reference::REF_STRUC;
//     case REF_DATA:
//       return quokka::Quokka::Reference::REF_DATA;
//     default:
//       return quokka::Quokka::Reference::REF_UNK;
//   }
// }

// void WriteLocation(quokka::Quokka::Location* proto_location,
//                    const Location& location) {
//   if (std::holds_alternative<ea_t>(location)) {
//     QLOGE << "Not supposed to hold ea_t during writing time";

//   } else if (std::holds_alternative<InstructionInstance>(location)) {
//     const auto& inst_instance = std::get<InstructionInstance>(location);
//     quokka::Quokka::Location::InstructionIdentifier* proto_inst =
//         proto_location->mutable_instruction_position();

//     auto block_idx =
//     inst_instance.chunk_->GetBlockIdx(inst_instance.block_);
//     proto_inst->set_block_idx(block_idx.value_or(-1));
//     proto_inst->set_instruction_idx(inst_instance.instruction_index);
//     proto_inst->set_func_chunk_idx(inst_instance.chunk_->proto_index);

//   } else if (const auto
//   data_ptr(std::get_if<std::shared_ptr<Data>>(&location));
//              data_ptr) {
//     proto_location->set_data_idx((*data_ptr)->proto_index);

//   } else if (const auto struct_ptr(
//                  std::get_if<std::shared_ptr<Structure>>(&location));
//              struct_ptr) {
//     quokka::Quokka::Location::StructurePosition* proto_struc =
//         proto_location->mutable_struct_position();
//     proto_struc->set_structure_idx(struct_ptr->get()->proto_index);
//     proto_struc->set_no_member(true);

//   } else if (const auto member_ptr(
//                  std::get_if<std::shared_ptr<StructureMember>>(&location));
//              member_ptr) {
//     quokka::Quokka::Location::StructurePosition* proto_struc =
//         proto_location->mutable_struct_position();

//     if (auto parent = (*member_ptr)->parent.lock()) {
//       proto_struc->set_structure_idx((*member_ptr)->parent.lock()->proto_index);
//     } else {
//       QLOGE << "Unable to acquire lock on parent";
//       return;
//     }

//     proto_struc->set_member_idx(member_ptr->get()->proto_index);

//   } else if (const auto func_ptr(
//                  std::get_if<std::shared_ptr<Function>>(&location));
//              func_ptr) {
//     proto_location->set_function_idx((*func_ptr)->proto_index);

//   } else if (const auto chunk_ptr(
//                  std::get_if<std::shared_ptr<FuncChunk>>(&location));
//              chunk_ptr) {
//     proto_location->set_chunk_idx((*chunk_ptr)->proto_index);

//   } else if (const auto inst_ptr(
//                  std::get_if<std::shared_ptr<Instruction>>(&location));
//              inst_ptr) {
//     proto_location->set_inst_idx((*inst_ptr)->proto_index);
//   } else {
//     QLOGE << "ERROR WHILE WRITING Location";
//   }
// }

// void WriteReferences(quokka::Quokka* proto, const ReferenceHolder&
// ref_holder) {
//   quokka::Quokka::Reference* proto_ref;
//   proto->mutable_references()->Reserve(static_cast<int>(ref_holder.size()));
//   for (const auto& reference : ref_holder) {
//     if (std::holds_alternative<ea_t>(reference.source_) ||
//         std::holds_alternative<ea_t>(reference.destination_)) {
//       continue;
//     }

//     proto_ref = proto->add_references();

//     proto_ref->set_reference_type(ToProtoReferenceType(reference.type));
//     WriteLocation(proto_ref->mutable_source(), reference.source_);
//     WriteLocation(proto_ref->mutable_destination(),
//     reference.destination_);
//   }
// }
// void WriteData(quokka::Quokka* proto, BucketNew<Data>& data_bucket) {
//   proto->mutable_data()->Reserve(static_cast<int>(data_bucket.size()));

//   absl::flat_hash_map<std::string, int> string_map;

//   // Set an empty string in the first offset to differentiate between
//   values set
//   // and non set.
//   proto->add_string_table("");

//   uint64_t base_addr = proto->meta().base_addr();

//   quokka::Quokka::Data* proto_data;
//   for (const auto& [ref_count, data] : data_bucket.SortByFrequency()) {
//     data->proto_index = proto->data_size();

//     proto_data = proto->add_data();
//     proto_data->set_offset(uint64_t(data->addr) - base_addr);
//     proto_data->set_type(ToProtoDataType(data->data_type));
//     proto_data->set_not_initialized(not data->IsInitialized());

//     if (data->HasVariableSize()) {
//       proto_data->set_size(uint32_t(data->size));
//     } else {
//       proto_data->set_no_size(true);
//     }

//     absl::string_view name = data->GetName();
//     if (not name.empty()) {
//       auto it = string_map.try_emplace(name, proto->string_table_size());
//       if (it.second) {
//         proto->add_string_table(it.first->first);
//       }
//       proto_data->set_name_index(it.first->second);
//     }
//   }
// }

// quokka::Quokka::Comment::CommentType ToProtoCommentType(
//     CommentType comment_type) {
//   switch (comment_type) {
//     case INSTRUCTION:
//       return quokka::Quokka::Comment::COMMENT_INSTRUCTION;
//     case FUNCTION:
//       return quokka::Quokka::Comment::COMMENT_FUNCTION;
//     case STRUCTURE:
//       return quokka::Quokka::Comment::COMMENT_STRUCTURE;
//     default:
//       return quokka::Quokka::Comment::COMMENT_INVALID;
//   }
// }

// void WriteComments(quokka::Quokka* proto, Comments* comments) {
//   std::unordered_map<int, int> string_idx_proto_idx;

//   proto->mutable_comment_table()->Reserve(comments->GetCommentStrings().size());
//   for (const auto& pair : comments->GetCommentStrings()) {
//     string_idx_proto_idx[pair.second] = proto->comment_table_size();
//     proto->add_comment_table(pair.first);
//   }

//   proto->mutable_comments()->Reserve(comments->GetComments().size());
//   for (const auto& comment : comments->GetComments()) {
//     quokka::Quokka::Comment* proto_comment = proto->add_comments();
//     proto_comment->set_type(ToProtoCommentType(comment.type));
//     proto_comment->set_string_idx(string_idx_proto_idx.at(comment.indice));

//     WriteLocation(proto_comment->mutable_location(), comment.location);
//   }
// }

quokka::Quokka::Meta::Hash::HashType ToProtoHashType(HashType hash_type) {
  switch (hash_type) {
    case HASH_SHA256:
      return quokka::Quokka::Meta::Hash::HASH_SHA256;
    case HASH_MD5:
      return quokka::Quokka::Meta::Hash::HASH_MD5;
    default:
      return quokka::Quokka::Meta::Hash::HASH_NONE;
  }
}

quokka::Quokka::CallingConvention ToProtoCallingConvention(
    CallingConvention cc) {
  switch (cc) {
    case CC_CDECL:
      return quokka::Quokka::CC_CDECL;
    case CC_ELLIPSIS:
      return quokka::Quokka::CC_ELLIPSIS;
    case CC_STDCALL:
      return quokka::Quokka::CC_STDCALL;
    case CC_PASCAL:
      return quokka::Quokka::CC_PASCAL;
    case CC_FASTCALL:
      return quokka::Quokka::CC_FASTCALL;
    case CC_THISCALL:
      return quokka::Quokka::CC_THISCALL;
    case CC_SWIFT:
      return quokka::Quokka::CC_SWIFT;
    case CC_GOLANG:
      return quokka::Quokka::CC_GOLANG;
    case CC_GOSTK:
      return quokka::Quokka::CC_GOSTK;
    default:
      return quokka::Quokka::CC_UNK;
  }
}

quokka::Quokka::AddressSize ToProtoAddressSize(AddressSize addr_size) {
  switch (addr_size) {
    case ADDR_64:
      return quokka::Quokka::ADDR_64;
    case ADDR_32:
      return quokka::Quokka::ADDR_32;
    default:
      return quokka::Quokka::ADDR_UNK;
  }
}

quokka::Quokka::Meta::Endianess ToProtoEndianness(Endianness endianness) {
  switch (endianness) {
    case END_BE:
      return quokka::Quokka::Meta::END_BE;
    case END_LE:
      return quokka::Quokka::Meta::END_LE;
    default:
      return quokka::Quokka::Meta::END_UNK;
  }
}

quokka::Quokka::Meta::ISA ToProtoIsa(ProcName proc_name) {
  switch (proc_name) {
    case PROC_X86:
      return quokka::Quokka::Meta::PROC_INTEL;
    case PROC_ARM:
      return quokka::Quokka::Meta::PROC_ARM;
    case PROC_DALVIK:
      return quokka::Quokka::Meta::PROC_DALVIK;
    case PROC_PPC:
      return quokka::Quokka::Meta::PROC_PPC;
    case PROC_MIPS:
      return quokka::Quokka::Meta::PROC_MIPS;
    default:
      return quokka::Quokka::Meta::PROC_UNK;
  }
}

void WriteMetadata(quokka::Quokka* proto, const Metadata& metadata) {
  quokka::Quokka::Meta* proto_meta = proto->mutable_meta();

  proto_meta->set_executable_name(metadata.file_name);

  proto_meta->set_isa(ToProtoIsa(metadata.proc_name));

  proto_meta->set_calling_convention(
      ToProtoCallingConvention(metadata.calling_convention));

  /* Set FileHash */
  quokka::Quokka::Meta::Hash* proto_hash = proto_meta->mutable_hash();
  proto_hash->set_hash_value(metadata.file_hash.value);
  proto_hash->set_hash_type(ToProtoHashType(metadata.file_hash.type));

  proto_meta->set_endianess(ToProtoEndianness(metadata.endianness));
  proto_meta->set_address_size(ToProtoAddressSize(metadata.address_size));

  auto* proto_backend = proto_meta->mutable_backend();
  proto_backend->set_name(quokka::Quokka::Meta::Backend::DISASS_IDA);
  proto_backend->set_version(metadata.ida_version);
  proto_meta->set_decompilation_activated(metadata.decompilation_activated);
}

void WriteCompositeTypes(quokka::Quokka* proto) {
  CompositeTypes& composite_types = CompositeTypes::GetInstance();

  auto write_composite_type = [&proto]<typename T>(T& composite) {
    composite.proto_index = proto->composite_types_size();

    Quokka::CompositeType* proto_composite_type = proto->add_composite_types();
    proto_composite_type->set_name(composite.name);
    proto_composite_type->set_type(CompositeSubTypeToProto<T>());
    proto_composite_type->set_size(composite.size);
  };

  auto write_members = [](auto& composite,
                          Quokka::CompositeType* proto_composite_type) {
    // Reserve the space
    proto_composite_type->mutable_members()->Reserve(composite.members.size());

    for (const auto& member : composite.members) {
      member.proto_index = proto_composite_type->members_size();

      Quokka::CompositeType::Member* proto_member =
          proto_composite_type->add_members();
      proto_member->set_offset(member.offset);
      proto_member->set_name(member.name);
      proto_member->set_type(ToProtoDataType(member.type));
      proto_member->set_size(member.size);

      // Optional type_index
      if (member.composite_type_ptr.has_value()) {
        std::visit(
            [&proto_member](auto& comp_ref) {
              proto_member->set_type_index(comp_ref.proto_index);
            },
            **member.composite_type_ptr);
      }
    }
  };

  proto->mutable_composite_types()->Reserve(composite_types.size());

  // First write all the composite types without members
  for (const auto& composite_type : composite_types)
    std::visit(write_composite_type, *composite_type);

  // Finally write all the members
  uint32_t i = 0;
  for (const auto& composite_type : composite_types) {
    Quokka::CompositeType* proto_composite_type =
        proto->mutable_composite_types(i);
    std::visit(
        [&proto_composite_type, &write_members](auto& composite) {
          write_members(composite, proto_composite_type);
        },
        *composite_type);
    ++i;
  }
}

quokka::Quokka::ExporterMeta::Mode ToProtoModeType(ExporterMode mode) {
  switch (mode) {
    case ExporterMode::MODE_LIGHT:
      return quokka::Quokka::ExporterMeta::MODE_LIGHT;
    case ExporterMode::MODE_SELF_CONTAINED:
      return quokka::Quokka::ExporterMeta::MODE_SELF_CONTAINED;
  }
  assert(false && "Should not reach this point");
}

void WriteExporterMeta(quokka::Quokka* proto) {
  Settings s = Settings::GetInstance();

  quokka::Quokka::ExporterMeta* proto_exportermeta =
      proto->mutable_exporter_meta();
  proto_exportermeta->set_version(GetVersion());
  proto_exportermeta->set_mode(ToProtoModeType(s.GetMode()));
}

quokka::Quokka::Segment::Type ToProtoSegmentType(SegmentType type) {
  switch (type) {
    case SegmentType::SEGMENT_CODE:
      return quokka::Quokka::Segment::SEGMENT_CODE;
    case SegmentType::SEGMENT_DATA:
      return quokka::Quokka::Segment::SEGMENT_DATA;
    case SegmentType::SEGMENT_BSS:
      return quokka::Quokka::Segment::SEGMENT_BSS;
    case SegmentType::SEGMENT_NULL:
      return quokka::Quokka::Segment::SEGMENT_NULL;
    case SegmentType::SEGMENT_EXTERN:
      return quokka::Quokka::Segment::SEGMENT_EXTERN;
    case SegmentType::SEGMENT_NORMAL:
      return quokka::Quokka::Segment::SEGMENT_NORMAL;
    case SegmentType::SEG_ABSOLUTE_SYMBOLS:
      return quokka::Quokka::Segment::SEGMENT_ABSOLUTE_SYMBOLS;
    default:
      return quokka::Quokka::Segment::SEGMENT_UNK;
  }
}

void WriteSegments(quokka::Quokka* proto) {
  Segments& segments = Segments::GetInstance();
  segments.Sort();

  proto->mutable_segments()->Reserve(segments.size());

  for (const Segment& segment : segments.GetSortedView()) {
    segment.proto_index = proto->segments_size();
    quokka::Quokka::Segment* proto_seg = proto->add_segments();
    proto_seg->set_name(segment.name);

    proto_seg->set_virtual_addr(uint64_t(segment.start_addr));
    proto_seg->set_size(uint64_t(segment.end_addr - segment.start_addr));

    proto_seg->set_permissions(segment.permissions);

    proto_seg->set_address_size(ToProtoAddressSize(segment.address_size));
    proto_seg->set_type(ToProtoSegmentType(segment.type));
    proto_seg->set_file_offset(segment.file_offset);
  }
}

quokka::Quokka::Layout::LayoutType GetLayoutTypeByState(State state) {
  assert(state != START && state != FINISH && state != TBD);
  switch (state) {
    case CODE:
      return quokka::Quokka::Layout::LAYOUT_CODE;

    case DATA:
      return quokka::Quokka::Layout::LAYOUT_DATA;

    case UNK:
    case UNK_WITH_XREF:  // Intentional fallthrough
      return quokka::Quokka::Layout::LAYOUT_UNK;

    case GAP:
      return quokka::Quokka::Layout::LAYOUT_GAP;

    default:
      QLOGE << "Error, type not handled";
      break;
  }

  return quokka::Quokka::Layout::LAYOUT_UNK;
}

void WriteLayout(quokka::Quokka* proto, const std::deque<Layout>& layouts) {
  proto->mutable_layout()->Reserve(static_cast<int>(layouts.size()));
  for (const Layout& layout : layouts) {
    quokka::Quokka::Layout* proto_layout = proto->add_layout();
    proto_layout->set_layout_type(GetLayoutTypeByState(layout.type));
    proto_layout->mutable_address_range()->set_start_address(layout.start);
    proto_layout->mutable_address_range()->set_size(layout.size);
  }
}

}  // namespace quokka
