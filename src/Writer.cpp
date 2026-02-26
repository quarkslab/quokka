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

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

// clang-format off: Compatibility.h must come before ida headers
#include "quokka/Compatibility.h"
// clang-format on
#include <pro.h>
#include <typeinf.hpp>

#include "quokka/Block.h"
#include "quokka/Bucket.h"
#include "quokka/Data.h"
#include "quokka/DataType.h"
#include "quokka/FileMetadata.h"
#include "quokka/Function.h"
#include "quokka/Layout.h"
#include "quokka/Logger.h"
#include "quokka/ProtoHelper.h"
#include "quokka/ProtoWrapper.h"
#include "quokka/Reference.h"
#include "quokka/Segment.h"
#include "quokka/Settings.h"
#include "quokka/Util.h"
#include "quokka/Version.h"
#include "quokka/Writer.h"

namespace quokka {

/**
 * Convert a function type to the proto associated type
 * @param func_type Type to convert
 * @return Converted type
 */
static constexpr Quokka::Function::FunctionType ToProtoFuncType(
    FunctionType func_type) {
  switch (func_type) {
    case TYPE_NORMAL:
      return Quokka::Function::TYPE_NORMAL;
    case TYPE_IMPORTED:
      return Quokka::Function::TYPE_IMPORTED;
    case TYPE_LIBRARY:
      return Quokka::Function::TYPE_LIBRARY;
    case TYPE_THUNK:
      return Quokka::Function::TYPE_THUNK;
    default:
      return Quokka::Function::TYPE_INVALID;
  }
}

/**
 * Convert a block type type to the proto associated type
 * @param block_type Type to convert
 * @return the protobuf converted BlockType
 */
static constexpr Quokka::Block::BlockType ToProtoBlockType(
    BlockType block_type) {
  switch (block_type) {
    case BTYPE_NORMAL:
      return Quokka::Block::BLOCK_TYPE_NORMAL;
    case BTYPE_INDJUMP:
      return Quokka::Block::BLOCK_TYPE_INDJUMP;
    case BTYPE_RET:
      return Quokka::Block::BLOCK_TYPE_RET;
    case BTYPE_NORET:
      return Quokka::Block::BLOCK_TYPE_NORET;
    case BTYPE_CNDRET:
      return Quokka::Block::BLOCK_TYPE_CNDRET;
    case BTYPE_ENORET:
      return Quokka::Block::BLOCK_TYPE_ENORET;
    case BTYPE_EXTERN:
      return Quokka::Block::BLOCK_TYPE_EXTERN;
    case BTYPE_ERROR:
      return Quokka::Block::BLOCK_TYPE_ERROR;
    default:
      assert(false && "Mismatch between BlockType enum");
  }
}

static constexpr size_t ToProtoBaseType(BaseType data_type) {
  // Use the underlying protobuf enum value as it is guaranteed that the first
  // elements of the `types` array are always the primitive types, ordered in
  // the same way as they are declared in the protobuf enum.
  // TODO one day use a more generic way of handling this
  switch (data_type) {
    case TYPE_B:
      return Quokka::BaseType::Quokka_BaseType_TYPE_B;
    case TYPE_W:
      return Quokka::BaseType::Quokka_BaseType_TYPE_W;
    case TYPE_DW:
      return Quokka::BaseType::Quokka_BaseType_TYPE_DW;
    case TYPE_QW:
      return Quokka::BaseType::Quokka_BaseType_TYPE_QW;
    case TYPE_OW:
      return Quokka::BaseType::Quokka_BaseType_TYPE_OW;
    case TYPE_FLOAT:
      return Quokka::BaseType::Quokka_BaseType_TYPE_FLOAT;
    case TYPE_DOUBLE:
      return Quokka::BaseType::Quokka_BaseType_TYPE_DOUBLE;
    case TYPE_VOID:
      return Quokka::BaseType::Quokka_BaseType_TYPE_VOID;
    default:
      return Quokka::BaseType::Quokka_BaseType_TYPE_UNK;
  }
}

/**
 * Convert a function type to the proto associated type
 * @param proc_name Type to convert
 * @return Converted type
 */
static constexpr Quokka::Meta::ISA ToProtoIsa(ProcName proc_name) {
  switch (proc_name) {
    case PROC_X86:
      return Quokka::Meta::PROC_INTEL;
    case PROC_ARM:
      return Quokka::Meta::PROC_ARM;
    case PROC_DALVIK:
      return Quokka::Meta::PROC_DALVIK;
    case PROC_PPC:
      return Quokka::Meta::PROC_PPC;
    case PROC_MIPS:
      return Quokka::Meta::PROC_MIPS;
    default:
      return Quokka::Meta::PROC_UNK;
  }
}

/**
 * Convert a function type to the proto associated type
 * @param endianness Type to convert
 * @return Converted type
 */
static constexpr Quokka::Meta::Endianess ToProtoEndianness(
    Endianness endianness) {
  switch (endianness) {
    case END_BE:
      return Quokka::Meta::END_BE;
    case END_LE:
      return Quokka::Meta::END_LE;
    default:
      return Quokka::Meta::END_UNK;
  }
}

/**
 * Convert a function type to the proto associated type
 * @param addr_size Type to convert
 * @return Converted type
 */
static constexpr Quokka::AddressSize ToProtoAddressSize(AddressSize addr_size) {
  switch (addr_size) {
    case ADDR_64:
      return Quokka::ADDR_64;
    case ADDR_32:
      return Quokka::ADDR_32;
    default:
      return Quokka::ADDR_UNK;
  }
}

/**
 * Convert a function type to the proto associated type
 * @param cc Type to convert
 * @return Converted type
 */
static constexpr Quokka::CallingConvention ToProtoCallingConvention(
    CallingConvention cc) {
  switch (cc) {
    case CC_CDECL:
      return Quokka::CC_CDECL;
    case CC_ELLIPSIS:
      return Quokka::CC_ELLIPSIS;
    case CC_STDCALL:
      return Quokka::CC_STDCALL;
    case CC_PASCAL:
      return Quokka::CC_PASCAL;
    case CC_FASTCALL:
      return Quokka::CC_FASTCALL;
    case CC_THISCALL:
      return Quokka::CC_THISCALL;
    case CC_SWIFT:
      return Quokka::CC_SWIFT;
    case CC_GOLANG:
      return Quokka::CC_GOLANG;
    case CC_GOSTK:
      return Quokka::CC_GOSTK;
    default:
      return Quokka::CC_UNK;
  }
}

/**
 * Convert a function type to the proto associated type
 * @param hash_type Type to convert
 * @return Converted type
 */
static constexpr Quokka::Meta::Hash::HashType ToProtoHashType(
    HashType hash_type) {
  switch (hash_type) {
    case HASH_SHA256:
      return Quokka::Meta::Hash::HASH_SHA256;
    case HASH_MD5:
      return Quokka::Meta::Hash::HASH_MD5;
    default:
      return Quokka::Meta::Hash::HASH_NONE;
  }
}

/**
 * Convert a function type to the proto associated type
 * @param state Type to convert
 * @return Converted type
 */
static constexpr Quokka::Layout::LayoutType GetLayoutTypeByState(State state) {
  assert(state != START && state != FINISH && state != TBD);
  switch (state) {
    case CODE:
      return Quokka::Layout::LAYOUT_CODE;

    case DATA:
      return Quokka::Layout::LAYOUT_DATA;

    case UNK:
    case UNK_WITH_XREF:  // Intentional fallthrough
      return Quokka::Layout::LAYOUT_UNK;

    case GAP:
      return Quokka::Layout::LAYOUT_GAP;

    default:
      QLOGE << "Error, type not handled";
      break;
  }

  return Quokka::Layout::LAYOUT_UNK;
}

/**
 * Convert a function type to the proto associated type
 * @param type Type to convert
 * @return Converted type
 */
static constexpr Quokka::Segment::Type ToProtoSegmentType(SegmentType type) {
  switch (type) {
    case SegmentType::SEGMENT_CODE:
      return Quokka::Segment::SEGMENT_CODE;
    case SegmentType::SEGMENT_DATA:
      return Quokka::Segment::SEGMENT_DATA;
    case SegmentType::SEGMENT_BSS:
      return Quokka::Segment::SEGMENT_BSS;
    case SegmentType::SEGMENT_NULL:
      return Quokka::Segment::SEGMENT_NULL;
    case SegmentType::SEGMENT_EXTERN:
      return Quokka::Segment::SEGMENT_EXTERN;
    case SegmentType::SEGMENT_NORMAL:
      return Quokka::Segment::SEGMENT_NORMAL;
    case SegmentType::SEG_ABSOLUTE_SYMBOLS:
      return Quokka::Segment::SEGMENT_ABSOLUTE_SYMBOLS;
    default:
      return Quokka::Segment::SEGMENT_UNK;
  }
}

/**
 * Convert a mode to the proto associated type
 * @param mode Type to convert
 * @return
 */
static constexpr Quokka::ExporterMeta::Mode ToProtoModeType(ExporterMode mode) {
  switch (mode) {
    case ExporterMode::MODE_LIGHT:
      return Quokka::ExporterMeta::MODE_LIGHT;
    case ExporterMode::MODE_SELF_CONTAINED:
      return Quokka::ExporterMeta::MODE_SELF_CONTAINED;
  }
  assert(false && "Should not reach this point");
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

  Quokka::Block* proto_block = proto_func->add_blocks();
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

  // Xrefs
  for (const auto& [instr_idx, xref_ptr] : block.xrefs) {
    for (const Reference* xref : xref_ptr->from) {
      Quokka::Block::InstructionXref* proto_xref =
          proto_block->add_instructions_xref_from();
      proto_xref->set_instr_bb_idx(instr_idx);
      proto_xref->set_xref_index(xref->proto_index);
    }
    for (const Reference* xref : xref_ptr->to) {
      Quokka::Block::InstructionXref* proto_xref =
          proto_block->add_instructions_xref_to();
      proto_xref->set_instr_bb_idx(instr_idx);
      proto_xref->set_xref_index(xref->proto_index);
    }
  }
}

static void WriteCompositeTypes(Quokka* proto) {
  const DataTypes& data_types = DataTypes::GetInstance();

  auto write_composite_type = [&proto]<typename T>(T& composite) {
    composite.proto_index = proto->types_size();

    Quokka::CompositeType* proto_composite_type =
        proto->add_types()->mutable_composite_type();
    proto_composite_type->set_name(composite.name);
    proto_composite_type->set_type(CompositeSubTypeToProto<T>());
    proto_composite_type->set_size(composite.size);

    // Xref
    for (const Reference* xref : composite.xref_to)
      proto_composite_type->add_xref_to(xref->proto_index);

    // Export type declaration as string
    if (!composite.c_str.empty()) {
      proto_composite_type->set_c_str(composite.c_str);
    }
  };

  auto write_members = [&data_types](
                           const auto& composite,
                           Quokka::CompositeType* proto_composite_type) {
    // Reserve the space
    proto_composite_type->mutable_members()->Reserve(composite.members.size());

    for (const auto& member : composite.members) {
      Quokka::CompositeType::Member* proto_member =
          proto_composite_type->add_members();
      proto_member->set_offset(member.offset);
      proto_member->set_name(member.name);
      // If it is not base type
      if (member.target_tuid.has_value()) {
        auto target_type = data_types.find_by_tuid(*member.target_tuid);
        assert(target_type != data_types.end());  // We should never have a miss
        proto_member->set_type_index(
            UpcastVariant<ProtoHelper>(target_type->second).proto_index);
      } else {
        proto_member->set_type_index(ToProtoBaseType(member.type));
      }
      proto_member->set_size(member.size);

      // Xref
      for (const Reference* xref : member.xref_to)
        proto_member->add_xref_to(xref->proto_index);
    }
  };

  // `types` might have already been partially populated
  uint32_t i = proto->types_size();

  // First write all the composite types without members
  for_each_visit<StructureType, UnionType>(data_types, write_composite_type);

  // Finally write all the members
  for_each_visit<StructureType, UnionType>(
      data_types, [&](const auto& composite) {
        Quokka::CompositeType* proto_composite_type =
            proto->mutable_types(i)->mutable_composite_type();
        write_members(composite, proto_composite_type);
        ++i;
      });
}

static void WriteEnums(Quokka* proto) {
  const DataTypes& data_types = DataTypes::GetInstance();

  for (const auto& [tid, enum_type] : data_types | filter_type<EnumType>) {
    Quokka::EnumType* proto_enum = proto->add_types()->mutable_enum_type();
    proto_enum->set_name(enum_type.name);

    // Xref
    for (const Reference* xref : enum_type.xref_to)
      proto_enum->add_xref_to(xref->proto_index);

    proto_enum->mutable_values()->Reserve(enum_type.values.size());
    if (!enum_type.c_str.empty()) {
      proto_enum->set_c_str(enum_type.c_str);
    }
    for (const auto& enum_value : enum_type.values) {
      Quokka::EnumType::EnumValue* proto_value = proto_enum->add_values();
      proto_value->set_name(enum_value.name);
      proto_value->set_value(enum_value.value);
      // Xref
      for (const Reference* xref : enum_value.xref_to)
        proto_value->add_xref_to(xref->proto_index);
    }
  }
}

static void WriteLocation(Quokka::Reference::Location* proto_location,
                          const Reference::Location& location) {
  std::visit(
      [&]<typename T>(const T& loc) {
        if constexpr (std::is_same<T, ea_t>()) {
          proto_location->set_address(loc);
        } else {
          auto* data_type = proto_location->mutable_data_type_identifier();
          data_type->set_type_index(loc.first->proto_index);
          data_type->set_member_index(loc.second);
        }
      },
      location);
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

void WriteFunctions(Quokka* proto, const std::vector<Function>& functions) {
  proto->mutable_functions()->Reserve(static_cast<int>(functions.size()));
  for (const auto& function : functions) {
    Quokka::Function* proto_func = proto->add_functions();
    proto_func->set_name(function.name);
    if (!function.mangled_name.empty())
      proto_func->set_mangled_name(function.mangled_name);

    if (!function.decompiled_code.empty())
      proto_func->set_decompiled_code(function.decompiled_code);

    if (!function.prototype.empty())
      proto_func->set_prototype(function.prototype);
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
      proto_edge->set_edge_type(edge.edge_type);
      proto_edge->set_source(edge.source_idx);
      proto_edge->set_destination(edge.destination_idx);
      proto_edge->set_user_defined(false);
    }
  }
}

void WriteReferences(Quokka* proto) {
  References::GetInstance().Sort();
  const References& references = References::GetInstance();

  proto->mutable_references()->Reserve(references.size());
  for (const auto& reference : references.GetSortedView()) {
    reference.proto_index = proto->references_size();

    Quokka::Reference* proto_ref = proto->add_references();
    proto_ref->set_reference_type(reference.type);
    WriteLocation(proto_ref->mutable_source(), reference.source);
    WriteLocation(proto_ref->mutable_destination(), reference.destination);
  }
}

void WriteData(Quokka* proto, SetBucket<Data>& data_bucket) {
  data_bucket.Sort();
  proto->mutable_data()->Reserve(static_cast<int>(data_bucket.size()));

  const DataTypes& data_types = DataTypes::GetInstance();

  for (const auto& data : data_bucket.GetSortedView()) {
    data.proto_index = proto->data_size();

    // Sanity checks
    assert(data.segment != nullptr && data.segment->start_addr <= data.addr &&
           data.addr < data.segment->end_addr);

    Quokka::Data* proto_data = proto->add_data();
    proto_data->set_segment_index(data.segment->proto_index);
    proto_data->set_segment_offset(data.addr - data.segment->start_addr);
    proto_data->set_file_offset(data.file_offset);
    if (data.target_tuid.has_value()) {
      auto it = data_types.find_by_tuid(*data.target_tuid);
      assert(it != data_types.end());  // Huge problem
      proto_data->set_type_index(
          UpcastVariant<ProtoHelper>(it->second).proto_index);
    } else {
      proto_data->set_type_index(ToProtoBaseType(data.base_type));
    }
    proto_data->set_size(data.size);
    proto_data->set_not_initialized(not data.IsInitialized());

    for (const Reference* xref : data.xrefs.from)
      proto_data->add_xref_from(xref->proto_index);
    for (const Reference* xref : data.xrefs.to)
      proto_data->add_xref_to(xref->proto_index);

    std::string_view name = data.GetName();
    if (not name.empty())
      proto_data->set_name(name);
  }
}

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

void WriteMetadata(Quokka* proto, const Metadata& metadata) {
  Quokka::Meta* proto_meta = proto->mutable_meta();

  proto_meta->set_executable_name(metadata.file_name);

  proto_meta->set_isa(ToProtoIsa(metadata.proc_name));

  proto_meta->set_calling_convention(
      ToProtoCallingConvention(metadata.calling_convention));

  /* Set FileHash */
  Quokka::Meta::Hash* proto_hash = proto_meta->mutable_hash();
  proto_hash->set_hash_value(metadata.file_hash.value);
  proto_hash->set_hash_type(ToProtoHashType(metadata.file_hash.type));

  proto_meta->set_endianess(ToProtoEndianness(metadata.endianness));
  proto_meta->set_address_size(ToProtoAddressSize(metadata.address_size));

  auto* proto_backend = proto_meta->mutable_backend();
  proto_backend->set_name(Quokka::Meta::Backend::DISASS_IDA);
  proto_backend->set_version(metadata.ida_version);
  proto_meta->set_decompilation_activated(metadata.decompilation_activated);
}

void WriteTypes(Quokka* proto) {
  // Try to reserve the right amount from the start
  proto->mutable_types()->Reserve(9 + DataTypes::GetInstance().size());

  // Start by writing the primitive types
  proto->add_types()->set_primitive_type(Quokka_BaseType_TYPE_UNK);
  proto->add_types()->set_primitive_type(Quokka_BaseType_TYPE_B);
  proto->add_types()->set_primitive_type(Quokka_BaseType_TYPE_W);
  proto->add_types()->set_primitive_type(Quokka_BaseType_TYPE_DW);
  proto->add_types()->set_primitive_type(Quokka_BaseType_TYPE_QW);
  proto->add_types()->set_primitive_type(Quokka_BaseType_TYPE_OW);
  proto->add_types()->set_primitive_type(Quokka_BaseType_TYPE_FLOAT);
  proto->add_types()->set_primitive_type(Quokka_BaseType_TYPE_DOUBLE);
  proto->add_types()->set_primitive_type(Quokka_BaseType_TYPE_VOID);

  // The order matters! The last ones should be composite types
  WriteEnums(proto);
  WriteCompositeTypes(proto);
}

class string_text_sink_t : public text_sink_t {
 public:
  std::string& buffer;

  string_text_sink_t(std::string& buf) : buffer(buf) {}

  int idaapi print(const char* str) override {
    buffer += str;
    return strlen(str);
  }
};

void WriteHeaders(Quokka* proto) {
  // Get the number of types
  til_t* ti = get_idati();
  if (!ti) {
    QLOGE << "Failed to get idati!\n";
    return;
  }

  string_text_sink_t printer(*proto->mutable_headers());
  qvector<uint32> ordvec_t;
  for (uint32 ord = 1; ord <= get_ordinal_count(ti); ord++) {
    ordvec_t.push_back(ord);
  }
  print_decls(printer, ti, &ordvec_t,
              PDF_INCL_DEPS | PDF_DEF_FWD | PDF_DEF_BASE | PDF_HEADER_CMT);
}

void WriteExporterMeta(Quokka* proto) {
  Settings s = Settings::GetInstance();

  Quokka::ExporterMeta* proto_exportermeta = proto->mutable_exporter_meta();
  proto_exportermeta->set_version(GetVersion());
  proto_exportermeta->set_mode(ToProtoModeType(s.GetMode()));
}

void WriteSegments(Quokka* proto) {
  Segments& segments = Segments::GetInstance();
  segments.Sort();

  proto->mutable_segments()->Reserve(segments.size());

  for (const Segment& segment : segments.GetSortedView()) {
    segment.proto_index = proto->segments_size();
    Quokka::Segment* proto_seg = proto->add_segments();
    proto_seg->set_name(segment.name);

    proto_seg->set_virtual_addr(uint64_t(segment.start_addr));
    proto_seg->set_size(uint64_t(segment.end_addr - segment.start_addr));

    proto_seg->set_permissions(segment.permissions);

    proto_seg->set_address_size(ToProtoAddressSize(segment.address_size));
    proto_seg->set_type(ToProtoSegmentType(segment.type));
    proto_seg->set_file_offset(segment.file_offset);
  }
}

void WriteLayout(Quokka* proto, const std::deque<Layout>& layouts) {
  proto->mutable_layout()->Reserve(static_cast<int>(layouts.size()));
  for (const Layout& layout : layouts) {
    Quokka::Layout* proto_layout = proto->add_layout();
    proto_layout->set_layout_type(GetLayoutTypeByState(layout.type));
    proto_layout->mutable_address_range()->set_start_address(layout.start);
    proto_layout->mutable_address_range()->set_size(layout.size);
  }
}

}  // namespace quokka
