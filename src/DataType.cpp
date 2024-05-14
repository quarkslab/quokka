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

#include <cstddef>
#include <string>
#include <variant>

// clang-format off: Compatibility.h must come before ida headers
#include "quokka/Compatibility.h"
// clang-format on
#include <pro.h>
#include <enum.hpp>
#include <struct.hpp>
#include <typeinf.hpp>

#include "absl/strings/str_format.h"
#include "absl/time/clock.h"

#include "quokka/Comment.h"
#include "quokka/DataType.h"
#include "quokka/Logger.h"  // Kept for logger
#include "quokka/Util.h"
#include "quokka/Writer.h"

namespace quokka {

DataType GetDataType(const tinfo_t& tinf) {
  auto int_from_tinfo_size = [&tinf]() {
    switch (tinf.get_unpadded_size()) {
      case 1:
        return TYPE_B;
      case 2:
        return TYPE_W;
      case 4:
        return TYPE_DW;
      case 8:
        return TYPE_QW;
      default:
        return TYPE_UNK;
    }
  };

  switch (tinf.get_realtype() & TYPE_BASE_MASK) {
    case BT_UNK:
      return TYPE_UNK;
    case BT_INT8:
      return TYPE_B;
    case BT_INT16:
      return TYPE_W;
    case BT_INT32:
      return TYPE_DW;
    case BT_INT64:
      return TYPE_QW;
    case BT_INT128:
      return TYPE_OW;
    case BT_INT:  // natural int. Query for size
      return int_from_tinfo_size();
    case BT_BOOL:
      switch (tinf.get_realtype() & TYPE_FLAGS_MASK) {
        case BTMT_DEFBOOL:  // size is model specific or unknown. Query for size
          return int_from_tinfo_size();
        case BTMT_BOOL1:
          return TYPE_B;
        case BTMT_BOOL2:  // BTMT_BOOL8
          return (inf_is_64bit() ? TYPE_QW : TYPE_W);
        case BTMT_BOOL4:
          return TYPE_DW;
        default:
          return TYPE_UNK;
      }
    case BT_FLOAT:
      switch (tinf.get_realtype() & TYPE_FLAGS_MASK) {
        case BTMT_FLOAT:
          return TYPE_FLOAT;
        case BTMT_DOUBLE:
          return TYPE_DOUBLE;
        default:  // Could actually be a long double or other len
          return TYPE_DOUBLE;
      }
    case BT_PTR:
      return TYPE_POINTER;
    case BT_ARRAY: {
      // Check if it is an array of char (aka a C string)
      array_type_data_t array_type;
      if (!tinf.get_array_details(&array_type))
        return TYPE_ARRAY;
      if (array_type.elem_type.is_char())
        return TYPE_ASCII;
      return TYPE_ARRAY;
    }
    case BT_COMPLEX:
      switch (tinf.get_realtype() & TYPE_FLAGS_MASK) {
        case BTMT_STRUCT:
          return TYPE_STRUCT;
        case BTMT_UNION:
          return TYPE_UNION;
        case BTMT_ENUM:
          return TYPE_ENUM;
        default:
          return TYPE_UNK;
      }
      // TODO TYPE_ALIGN is missing
    default:
      return TYPE_UNK;
  }
}

CompositeType::CompositeType(std::string&& n, tid_t id, size_t sz)
    : name(std::forward<std::string>(n)), type_id(id), size(sz) {}

CompositeTypeMember::CompositeTypeMember(ea_t o, std::string&& n, DataType t,
                                         asize_t sz)
    : offset(o), name(std::forward<std::string>(n)), type(t), size(sz){};

/**
 * Export the composite type members
 *
 * Iterate through the ida-struct (can be either a struct or a union) members
 * and export each of them.
 *
 * @param composite_type The `CompositeType` object to analyze
 */
static void ExportCompositeMembers(
    std::shared_ptr<CompositeConcreteType>& composite_type_ptr) {
  // Get the underlying object
  CompositeConcreteType& composite_type = *composite_type_ptr;

  bool is_union = std::holds_alternative<UnionType>(composite_type);

  struc_t* ida_struct = get_struc(
      std::visit([](const auto& t) { return t.type_id; }, composite_type));

  for (ea_t member_offset = get_struc_first_offset(ida_struct);
       member_offset != BADADDR;
       member_offset = get_struc_next_offset(ida_struct, member_offset)) {
    member_t* ida_member = get_member(ida_struct, member_offset);
    if (ida_member == nullptr)
      continue;

    asize_t size;
    if (is_varmember(ida_member)) {
      QLOGE << "Found variable member `"
            << ConvertIdaString(get_member_name(ida_member->id))
            << "` that has variable size! Use size of 0.";
      size = 0;
    }
    size = get_member_size(ida_member);

    tinfo_t tinf;
    DataType type;
    std::string base_type_name;
    if (get_member_tinfo(&tinf, ida_member)) {
      type = GetDataType(tinf);
      // Get struct or union type name for later
      qstring ida_string;
      tinf.get_type_name(&ida_string);
      base_type_name = ConvertIdaString(ida_string);
    } else {
      QLOGE << "Cannot get the tinfo_t * for member `"
            << ConvertIdaString(get_member_name(ida_member->id));
      type = TYPE_UNK;
    }

    // Unions always have 0 offsets
    const ea_t offset = (is_union ? 0 : ida_member->soff);

    // Emplace the CompositeTypeMember
    auto& member = std::visit(
        [&](auto& composite) -> auto& {
          return composite.members.emplace_back(
              offset, ConvertIdaString(get_member_name(ida_member->id)), type,
              size);
        },
        composite_type);

    // Add the composite type pointer if the member is composite as well
    if (type == TYPE_STRUCT || type == TYPE_UNION) {
      // Ask the CompositeTypes manager to give us the relevant struct/union
      const auto& composite_types = CompositeTypes::GetInstance();
      const auto& it = composite_types.get_by_name(base_type_name);

      if (it == composite_types.end()) {
        QLOGE << "Member `" << ConvertIdaString(get_member_name(ida_member->id))
              << "` is of composite type `" << base_type_name
              << "` but it was not found within the exported composite types.";
      } else {
        member.composite_type_ptr = *it;
      }
    }

    /* Retrieve comments */
    std::visit(
        [&](auto& composite) {
          GetStructureMemberComment(composite_type_ptr,
                                    composite.members.size(), ida_member->id);
        },
        composite_type);

    // TODO references
    //   ExportStructureMemberReference(ea_t(ida_member->id),
    //                                  structure->members.back(),
    //                                  STRUCT_STRUCT);
  }
}

/**
 * Export an IDA-struct, that can either be a struct or a union.
 *
 * Completely export a structure or a union type, including the references and
 * comments. Will populate the `CompositeTypes` singleton container.
 *
 * @see ExportStructureReference
 * @see GetCompositeTypeComment
 *
 * @param ida_struct A pointer to the IDA struct
 */
static void ExportStructOrUnion(struc_t* ida_struct) {
  if (ida_struct->is_varstr()) {
    QLOGE << "Found composite type `"
          << ConvertIdaString(get_struc_name(ida_struct->id))
          << "` that has variable size! Ignoring it.";
    return;
  }

  CompositeTypes& composite_types = CompositeTypes::GetInstance();
  size_t size = get_struc_size(ida_struct);

  if (is_union(ida_struct->id))
    composite_types.emplace_back<UnionType>(
        ConvertIdaString(get_struc_name(ida_struct->id)), ida_struct->id, size);
  else
    composite_types.emplace_back<StructureType>(
        ConvertIdaString(get_struc_name(ida_struct->id)), ida_struct->id, size);

  // TODO references
  //   ExportStructureReference(ea_t(structure->addr), structure,
  //   STRUCT_STRUCT);

  GetCompositeTypeComment(composite_types.back());
}

void ExportCompositeDataTypes(Quokka* proto) {
  QLOGI << "Start exporting composite types";
  Timer timer(absl::Now());

  // First export all the composite types
  uval_t idx = get_first_struc_idx();

  // FIX: Even if IDA SDK says the opposite, get_first_struc_idx() may
  // return NULL when no structures_ are defined
  while (idx != BADADDR) {
    tid_t struct_idx = get_struc_by_idx(idx);
    struc_t* ida_struct = get_struc(struct_idx);
    if (ida_struct != nullptr)
      ExportStructOrUnion(ida_struct);

    idx = get_next_struc_idx(idx);
  }

  // After Exporting all the composite types, export the members of the
  // composite types. We need to do it in this order or we won't be able to have
  // members referencing structures that have yet to be exported or are
  // incomplete.
  // For ex: struct A { A *a; };
  CompositeTypes& composite_types = CompositeTypes::GetInstance();
  for (auto& composite_type_ptr : composite_types) {
    std::visit(
        [&composite_type_ptr](auto& composite) {
          struc_t* ida_struct = get_struc(composite.type_id);

          if (ida_struct->memqty != 0)
            ExportCompositeMembers(composite_type_ptr);
        },
        *composite_type_ptr);
  }

  WriteCompositeTypes(proto);

  QLOGI << absl::StrFormat("Composite types written (took %.2fs)",
                           timer.ElapsedSeconds(absl::Now()));
}

/**
 * Export the enum members of enumeration.
 *
 * @note Use a visitor pattern because that's the IDA way of iterating
 * through the enum members.
 *
 * @param enum_type The enum type object that define the whole type
 * @param ida_enum Ida-enum
 */
static void ExportEnumMembers(std::shared_ptr<EnumType>& enum_type,
                              enum_t ida_enum) {
  class EnumMemberVisitor : public enum_member_visitor_t {
   private:
    std::shared_ptr<EnumType>& enum_type;

   public:
    EnumMemberVisitor(std::shared_ptr<EnumType>& enum_type)
        : enum_type(enum_type) {}

    int idaapi visit_enum_member(const_t cid, uval_t value) override {
      qstring member_name;
      get_enum_member_name(&member_name, cid);

      enum_type->values.emplace_back(ConvertIdaString(member_name),
                                     static_cast<int64_t>(value));

      /* Retrieve comments */
      GetEnumMemberComment(enum_type, enum_type->values.size(), cid);

      // TODO references
      // ExportStructureMemberReference(
      //     ea_t(cid), this->enumeration->members.back(), STRUCT_ENUM);
      return 0;
    }
  };

  EnumMemberVisitor visitor(enum_type);
  for_all_enum_members(ida_enum, visitor);
}

void ExportEnums(Quokka* proto) {
  QLOGI << "Start exporting enums";
  Timer timer(absl::Now());

  auto& enums = Enums::GetInstance();

  enum_t ida_enum;
  for (int ida_enum_idx = 0; (ida_enum = getn_enum(ida_enum_idx)) != BADADDR;
       ++ida_enum_idx) {
    auto& enum_type =
        enums.emplace_back(ConvertIdaString(get_enum_name(ida_enum)), ida_enum);

    // Export the values (aka members)
    if (get_enum_size(ida_enum) > 0)
      ExportEnumMembers(enum_type, ida_enum);

    // TODO References
    // ExportStructureReference(ea_t(ida_enum), structure, STRUCT_STRUCT);

    // Check for comment for the enum
    GetEnumComment(enum_type);
  }

  WriteEnums(proto);

  QLOGI << absl::StrFormat("Enums written (took %.2fs)",
                           timer.ElapsedSeconds(absl::Now()));
}

}  // namespace quokka