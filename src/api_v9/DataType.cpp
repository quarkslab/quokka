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
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <variant>

// clang-format off: Compatibility.h must come before ida headers
#include "quokka/Compatibility.h"
// clang-format on
#include <typeinf.hpp>

#include "absl/strings/str_format.h"

#include "quokka/DataType.h"
#include "quokka/Logger.h"
#include "quokka/Reference.h"
#include "quokka/Util.h"

namespace quokka {

/**
 * Export the composite type members
 *
 * Iterate through the ida-struct (can be either a struct or a union) members
 * and export each of them.
 *
 * @param composite_type The `CompositeType` object to analyze
 * @param tif The IDA type info
 */
template <std::derived_from<CompositeType> T>
static void ExportCompositeMembers(T& composite_type, const tinfo_t& tif) {
  const auto& data_types = DataTypes::GetInstance();

  udt_type_data_t udt;
  tif.get_udt_details(&udt);

  uint32_t member_idx = 0;
  for (const udm_t& udm : udt) {
    tinfo_t member_tif = udm.type;  // We have more control by copying it

    // Typedef/typeref need to be resolved to the final type
    ResolveTypedef(member_tif);

    uint64_t size = udm.size;
    if (member_tif.is_varmember()) {
      QLOGD << absl::StrFormat(
          "Member `%s` is variable-length; forcing size to 0.",
          ConvertIdaString(udm.name));
      size = 0;
    }

    BaseType member_base_type = GetBaseType(member_tif);

    // Emplace the CompositeTypeMember
    CompositeTypeMember& member = composite_type.members.emplace_back(
        udm.offset / 8, ConvertIdaString(udm.name), member_base_type, size);

    if (member_tif.is_from_subtil()) {
      qstring ida_string;
      tif.get_type_name(&ida_string);
      QLOGW << absl::StrFormat(
          "Member `%s` in `%s` comes from a different library. Treating it as "
          "TYPE_UNK",
          member.name, ida_string.c_str());
      member.type = TYPE_UNK;
      goto member_created;
    }

    // Add the target type if needed
    switch (member_base_type) {
      case TYPE_UNK: {
        if (member_tif.is_bitfield()) {
          qstring ida_string;
          tif.get_type_name(&ida_string);
          QLOGW << absl::StrFormat(
              "Bitfield member `%s` in `%s` is not supported; treating as "
              "TYPE_UNK.",
              ConvertIdaString(udm.name), ConvertIdaString(ida_string));
          member.type = TYPE_UNK;
          break;
        }

        // Ask the CompositeTypes manager to give us the relevant struct/union
        auto it = data_types.find_by_tuid(GetTypeUid(member_tif));

        if (it == data_types.end()) {
          qstring ida_string;
          tif.get_type_name(&ida_string);
          QLOGE << absl::StrFormat(
              "Cannot resolve type for member `%s` in `%s`.",
              ConvertIdaString(udm.name), ConvertIdaString(ida_string));
          member.type = TYPE_UNK;
          break;
        }

        member.target_tuid = it->first;
        break;
      }

      case TYPE_POINTER:
        member.target_tuid = ExportPointer(member_tif);
        break;

      case TYPE_ARRAY:
        member.target_tuid = ExportArray(member_tif);
        break;

      case TYPE_STR:  // String literal, No tinfo_t available
        if (guess_tinfo(&member_tif, member_tif.get_tid()) > 0) {
          member.target_tuid = ExportArray(member_tif);
        } else {
          qstring ida_string;
          tif.get_type_name(&ida_string);
          QLOGE << absl::StrFormat(
              "Cannot recover tinfo_t for string literal member `%s` in `%s`; "
              "treating as TYPE_UNK.",
              ConvertIdaString(udm.name), ConvertIdaString(ida_string));
          member.type = TYPE_UNK;
        }
        break;

      default:  // No target type needed
        break;
    }

  member_created:  // Here the member is valid and safe to use

    // Assert that the parsing went well and data type is consistent
    assert(IsPrimitiveType(member.type) || member.target_tuid.has_value());

    /* TODO Retrieve comments */
    ExportSymbolReference(&composite_type, member.xref_to,
                          tif.get_udm_tid(member_idx), member_idx);
    //   GetStructureMemberComment(composite_type_ptr,
    //                             composite.members.size(),
    //                             ida_member->id);
    //   GetStructureMemberComment_v9(structure_member, udm);

    ++member_idx;
  }
}

/**
 * Export an IDA-struct, that can either be a struct or a union.
 *
 * Completely export a structure or a union type, including the references and
 * comments. Will populate the `DataTypes` singleton container.
 *
 * @see ExportStructureReference
 * @see GetCompositeTypeComment
 *
 * @param tif The IDA type info
 */
static void ExportStructOrUnion(const tinfo_t& tif) {
  qstring name;
  tif.get_type_name(&name);
  tid_t tid = tif.get_tid();
  type_uid_t tuid = GetTypeUid(tif);

  DataTypes& data_types = DataTypes::GetInstance();
  size_t size = tif.is_forward_decl() ? 0 : tif.get_size();

  auto finalize_export = [&tid](const auto& type) {
    ExportSymbolReference(&type, type.xref_to, tid, reference::WHOLE_TYPE);
    // TODO comments
    //   GetCompositeTypeComment(composite_types.back());
  };

  if (tif.is_union()) {
    const auto& type =
        data_types.emplace<UnionType>(tuid, ConvertIdaString(name), tid, size);
    finalize_export(type);
  } else {
    const auto& type = data_types.emplace<StructureType>(
        tuid, ConvertIdaString(name), tid, size);
    finalize_export(type);
  }
}

static std::variant<type_uid_t, BaseType> ExportInnerElement(
    const tinfo_t& arg_tif) {
  if (arg_tif.empty())
    return TYPE_UNK;

  if (arg_tif.is_from_subtil()) {
    qstring name;
    arg_tif.get_type_name(&name);
    QLOGW << absl::StrFormat(
        "Data type `%s` comes from a different library. Treating it as "
        "TYPE_UNK",
        name.c_str());
    return TYPE_UNK;
  }

  tinfo_t tif = arg_tif;  // Copy it to have a mutable variable
  ResolveTypedef(tif);

  const DataTypes& data_types = DataTypes::GetInstance();

  BaseType base_type = GetBaseType(tif);

  switch (base_type) {
    case TYPE_POINTER:
      return ExportPointer(tif);
    case TYPE_ARRAY:
      return ExportArray(tif);
      return TYPE_UNK;
    case TYPE_UNK: {
      type_uid_t tuid = GetTypeUid(tif);
      // We should already have exported the data types
      assert(data_types.find_by_tuid(tuid) != data_types.end());
      return tuid;
    }
    default:  // Primitive type
      break;
  }

  return base_type;
}

void ExportCompositeDataTypes() {
  for (uint32_t ordinal = 1; ordinal < get_ordinal_limit(); ++ordinal) {
    tinfo_t tif;
    if (!tif.get_numbered_type(ordinal, BTF_STRUCT) &&
        !tif.get_numbered_type(ordinal, BTF_UNION))
      continue;
    if (tif.is_typedef())  // Skip typedef
      continue;

    ExportStructOrUnion(tif);
  }

  // After Exporting all the composite types, export the members of the
  // composite types. We need to do it in this order or we won't be able to have
  // members referencing structures that have yet to be exported or are
  // incomplete.
  // For ex: struct A { A *a; };
  for_each_visit<StructureType, UnionType>(
      DataTypes::GetInstance(),
      [](const type_uid_t& tuid, auto& data_type) -> void {
        assert(tuid.is_real_tid);  // We should never ever have a fake tid here
        tinfo_t tif;
        bool res = tif.get_type_by_tid(tuid.tid);
        assert(res && "Couldn't retrieve the tinfo_t object from the tid_t");

        // Print the enum as a C-string if possible
        qstring composite_name;
        tif.get_type_name(&composite_name);
        qstring decl;
        if (tif.print(&decl, composite_name.c_str(),
                      PRTYPE_TYPE | PRTYPE_MULTI | PRTYPE_DEF | PRTYPE_SEMI))
          data_type.c_str = ConvertIdaString(decl);

        // Export the members of the struct/union
        if (!tif.is_empty_udt() && !tif.is_forward_decl())
          ExportCompositeMembers(data_type, tif);
      });
}

void ExportEnums() {
  DataTypes& data_types = DataTypes::GetInstance();

  for (uint32_t ordinal = 1; ordinal < get_ordinal_limit(); ++ordinal) {
    tinfo_t tif;
    if (!tif.get_numbered_type(ordinal, BTF_ENUM))
      continue;
    if (tif.is_forward_decl())  // Skip forward decls
      continue;
    if (tif.is_typedef())  // Skip typedef
      continue;

    qstring enum_name;
    tif.get_type_name(&enum_name);
    enum_type_data_t edt;
    tif.get_enum_details(&edt);
    bool has_members =
        tif.get_realtype() != (BTMT_SIZE0 | BT_UNK) && !tif.is_empty_enum();

    EnumType enum_type(ConvertIdaString(enum_name));

    // Export the values (aka members)
    if (has_members) {
      for (const edm_t& edm : edt) {
        enum_type.values.push_back(
            {ConvertIdaString(edm.name), static_cast<int64_t>(edm.value)});
        /* Retrieve comments */
        // GetEnumMemberComment_v9(member, edm);
      }
    }

    // Print the enum as a C-string if possible
    qstring decl;
    if (tif.print(&decl, enum_name.c_str(),
                  PRTYPE_TYPE | PRTYPE_MULTI | PRTYPE_DEF | PRTYPE_SEMI))
      enum_type.c_str = ConvertIdaString(decl);

    const EnumType& new_obj =
        data_types.insert(GetTypeUid(tif), std::move(enum_type));

    // References
    ExportSymbolReference(&new_obj, new_obj.xref_to, tif.get_tid(),
                          reference::WHOLE_TYPE);
    if (has_members) {
      for (size_t i = 0; const edm_t& edm : edt) {
        ExportSymbolReference(&new_obj, new_obj.xref_to, tif.get_edm_tid(i), i);
        ++i;
      }
    }

    // TODO comments
    // Check for comment for the enum
    // GetEnumComment(enum_type);
  }
}

type_uid_t ExportPointer(const tinfo_t& tif) {
  DataTypes& data_types = DataTypes::GetInstance();

  if (tif.is_from_subtil())
    throw std::invalid_argument("Type cannot come from an external library");

  // First check if it has already been exported
  type_uid_t tuid = GetTypeUid(tif);
  auto it = data_types.find_by_tuid(tuid);
  if (it != data_types.end())
    return tuid;

  ptr_type_data_t pi;
  if (!tif.get_ptr_details(&pi))
    assert(false);

  size_t size = tif.is_forward_decl() ? 0 : tif.get_size();
  tid_t tid = tif.get_tid();
  qstring name;
  tif.get_type_name(&name);

  PointerType& pointer_type =
      data_types.emplace<PointerType>(tuid, ConvertIdaString(name), tid, size);

  if (pi.is_code_ptr())  // Function pointer, store it as pointer to UNK
    pointer_type.element_type = TYPE_UNK;
  else
    pointer_type.element_type = ExportInnerElement(pi.obj_type);

  // Print the type as a C-string if possible
  qstring decl;
  if (tif.print(&decl, name.c_str(),
                PRTYPE_TYPE | PRTYPE_MULTI | PRTYPE_DEF | PRTYPE_SEMI))
    pointer_type.c_str = ConvertIdaString(decl);

  return tuid;
}

type_uid_t ExportArray(const tinfo_t& tif) {
  DataTypes& data_types = DataTypes::GetInstance();

  if (tif.is_from_subtil())
    throw std::invalid_argument("Type cannot come from an external library");

  // First check if it has already been exported
  type_uid_t tuid = GetTypeUid(tif);
  auto it = data_types.find_by_tuid(tuid);
  if (it != data_types.end())
    return tuid;

  array_type_data_t ai;
  if (!tif.get_array_details(&ai))
    assert(false);

  size_t size = ai.nelems * GetTinfoSize(ai.elem_type);

  tid_t tid = tif.get_tid();
  qstring name;
  tif.get_type_name(&name);

  ArrayType& array_type =
      data_types.emplace<ArrayType>(tuid, ConvertIdaString(name), tid, size);

  array_type.element_type = ExportInnerElement(ai.elem_type);

  // Print the type as a C-string if possible
  qstring decl;
  if (tif.print(&decl, name.c_str(),
                PRTYPE_TYPE | PRTYPE_MULTI | PRTYPE_DEF | PRTYPE_SEMI))
    array_type.c_str = ConvertIdaString(decl);

  return tuid;
}

}  // namespace quokka