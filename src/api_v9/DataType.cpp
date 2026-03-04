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
#include <vector>

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
        udm.offset, ConvertIdaString(udm.name), member_base_type, size);

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

  // After exporting all the composite types, export their members.
  // We need to do it in this order or we won't be able to have members
  // referencing structures that have yet to be exported or are incomplete.
  // For ex: struct A { A *a; };
  //
  // IMPORTANT: We snapshot the keys before iterating because
  // ExportCompositeMembers() may call ExportPointer()/ExportArray() which
  // insert new entries into the same map, invalidating iterators.
  DataTypes& data_types = DataTypes::GetInstance();
  std::vector<type_uid_t> composite_keys;
  for_each_visit<StructureType, UnionType>(
      data_types,
      [&composite_keys](const type_uid_t& tuid, auto&) {
        composite_keys.push_back(tuid);
      });

  for (const auto& tuid : composite_keys) {
    auto it = data_types.find_by_tuid(tuid);
    assert(it != data_types.end());

    assert(tuid.is_real_tid);  // We should never ever have a fake tid here
    tinfo_t tif;
    bool res = tif.get_type_by_tid(tuid.tid);
    assert(res && "Couldn't retrieve the tinfo_t object from the tid_t");

    qstring composite_name;
    tif.get_type_name(&composite_name);
    qstring decl;

    visit_selected<StructureType, UnionType>(
        it->second, [&](auto& data_type) {
          // Print the type as a C-string if possible
          if (tif.print(&decl, composite_name.c_str(),
                        PRTYPE_TYPE | PRTYPE_MULTI | PRTYPE_DEF | PRTYPE_SEMI))
            data_type.c_str = ConvertIdaString(decl);

          // Export the members of the struct/union
          if (!tif.is_empty_udt() && !tif.is_forward_decl())
            ExportCompositeMembers(data_type, tif);
        });
  }
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

/**
 * Resolve the element_type for a typedef from a tinfo_t.
 *
 * Determines the correct element_type by inspecting @p target_tif
 * (which is the immediate next type in the typedef chain).
 * Handles pointers, arrays, composites (struct/union/enum), and
 * primitives. Sets element_type to TYPE_UNK for types that could
 * not be resolved (e.g. from a sub-TIL).
 */
static void ResolveTypedefElement(TypedefType& typedef_type,
                                  const tinfo_t& target_tif) {
  DataTypes& data_types = DataTypes::GetInstance();

  BaseType base_type = GetBaseType(target_tif);
  switch (base_type) {
    case TYPE_POINTER:
      typedef_type.element_type = ExportPointer(target_tif);
      break;
    case TYPE_ARRAY:
      typedef_type.element_type = ExportArray(target_tif);
      break;
    case TYPE_UNK: {
      type_uid_t target_tuid = GetTypeUid(target_tif);
      if (data_types.find_by_tuid(target_tuid) != data_types.end())
        typedef_type.element_type = target_tuid;
      else
        typedef_type.element_type = TYPE_UNK;
      break;
    }
    default:  // Primitive type
      typedef_type.element_type = base_type;
      break;
  }
}

/**
 * Export a single typedef by ordinal, recursively exporting any
 * intermediate typedef targets first so that element_type points
 * to the immediate next type in the chain (single-step resolution).
 *
 * @param ordinal The IDA type ordinal to export
 * @return The type_uid_t of the exported (or already-existing) typedef
 */
static type_uid_t ExportSingleTypedef(uint32_t ordinal) {
  DataTypes& data_types = DataTypes::GetInstance();

  tinfo_t tif;
  if (!tif.get_numbered_type(ordinal))
    assert(false && "Cannot get type info for typedef ordinal");

  type_uid_t tuid = GetTypeUid(tif);

  // Already exported (handles revisits and potential cycles)
  if (data_types.find_by_tuid(tuid) != data_types.end())
    return tuid;

  qstring name;
  tif.get_type_name(&name);

  // Get size via full resolution (need the concrete type's size)
  tinfo_t fully_resolved = tif;
  ResolveTypedef(fully_resolved);
  size_t size = GetTinfoSize(fully_resolved);
  tid_t tid = tif.get_tid();

  // Create the entry early so recursive calls see it (avoids cycles).
  // The reference remains valid across hash-map rehashes because
  // DataTypes stores unique_ptr<TypeT> (heap-allocated, stable address).
  TypedefType& typedef_type =
      data_types.emplace<TypedefType>(tuid, ConvertIdaString(name), tid, size);

  // --- Single-step element_type resolution ---
  // get_next_type_name() returns the name of the immediate target in
  // the typedef chain (one step).  It fails when the typedef directly
  // aliases a primitive or anonymous type (pointer, array, etc.).
  qstring next_name;
  bool resolved_element = false;

  if (tif.get_next_type_name(&next_name)) {
    tinfo_t next_tif;
    if (next_tif.get_named_type(next_name.c_str())) {
      // Check if the target comes from a different TIL library
      if (next_tif.is_from_subtil()) {
        typedef_type.element_type = TYPE_UNK;
        resolved_element = true;
      } else if (next_tif.is_typedef()) {
        // Target is another typedef -- export it first (recursive)
        uint32_t next_ord = next_tif.get_ordinal();
        if (next_ord > 0) {
          type_uid_t target_tuid = ExportSingleTypedef(next_ord);
          typedef_type.element_type = target_tuid;
          resolved_element = true;
        }
        // else: typedef without ordinal -- fall through to element
        // resolution from the next_tif itself (it IS the immediate target)
        if (!resolved_element) {
          ResolveTypedefElement(typedef_type, next_tif);
          resolved_element = true;
        }
      } else {
        // Target is a concrete named type (struct, union, enum, ...)
        // Use the next_tif directly for single-step resolution
        ResolveTypedefElement(typedef_type, next_tif);
        resolved_element = true;
      }
    } else {
      // get_named_type failed despite having a name -- the name might
      // refer to a built-in type (e.g. "int", "char") that IDA knows
      // but doesn't store in the local type library.
      // Fall through to anonymous/primitive resolution below.
      QLOGD << absl::StrFormat(
          "Typedef `%s`: get_named_type failed for next name `%s`, "
          "falling back to resolved type",
          name.c_str(), next_name.c_str());
    }
  }

  if (!resolved_element) {
    // The typedef aliases a primitive, anonymous pointer/array, or a
    // type whose name could not be looked up.  Use the fully resolved
    // concrete type (this IS single-step for anonymous targets, since
    // anonymous types are never typedefs themselves).
    ResolveTypedefElement(typedef_type, fully_resolved);
  }

  // Guard against self-references: when a typedef wraps a pointer/array
  // that shares the same IDA ordinal (e.g. `typedef U32 *PU32`),
  // ExportPointer/ExportArray returns the typedef's own tuid because it
  // was registered first.  Detect and break the cycle by falling back
  // to the corresponding BaseType.
  if (typedef_type.element_type.has_value()) {
    auto* et_tuid = std::get_if<type_uid_t>(&*typedef_type.element_type);
    if (et_tuid && *et_tuid == tuid) {
      typedef_type.element_type = GetBaseType(tif);
    }
  }

  // Print the type as a C-string if possible
  qstring decl;
  if (tif.print(&decl, name.c_str(),
                PRTYPE_TYPE | PRTYPE_MULTI | PRTYPE_DEF | PRTYPE_SEMI))
    typedef_type.c_str = ConvertIdaString(decl);

  // Export xrefs
  ExportSymbolReference(&typedef_type, typedef_type.xref_to, tid,
                        reference::WHOLE_TYPE);

  return tuid;
}

void ExportTypedefs() {
  for (uint32_t ordinal = 1; ordinal < get_ordinal_limit(); ++ordinal) {
    tinfo_t tif;
    if (!tif.get_numbered_type(ordinal))
      continue;
    if (!tif.is_typedef())
      continue;

    ExportSingleTypedef(ordinal);
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