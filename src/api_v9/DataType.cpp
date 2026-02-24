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
#include <cstdint>
#include <memory>
#include <string>
#include <variant>

// clang-format off: Compatibility.h must come before ida headers
#include "quokka/Compatibility.h"
// clang-format on
#include <typeinf.hpp>

#include "absl/strings/str_format.h"

#include "quokka/DataType.h"
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
static void ExportCompositeMembers(
    std::shared_ptr<CompositeConcreteType>& composite_type_ptr,
    const tinfo_t& tif) {
  // Get the underlying object
  CompositeConcreteType& composite_type = *composite_type_ptr;

  udt_type_data_t udt;
  tif.get_udt_details(&udt);

  uint32_t member_idx = 0;
  for (const udm_t& udm : udt) {
    uint64_t size = udm.size;
    if (udm.type.is_varmember()) {
      QLOGD << absl::StrFormat(
          "Found variable member `%s` that has variable size! Forcing size of "
          "0.",
          ConvertIdaString(udm.name));
      size = 0;
    }

    BaseType member_type = GetBaseType(udm.type);

    // Emplace the CompositeTypeMember
    auto& member = std::visit(
        [&](auto& composite) -> auto& {
          return composite.members.emplace_back(
              udm.offset / 8, ConvertIdaString(udm.name), member_type, size);
        },
        composite_type);

    // TODO adapt for enum/pointer/array
    // Add the composite type pointer if the member is composite as well
    if (member_type == TYPE_UNK) {
      std::string base_type_name;
      qstring ida_string;
      udm.type.get_type_name(&ida_string);
      base_type_name = ConvertIdaString(ida_string);

      // Ask the CompositeTypes manager to give us the relevant struct/union
      const auto& composite_types = CompositeTypes::GetInstance();
      const auto& it = composite_types.get_by_id(udm.type.get_tid());

      if (it == composite_types.end()) {
        QLOGE << absl::StrFormat(
            "Member `%s` is of composite type `%s` but it was not found within "
            "the exported composite types.",
            ConvertIdaString(udm.name), base_type_name);
      } else {
        member.composite_type_ptr = *it;
      }
    }

    /* TODO Retrieve comments */
    std::visit(
        [&](auto& composite) {
          ExportSymbolReference(&composite, member.xref_to, tif.get_tid(),
                                member_idx);
          //   GetStructureMemberComment(composite_type_ptr,
          //                             composite.members.size(),
          //                             ida_member->id);
          //   GetStructureMemberComment_v9(structure_member, udm);
        },
        composite_type);

    ++member_idx;
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
 * @param tif The IDA type info
 */
static void ExportStructOrUnion(const tinfo_t& tif) {
  qstring name;
  tif.get_type_name(&name);

  CompositeTypes& composite_types = CompositeTypes::GetInstance();
  size_t size = tif.is_forward_decl() ? 0 : tif.get_size();

  CompositeTypes::ElementT type;
  if (tif.is_union())
    type = composite_types.emplace_back<UnionType>(ConvertIdaString(name),
                                                   tif.get_tid(), size);
  else
    type = composite_types.emplace_back<StructureType>(ConvertIdaString(name),
                                                       tif.get_tid(), size);

  std::visit(
      [&tif](const auto& x) {
        ExportSymbolReference(&x, x.xref_to, tif.get_tid(),
                              reference::WHOLE_TYPE);
      },
      *type);

  // TODO comments
  //   GetCompositeTypeComment(composite_types.back());
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
  CompositeTypes& composite_types = CompositeTypes::GetInstance();
  for (auto& composite_type_ptr : composite_types) {
    std::visit(
        [&composite_type_ptr](auto& composite) {
          tinfo_t tif;
          bool res = tif.get_type_by_tid(composite.id);
          assert(res && "Couldn't retrieve the tinfo_t object from the tid_t");

          // Print the enum as a C-string if possible
          qstring composite_name;
          tif.get_type_name(&composite_name);
          qstring decl;
          if (tif.print(&decl, composite_name.c_str(), PRTYPE_TYPE | PRTYPE_MULTI | PRTYPE_DEF | PRTYPE_SEMI))
            composite.c_str = ConvertIdaString(decl);
          
          // Export the members of the struct/union
          if (!tif.is_empty_udt() && !tif.is_forward_decl())
            ExportCompositeMembers(composite_type_ptr, tif);
        },
        *composite_type_ptr);
  }
}

void ExportEnums() {
  auto& enums = Enums::GetInstance();

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
    if (tif.print(&decl, enum_name.c_str(), PRTYPE_TYPE | PRTYPE_MULTI | PRTYPE_DEF | PRTYPE_SEMI))
      enum_type.c_str = ConvertIdaString(decl);

    const EnumType& new_obj = enums.insert(std::move(enum_type));

    // References
    ExportSymbolReference(&new_obj, new_obj.xref_to, tif.get_tid(),
                          reference::WHOLE_TYPE);
    if (has_members) {
      for (size_t i = 0; const edm_t& edm : edt) {
        ExportSymbolReference(&new_obj, new_obj.xref_to, edm.get_tid(), i);
        ++i;
      }
    }


    // TODO comments
    // Check for comment for the enum
    // GetEnumComment(enum_type);
  }
}

}  // namespace quokka