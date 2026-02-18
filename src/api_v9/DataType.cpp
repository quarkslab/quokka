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
      QLOGE << absl::StrFormat(
          "Found variable member `%s` that has variable size! Forcing size of "
          "0.",
          ConvertIdaString(udm.name));
      size = 0;
    }

    DataType member_type = GetDataType(udm.type);

    // Emplace the CompositeTypeMember
    auto& member = std::visit(
        [&](auto& composite) -> auto& {
          return composite.members.emplace_back(
              udm.offset / 8, ConvertIdaString(udm.name), member_type, size);
        },
        composite_type);

    // Add the composite type pointer if the member is composite as well
    if (member_type == TYPE_STRUCT || member_type == TYPE_UNION) {
      std::string base_type_name;
      qstring ida_string;
      udm.type.get_type_name(&ida_string);
      base_type_name = ConvertIdaString(ida_string);

      // Ask the CompositeTypes manager to give us the relevant struct/union
      const auto& composite_types = CompositeTypes::GetInstance();
      const auto& it = composite_types.get_by_name(base_type_name);

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
          //   GetStructureMemberComment(composite_type_ptr,
          //                             composite.members.size(),
          //                             ida_member->id);
          //   GetStructureMemberComment_v9(structure_member, udm);
        },
        composite_type);

    // TODO references
    //   ExportStructureMemberReference(ea_t(ida_member->id),
    //                                  structure->members.back(),
    //                                  STRUCT_STRUCT);
    // ExportStructureMemberReference(ea_t(struct_tif.get_udm_tid(member_idx)),
    //                                structure_member, STRUCT_STRUCT);

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

  if (tif.is_varstruct()) {
    QLOGE << "Found composite type `" << ConvertIdaString(name)
          << "` that has variable size! Ignoring it.";
    return;
  }

  CompositeTypes& composite_types = CompositeTypes::GetInstance();
  size_t size = tif.is_forward_decl() ? 0 : tif.get_size();

  if (tif.is_union())
    composite_types.emplace_back<UnionType>(ConvertIdaString(name),
                                            tif.get_tid(), size);
  else
    composite_types.emplace_back<StructureType>(ConvertIdaString(name),
                                                tif.get_tid(), size);

  // TODO references & comments
  //   ExportStructureReference(ea_t(structure->addr), structure,
  //   STRUCT_STRUCT);

  //   GetCompositeTypeComment(composite_types.back());
}

void ExportCompositeDataTypes() {
  for (uint32_t ordinal = 1; ordinal < get_ordinal_limit(); ++ordinal) {
    tinfo_t tif;
    if (!tif.get_numbered_type(ordinal, BTF_STRUCT) &&
        !tif.get_numbered_type(ordinal, BTF_UNION))
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

          if (!tif.is_empty_udt() && !tif.is_forward_decl())
            ExportCompositeMembers(composite_type_ptr, tif);
        },
        *composite_type_ptr);
  }
}

}  // namespace quokka