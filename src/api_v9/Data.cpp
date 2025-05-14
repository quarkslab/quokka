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

#include "quokka/Data.h"

#include "quokka/Compatibility.h"

#include <typeinf.hpp>

#include "quokka/Comment.h"
#include "quokka/Reference.h"

#if IDA_SDK_VERSION < 900
#error "api_v9/Data.cpp can only be used with IDA SDK >= 9.0"
#endif

namespace quokka {

static StructureMember MakeStructureMember(const udm_t& udm) {
  return StructureMember(udm.offset / 8, udm.name, GetDataType(udm.type));
}

static StructureMember MakeStructureMember(const edm_t& edm) {
  return StructureMember(edm.get_tid(), edm.name, TYPE_B, 0, edm.value);
}

/**
 * Export the struct members
 *
 * Iterate through the ida-struct member and export each of them.
 *
 * @param structure A pointer to the `Structure` object
 * @param struct_tif The IDA struct type info
 */
static void ExportStructMembers(std::shared_ptr<Structure>& structure,
                                const tinfo_t& struct_tif) {
  udt_type_data_t udt;
  struct_tif.get_udt_details(&udt);

  uint32_t member_idx = 0;
  for (const udm_t& udm : udt) {
    auto structure_member =
        std::make_shared<StructureMember>(MakeStructureMember(udm));
    structure_member->parent = structure;

    if (!structure->has_variable_size || !udm.type.is_varmember())
      structure_member->size = udm.size;

    structure->members.push_back(structure_member);

    /* Retrieve comments */
    GetStructureMemberComment_v9(structure_member, udm);
    ExportStructureMemberReference(ea_t(struct_tif.get_udm_tid(member_idx)),
                                   structure_member, STRUCT_STRUCT);

    ++member_idx;
  }
}

/**
 * Export an IDA-struct or an union
 *
 * Completely export a structure, including the references and comments.
 *
 * @see ExportStructureReference
 * @see GetStructureComment
 *
 * @param struct_tif The IDA struct type info
 * @return Created structure
 */
static std::shared_ptr<Structure> ExportStructure(const tinfo_t& struct_tif) {
  std::shared_ptr<Structure> structure = std::make_shared<Structure>();
  qstring struct_name;
  struct_tif.get_type_name(&struct_name);
  structure->name = ConvertIdaString(struct_name);
  structure->addr = struct_tif.get_tid();

  if (struct_tif.is_union())
    structure->type = STRUCT_UNION;
  else
    structure->type = STRUCT_STRUCT;

  if (!struct_tif.is_varstruct())
    structure->size = struct_tif.is_forward_decl() ? 0 : struct_tif.get_size();
  else
    structure->has_variable_size = true;

  ExportStructureReference(ea_t(structure->addr), structure, STRUCT_STRUCT);

  if (!struct_tif.is_empty_udt() && !struct_tif.is_forward_decl())
    ExportStructMembers(structure, struct_tif);

  GetStructureComment_v9(structure, struct_tif);

  return structure;
}

void ExportStructures(Structures& structures) {
  for (uint32_t ordinal = 1; ordinal < get_ordinal_limit(); ++ordinal) {
    tinfo_t tif;
    if (!tif.get_numbered_type(ordinal, BTF_STRUCT) &&
        !tif.get_numbered_type(ordinal, BTF_UNION))
      continue;

    structures.emplace_back(ExportStructure(tif));
  }
}

/**
 * Export the enum members of enumeration.
 *
 * @param enumeration A pointer to the quokka::Structure
 * @param enum_tif Ida enum type info
 */
static void ExportEnumMembers(std::shared_ptr<Structure>& enumeration,
                              const tinfo_t& enum_tif) {
  enum_type_data_t edt;
  enum_tif.get_enum_details(&edt);

  for (const edm_t& edm : edt) {
    auto member = std::make_shared<StructureMember>(MakeStructureMember(edm));
    member->parent = enumeration;

    enumeration->members.push_back(member);

    /* Retrieve comments */
    GetEnumMemberComment_v9(member, edm);
    ExportStructureMemberReference(edm.get_tid(), member, STRUCT_ENUM);
  }
}

/**
 * Export an enum
 *
 * @param enum_tif Ida enum type info
 * @return Created structure
 */
static std::shared_ptr<Structure> ExportEnum(const tinfo_t& enum_tif) {
  std::shared_ptr<Structure> structure = std::make_shared<Structure>();
  qstring enum_name;
  enum_tif.get_type_name(&enum_name);
  structure->name = ConvertIdaString(enum_name);
  structure->type = STRUCT_ENUM;
  structure->size = enum_tif.get_size();
  structure->addr = enum_tif.get_tid();

  if (!enum_tif.is_empty_enum())
    ExportEnumMembers(structure, enum_tif);

  ExportStructureReference(enum_tif.get_tid(), structure, STRUCT_STRUCT);

  // Check for comment for the enum
  GetEnumComment_v9(structure, enum_tif);

  return structure;
}

void ExportEnums(Structures& structures) {
  for (uint32_t ordinal = 1; ordinal < get_ordinal_limit(); ++ordinal) {
    tinfo_t tif;
    if (!tif.get_numbered_type(ordinal, BTF_ENUM))
      continue;
    if (tif.is_empty_enum())  // Do not export empty enums
      continue;

    structures.emplace_back(ExportEnum(tif));
  }
}

}  // namespace quokka
