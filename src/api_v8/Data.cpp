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

#include <struct.hpp>

#include "quokka/Comment.h"
#include "quokka/Reference.h"

#if IDA_SDK_VERSION >= 900
#error "api_v8/Data.cpp can only be used with IDA SDK < 9.0"
#endif

namespace quokka {

static StructureMember MakeStructureMember(member_t* ida_member) {
  return StructureMember(ida_member->soff, get_member_name(ida_member->id),
                         GetDataType(ida_member->flag));
}

static StructureMember MakeStructureMember(const_t cid, uval_t member_value) {
  qstring member_name;
  get_enum_member_name(&member_name, cid);

  return StructureMember(ea_t(cid), member_name, TYPE_B, 0, member_value);
}

/**
 * Export the struct members
 *
 * Iterate through the ida-struct member and export each of them.
 *
 * @param structure A pointer to the `Structure` object
 * @param ida_struc A pointer to the IDA struct
 */
static void ExportStructMembers(std::shared_ptr<Structure>& structure,
                                struc_t* ida_struc) {
  ea_t member_offset = get_struc_first_offset(ida_struc);
  int member_index = 0;
  while (member_offset != BADADDR) {
    member_t* ida_member = get_member(ida_struc, member_offset);
    if (ida_member != nullptr) {
      auto structure_member =
          std::make_shared<StructureMember>(MakeStructureMember(ida_member));
      structure_member->parent = structure;

      if (!structure->has_variable_size || !is_varmember(ida_member)) {
        structure_member->size = get_member_size(ida_member);
      }

      structure->members.push_back(structure_member);

      /* Retrieve comments */
      GetStructureMemberComment_v8(structure->members.back(), ida_member->id);
      ExportStructureMemberReference(ea_t(ida_member->id),
                                     structure->members.back(), STRUCT_STRUCT);
      member_index++;
    }

    member_offset = get_struc_next_offset(ida_struc, member_offset);
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
 * @param ida_struct A pointer to the IDA struct
 * @return Created structure
 */
static std::shared_ptr<Structure> ExportStructure(struc_t* ida_struct) {
  std::shared_ptr<Structure> structure = std::make_shared<Structure>();
  structure->name = ConvertIdaString(get_struc_name(ida_struct->id));
  structure->addr = ida_struct->id;

  if (is_union(ida_struct->id)) {
    structure->type = STRUCT_UNION;
  } else {
    structure->type = STRUCT_STRUCT;
  }

  if (!ida_struct->is_varstr()) {
    structure->size = get_struc_size(ida_struct);
  } else {
    structure->has_variable_size = true;
  }

  ExportStructureReference(ea_t(structure->addr), structure, STRUCT_STRUCT);

  if (ida_struct->memqty != 0) {
    ExportStructMembers(structure, ida_struct);
  }

  GetStructureComment_v8(structure, ida_struct->id);

  return structure;
}

void ExportStructures(Structures& structures) {
  uval_t idx = get_first_struc_idx();

  // FIX: Even if IDA SDK says the opposite, get_first_struc_idx() may
  // return NULL when no structures_ are defined
  while (idx != BADADDR) {
    tid_t struct_idx = get_struc_by_idx(idx);
    struc_t* ida_struct = get_struc(struct_idx);
    if (ida_struct != nullptr) {
      structures.emplace_back(ExportStructure(ida_struct));
    }

    idx = get_next_struc_idx(idx);
  }
}

/**
 * Export the enum members of enumeration.
 *
 * @note Use a visitor pattern because that's the IDA way of iterating
 * through the enum members ..
 *
 * @param enumeration A pointer to the quokka::Structure
 * @param ida_enum Ida-enum
 * @param enum_idx Index of the enumeration (@see ExportEnum)
 */
static void ExportEnumMembers(std::shared_ptr<Structure>& enumeration,
                              enum_t ida_enum, size_t enum_idx) {
  class EnumMemberVisitor : public enum_member_visitor_t {
   public:
    std::shared_ptr<Structure> enumeration;
    int member_idx = 0;
    int enum_idx = 0;

    explicit EnumMemberVisitor(std::shared_ptr<Structure>& enumeration,
                               int enum_idx) {
      this->enumeration = enumeration;
      this->enum_idx = enum_idx;
    }

    int idaapi visit_enum_member(const_t cid, uval_t value) override {
      auto member =
          std::make_shared<StructureMember>(MakeStructureMember(cid, value));
      member->parent = this->enumeration;

      this->enumeration->members.push_back(member);

      /* Retrieve comments */
      GetEnumMemberComment_v8(this->enumeration->members.back(), cid);
      ExportStructureMemberReference(
          ea_t(cid), this->enumeration->members.back(), STRUCT_ENUM);
      this->member_idx++;

      return 0;
    }
  };

  EnumMemberVisitor visitor = EnumMemberVisitor(enumeration, int(enum_idx));
  for_all_enum_members(ida_enum, visitor);
}

/**
 * Export an enum
 *
 * Ghost enum don't have an index, so we use the position in the `Structures`
 * for all of enumeration as an index. It will be used for attaching comments
 * and references.
 *
 * @param ida_enum Ida-enum
 * @param enum_idx Index of the enumeration (position in the Structures
 *                 container)
 * @return Created structure
 */
static std::shared_ptr<Structure> ExportEnum(enum_t ida_enum, size_t enum_idx) {
  std::shared_ptr<Structure> structure = std::make_shared<Structure>();
  structure->name = ConvertIdaString(get_enum_name(ida_enum));
  structure->type = STRUCT_ENUM;
  structure->size = get_enum_size(ida_enum);
  structure->addr = tid_t(ida_enum);

  if (get_enum_size(ida_enum) > 0) {
    ExportEnumMembers(structure, ida_enum, enum_idx);
  }

  ExportStructureReference(ea_t(ida_enum), structure, STRUCT_STRUCT);

  // Check for comment for the enum
  GetEnumComment_v8(structure, ida_enum);

  return structure;
}

void ExportEnums(Structures& structures) {
  size_t ida_enum_idx = 0;
  enum_t ida_enum;

  while ((ida_enum = getn_enum(ida_enum_idx)) != BADADDR) {
    // Ghost enums don't have any members, so it's not useful to export them
    if (!is_ghost_enum(ida_enum)) {
      structures.emplace_back(ExportEnum(ida_enum, structures.size()));
    }

    /* The enum idx used in the more specialized functions
     * is used to attach a comment to the structure */
    ++ida_enum_idx;
  }
}

}  // namespace quokka
