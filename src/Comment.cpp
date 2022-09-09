// Copyright 2022 Quarkslab
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

#include "quokka/Comment.h"

#include "quokka/Data.h"
#include "quokka/Function.h"
#include "quokka/Instruction.h"

namespace quokka {

int Comments::GetIndice(const std::string& comment) {
  auto [it, inserted] =
      this->comment_strings.try_emplace(comment, this->comment_strings.size());
  return it->second;
}

void GetRegularComments(Comments& comments, ea_t addr,
                        std::shared_ptr<Instruction>& inst) {
  qstring ida_comment;

  for (bool repeatable : {false, true}) {
    if (get_cmt(&ida_comment, addr, repeatable) > 0) {
      comments.insert(ConvertIdaString(ida_comment), Location(inst),
                      INSTRUCTION);
    }
  }
}

bool GetLineComment(ea_t addr, int index, std::string* output) {
  qstring ida_comment;
  ssize_t result = get_extra_cmt(&ida_comment, addr, index);
  *output = ConvertIdaString(ida_comment);

  return result >= 0;
}

void GetLineComments(Comments& comments, ea_t addr,
                     std::shared_ptr<Instruction>& inst) {
  std::string buffer;

  for (int index : {E_PREV, E_NEXT}) {
    for (int i = 0; GetLineComment(addr, index + i, &buffer); ++i) {
      if (!buffer.empty()) {
        comments.insert(buffer, Location(inst), INSTRUCTION);
      }
      buffer.clear();
    }
  }
}

void GetComments(ea_t addr, std::shared_ptr<Instruction>& inst) {
  Comments& comments = Comments::GetInstance();

  GetRegularComments(comments, addr, inst);
  GetLineComments(comments, addr, inst);
}

void GetFunctionComments(Comments& comments, const func_t* func,
                         std::shared_ptr<Function> function_p) {
  qstring ida_comment;
  for (bool repeatable : {false, true}) {
    if (get_func_cmt(&ida_comment, func, repeatable) > 0) {
      comments.insert(ConvertIdaString(ida_comment), Location(function_p),
                      FUNCTION);
    }
  }
}

void GetEnumMemberComment(std::shared_ptr<StructureMember> member_p,
                          const_t member) {
  qstring ida_comment;
  Comments& comments = Comments::GetInstance();

  for (bool repeatable : {false, true}) {
    if (get_enum_member_cmt(&ida_comment, member, repeatable) > 0) {
      comments.insert(ConvertIdaString(ida_comment), Location(member_p),
                      STRUCTURE);
    }
  }
}

void GetEnumComment(std::shared_ptr<Structure> structure, enum_t ida_enum) {
  qstring ida_comment;
  Comments& comments = Comments::GetInstance();

  for (bool repeatable : {false, true}) {
    if (get_enum_cmt(&ida_comment, ida_enum, repeatable) > 0) {
      comments.insert(ConvertIdaString(ida_comment), Location(structure),
                      STRUCTURE);
    }
  }
}

void GetStructureMemberComment(std::shared_ptr<StructureMember> member_p,
                               tid_t member) {
  qstring ida_comment;
  Comments& comments = Comments::GetInstance();

  for (bool repeatable : {false, true}) {
    if (get_member_cmt(&ida_comment, member, repeatable) > 0) {
      comments.insert(ConvertIdaString(ida_comment), Location(member_p),
                      STRUCTURE);
    }
  }
}

void GetStructureComment(std::shared_ptr<Structure> structure,
                         tid_t ida_struct) {
  qstring ida_comment;
  Comments& comments = Comments::GetInstance();

  for (bool repeatable : {false, true}) {
    if (get_struc_cmt(&ida_comment, ida_struct, repeatable) > 0) {
      comments.insert(ConvertIdaString(ida_comment), Location(structure),
                      STRUCTURE);
    }
  }
}
}  // namespace quokka