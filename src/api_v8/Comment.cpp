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

#include "quokka/Comment.h"

#include "quokka/Compatibility.h"

#include <enum.hpp>
#include <struct.hpp>

#include "quokka/Data.h"
#include "quokka/Util.h"

#if IDA_SDK_VERSION >= 900
#error "api_v8/Comment.cpp can only be used with IDA SDK < 9.0"
#endif

namespace quokka {

void GetStructureMemberComment_v8(std::shared_ptr<StructureMember> member_p,
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

void GetStructureComment_v8(std::shared_ptr<Structure> structure,
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

void GetEnumMemberComment_v8(std::shared_ptr<StructureMember> member_p,
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

void GetEnumComment_v8(std::shared_ptr<Structure> structure, enum_t ida_enum) {
  qstring ida_comment;
  Comments& comments = Comments::GetInstance();

  for (bool repeatable : {false, true}) {
    if (get_enum_cmt(&ida_comment, ida_enum, repeatable) > 0) {
      comments.insert(ConvertIdaString(ida_comment), Location(structure),
                      STRUCTURE);
    }
  }
}

}  // namespace quokka
