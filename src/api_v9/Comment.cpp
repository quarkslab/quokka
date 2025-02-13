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

#include "quokka/Data.h"
#include "quokka/Util.h"

#if IDA_SDK_VERSION < 900
#error "api_v9/Comment.cpp can only be used with IDA SDK >= 9.0"
#endif

namespace quokka {

void GetStructureMemberComment_v9(std::shared_ptr<StructureMember> member_p,
                                  const udm_t& udm) {
  if (!udm.cmt.empty())
    Comments::GetInstance().insert(ConvertIdaString(udm.cmt),
                                   Location(member_p), STRUCTURE);
}

void GetStructureComment_v9(std::shared_ptr<Structure> structure,
                            const tinfo_t& struct_tif) {
  qstring ida_comment;

  if (struct_tif.get_type_cmt(&ida_comment) > 0)
    Comments::GetInstance().insert(ConvertIdaString(ida_comment),
                                   Location(structure), STRUCTURE);
}

void GetEnumMemberComment_v9(std::shared_ptr<StructureMember> member_p,
                             const edm_t& edm) {
  if (!edm.cmt.empty())
    Comments::GetInstance().insert(ConvertIdaString(edm.cmt),
                                   Location(member_p), STRUCTURE);
}

void GetEnumComment_v9(std::shared_ptr<Structure> structure,
                       const tinfo_t& enum_tif) {
  qstring ida_comment;

  if (enum_tif.get_type_cmt(&ida_comment) > 0)
    Comments::GetInstance().insert(ConvertIdaString(ida_comment),
                                   Location(structure), STRUCTURE);
}

}  // namespace quokka