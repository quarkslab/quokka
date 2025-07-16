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

#include "quokka/Reference.h"

#include <algorithm>
#include <memory>

#include "quokka/Compatibility.h"

#include <struct.hpp>

#include "quokka/Data.h"
#include "quokka/Localization.h"

#if IDA_SDK_VERSION >= 850
#error "api_v8/Reference.cpp can only be used with IDA SDK < 8.5"
#endif

namespace quokka {

Location ResolveStructure(ea_t addr, const Structures& structures) {
  struc_t* struc;
  member_t* member = get_member_by_id(tid_t(addr));
  if (member == nullptr) {
    struc = get_struc(tid_t(addr));
  } else {
    struc = get_sptr(member);
  }

  if (struc == nullptr) {
    return BADADDR;
  }
  auto it = std::find_if(structures.begin(), structures.end(),
                         [&](const std::shared_ptr<Structure>& s) -> bool {
                           return s->addr == ea_t(struc->id);
                         });

  if (it != structures.end()) {
    if (member == nullptr) {
      return *it;
    } else {
      for (const std::shared_ptr<StructureMember>& m : (*it)->members) {
        if (member->soff == m->offset) {
          return m;
        }
      }
    }
  }

  return BADADDR;
}

}  // namespace quokka