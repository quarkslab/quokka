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

#include "quokka/Data.h"
#include "quokka/Localization.h"

#if IDA_SDK_VERSION < 900
#error "api_v9/Reference.cpp can only be used with IDA SDK >= 9.0"
#endif

namespace quokka {

Location ResolveStructure(ea_t addr, const Structures& structures) {
  tinfo_t struct_tif;
  if (!struct_tif.get_type_by_tid((tid_t)addr))
    return BADADDR;

  auto it = std::find_if(structures.begin(), structures.end(),
                         [&](const std::shared_ptr<Structure>& s) -> bool {
                           return s->addr == (ea_t)struct_tif.get_tid();
                         });
  if (it == structures.end())
    return BADADDR;

  udm_t udm;
  if (struct_tif.get_udm_by_tid(&udm, (tid_t)addr) < 0)
    return *it;

  for (const std::shared_ptr<StructureMember>& m : (*it)->members) {
    if (udm.offset / 8 == m->offset)
      return m;
  }

  // Something really strange happened to reach this
  return BADADDR;
}

}  // namespace quokka