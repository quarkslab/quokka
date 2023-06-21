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

#include "quokka/Imports.h"

#include "quokka/Function.h"
#include "quokka/Util.h"

namespace quokka {

ImportManager::ImportManager() {
  for (int i = 0; i < get_import_module_qty(); ++i) {
    enum_import_names(
        i,
        [](ea_t ea, const char* name, uval_t ord, void* params) {
          auto import_manager = static_cast<ImportManager*>(params);
          if (name == nullptr) {
            // Since IDA is such a bad tool, it might know the name even if it
            // is not reporting it now.
            import_manager->AddImport(ea, GetName(ea), ord);
          } else {
            import_manager->AddImport(ea, std::string(name), ord);
          }

          if (import_manager->ranges.empty()) {
            import_manager->ranges.emplace_back(ea, ea + get_item_size(ea));
          } else {
            auto last_range = import_manager->ranges.rbegin();
            if (last_range->end != ea) {
              import_manager->ranges.emplace_back(ea, ea + get_item_size(ea));
            } else {
              last_range->end = ea + get_item_size(ea);
            }
          }

          return 1;
        },
        this);
  }
}

bool ImportManager::InImport(const ea_t address) const {
  return std::any_of(
      ranges.begin(), ranges.end(),
      [&address](const Range& range) { return range.InRange(address); });
}

void ImportManager::AddImport(ea_t address, std::string name, uint64_t ord) {
  this->imports.try_emplace(address, Import(std::move(name), ord));
}

void ImportManager::AddMissingChunks(FuncChunkCollection& chunks) {
  chunks.Sort();

  // First, list the chunks that need to be added
  std::vector<ea_t> addresses;
  for (const auto& [address, _] : this->imports) {
    if (chunks.GetElement(address, true) == nullptr) {
      addresses.emplace_back(address);
    }
  }

  // Secondly, add them. This must be done in two steps as the GetElement expect
  // the ChunkCollection to be sorted.
  for (const auto& address : addresses) {
    chunks.Insert(address, /* is_import */ true);
  }
}
}  // namespace quokka
