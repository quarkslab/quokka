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

#ifndef QUOKKA_IMPORTS_H
#define QUOKKA_IMPORTS_H

#include <absl/container/flat_hash_map.h>

#include <pro.h>
#include <nalt.hpp>
#include <utility>
#include <vector>

#include "Windows.h"

namespace quokka {

/**
 * Import
 * An import is simply represented by its name or its ordinal.
 * TODO: Deal with the ordinal when the name is missing
 */
struct Import {
  std::string name;
  uint64_t ord;

  Import(std::string name_, uint64_t ord_)
      : name(std::move(name_)), ord(ord_) {}
};

class FuncChunkCollection;

struct Range {
  ea_t start = BADADDR64;
  ea_t end = BADADDR64;

  bool operator<(const Range& other) const { return start < other.start; }

  [[nodiscard]] bool InRange(const ea_t value) const {
    return start <= value and value < end;
  }

  explicit Range(ea_t start_, ea_t end_) : start(start_), end(end_){};
};

class ImportManager {
 private:
  /**
   * Range of imports address
   */
  std::vector<Range> ranges;
  // absl::btree_set<Range> ranges;

 public:
  /**
   * Imports list
   */
  absl::flat_hash_map<ea_t, Import> imports;

  /**
   * Constructor
   */
  explicit ImportManager();

  /**
   * Check if the address is in the import range
   * @param address Address to check
   * @return Boolean for success
   */
  [[nodiscard]] bool InImport(ea_t address) const;

  /**
   * Check if the address is an import (e.g. the start of)
   * @param address Address to check
   * @return Boolean for success
   */
  [[nodiscard]] bool IsImport(const ea_t address) const {
    return this->imports.find(address) != this->imports.end();
  }

  /**
   * Add an import in the import list
   * @param address Address of the import
   * @param name Name of the import
   * @param ord Import ordinal
   */
  void AddImport(ea_t address, std::string name, uint64_t ord);

  /**
   * Update the ChunkCollection to add the missing chunks
   * In PE format, the imports are considered as data so no chunk is created.
   * @param chunks Collection of chunks
   */
  void AddMissingChunks(FuncChunkCollection& chunks);
};

}  // namespace quokka
#endif  // QUOKKA_IMPORTS_H
