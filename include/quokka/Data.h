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

/**
 * @file Data.h
 *
 * Functions related to the Data management
 */

#ifndef QUOKKA_DATA_H
#define QUOKKA_DATA_H

#include <concepts>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>

// clang-format off: Compatibility.h must come before ida headers
#include "Compatibility.h"
// clang-format on

#include <pro.h>
#include <bytes.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <typeinf.hpp>

// #include "absl/hash/hash.h"
#include "absl/strings/str_format.h"

#include "DataType.h"
#include "ProtoHelper.h"  // Kept for ProtoHelper
#include "Segment.h"
#include "Util.h"

namespace quokka {

/**
 * -----------------------------------------------------------------------------
 * quokka::Data
 * -----------------------------------------------------------------------------
 * Data representation
 *
 * `Data` represents everything IDA considers to be data.
 */
class Data : public ProtoHelper {
 private:
  using RefTypeT =
      std::variant<RefCounter<EnumType>, RefCounter<CompositeConcreteType>>;

  std::string name;  ///< If applicable, the name of the data
  std::optional<RefTypeT>
      ref_type;  ///< Referenced type when the data type is enum or composite

  template <typename T>
  void SetReferenceTypeImpl(RefCounter<T> type) {
    this->ref_type = RefTypeT(type);
  }

  /**
   * Has the data a name ?
   *
   * Answers using the flags associated to the address.
   *
   * @param any_name Check any name or just the user_name
   */
  [[nodiscard]] bool HasName(bool any_name) const;

  /**
   * Set the name of the data
   */
  void SetName();

 public:
  ea_t addr = BADADDR;       ///< Address attached to the data
  DataType type = TYPE_UNK;  ///< Data type
  uint64_t size;  ///< Size of the data (not always redundant for certain types)
  RefCounter<Segment> segment;  ///< Reference to the segment

  /**
   * Constructor
   *
   * @param addr_ Address where the data has been found
   * @param data_type_ Type of the data
   * @param size_ Size of the data
   */
  Data(ea_t addr_, DataType data_type_, uint64_t size_,
       RefCounter<Segment> segment_)
      : addr(addr_), type(data_type_), size(size_), segment(segment_) {
    if (HasName(false))
      this->SetName();
  }

  Data(const Data& data)
      : addr(data.addr),
        type(data.type),
        size(data.size),
        segment(data.segment) {}

  Data(Data&& data)
      : addr(std::exchange(data.addr, 0)),
        type(std::exchange(data.type, TYPE_UNK)),
        size(std::exchange(data.size, 0)),
        segment(std::move(data.segment)) {}

  Data& operator=(const Data& data) {
    addr = data.addr;
    type = data.type;
    size = data.size;
    segment = data.segment;
    return *this;
  }

  Data& operator=(Data&& data) {
    addr = std::exchange(data.addr, 0);
    type = std::exchange(data.type, TYPE_UNK);
    size = std::exchange(data.size, 0);
    segment = std::move(data.segment);
    return *this;
  }

  /**
   * Accessor for the name
   * @return The name
   */
  [[nodiscard]] const std::string& GetName() const { return name; }

  /**
   * Tells if the data referenced is initialized or not (like in .bss
   segment)
   * using the flags associated to the address.
   *
   * @return True if the data is initialized, False otherwise.
   */
  [[nodiscard]] bool IsInitialized() const;

  /**
   * Proxy for template argument deduction
   */
  template <template <typename> typename T, typename L>
    requires(std::constructible_from<RefCounter<L>, T<L>>)
  void SetReferenceType(T<L> type) {
    this->SetReferenceTypeImpl(RefCounter<L>(type));
  }

  const std::optional<RefTypeT>& GetReferenceType() { return this->ref_type; }

  /**
   * Equality operator
   *
   * Two objects are considered equal when they are at the same address, they
   * have the same type and size
   */
  bool operator==(const Data& rhs) const {
    return addr == rhs.addr && type == rhs.type && size == rhs.size;
  }

  /**
   * Inequality operator
   */
  bool operator!=(const Data& rhs) const { return !(rhs == *this); }

  /**
   * Hash implementation of the object using absl::Hash
   * @tparam H Hash
   * @param h Hash value
   * @param m Data object
   * @return An hash value for the object
   */
  template <typename H>
  friend H AbslHashValue(H h, const Data& m) {
    return H::combine(std::move(h), m.addr, m.type, m.size);
  }
};

Data MakeData(ea_t addr, uint64_t size);

}  // namespace quokka

#endif  // QUOKKA_DATA_H
