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
 * @file Reference.h
 * Management of references
 */

#ifndef QUOKKA_REFERENCE_H
#define QUOKKA_REFERENCE_H

#include <cstdint>
#include <utility>
#include <variant>

// clang-format off: Compatibility.h must come before ida headers
#include "Compatibility.h"
// clang-format on
#include <pro.h>
#include <typeinf.hpp>

#include "Bucket.h"
#include "Data.h"
#include "DataType.h"
#include "ProtoHelper.h"
#include "quokka.pb.h"

namespace quokka {

namespace reference {
inline constexpr int32_t WHOLE_TYPE = -1;
}

/**
 * ---------------------------------------------
 * quokka::Reference
 * ---------------------------------------------
 * Represent a reference
 *
 * A reference is a link between two elements
 * They have a direction (source to destination)
 */
class Reference : public ProtoHelper {
 public:
  // Either an address or a pair {Type*, member_index/-1 if no member}.
  using Location = std::variant<ea_t, std::pair<const ProtoHelper*, int32_t>>;
  using ReferenceType = Quokka::Reference::ReferenceType;

  Location source;       ///< Source of the reference
  Location destination;  ///< Destination
  ReferenceType type;    ///< Type of reference

  /**
   * Constructor
   * @param source_ Source
   * @param destination_ Destination
   * @param type_ Reference type
   */
  Reference(Location source_, Location destination_, ReferenceType type_)
      : source(std::move(source_)),
        destination(std::move(destination_)),
        type(type_) {}

  bool operator==(const Reference& other) const noexcept {
    return source == other.source && destination == other.destination &&
           type == other.type;
  }

  /**
   * Hash implementation of the object using absl::Hash
   * @tparam H Hash
   * @param h Hash value
   * @param m Reference object
   * @return An hash value for the object
   */
  template <typename H>
  friend H AbslHashValue(H h, const Reference& m) {
    return H::combine(std::move(h), m.source, m.destination, m.type);
  }
};

/**
 * ---------------------------------------------
 * quokka::References
 * ---------------------------------------------
 * Collection holding every reference found in the binary
 */
class References : public SetBucket<Reference> {
 private:
  explicit References() = default;

 public:
  using SetBucket<Reference>::SetBucket;

  /**
   * Singleton pattern
   * @return References instance
   */
  static References& GetInstance() {
    static References instance;
    return instance;
  }

  /**
   * Delete methods for singleton pattern
   */
  References(References const&) = delete;
  References(References&&) = delete;
  void operator=(References const&) = delete;
  void operator=(References&&) = delete;
};

/**
 * Export all code references to address
 *
 * @param address Address
 */
void ExportCodeReference(ea_t address);

/**
 * Export all the references to the provided data
 *
 * @param data Data object
 */
void ExportDataReferences(const Data& data);

// /**
//  * Export all the references towards the unknown at current_ea
//  *
//  * This is a special case from DataReferences has the data does not really
//  * exist but will be put in the DataBucket if we find some references towards
//  * it (the resulting data will be of size 1 and type UNKNOWN).
//  *
//  * @param current_ea Address
//  * @param data_bucket Data holder
//  */
// void ExportUnkReferences(ea_t current_ea, BucketNew<Data>& data_bucket);

/**
 * Export all references towards a enum
 *
 * @param type The type for which to export the references
 * @param enum_tid Ida type ID
 */
void ExportSymbolReference(const ProtoHelper* type, const tid_t& tid,
                           int32_t index);

// /**
//  * Get the code reference from the start address
//  *
//  * @param code_refs (Out) A list of references
//  * @param start_addr Starting address
//  */
// void GetCodeRefFrom(std::vector<ea_t>& code_refs, ea_t start_addr);

}  // namespace quokka
#endif  // QUOKKA_REFERENCE_H
