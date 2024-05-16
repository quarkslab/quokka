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
 * @file DataType.h
 *
 * Functions and classes related to data types
 */

#ifndef QUOKKA_COMPOSITE_DATA_H
#define QUOKKA_COMPOSITE_DATA_H

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

// clang-format off: Compatibility.h must come before ida headers
#include "Compatibility.h"
// clang-format on
#include <pro.h>
#include <enum.hpp>
#include <typeinf.hpp>

#include "ProtoHelper.h"  // Kept for ProtoHelper
#include "ProtoWrapper.h"
#include "Util.h"

namespace quokka {

/**
 * Type of data. This replicates the enumeration of IDA for data type but is
 * kept as a separate enum to better handle the translation to the protobuf.
 */
enum DataType : short {
  TYPE_UNK = 0,
  TYPE_B,
  TYPE_W,
  TYPE_DW,
  TYPE_QW,
  TYPE_OW,
  TYPE_FLOAT,
  TYPE_DOUBLE,
  TYPE_ASCII,
  TYPE_STRUCT,
  TYPE_ALIGN,
  TYPE_POINTER,
  TYPE_ENUM,
  TYPE_UNION,
  TYPE_ARRAY,
};

DataType GetDataType(const tinfo_t& flags);
DataType GetDataType(flags_t flags);

struct CompositeTypeMember;  // forward declaration

/**
 * -----------------------------------------------------------------------------
 * quokka::CompositeType
 * -----------------------------------------------------------------------------
 * Base class representing a generic composite data type.
 *
 * A composite data type might contain heterogeneous members.
 */
class CompositeType : public ProtoHelper {
 public:
  CompositeType(std::string&& n, tid_t id, size_t sz);

  std::string name;  ///< Composite type name
  tid_t id;          ///< Type id (IDA internal)
  size_t size;       ///< Structure size

  std::vector<CompositeTypeMember> members;  ///< Members list
};

/**
 * -----------------------------------------------------------------------------
 * quokka::StructureType
 * -----------------------------------------------------------------------------
 * A class representing a structure data type in IDA.
 */
class StructureType : public CompositeType {
 public:
  template <typename... ArgsT>
  StructureType(ArgsT&&... Args)
      : CompositeType(std::forward<ArgsT>(Args)...) {}
};

/**
 * -----------------------------------------------------------------------------
 * quokka::UnionType
 * -----------------------------------------------------------------------------
 * A class representing a union data type in IDA.
 */
class UnionType : public CompositeType {
 public:
  template <typename... ArgsT>
  UnionType(ArgsT&&... Args) : CompositeType(std::forward<ArgsT>(Args)...) {}
};

using CompositeConcreteType = std::variant<StructureType, UnionType>;

/**
 * -----------------------------------------------------------------------------
 * quokka::CompositeTypeMember
 * -----------------------------------------------------------------------------
 * A member of a composite type.
 */
class CompositeTypeMember : public ProtoHelper {
 public:
  CompositeTypeMember(ea_t o, std::string&& n, DataType t, asize_t sz);

  ea_t offset;       ///< Field offset (IDA internal)
  std::string name;  ///< Name of the field
  DataType type;     ///< Type of the value
  std::optional<RefCounter<CompositeConcreteType>>
      composite_type_ptr;  ///< Pointer to the CompositeType if
                           ///< the member type is composite
  asize_t size;            ///< Size of the field
};

/**
 * -----------------------------------------------------------------------------
 * quokka::CompositeTypes
 * -----------------------------------------------------------------------------
 * Container for all the composite data types in the program (like struct or
 * unions).
 *
 * Use a singleton pattern and act like a std::vector.
 */
class CompositeTypes {
 private:
  using ElementT = std::shared_ptr<CompositeConcreteType>;
  std::vector<ElementT> composite_types_;  ///< Internal list

  explicit CompositeTypes() = default;  ///< Private constructor

 public:
  using iterator = std::vector<ElementT>::iterator;
  using const_iterator = std::vector<ElementT>::const_iterator;

  /**
   * Return the instance of the `CompositeTypes` class.
   * Used for the singleton pattern.
   * @return `CompositeTypes`
   */
  static CompositeTypes& GetInstance() {
    static CompositeTypes instance;
    return instance;
  }

  /**
   * Delete constructors for singleton pattern
   */
  CompositeTypes(CompositeTypes const&) = delete;
  void operator=(CompositeTypes const&) = delete;

  /**
   * Creates the object of type T and pushes into the collection.
   *
   * @tparam T The type of the object to store. Must be a type from
   * CompositeConcreteType
   * @tparam Args Arguments to be forwarded to the T constructor
   * @param args Arguments of the T constructor
   * @return A reference to the newly added object
   */
  template <IsOneOf<CompositeConcreteType> T, typename... ArgsT>
  ElementT& emplace_back(ArgsT&&... args) {
    return composite_types_.emplace_back(
        std::make_shared<CompositeConcreteType>(
            T(std::forward<ArgsT>(args)...)));
  }

  /**
   * Find the composite type with the specified name.
   * @return An iterator to the requested element. If no such element is found,
   * past-the-end (see end()) iterator is returned.
   */
  constexpr const_iterator get_by_name(const std::string& name) const {
    return std::find_if(
        composite_types_.begin(), composite_types_.end(),
        [&name](const auto& element) {
          return std::visit([&name](const auto& el) { return el.name == name; },
                            *element);
        });
  }

  /**
   * Find the composite type with the specified ID.
   * @return An iterator to the requested element. If no such element is found,
   * past-the-end (see end()) iterator is returned.
   */
  constexpr const_iterator get_by_id(tid_t type_id) const {
    return std::find_if(
        composite_types_.begin(), composite_types_.end(),
        [&type_id](const auto& element) {
          return std::visit(
              [&type_id](const auto& el) { return el.id == type_id; },
              *element);
        });
  }

  /**
   * Proxy for the std::vector::size()
   * @return Size of the container
   */
  [[nodiscard]] std::size_t size() const { return composite_types_.size(); }

  /**
   * Proxy for the std::vector::back()
   * @return Reference to the last element
   */
  constexpr ElementT& back() { return composite_types_.back(); }
  constexpr const ElementT& back() const { return composite_types_.back(); }

  /**
   * Proxy iterators
   */
  iterator begin() { return composite_types_.begin(); }
  iterator end() { return composite_types_.end(); }
  [[nodiscard]] const_iterator begin() const {
    return composite_types_.cbegin();
  }
  [[nodiscard]] const_iterator end() const { return composite_types_.cend(); }
};

/**
 * -----------------------------------------------------------------------------
 * quokka::EnumType
 * -----------------------------------------------------------------------------
 * Base class representing a enum defined in the program.
 */
class EnumType : public ProtoHelper {
 public:
  EnumType(std::string&& n, enum_t t)
      : name(std::forward<std::string>(n)), type_id(t) {}

  std::string name;  ///< Name of the enum
  enum_t type_id;    ///< IDA type ID
  std::vector<std::pair<std::string, int64_t>>
      values;  ///< Internal values of the enum as pairs (name, value)
};

/**
 * -----------------------------------------------------------------------------
 * quokka::Enums
 * -----------------------------------------------------------------------------
 * Container for all the enum types in the program.
 *
 * Use a singleton pattern and act like a std::vector.
 */
class Enums {
 private:
  using ElementT = std::shared_ptr<EnumType>;
  std::vector<ElementT> enums_;  ///< Internal list

  explicit Enums() = default;  ///< Private constructor

 public:
  using iterator = std::vector<ElementT>::iterator;
  using const_iterator = std::vector<ElementT>::const_iterator;

  /**
   * Return the instance of the `Enums` class.
   * Used for the singleton pattern.
   * @return `Enums`
   */
  static Enums& GetInstance() {
    static Enums instance;
    return instance;
  }

  /**
   * Delete constructors for singleton pattern
   */
  Enums(Enums const&) = delete;
  void operator=(Enums const&) = delete;

  /**
   * Creates the EnumType object and pushes into the collection.
   *
   * @tparam Args Arguments to be forwarded to the EnumType constructor
   * @param args Arguments of the EnumType constructor
   * @return A reference to the newly added object
   */
  template <typename... ArgsT>
  constexpr ElementT& emplace_back(ArgsT&&... args) {
    return enums_.emplace_back(
        std::make_shared<EnumType>(std::forward<ArgsT>(args)...));
  }

  /**
   * Proxy for the std::vector::size()
   * @return Size of the container
   */
  [[nodiscard]] std::size_t size() const { return enums_.size(); }

  /**
   * Proxy iterators
   */
  iterator begin() { return enums_.begin(); }
  iterator end() { return enums_.end(); }
  [[nodiscard]] const_iterator begin() const { return enums_.cbegin(); }
  [[nodiscard]] const_iterator end() const { return enums_.cend(); }
};

/**
 * Export and write the composite data types of the program.
 *
 * Will populate the `CompositeTypes` singleton container.
 * This is usually fast because not many structures are defined in a program.
 *
 * @param proto A pointer to the main protobuf object.
 */
void ExportCompositeDataTypes(Quokka* proto);

/**
 * Export all the enums defined in the program
 *
 * @param structure_list Structures container
 */
void ExportEnums(Quokka* proto);

}  // namespace quokka

#endif  // QUOKKA_COMPOSITE_DATA_H
