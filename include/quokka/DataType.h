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
#include <cstdint>
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
#include <typeinf.hpp>

#include "absl/container/flat_hash_map.h"

#include "Bucket.h"
#include "ProtoHelper.h"  // Kept for ProtoHelper
#include "ProtoWrapper.h"
#include "Reference.h"
#include "Util.h"

// #if IDA_SDK_VERSION < 850
// #include "api_v8/DataType_v8.h"
// #else
// #include "api_v9/DataType_v9.h"
// #endif

namespace quokka {

/**
 * Type of data. This replicates the enumeration of IDA for data type but is
 * kept as a separate enum to better handle the translation to the protobuf.
 */
enum BaseType : uint8_t {
  TYPE_UNK = 0,
  TYPE_B,
  TYPE_W,
  TYPE_DW,
  TYPE_QW,
  TYPE_OW,
  TYPE_FLOAT,
  TYPE_DOUBLE,
};

BaseType GetBaseType(const tinfo_t& flags);
BaseType GetBaseType(flags_t flags);

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
  std::string c_str;  ///< C-string representation of the composite type (if any)
  std::vector<CompositeTypeMember> members;  ///< Members list
  mutable std::vector<const Reference*> xref_to;
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
  CompositeTypeMember(ea_t o, std::string&& n, BaseType t, asize_t sz);

  ea_t offset;       ///< Field offset (IDA internal)
  std::string name;  ///< Name of the field
  BaseType type;     ///< Base type of the value
  std::optional<RefCounter<CompositeConcreteType>>
      composite_type_ptr;  ///< Pointer to the CompositeType if
                           ///< the member type is composite
  asize_t size;            ///< Size of the field
  std::vector<const Reference*> xref_to;
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
 public:
  using ElementT = std::shared_ptr<CompositeConcreteType>;
  using iterator = std::vector<ElementT>::iterator;
  using const_iterator = std::vector<ElementT>::const_iterator;

 private:
  std::vector<ElementT> composite_types_;  ///< Internal list

  explicit CompositeTypes() = default;  ///< Private constructor

 public:
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
  const_iterator begin() const { return composite_types_.cbegin(); }
  const_iterator end() const { return composite_types_.cend(); }
};

struct EnumValue {
  std::string name;
  int64_t value;
  std::vector<const Reference*> xref_to;
};

/**
 * -----------------------------------------------------------------------------
 * quokka::EnumType
 * -----------------------------------------------------------------------------
 * Base class representing a enum defined in the program.
 * @note Two EnumType are considered equal if they have the same name
 */
class EnumType : public ProtoHelper {
 public:
  EnumType(std::string n) : name(std::move(n)) {}

  std::string name;               ///< Name of the enum
  std::vector<EnumValue> values;  ///< Internal values of the enum
  mutable std::vector<const Reference*> xref_to;
  std::string c_str; ///< C-string representation of the enum (if any)
  bool operator==(const EnumType& o) const noexcept {
    return this->name == o.name;
  }

  /**
   * Hash implementation of the object using absl::Hash
   * @tparam H Hash
   * @param h Hash value
   * @param m EnumType object
   * @return An hash value for the object
   */
  template <typename H>
  friend H AbslHashValue(H h, const EnumType& m) {
    return H::combine(std::move(h), m.name);
  }
};

/**
 * -----------------------------------------------------------------------------
 * quokka::Enums
 * -----------------------------------------------------------------------------
 * Container for all the enum types in the program.
 *
 * Use a singleton pattern and act like a set.
 */
class Enums : public SetBucket<EnumType> {
 private:
  explicit Enums() = default;  ///< Private constructor

 public:
  using SetBucket<EnumType>::SetBucket;

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
  Enums(Enums&&) = delete;
  void operator=(Enums const&) = delete;
  void operator=(Enums&&) = delete;
};

template <typename T>
constexpr Quokka::CompositeType::CompositeSubType CompositeSubTypeToProto() {
  using U = std::remove_cvref_t<T>;
  if constexpr (std::is_same_v<U, UnionType>)
    return Quokka_CompositeType_CompositeSubType_TYPE_UNION;
  else if constexpr (std::is_same_v<U, StructureType>)
    return Quokka_CompositeType_CompositeSubType_TYPE_STRUCT;
  else
    static_assert(false, "Mismatch between the CompositeSubTypes");
}

class DataTypes {
 public:
  using TypeT = std::variant<StructureType, UnionType, EnumType>;
  using CollectionT = absl::flat_hash_map<tid_t, std::unique_ptr<TypeT>>;

 private:
  CollectionT collection;

  template <bool IsConst>
  class value_iterator {
    template <bool>
    friend class value_iterator;
    friend class DataTypes;

    using BaseIt =
        std::conditional_t<IsConst, typename CollectionT::const_iterator,
                           typename CollectionT::iterator>;

   public:
    using iterator_category = std::forward_iterator_tag;
    using difference_type =
        typename std::iterator_traits<BaseIt>::difference_type;
    using value_type = TypeT;
    using reference = std::conditional_t<IsConst, const TypeT&, TypeT&>;
    using pointer = std::conditional_t<IsConst, const TypeT*, TypeT*>;

    value_iterator() = default;

    // Allow conversion: iterator -> const_iterator
    value_iterator(const value_iterator<false>& other)
      requires IsConst
        : it_(other.it_) {}

    reference operator*() const {
      assert(it_ != BaseIt{});  // optional sanity check
      assert(it_->second && "null TypeT pointer in DataTypes::collection");
      return *(it_->second);
    }

    pointer operator->() const {
      assert(it_ != BaseIt{});  // optional sanity check
      assert(it_->second && "null TypeT pointer in DataTypes::collection");
      return it_->second.get();
    }

    value_iterator& operator++() {
      ++it_;
      return *this;
    }

    value_iterator operator++(int) {
      value_iterator tmp = *this;
      ++(*this);
      return tmp;
    }

    friend bool operator==(const value_iterator& a, const value_iterator& b) {
      return a.it_ == b.it_;
    }

    friend bool operator!=(const value_iterator& a, const value_iterator& b) {
      return !(a == b);
    }

   private:
    explicit value_iterator(BaseIt it) : it_(it) {}
    BaseIt it_{};
  };

  explicit DataTypes() = default;  ///< Private constructor

 public:
  using iterator = value_iterator<false>;
  using const_iterator = value_iterator<true>;

  iterator begin() { return iterator{collection.begin()}; }
  iterator end() { return iterator{collection.end()}; }

  const_iterator begin() const { return const_iterator{collection.begin()}; }
  const_iterator end() const { return const_iterator{collection.end()}; }

  const_iterator cbegin() const { return const_iterator{collection.cbegin()}; }
  const_iterator cend() const { return const_iterator{collection.cend()}; }

  /**
   * Return the instance of the `DataTypes` class.
   * Used for the singleton pattern.
   * @return `DataTypes`
   */
  static DataTypes& GetInstance() {
    static DataTypes instance;
    return instance;
  }

  /**
   * Delete constructors for singleton pattern
   */
  DataTypes(DataTypes const&) = delete;
  DataTypes(DataTypes&&) = delete;
  void operator=(DataTypes const&) = delete;
  void operator=(DataTypes&&) = delete;

  /**
   * Creates the object of type T and pushes into the collection.
   *
   * @tparam T The type of the object to store. Must be a type from
   * TypeT
   * @tparam Args Arguments to be forwarded to the T constructor
   * @param tid The IDA tid of the type
   * @param args Arguments of the T constructor
   * @return A reference to the newly added object
   */
  template <IsOneOf<TypeT> T, typename... ArgsT>
  TypeT& emplace_back(tid_t tid, ArgsT&&... args) {
    return collection.emplace(
        {tid, std::make_unique<TypeT>(T(std::forward<ArgsT>(args)...))});
  }

  /**
   * Find the type corresponding to the specified tid.
   * @return An iterator to the requested element. If no such element is found,
   * past-the-end (see end()) iterator is returned.
   */
  const_iterator find_by_tid(tid_t tid) const {
    return const_iterator{collection.find(tid)};
  }

  size_t size() const { return collection.size(); }
};

/**
 * Export the composite data types of the program.
 *
 * Will populate the `CompositeTypes` singleton container.
 * This is usually fast because not many structures are defined in a program.
 */
void ExportCompositeDataTypes();

/**
 * Export all the enums defined in the program
 */
void ExportEnums();

}  // namespace quokka

#endif  // QUOKKA_COMPOSITE_DATA_H
