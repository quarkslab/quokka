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

#include <cstdint>
#include <memory>
#include <string>

#include "Compatibility.h"

#include <bytes.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <typeinf.hpp>

#include "absl/hash/hash.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"

#include "Logger.h"       // Kept for logger
#include "ProtoHelper.h"  // Kept for ProtoHelper
#include "ProtoWrapper.h"
#include "Util.h"
#include "Windows.h"

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
};

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
  std::string content;  ///< If applicable, the string value of the data
  std::string name;     ///< If applicable, the name of the data

 public:
  ea_t addr = BADADDR;            ///< Address attached to the data
  DataType data_type = TYPE_UNK;  ///< Data type
  uint64_t size;  ///< Size of the data (not always redundant for certain types)

  /**
   * Constructor
   *
   * @param addr_ Address where the data has been found
   * @param data_type_ Type of the data
   * @param size_ Size of the data
   */
  Data(ea_t addr_, DataType data_type_, uint64_t size_)
      : addr(addr_), data_type(data_type_), size(size_) {
    if (HasName(false)) {
      this->SetName();
    }
  }

  /**
   * Has the data a variable size ?
   *
   * @return True for ASCII, STRUCT, ALIGN and UNKNOWN. False otherwise
   */
  [[nodiscard]] bool HasVariableSize() const;

  /**
   * Has the data a name ?
   *
   * Answers using the flags associated to the address.
   *
   * @param any_name Check any name or juste the user_name
   */
  [[nodiscard]] bool HasName(bool any_name) const;

  /**
   * Set the name of the data
   */
  void SetName();

  /**
   * Accessor for the name
   * @return A string_view of the name
   */
  [[nodiscard]] absl::string_view GetName() const { return name; }

  /**
   * Tells if the data referenced is initialized or not (like in .bss segment)
   * using the flags associated to the address.
   *
   * @return True if the data is initialized, False otherwise.
   */
  [[nodiscard]] bool IsInitialized() const;

  /**
   * Equality operator
   */
  bool operator==(const Data& rhs) const {
    return content == rhs.content && name == rhs.name && addr == rhs.addr &&
           data_type == rhs.data_type && size == rhs.size;
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
    return H::combine(std::move(h), m.name, m.addr, m.data_type, m.size,
                      m.content);
  }
};

/**
 * Return the type associated to the data.
 *
 * @param flags Flags of the data address
 * @return A data type
 */
DataType GetDataType(flags_t flags);

/**
 * Return the type associated to the data.
 *
 * @param tinf IDA Type info object
 * @return A data type
 */
DataType GetDataType(const tinfo_t& tinf);

class Structure;

/**
 * -----------------------------------------------------------------------------
 * quokka::StructureMember
 * -----------------------------------------------------------------------------
 * A member of a structure (either a struct or an enum).
 */
struct StructureMember : public ProtoHelper {
  ea_t offset;       ///< Field offset (IDA internal)
  std::string name;  ///< Name of the field
  DataType type;     ///< Type of the value
  asize_t size = 0;  ///< Size of the field
  uint64 value = 0;  ///< Value of the field

  std::weak_ptr<Structure> parent;  ///< Back pointer towards the parent

  StructureMember(const StructureMember& obj)
      : offset(obj.offset),
        name(obj.name),
        type(obj.type),
        size(obj.size),
        value(obj.value),
        parent(obj.parent) {}

  StructureMember(StructureMember&& obj)
      : offset(obj.offset),
        name(std::move(obj.name)),
        type(obj.type),
        size(obj.size),
        value(obj.value),
        parent(std::move(obj.parent)) {}

  /**
   * Constructor for struct member
   *
   * @param _offset Field offset (IDA internal)
   * @param _name Name of the field
   * @param _type Type of the value
   * @param _size Size of the field
   * @param _value Value of the field
   */
  explicit StructureMember(ea_t _offset, const qstring& _name, DataType _type,
                           asize_t _size = 0, uint64_t _value = 0)
      : offset(_offset),
        name(ConvertIdaString(_name)),
        type(_type),
        size(_size),
        value(_value) {}
};

/**
 * Type of structures exported
 */
enum StructureType : short {
  STRUCT_UNK = 0,
  STRUCT_ENUM,
  STRUCT_STRUCT,
  STRUCT_UNION,
};

/**
 * -----------------------------------------------------------------------------
 * quokka::Structure
 * -----------------------------------------------------------------------------
 * A class representing every structure component in IDA.
 *
 * Correctly handles enums, structs, and unions and unify their
 * representation for the export.
 */
class Structure : public ProtoHelper {
 public:
  std::string name;                 ///< Structure name
  StructureType type = STRUCT_UNK;  ///< Structure type
  tid_t addr;   ///< Type id (IDA internal) - is actually an address
  size_t size;  ///< Structure size
  bool has_variable_size = false;  ///< Has a variable size

  std::vector<std::shared_ptr<StructureMember>> members;  ///< Members list
};

/**
 * -----------------------------------------------------------------------------
 * quokka::Structures
 * -----------------------------------------------------------------------------
 * Container for all the structures in the program.
 *
 * Use a singleton pattern and act like a std::vector .
 */
class Structures {
 private:
  std::vector<std::shared_ptr<Structure>> structures_;  ///< Internal list

  explicit Structures() = default;  ///< Private constructor

 public:
  using iterator = std::vector<std::shared_ptr<Structure>>::iterator;
  using const_iterator =
      std::vector<std::shared_ptr<Structure>>::const_iterator;

  /**
   * Return the instance of the `Structures` class.
   * Used for the singleton pattern.
   * @return `Structures`
   */
  static Structures& GetInstance() {
    static Structures instance;
    return instance;
  }

  /**
   * Deleted constructors for singleton pattern
   */
  Structures(Structures const&) = delete;
  void operator=(Structures const&) = delete;

  /**
   * Proxy for the std::vector emplace method
   * @tparam Args Arguments to be forwarded
   * @param args Arguments of the constructor
   * @return A shared pointer to Structure
   */
  template <typename... Args>
  std::shared_ptr<Structure>& emplace_back(Args&&... args) {
    return structures_.emplace_back(std::forward<Args>(args)...);
  }

  /**
   * Proxy for the std::vector::size()
   * @return Size of the container
   */
  [[nodiscard]] std::size_t size() const { return structures_.size(); }

  /**
   * Proxy iterators
   */
  iterator begin() { return structures_.begin(); }
  iterator end() { return structures_.end(); }
  [[nodiscard]] const_iterator begin() const { return structures_.begin(); }
  [[nodiscard]] const_iterator end() const { return structures_.end(); }
};

/**
 * Export all the structures defined in the program
 *
 * Will populate the `Structures` container.
 *
 * @param structure_list The structures container
 */
void ExportStructures(Structures& structure_list);

/**
 * Export all the enums defined in the program
 *
 * @see ExportStructures
 *
 * @param structure_list Structures container
 */
void ExportEnums(Structures& structure_list);

/**
 * Export and write the structures and enumerations of the program.
 *
 * This is usually fast because not many structures are defined in a program.
 *
 * @param proto A pointer to the main protobuf object.
 */
void ExportEnumAndStructures(quokka::Quokka* proto);

}  // namespace quokka

#endif  // QUOKKA_DATA_H
