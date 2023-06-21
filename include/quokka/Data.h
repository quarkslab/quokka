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

#include <cassert>
#include <cstdint>

#include <bytes.hpp>
#include <enum.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <struct.hpp>

#include "absl/hash/hash.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"

#include "Logger.h"       // Kept for logger
#include "ProtoHelper.h"  // Kept for ProtoHelper
#include "Util.h"
#include "Windows.h"

#include "ProtoWrapper.h"

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
  int64 value = 0;   ///< Value of the field

  std::weak_ptr<Structure> parent;  ///< Back pointer towards the parent

  /**
   * Constructor for struct member
   *
   * @param ida_member A ida structure of the struct member
   */
  explicit StructureMember(member_t* ida_member) {
    offset = ida_member->soff;
    name = ConvertIdaString(get_member_name(ida_member->id));
    type = GetDataType(ida_member->flag);
  }

  /**
   * Constructor for enum member
   *
   * @param cid Enum id
   * @param member_value Member value
   */
  explicit StructureMember(const_t cid, uval_t member_value) {
    qstring member_name;
    get_enum_member_name(&member_name, cid);
    offset = ea_t(cid);
    name = ConvertIdaString(member_name);
    // TODO(dm) IDA reports member value as a *positive* integer
    value = int64_t(member_value);
    type = TYPE_B;
  }
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
 * Export the struct members
 *
 * Iterate through the ida-struct member and export each of them.
 *
 * @param structure A pointer to the `Structure` object
 * @param ida_struc A pointer to the IDA struct
 */
void ExportStructMembers(std::shared_ptr<Structure>& structure,
                         struc_t* ida_struc);

/**
 * Export an IDA-struct or an union
 *
 * Completely export a structure, including the references and comments.
 *
 * @see ExportStructureReference
 * @see GetStructureComment
 *
 * @param ida_struct A pointer to the IDA struct
 * @return Created structure
 */
std::shared_ptr<Structure> ExportStructure(struc_t* ida_struct);

/**
 * Export all the structures defined in the program
 *
 * Will populate the `Structures` container.
 *
 * @param structure_list The structures container
 */
void ExportStructures(Structures& structure_list);

/**
 * Export the enum members of enumeration.
 *
 * @note Use a visitor pattern because that's the IDA way of iterating
 * through the enum members ..
 *
 * @param enumeration A pointer to the quokka::Structure
 * @param ida_enum Ida-enum
 * @param enum_idx Index of the enumeration (@see ExportEnum)
 */
void ExportEnumMembers(std::shared_ptr<Structure>& enumeration, enum_t ida_enum,
                       size_t enum_idx);

/**
 * Export an enum
 *
 * Ghost enum don't have an index, so we use the position in the `Structures`
 * for all of enumeration as an index. It will be used for attaching comments
 * and references.
 *
 * @param ida_enum Ida-enum
 * @param enum_idx Index of the enumeration (position in the Structures
 *                 container)
 * @return Created structure
 */
std::shared_ptr<Structure> ExportEnum(enum_t ida_enum, size_t enum_idx);

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
