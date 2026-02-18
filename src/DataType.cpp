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

#include <cstddef>
#include <string>
#include <utility>

// clang-format off: Compatibility.h must come before ida headers
#include "quokka/Compatibility.h"
// clang-format on
#include <pro.h>
#include <bytes.hpp>
#include <typeinf.hpp>

#include "quokka/DataType.h"

#if IDA_SDK_VERSION < 850
#include "api_v8/DataType.cpp"
#else
#include "api_v9/DataType.cpp"
#endif

namespace quokka {

DataType GetDataType(flags_t flags) {
  if (is_byte(flags)) {
    return TYPE_B;
  } else if (is_word(flags)) {
    return TYPE_W;
  } else if (is_dword(flags)) {
    return TYPE_DW;
  } else if (is_qword(flags)) {
    return TYPE_QW;
  } else if (is_oword(flags)) {
    return TYPE_OW;
  } else if (is_float(flags)) {
    return TYPE_FLOAT;
  } else if (is_double(flags)) {
    return TYPE_DOUBLE;
  } else if (is_struct(flags)) {
    return TYPE_STRUCT;
  } else if (is_strlit(flags)) {
    return TYPE_ASCII;
  } else if (is_align(flags)) {
    return TYPE_ALIGN;
  }

  return TYPE_UNK;
}

DataType GetDataType(const tinfo_t& tinf) {
  auto int_from_tinfo_size = [&tinf]() {
    switch (tinf.get_unpadded_size()) {
      case 1:
        return TYPE_B;
      case 2:
        return TYPE_W;
      case 4:
        return TYPE_DW;
      case 8:
        return TYPE_QW;
      default:
        return TYPE_UNK;
    }
  };

  switch (tinf.get_realtype() & TYPE_BASE_MASK) {
    case BT_UNK:
      return TYPE_UNK;
    case BT_INT8:
      return TYPE_B;
    case BT_INT16:
      return TYPE_W;
    case BT_INT32:
      return TYPE_DW;
    case BT_INT64:
      return TYPE_QW;
    case BT_INT128:
      return TYPE_OW;
    case BT_INT:  // natural int. Query for size
      return int_from_tinfo_size();
    case BT_BOOL:
      switch (tinf.get_realtype() & TYPE_FLAGS_MASK) {
        case BTMT_DEFBOOL:  // size is model specific or unknown. Query for size
          return int_from_tinfo_size();
        case BTMT_BOOL1:
          return TYPE_B;
        case BTMT_BOOL2:  // BTMT_BOOL8
          return (inf_is_64bit() ? TYPE_QW : TYPE_W);
        case BTMT_BOOL4:
          return TYPE_DW;
        default:
          return TYPE_UNK;
      }
    case BT_FLOAT:
      switch (tinf.get_realtype() & TYPE_FLAGS_MASK) {
        case BTMT_FLOAT:
          return TYPE_FLOAT;
        case BTMT_DOUBLE:
          return TYPE_DOUBLE;
        default:  // Could actually be a long double or other len
          return TYPE_DOUBLE;
      }
    case BT_PTR:
      return TYPE_POINTER;
    case BT_ARRAY: {
      // Check if it is an array of char (aka a C string)
      array_type_data_t array_type;
      if (!tinf.get_array_details(&array_type))
        return TYPE_ARRAY;
      if (array_type.elem_type.is_char())
        return TYPE_ASCII;
      return TYPE_ARRAY;
    }
    case BT_COMPLEX:
      switch (tinf.get_realtype() & TYPE_FLAGS_MASK) {
        case BTMT_STRUCT:
          return TYPE_STRUCT;
        case BTMT_UNION:
          return TYPE_UNION;
        case BTMT_ENUM:
          return TYPE_ENUM;
        default:
          return TYPE_UNK;
      }
      // TODO TYPE_ALIGN is missing
    default:
      return TYPE_UNK;
  }
}

CompositeType::CompositeType(std::string&& n, tid_t id_, size_t sz)
    : name(std::forward<std::string>(n)), id(id_), size(sz) {}

CompositeTypeMember::CompositeTypeMember(ea_t o, std::string&& n, DataType t,
                                         asize_t sz)
    : offset(o), name(std::forward<std::string>(n)), type(t), size(sz) {};

}  // namespace quokka