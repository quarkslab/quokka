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
#include <stdexcept>
#include <string>
#include <utility>

// clang-format off: Compatibility.h must come before ida headers
#include "quokka/Compatibility.h"
// clang-format on
#include <pro.h>
#include <bytes.hpp>
#include <typeinf.hpp>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/str_format.h"

#include "quokka/DataType.h"

#if IDA_SDK_VERSION < 850
#include "api_v8/DataType.cpp"
#else
#include "api_v9/DataType.cpp"
#endif

namespace quokka {

BaseType GetBaseType(flags_t flags) {
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
  } else if (is_strlit(flags)) {
    return TYPE_STR;
  } else if (is_align(flags)) {
    return TYPE_ALIGN;
  }
  // TYPE_VOID can never be identified through flags
  return TYPE_UNK;
}

BaseType GetBaseType(const tinfo_t& tinf) {
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
    case BTF_VOID:
      return TYPE_VOID;
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
      return TYPE_ARRAY;
    }
    default:
      return TYPE_UNK;
  }
}

static std::string MakeCanonicalKey(const tinfo_t& tif) {
  qtype type_bytes, field_bytes;
  if (!tif.serialize(&type_bytes, &field_bytes, nullptr)) {
    qstring type_str;
    tif.print(&type_str);
    throw std::runtime_error(
        absl::StrFormat("Cannot serialize type %s", type_str.c_str()));
  }

  std::string key;
  key.reserve(type_bytes.size() + 1 + field_bytes.size());
  key.append((const char*)type_bytes.c_str(), type_bytes.size());
  key.push_back('\0');
  key.append((const char*)field_bytes.c_str(), field_bytes.size());
  return key;
}

type_uid_t GetTypeUid(const tinfo_t& tif) {
  static absl::flat_hash_map<std::string, tid_t> key_to_synth;
  static tid_t next_synth_id = 0;

  tid_t tid = tif.get_tid();
  if (tid != BADADDR)
    return {true, tid};  // Keep consistency with IDA

  // No tid, use serialization and internal mapping
  auto key = MakeCanonicalKey(tif);

  auto it = key_to_synth.find(key);
  if (it != key_to_synth.end())
    return {false, it->second};

  tid_t sid = next_synth_id++;
  key_to_synth[key] = sid;
  return {false, sid};
}

type_uid_t GetTypeUid(const tid_t& tid) {
  if (tid == BADADDR)
    throw std::invalid_argument(
        "Cannot build a valid type_uid_t from an invalid tid_t");
  return {true, tid};
}

CompositeType::CompositeType(std::string&& n, tid_t id_, size_t sz)
    : name(std::forward<std::string>(n)), id(id_), size(sz) {}

CompositeTypeMember::CompositeTypeMember(ea_t o, std::string&& n, BaseType t,
                                         asize_t sz)
    : offset(o), name(std::forward<std::string>(n)), type(t), size(sz) {};

}  // namespace quokka