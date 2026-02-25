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

#include <cassert>
#include <cstdint>
#include <stdexcept>

// clang-format off: Compatibility.h must come before ida headers
#include "quokka/Compatibility.h"
// clang-format on
#include <pro.h>
#include <bytes.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <typeinf.hpp>

#include "absl/strings/str_format.h"

#include "quokka/Data.h"
#include "quokka/DataType.h"
#include "quokka/Segment.h"

// #if IDA_SDK_VERSION < 850
// #include "api_v8/Data.cpp"
// #else
// #include "api_v9/Data.cpp"
// #endif

namespace quokka {

bool Data::HasName(bool any_name = false) const {
  if (any_name) {
    return has_any_name(get_flags(this->addr));
  } else {
    return has_user_name(get_flags(this->addr));
  }
}

void Data::SetName() {
  qstring ida_name = get_name(this->addr, GN_NOT_DUMMY);
  if (!ida_name.empty()) {
    this->name = ConvertIdaString(ida_name);
  }
}

bool Data::IsInitialized() const {
  return has_value(get_full_flags(this->addr));
}

Data Data::Make(ea_t addr, uint32_t size) {
  BaseType data_type;
  tinfo_t tinf;
  tid_t tid = BADADDR;

  if (has_ti(addr)) {  // Try to obtain the tinfo descriptor
    if (!get_tinfo(&tinf, addr))
      assert(false);

    // Resolve the typedef/typeref to final type
    if (tinf.is_typeref() || tinf.is_typedef()) {
      uint32_t final_ordinal = tinf.get_final_ordinal();
      assert(final_ordinal > 0 &&
             "Got a typedef/typeref type without a final ordinal");
      if (!tinf.get_numbered_type(final_ordinal))
        assert(false && "Cannot retrieve the final ordinal tinfo_t");
    }
    tid = tinf.get_tid();
    data_type = GetBaseType(tinf);
  } else {  // No tinfo, fall back on the flags
    data_type = GetBaseType(get_flags(addr));
  }

  // TYPE_POINTER => !tinfo.empty()
  assert(data_type != TYPE_POINTER || !tinf.empty());
  // TYPE_ARRAY => !tinfo.empty()
  assert(data_type != TYPE_POINTER || !tinf.empty());

  const Segments& segments = Segments::GetInstance();

  segment_t* ida_seg = getseg(addr);
  if (!ida_seg ||
      !segments.contains(ida_seg->sel, ida_seg->start_ea, ida_seg->end_ea)) {
    throw std::runtime_error(absl::StrFormat(
        "Data at address 0x%x doesn't belong to any segment", addr));
  }

  // Address must always be inside the boundaries of the segment
  const auto& segment =
      segments.get_exact(ida_seg->sel, ida_seg->start_ea, ida_seg->end_ea);
  assert(addr >= segment.start_addr && addr < segment.end_addr);

  Data data(addr, data_type, size, get_fileregion_offset(addr), &segment);

  const DataTypes& data_types = DataTypes::GetInstance();

  if (data_type == TYPE_POINTER) {
    data.target_tuid = ExportPointer(tinf);

  } else if (data_type == TYPE_ARRAY) {
    data.target_tuid = ExportArray(tinf);

  } else if (data_type == TYPE_STR) {  // String literal, No tinfo_t available
    if (guess_tinfo(&tinf, addr) > 0) {
      data.target_tuid = ExportArray(tinf);
    } else {
      QLOGE << absl::StrFormat(
          "Couldn't recover the tinfo_t from the string literal at address "
          "0x%08llx. Marking it as TYPE_UNK",
          addr);
      data.base_type = TYPE_UNK;
    }

  } else if (data_type == TYPE_ALIGN) {
    data.base_type = TYPE_UNK;  // This is useless data. Mark it as unknown

  } else if (data_type == TYPE_UNK) {  // Most likely a enum/struct/union
    // Sometimes IDA fails at giving us the correct tinfo_t. Try to recover it
    // through unconventional means
    if (tid == BADADDR) {
      tid = get_strid(addr);
      if (tid == BADADDR) {
        QLOGE << absl::StrFormat(
            "Cannot correctly identify the type of data at address 0x%08llx. "
            "Marking it as TYPE_UNK",
            addr);
        data.base_type = TYPE_UNK;
        goto data_exported;  // Skip to the end
      }
    }

    // Failing to resolve the data type at this point is really bad
    // Note: here tid is guaranteed to be valid but tinf might not be
    const auto& it = data_types.find_by_tuid(GetTypeUid(tid));

    if (it == data_types.end()) {
      QLOGE << absl::StrFormat(
          "Data at address 0x%x is of type composite but the "
          "associated composite type was not exported",
          addr);
      // Change the type to TYPE_UNK to avoid breaking the protobuf
      data.base_type = TYPE_UNK;
    } else {
      data.target_tuid = it->first;
    }
  }

data_exported:
  // Increment the ref-counter of the segment
  segment.ref_count++;

  return data;
}

}  // namespace quokka
