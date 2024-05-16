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

#include <cstdint>
#include <stdexcept>

// clang-format off: Compatibility.h must come before ida headers
#include "quokka/Compatibility.h"
// clang-format on
#include <pro.h>
#include <bytes.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <typeinf.hpp>

#include "absl/strings/str_format.h"

#include "quokka/Data.h"
#include "quokka/DataType.h"
#include "quokka/Segment.h"

#if IDA_SDK_VERSION < 850
#include "api_v8/Data.cpp"
#else
#include "api_v9/Data.cpp"
#endif

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

Data MakeData(ea_t addr, uint64_t size) {
  DataType data_type;
  tinfo_t tinf;
  // Try to obtain the tinfo descriptor
  if (get_tinfo(&tinf, addr))
    data_type = GetDataType(tinf);
  else  // No tinfo, fall back on the flags
    data_type = GetDataType(get_flags(addr));

  const Segments& segments = Segments::GetInstance();

  segment_t* ida_seg = getseg(addr);
  const auto& it = segments.get_by_id(ida_seg->sel);
  if (it == segments.end()) {
    QLOGE << absl::StrFormat(
        "Data at address 0x%x doesn't belong to any segment", addr);
    throw new std::runtime_error(absl::StrFormat(
        "Data at address 0x%x doesn't belong to any segment", addr));
  }

  Data data(addr, data_type, size, *it);

  const CompositeTypes& composite_types = CompositeTypes::GetInstance();

  // Get the pointed type
  switch (data_type) {
    case TYPE_UNION:
    case TYPE_STRUCT: {
      const auto& it = composite_types.get_by_id(get_strid(addr));

      if (it == composite_types.end()) {
        QLOGE << absl::StrFormat(
            "Data at address 0x%x is of type composite but the "
            "associated composite type was not exported",
            addr);
        // Change the type to TYPE_UNK to avoid breaking the protobuf
        data.type = TYPE_UNK;
      } else {
        data.SetReferenceType(*it);
      }
      break;
    }
    case TYPE_ENUM:
      // TODO
      break;
    default:
      break;
  }

  return data;
}

}  // namespace quokka
