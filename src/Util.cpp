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
#include <string>
#include <string_view>

// clang-format off: Compatibility.h must come before ida headers
#include "quokka/Compatibility.h"
// clang-format on
#include <pro.h>
#include <bytes.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <typeinf.hpp>

#include "absl/strings/str_cat.h"

#include "quokka/Util.h"

namespace quokka {

std::string ConvertIdaString(const qstring& ida_string) {
  return {ida_string.c_str(), ida_string.length()};
}

std::string ReplaceFileExtension(std::string_view path,
                                 std::string_view new_extension) {
  auto pos = path.find_last_of('.');
  return absl::StrCat(path.substr(0, pos), new_extension);
}

std::string GetName(ea_t address, bool mangled) {
  flags_t flags = get_flags(address);
  if (!mangled && has_user_name(flags)) {
    return ConvertIdaString(get_short_name(address));
  }

  return ConvertIdaString(get_name(address, GN_VISIBLE));
}

processor_t* GetProcessor() {
#if IDA_SDK_VERSION >= 750
  return get_ph();
#else
  return &ph;
#endif
}

std::string GetMnemonic(const insn_t& instruction) {
#if IDA_SDK_VERSION >= 750
  processor_t* processor = get_ph();
  return {instruction.get_canon_mnem(*processor)};
#else
  return {instruction.get_canon_mnem()};
#endif
}

void ResolveTypedef(tinfo_t& tif) {
  if (tif.is_typedef() || tif.is_typeref()) {
    uint32_t final_ordinal = tif.get_final_ordinal();
    assert(final_ordinal > 0 && "Typedef/typeref doesn't have a final ordinal");
    if (!tif.get_numbered_type(final_ordinal))
      assert(false && "Cannot get type info for resolved ordinal");
  }
}

}  // namespace quokka