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

#include "quokka/Util.h"

namespace quokka {

std::string ConvertIdaString(const qstring& ida_string) {
  return {ida_string.c_str(), ida_string.length()};
}

std::string ReplaceFileExtension(absl::string_view path,
                                 absl::string_view new_extension) {
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

bool StrToBoolean(const std::string& option) { return !option.empty(); }

}  // namespace quokka