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
 * @file Version.h
 * Version file
 */

#ifndef QUOKKA_VERSION_H
#define QUOKKA_VERSION_H

#include <string_view>

namespace quokka {

/**
 * Get the version string (format: "MAJOR.MINOR.PATCH")
 * @return A formatted version string
 */
constexpr std::string_view GetVersion();

/**
 * Get version major
 * @return Version major
 */
constexpr unsigned int GetVersionMajor();

/**
 * Get version minor
 * @return Version minor
 */
constexpr unsigned int GetVersionMinor();

/**
 * Get version patch
 * @return Version patch
 */
constexpr unsigned int GetVersionPatch();

}  // namespace quokka

#endif  // QUOKKA_VERSION_H
