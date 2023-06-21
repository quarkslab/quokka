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
 * @file Compatibility.h
 * Compatibility file
 *
 * Proxy methods for IDA when some functions in the SDK changes.
 */

#ifndef QUOKKA_COMPATIBILITY_H
#define QUOKKA_COMPATIBILITY_H

#include <idp.hpp>
#include <ua.hpp>

#include "Windows.h"

/**
 * Get the processor "ph" variable
 *
 * New for IDA SDK 7.5
 *
 * @return A pointer to the processor object
 */
processor_t* GetProcessor();

/**
 * Retrieve the mnemonic name
 *
 * New in IDA 7.5
 *
 * @param instruction IDA instruction structure
 * @return A string containing the mnemonic
 */
std::string GetMnemonic(const insn_t& instruction);

#endif  // QUOKKA_COMPATIBILITY_H
