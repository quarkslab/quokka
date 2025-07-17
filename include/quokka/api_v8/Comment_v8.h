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
 * @file Comment_v9.h
 * Management of comments specific for the old IDA API (v8).
 */

#ifndef QUOKKA_COMMENT_V8_H
#define QUOKKA_COMMENT_V8_H

#include <memory>

#include "../Compatibility.h"

#include <enum.hpp>

#include "../Data.h"

#if IDA_SDK_VERSION >= 850
#error "Comment_v8.h can only be used with IDA SDK < 8.5"
#endif

namespace quokka {

/**
 * Retrieve the comments associated to the members of a structure
 *
 * @param member_p Pointer to the `quokka::StructureMember`
 * @param member Pointer to the `tid_t` (IDA)
 */
void GetStructureMemberComment_v8(std::shared_ptr<StructureMember> member_p,
                                  tid_t member);

/**
 * Retrieve the comments associated to the structure.
 *
 * @warning Does not retrieve the comments associated to the struct member
 *
 * @param structure A quokka::Structure pointer
 * @param ida_struct The ida struct
 */
void GetStructureComment_v8(std::shared_ptr<Structure> structure,
                            tid_t ida_struct);

/**
 * Retrieve the comments associated to the member of an enumeration.
 *
 * @param member_p Pointer to the `quokka::StructureMember`
 * @param member Pointer to the `const_t` (IDA)
 */
void GetEnumMemberComment_v8(std::shared_ptr<StructureMember> member_p,
                             const_t member);

/**
 * Retrieve the comments associated to the enum.
 *
 * @warning Does not retrieve the comments associated to the enum member
 *
 * @param structure A quokka::Structure pointer
 * @param ida_enum The ida enum
 */
void GetEnumComment_v8(std::shared_ptr<Structure> structure, enum_t ida_enum);

}  // namespace quokka

#endif  // QUOKKA_COMMENT_V8_H
