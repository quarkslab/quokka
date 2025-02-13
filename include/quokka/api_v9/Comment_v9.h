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
 * Management of comments specific for the new IDA API (v9).
 */

#ifndef QUOKKA_COMMENT_V9_H
#define QUOKKA_COMMENT_V9_H

#include <memory>

#include "../Compatibility.h"

#include <typeinf.hpp>

#include "../Data.h"

#if IDA_SDK_VERSION < 900
#error "Comment_v9.h can only be used with IDA SDK >= 9.0"
#endif

namespace quokka {

/**
 * Retrieve the comments associated to the members of a structure
 *
 * @param member_p Pointer to the `quokka::StructureMember`
 * @param udm IDA user-defined member
 */
void GetStructureMemberComment_v9(std::shared_ptr<StructureMember> member_p,
                                  const udm_t& udm);

/**
 * Retrieve the comments associated to the structure.
 *
 * @warning Does not retrieve the comments associated to the struct member
 *
 * @param structure A quokka::Structure pointer
 * @param struct_tif The IDA struct type info
 */
void GetStructureComment_v9(std::shared_ptr<Structure> structure,
                            const tinfo_t& struct_tif);

/**
 * Retrieve the comments associated to the member of an enumeration.
 *
 * @param member_p Pointer to the `quokka::StructureMember`
 * @param edm Enum member IDA object
 */
void GetEnumMemberComment_v9(std::shared_ptr<StructureMember> member_p,
                             const edm_t& edm);

/**
 * Retrieve the comments associated to the enum.
 *
 * @warning Does not retrieve the comments associated to the enum member
 *
 * @param structure A quokka::Structure pointer
 * @param enum_tif Ida enum type info
 */
void GetEnumComment_v9(std::shared_ptr<Structure> structure,
                       const tinfo_t& enum_tif);

}  // namespace quokka

#endif  // QUOKKA_COMMENT_V9_H
