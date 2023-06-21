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
 * @file ProtoHelper.h
 * Proto helper method
 */
#ifndef QUOKKA_PROTOHELPER_H
#define QUOKKA_PROTOHELPER_H

#include <cstdint>

namespace quokka {

/**
 * ---------------------------------------------
 * quokka::ProtoHelper
 * ---------------------------------------------
 * Helper for deduplication purposes
 *
 * @see quokka::BucketNew
 */
class ProtoHelper {
 public:
  uint32_t ref_count = 0;  ///< Ref counter
  int proto_index = 0;     ///< Index in the protobuf file
};

}  // namespace quokka
#endif  // QUOKKA_PROTOHELPER_H
