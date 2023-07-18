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
 * @file Segment.h
 * Management of segments
 */

#ifndef QUOKKA_SEGMENT_H
#define QUOKKA_SEGMENT_H

#include "Compatibility.h"
#include <loader.hpp>
#include <name.hpp>
#include <segment.hpp>

#include "absl/strings/str_format.h"

#include "Logger.h"
#include "ProtoWrapper.h"
#include "Util.h"
#include "Windows.h"

namespace quokka {

enum AddressSize : short;

/**
 * Segment types
 */
enum SegmentType : short {
  SEGMENT_UNK = 0,
  SEGMENT_CODE,
  SEGMENT_DATA,
  SEGMENT_BSS,
  SEGMENT_NULL,
  SEGMENT_EXTERN,
  SEGMENT_NORMAL,
  SEG_ABSOLUTE_SYMBOLS,
};

/**
 * ---------------------------------------------
 * quokka::Segment
 * ---------------------------------------------
 * Represents a segment
 */
struct Segment {
  std::string name;  ///< Name of the segment

  ea_t start_addr;  ///< Start address
  ea_t end_addr;    ///< End address

  uint8 permissions = 0;  ///< Segment permissions

  AddressSize address_size;        ///< Address size for the segment
  SegmentType type = SEGMENT_UNK;  ///< Segment type

  /**
   * File offset of the segment, < 0 means no segment
   */
  int64 file_offset;

  /**
   * Constructor
   * @param segment IDA-segment
   */
  explicit Segment(segment_t* segment);
};

/**
 * Retrieve the type of a segment
 *
 * @param seg_type IDA segment type
 * @return
 */
SegmentType GetSegmentType(uchar seg_type);

/**
 * Export all segments
 *
 * Iterate through every segment defined in IDA and exports them.
 *
 * @param proto Main protobuf
 * @return
 */
int ExportSegments(quokka::Quokka* proto);

}  // namespace quokka
#endif  // QUOKKA_SEGMENT_H
