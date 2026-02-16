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

#include <algorithm>
#include <cstdint>
#include <ranges>
#include <stdexcept>
#include <utility>

// clang-format off: Compatibility.h must come before ida headers
#include "Compatibility.h"
// clang-format on
#include <pro.h>
#include <loader.hpp>
#include <name.hpp>
#include <segment.hpp>

#include "absl/strings/str_format.h"

#include "Bucket.h"
#include "Logger.h"
#include "ProtoHelper.h"
#include "ProtoWrapper.h"
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
struct Segment : ProtoHelper {
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

  /**
   * Equality operator
   *
   * Two objects are considered equal when they perfectly overlap the address
   * range, they have the same permissions and same file offset.
   */
  bool operator==(const Segment& rhs) const {
    return start_addr == rhs.start_addr && end_addr == rhs.end_addr &&
           permissions == rhs.permissions && file_offset == rhs.file_offset;
  }

  bool operator!=(const Segment& rhs) const { return !(rhs == *this); }

  /**
   * Hash implementation of the object using absl::Hash
   * @tparam H Hash
   * @param h Hash value
   * @param m Segment object
   * @return An hash value for the object
   */
  template <typename H>
  friend H AbslHashValue(H h, const Segment& m) {
    return H::combine(std::move(h), m.start_addr, m.end_addr, m.permissions,
                      m.file_offset);
  }
};

/**
 * ---------------------------------------------
 * quokka::Segments
 * ---------------------------------------------
 * MultiMap-like collection of segments that stores them like {segment_id ->
 * Segment}. Ida being Ida, we cannot trust the `sel_t sel` to be unique per
 * segment. Despite being written in the documentation that it should be unique,
 * there are plenty of counter-examples, even in simple elf x86 binaries. This
 * is why we have to rely on multimaps instead of a cleaner approach with maps.
 */
class Segments final : public MultiMapBucket<sel_t, Segment> {
 private:
  explicit Segments() = default;

 public:
  using MultiMapBucket<sel_t, Segment>::MultiMapBucket;

  /**
   * Return the instance of the `Segments` class.
   * Used for the singleton pattern.
   * @return `Segments`
   */
  static Segments& GetInstance() {
    static Segments instance;
    return instance;
  }

  Segments(Segments const&) = delete;
  void operator=(Segments const&) = delete;
  Segments(Segments&&) = delete;
  void operator=(Segments&&) = delete;

  /**
   * Overloaded method to check if there is a Segment with the provided ida
   * selector (sel_t) and the provided address range
   *
   * @param sel the segment selector
   * @param start the starting address of the segment
   * @param end the ending address of the segment
   * @return true if there is such an element, otherwise false
   */
  bool contains(const sel_t sel, const ea_t start, const ea_t end) const {
    auto [first, last] = storage->bucket.equal_range(sel);
    return std::any_of(first, last, [&](const auto& pair) {
      return pair.second.start_addr == start && pair.second.end_addr == end;
    });
  }

  /**
   * Search a Segment in the collection with the provided ida selector (sel_t)
   * and address range.
   *
   * @param sel the segment selector
   * @param start the starting address of the segment
   * @param end the ending address of the segment
   * @return A const reference to the requested Segment
   */
  const Segment& get_exact(sel_t sel, ea_t start, ea_t end) const;
};

/**
 * Retrieve the Segment object from an address.
 *
 * @param addr the address for which the Segment is requested
 * @return The segment object
 * @throws out_of_range if the address doesn't belong to any segment
 */
const Segment& GetSegment(ea_t addr);

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
 * @return 0 if succeded otherwise an error code
 */
int ExportSegments();

}  // namespace quokka
#endif  // QUOKKA_SEGMENT_H
