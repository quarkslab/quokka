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

#include "quokka/Segment.h"
#include <cstdint>
#include <stdexcept>

#include "quokka/FileMetadata.h"
#include "quokka/Util.h"
#include "quokka/Writer.h"

namespace quokka {

SegmentType GetSegmentType(uchar seg_type) {
  switch (seg_type) {
    case SEG_CODE:
      return SegmentType::SEGMENT_CODE;
    case SEG_DATA:
      return SegmentType::SEGMENT_DATA;
    case SEG_BSS:
      return SegmentType::SEGMENT_BSS;
    case SEG_NULL:
      return SegmentType::SEGMENT_NULL;
    case SEG_NORM:
      return SegmentType::SEGMENT_NORMAL;
    case SEG_XTRN:
      return SegmentType::SEGMENT_EXTERN;
    case SEG_ABSSYM:
      return SegmentType::SEG_ABSOLUTE_SYMBOLS;
    default:
      QLOGD << absl::StrFormat("Unknown segment type %u", seg_type);
      return SEGMENT_UNK;
  }
}

Segment::Segment(segment_t* segment) {
  qstring segment_name;
  if (get_segm_name(&segment_name, segment, GN_VISIBLE) != -1) {
    name = std::move(ConvertIdaString(segment_name));
  }

  start_addr = segment->start_ea;
  end_addr = segment->end_ea;

  // 1 - EXEC / 2-WRITE / 4-READ
  permissions = uint8(segment->perm);

#if IDA_SDK_VERSION >= 760
  if (segment->is_64bit()) {
    address_size = ADDR_64;
  } else if (segment->is_32bit()) {
    address_size = ADDR_32;
  } else {
    address_size = ADDR_UNK;
  }
#else

  if (segment->use64()) {
    address_size = ADDR_64;
  } else if (segment->use32()) {
    address_size = ADDR_32;
  } else {
    address_size = ADDR_UNK;
  }
#endif
  type = GetSegmentType(segment->type);

  file_offset = get_fileregion_offset(segment->start_ea);
}

const Segment& Segments::get_exact(sel_t sel, ea_t start, ea_t end) const {
  auto [first, last] = storage->bucket.equal_range(sel);

  // The iterator with filtering
  auto check_range = [&](const auto& pair) {
    return pair.second.start_addr == start && pair.second.end_addr == end;
  };
  auto it = std::ranges::find_if(first, last, check_range);

  // No element, throw exception
  if (it == last)
    throw std::out_of_range(
        absl::StrFormat("No matching Segment with sel=%d and range [0x%08x; "
                        "0x%08x] in the collection",
                        sel, start, end));

  assert(std::ranges::find_if(std::next(it), last, check_range) == last &&
         "Found multiple Segments with the same [sel, start, end]");

  return it->second;
}

const Segment& GetSegment(ea_t addr) {
  const Segments& segments = Segments::GetInstance();

  segment_t* ida_seg = getseg(addr);
  if (!ida_seg ||
      !segments.contains(ida_seg->sel, ida_seg->start_ea, ida_seg->end_ea)) {
    throw std::out_of_range(
        absl::StrFormat("Address 0x%x doesn't belong to any segment", addr));
  }

  const auto& segment =
      segments.get_exact(ida_seg->sel, ida_seg->start_ea, ida_seg->end_ea);
  assert(addr >= segment.start_addr && addr < segment.end_addr);

  return segment;
}

int ExportSegments() {
  Timer timer(absl::Now());
  QLOG_INFO << "Start to export segments";

  Segments& segments = Segments::GetInstance();

  segment_t* seg = get_first_seg();
  while (seg != nullptr) {
    // A HEADER segment is considered ephemeral even though instructions might
    // reference it. See https://github.com/quarkslab/quokka/issues/29
    if (seg->is_header_segm() ||
        (is_visible_segm(seg) && !is_ephemeral_segm(seg->start_ea))) {
      segments.emplace(seg->sel, seg);
    }

    seg = get_next_seg(seg->start_ea);
  }

  QLOG_INFO << absl::StrFormat("Segments exported (took: %.2fs)",
                               timer.ElapsedSeconds(absl::Now()));

  segments.Freeze();  // Freezing guarantees stable pointers

  return 0;
}
}  // namespace quokka