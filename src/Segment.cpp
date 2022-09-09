// Copyright 2022 Quarkslab
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

#include "quokka/FileMetadata.h"
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

int ExportSegments(quokka::Quokka* proto) {
  Timer timer(absl::Now());
  QLOG_INFO << "Start to export segments";

  std::vector<Segment> segments;
  segments.reserve(get_segm_qty());

  segment_t* seg = get_first_seg();
  while (seg != nullptr) {
    if (is_visible_segm(seg) && not is_ephemeral_segm(seg->start_ea)) {
      segments.emplace_back(seg);
    }

    seg = get_next_seg(seg->start_ea);
  }

  WriteSegments(proto, segments);
  QLOG_INFO << absl::StrFormat("Segments exported (took %f)",
                               timer.ElapsedMilliSeconds(absl::Now()));

  return eOk;
}
}  // namespace quokka