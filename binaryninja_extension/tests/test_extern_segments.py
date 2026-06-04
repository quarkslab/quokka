"""Tests for the SEGMENT_EXTERN pseudo-segment synthesis.

Pure segment math: runs against the conftest BinaryNinja stub.
"""

from __future__ import annotations

import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT))

from bn_quokka.quokka_pb2 import Quokka  # noqa: E402
from bn_quokka.util import (  # noqa: E402
    SegmentInfo,
    build_extern_segments,
    find_segment_index,
)

SEGMENT_EXTERN = int(Quokka.Segment.SEGMENT_EXTERN)


def seg(start: int, size: int, name: str = "seg") -> SegmentInfo:
    return SegmentInfo(name=name, start_offset=start, size=size)


def test_no_addresses_yields_nothing():
    assert build_extern_segments([], [seg(0x1000, 0x100)], 8) == []


def test_mapped_addresses_yield_nothing():
    segments = [seg(0x1000, 0x100)]
    assert build_extern_segments([0x1000, 0x10FF], segments, 8) == []


def test_single_cluster_after_last_segment():
    segments = [seg(0x1000, 0x1000)]
    result = build_extern_segments([0x5000, 0x5008, 0x5008], segments, 8)

    assert len(result) == 1
    extern = result[0]
    assert extern.name == "extern"
    assert extern.start_offset == 0x5000
    assert extern.size == 0x5008 + 8 - 0x5000
    assert extern.proto_seg_type == SEGMENT_EXTERN
    assert extern.file_offset == -1
    assert extern.data_size == 0


def test_clusters_split_by_existing_segment():
    segments = [seg(0x2000, 0x1000)]
    result = build_extern_segments([0x1000, 0x1008, 0x4000], segments, 8)

    assert [extern.start_offset for extern in result] == [0x1000, 0x4000]
    assert [extern.name for extern in result] == ["extern", "extern_1"]


def test_extern_segment_clamped_to_next_segment():
    segments = [seg(0x2000, 0x1000)]
    result = build_extern_segments([0x1FFC], segments, 8)

    assert len(result) == 1
    extern = result[0]
    assert extern.start_offset == 0x1FFC
    assert extern.start_offset + extern.size <= 0x2000
    assert extern.size >= 1


def test_extern_addresses_resolve_after_merge():
    segments = [seg(0x1000, 0x1000), seg(0x3000, 0x1000)]
    externs = build_extern_segments([0x2000, 0x8000], segments, 8)

    merged = sorted(segments + externs, key=lambda item: item.start_offset)
    for addr in (0x2000, 0x8000):
        idx = find_segment_index(merged, addr)
        assert idx >= 0
        assert merged[idx].proto_seg_type == SEGMENT_EXTERN
    # Real segments still resolve to themselves.
    assert merged[find_segment_index(merged, 0x1000)].name == "seg"
