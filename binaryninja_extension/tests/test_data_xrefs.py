"""Tests for the indexed data cross-reference population."""

from __future__ import annotations

import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT))

from bn_quokka.exporters.binary import (  # noqa: E402
    _build_reference_index,
    _populate_data_xrefs,
    _refs_in_range,
)
from bn_quokka.quokka_pb2 import Quokka  # noqa: E402


def make_builder(references: list[tuple[int | None, int | None]]) -> Quokka:
    builder = Quokka()
    for source, destination in references:
        reference = builder.references.add()
        if source is not None:
            reference.source.address = source
        if destination is not None:
            reference.destination.address = destination
    return builder


def test_index_splits_sources_and_destinations():
    builder = make_builder([(0x100, 0x200), (None, 0x300), (0x400, None)])

    destinations, sources = _build_reference_index(builder)

    assert destinations == [(0x200, 0), (0x300, 1)]
    assert sources == [(0x100, 0), (0x400, 2)]


def test_index_skips_type_references():
    builder = Quokka()
    reference = builder.references.add()
    reference.source.data_type_identifier.type_index = 9
    reference.destination.data_type_identifier.type_index = 10

    destinations, sources = _build_reference_index(builder)

    assert destinations == []
    assert sources == []


def test_refs_in_range_is_half_open():
    index = [(0x100, 0), (0x104, 1), (0x108, 2)]

    assert _refs_in_range(index, 0x100, 0x108) == [0, 1]
    assert _refs_in_range(index, 0x108, 0x110) == [2]
    assert _refs_in_range(index, 0x0, 0x100) == []


def test_populate_data_xrefs_matches_addresses_in_record():
    builder = make_builder(
        [
            (0x900, 0x1000),  # destination inside the record
            (0x1004, 0x2000),  # source inside the record
            (0x900, 0x2000),  # unrelated
            (0x900, 0x1007),  # destination at the last byte
            (0x900, 0x1008),  # destination just past the end
        ]
    )
    destination_index, source_index = _build_reference_index(builder)
    data = builder.data.add()

    _populate_data_xrefs(data, 0x1000, 8, destination_index, source_index)

    assert list(data.xref_to) == [0, 3]
    assert list(data.xref_from) == [1]


def test_populate_data_xrefs_returns_indices_in_reference_order():
    # Addresses deliberately out of reference order inside the record.
    builder = make_builder([(None, 0x1006), (None, 0x1002), (None, 0x1004)])
    destination_index, source_index = _build_reference_index(builder)
    data = builder.data.add()

    _populate_data_xrefs(data, 0x1000, 8, destination_index, source_index)

    assert list(data.xref_to) == [0, 1, 2]
