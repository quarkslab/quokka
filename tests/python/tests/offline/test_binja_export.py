#  Copyright 2022-2026 Quarkslab
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Integration tests for BinaryNinja-exported .quokka files.

These tests load .quokka files exported by the BinaryNinja extension through
the Python bindings - the real compatibility contract - and verify structural
correctness. They skip gracefully if the BinaryNinja-exported fixture is not
found; regenerate it with:

    python binaryninja_extension/export_headless.py docs/samples/qb-crackme \
        -o tests/dataset/qb-crackme_binja.quokka

Tests assert structural properties (functions exist, segments load, types
indexed correctly) rather than exact counts, since BinaryNinja analysis may
differ from IDA.
"""

import pytest
from pathlib import Path

import quokka
from quokka.types import FunctionType


@pytest.fixture
def binja_crackme_prog(root_directory: Path):
    binary = root_directory / "docs/samples/qb-crackme"
    quokka_path = root_directory / "tests/dataset/qb-crackme_binja.quokka"
    if not quokka_path.exists():
        pytest.skip("BinaryNinja-exported qb-crackme_binja.quokka not found")
    return quokka.Program(quokka_path, binary)


class TestBinjaExportBasic:
    """Basic structural tests for BinaryNinja-exported .quokka files."""

    def test_loads_without_error(self, binja_crackme_prog):
        assert binja_crackme_prog is not None

    def test_disassembler_is_binary_ninja(self, binja_crackme_prog):
        prog = binja_crackme_prog
        assert prog.proto.meta.backend.name == 3  # DISASS_BINARY_NINJA

    def test_mode_is_light(self, binja_crackme_prog):
        prog = binja_crackme_prog
        assert prog.proto.exporter_meta.mode == 0  # MODE_LIGHT

    def test_has_functions(self, binja_crackme_prog):
        prog = binja_crackme_prog
        assert len(prog.fun_names) > 0

    def test_has_segments(self, binja_crackme_prog):
        prog = binja_crackme_prog
        assert len(prog.proto.segments) > 0

    def test_has_types(self, binja_crackme_prog):
        prog = binja_crackme_prog
        # At minimum, the 9 primitive types must exist
        assert len(prog.proto.types) >= 9


class TestBinjaExportFunctions:
    """Function-level tests for BinaryNinja-exported .quokka files."""

    def test_function_has_start_address(self, binja_crackme_prog):
        prog = binja_crackme_prog
        for func in prog.values():
            assert func.start > 0
            break  # Just check first function

    def test_normal_function_has_blocks(self, binja_crackme_prog):
        prog = binja_crackme_prog
        normal_funcs = [
            f for f in prog.values()
            if f.type == FunctionType.NORMAL
        ]
        assert len(normal_funcs) > 0
        # At least some normal functions should have blocks
        funcs_with_blocks = [
            f for f in normal_funcs
            if len(list(f.keys())) > 0
        ]
        assert len(funcs_with_blocks) > 0

    def test_function_addresses_are_unique(self, binja_crackme_prog):
        # Regression: extern/imported functions whose synthetic addresses lie
        # outside every mapped segment used to be encoded as segment 0 +
        # offset 0, collapsing them all onto one address. They must resolve
        # to distinct addresses (via SEGMENT_EXTERN pseudo-segments).
        prog = binja_crackme_prog
        segments = prog.proto.segments
        addresses = [
            segments[func.segment_index].virtual_addr + func.segment_offset
            for func in prog.proto.functions
        ]
        assert len(addresses) == len(set(addresses))


class TestBinjaExportTypes:
    """Type system tests for BinaryNinja-exported .quokka files."""

    def test_primitive_types_at_indices_0_through_8(self, binja_crackme_prog):
        prog = binja_crackme_prog
        types = prog.proto.types
        for i in range(9):
            assert types[i].HasField("primitive_type"), \
                f"Type at index {i} should be primitive"

    def test_primitive_type_order(self, binja_crackme_prog):
        prog = binja_crackme_prog
        types = prog.proto.types
        for i in range(9):
            assert types[i].primitive_type == i, \
                f"Type at index {i} should have value {i}"


class TestBinjaExportSegments:
    """Segment-level tests for BinaryNinja-exported .quokka files."""

    def test_segments_sorted_by_va(self, binja_crackme_prog):
        prog = binja_crackme_prog
        segs = prog.proto.segments
        for i in range(1, len(segs)):
            assert segs[i].virtual_addr >= segs[i - 1].virtual_addr, \
                "Segments must be sorted by virtual address"

    def test_segments_have_names(self, binja_crackme_prog):
        prog = binja_crackme_prog
        for seg in prog.proto.segments:
            assert seg.name, "Each segment must have a name"
