#  Copyright 2022-2023 Quarkslab
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

"""Integration tests for Ghidra-exported .quokka files.

These tests load .quokka files exported by the Ghidra extension and verify
structural correctness. They skip gracefully if Ghidra-exported fixtures
are not found (they must be generated separately).

Tests assert structural properties (functions exist, segments load, types
indexed correctly) rather than exact counts, since Ghidra analysis may
differ from IDA.
"""

import pytest
from pathlib import Path

import quokka
from quokka.types import FunctionType


@pytest.fixture
def ghidra_many_types_prog(root_directory: Path):
    binary = root_directory / "tests/dataset/many_types_cpp"
    quokka_path = root_directory / "tests/dataset/many_types_cpp_ghidra.quokka"
    if not quokka_path.exists():
        pytest.skip("Ghidra-exported many_types_cpp.quokka not found")
    return quokka.Program(quokka_path, binary)


@pytest.fixture
def ghidra_pura_update_prog(root_directory: Path):
    binary = root_directory / "tests/dataset/puraUpdate"
    quokka_path = root_directory / "tests/dataset/puraUpdate_ghidra.quokka"
    if not quokka_path.exists():
        pytest.skip("Ghidra-exported puraUpdate.quokka not found")
    return quokka.Program(quokka_path, binary)


class TestGhidraExportBasic:
    """Basic structural tests for Ghidra-exported .quokka files."""

    def test_loads_without_error(self, ghidra_many_types_prog):
        assert ghidra_many_types_prog is not None

    def test_disassembler_is_ghidra(self, ghidra_many_types_prog):
        prog = ghidra_many_types_prog
        assert prog.proto.meta.backend.name == 2  # DISASS_GHIDRA

    def test_mode_is_light(self, ghidra_many_types_prog):
        prog = ghidra_many_types_prog
        assert prog.proto.exporter_meta.mode == 0  # MODE_LIGHT

    def test_has_functions(self, ghidra_many_types_prog):
        prog = ghidra_many_types_prog
        assert len(prog.fun_names) > 0

    def test_has_segments(self, ghidra_many_types_prog):
        prog = ghidra_many_types_prog
        assert len(prog.proto.segments) > 0

    def test_has_types(self, ghidra_many_types_prog):
        prog = ghidra_many_types_prog
        # At minimum, the 9 primitive types must exist
        assert len(prog.proto.types) >= 9


class TestGhidraExportFunctions:
    """Function-level tests for Ghidra-exported .quokka files."""

    def test_function_has_start_address(self, ghidra_many_types_prog):
        prog = ghidra_many_types_prog
        for func in prog.values():
            assert func.start > 0
            break  # Just check first function

    def test_normal_function_has_blocks(self, ghidra_many_types_prog):
        prog = ghidra_many_types_prog
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

    def test_blocks_have_size(self, ghidra_many_types_prog):
        prog = ghidra_many_types_prog
        for func in prog.values():
            if func.type != FunctionType.NORMAL:
                continue
            for addr in func.keys():
                block = func[addr]
                assert block.size > 0
                break
            break


class TestGhidraExportTypes:
    """Type system tests for Ghidra-exported .quokka files."""

    def test_primitive_types_at_indices_0_through_8(self, ghidra_many_types_prog):
        prog = ghidra_many_types_prog
        types = prog.proto.types
        for i in range(9):
            assert types[i].HasField("primitive_type"), \
                f"Type at index {i} should be primitive"

    def test_primitive_type_order(self, ghidra_many_types_prog):
        prog = ghidra_many_types_prog
        types = prog.proto.types
        for i in range(9):
            assert types[i].primitive_type == i, \
                f"Type at index {i} should have value {i}"


class TestGhidraExportSegments:
    """Segment-level tests for Ghidra-exported .quokka files."""

    def test_segments_sorted_by_va(self, ghidra_many_types_prog):
        prog = ghidra_many_types_prog
        segs = prog.proto.segments
        for i in range(1, len(segs)):
            assert segs[i].virtual_addr >= segs[i - 1].virtual_addr, \
                "Segments must be sorted by virtual address"

    def test_segments_have_names(self, ghidra_many_types_prog):
        prog = ghidra_many_types_prog
        for seg in prog.proto.segments:
            assert seg.name, "Each segment must have a name"
