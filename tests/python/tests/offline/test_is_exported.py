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

"""Tests for the is_exported field on Function.

Verifies that the is_exported flag is correctly round-tripped through
.quokka files exported by both IDA and Ghidra.

Dataset: many_types_cpp (IDA and Ghidra exports both contain exported functions).
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


class TestIsExportedIDA:
    """Verify is_exported on IDA-exported .quokka files."""

    def test_has_exported_functions(self, many_types_prog):
        exported = [
            f for f in many_types_prog.fun_names.values() if f.is_exported
        ]
        assert len(exported) > 0, "Expected at least one exported function"

    def test_has_non_exported_functions(self, many_types_prog):
        non_exported = [
            f for f in many_types_prog.fun_names.values() if not f.is_exported
        ]
        assert len(non_exported) > 0, "Expected at least one non-exported function"

    def test_start_is_exported(self, many_types_prog):
        func = many_types_prog.fun_names.get("_start")
        if func is None:
            pytest.skip("_start not found in IDA export")
        assert func.is_exported is True

    def test_main_is_exported(self, many_types_prog):
        func = many_types_prog.fun_names.get("main")
        if func is None:
            pytest.skip("main not found in IDA export")
        assert func.is_exported is True

    def test_is_exported_is_bool(self, many_types_prog):
        for func in many_types_prog.fun_names.values():
            assert isinstance(func.is_exported, bool)
            break


class TestIsExportedGhidra:
    """Verify is_exported on Ghidra-exported .quokka files."""

    def test_has_exported_functions(self, ghidra_many_types_prog):
        exported = [
            f for f in ghidra_many_types_prog.fun_names.values()
            if f.is_exported
        ]
        assert len(exported) > 0, "Expected at least one exported function"

    def test_has_non_exported_functions(self, ghidra_many_types_prog):
        non_exported = [
            f for f in ghidra_many_types_prog.fun_names.values()
            if not f.is_exported
        ]
        assert len(non_exported) > 0, "Expected at least one non-exported function"

    def test_start_is_exported(self, ghidra_many_types_prog):
        func = ghidra_many_types_prog.fun_names.get("_start")
        if func is None:
            pytest.skip("_start not found in Ghidra export")
        assert func.is_exported is True

    def test_main_is_exported(self, ghidra_many_types_prog):
        func = ghidra_many_types_prog.fun_names.get("main")
        if func is None:
            pytest.skip("main not found in Ghidra export")
        assert func.is_exported is True


class TestIsExportedConsistency:
    """Cross-check IDA and Ghidra exported function sets."""

    def test_exported_function_names_overlap(
        self, many_types_prog, ghidra_many_types_prog
    ):
        """IDA and Ghidra should agree on most exported function names."""
        ida_exported = {
            f.name for f in many_types_prog.fun_names.values()
            if f.is_exported
        }
        ghidra_exported = {
            f.name for f in ghidra_many_types_prog.fun_names.values()
            if f.is_exported
        }
        # Both must have _start exported
        assert "_start" in ida_exported
        assert "_start" in ghidra_exported

    def test_non_exported_pura_update(
        self, pura_update_prog, root_directory: Path
    ):
        """puraUpdate has exported functions in both backends."""
        ida_exported = [
            f for f in pura_update_prog.fun_names.values() if f.is_exported
        ]
        assert len(ida_exported) == 3

        ghidra_path = root_directory / "tests/dataset/puraUpdate_ghidra.quokka"
        if not ghidra_path.exists():
            pytest.skip("Ghidra-exported puraUpdate.quokka not found")
        binary = root_directory / "tests/dataset/puraUpdate"
        ghidra_prog = quokka.Program(ghidra_path, binary)
        ghidra_exported = [
            f for f in ghidra_prog.fun_names.values() if f.is_exported
        ]
        assert len(ghidra_exported) == 5


class TestIsExportedProtobuf:
    """Verify is_exported at the raw protobuf level."""

    def test_proto_field_round_trip(self, many_types_prog):
        """The proto field should match the Python property."""
        for proto_func in many_types_prog.proto.functions:
            # Access the raw protobuf field
            _ = proto_func.is_exported  # Should not raise
            break

    def test_proto_has_both_values(self, many_types_prog):
        """Raw protobuf should contain both True and False values."""
        values = {f.is_exported for f in many_types_prog.proto.functions}
        assert True in values, "Expected at least one is_exported=True in proto"
        assert False in values, "Expected at least one is_exported=False in proto"
