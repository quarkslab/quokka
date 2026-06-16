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

"""Ghidra apply-back integration tests."""

import shutil
from pathlib import Path

import pytest

import quokka
from quokka.types import Disassembler

from .conftest import requires_ghidra


@requires_ghidra
class TestGhidraApplyBack:
    """Exercise commit() against a real persistent Ghidra project."""

    def test_commit_renames_function_and_reexport_reflects_it(
        self,
        root_directory: Path,
        tmp_path: Path,
    ):
        binary_src = root_directory / "tests" / "dataset" / "sig_test"
        if not binary_src.exists():
            pytest.skip("sig_test binary not found in tests/dataset/")

        binary = tmp_path / "sig_test"
        shutil.copy2(binary_src, binary)

        database = tmp_path / "ghidra_project" / "sig_test.gpr"
        quokka_file = tmp_path / "sig_test.quokka"

        prog = quokka.Program.from_binary(
            binary,
            output_file=quokka_file,
            database_file=database,
            disassembler=Disassembler.GHIDRA,
            timeout=600,
        )

        original = prog.get_function("add_two")
        if original is None:
            pytest.skip("Function 'add_two' not found in sig_test")

        original_addr = original.address
        new_name = "quokka_ghidra_apply_name"
        original.name = new_name

        errors = prog.commit(
            database_file=database,
            overwrite=True,
            timeout=600,
        )
        assert errors == 0
        assert database.exists()

        reexport = tmp_path / "sig_test_reexport.quokka"
        updated = quokka.Program.from_binary(
            binary,
            output_file=reexport,
            database_file=database,
            disassembler=Disassembler.GHIDRA,
            override=True,
            timeout=600,
        )

        assert updated[original_addr].name == new_name
