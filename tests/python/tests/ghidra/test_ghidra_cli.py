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

"""Ghidra CLI and Program.generate() integration tests.

Tests that Program.generate() and quokka-cli work with the Ghidra backend.
Auto-skipped when GHIDRA_INSTALL_DIR is not set.
"""

import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

import quokka
from quokka.types import Disassembler, ExporterMode
from quokka.__main__ import main as quokka_cli

from .conftest import requires_ghidra, GHIDRA_DIR


@requires_ghidra
class TestGhidraGenerate:
    """Test Program.generate() with disassembler=Disassembler.GHIDRA."""

    def test_generate_produces_quokka(self, root_directory, tmp_path):
        binary = root_directory / "docs" / "samples" / "qb-crackme"
        if not binary.exists():
            pytest.skip("qb-crackme binary not found")

        output = tmp_path / "qb-crackme.quokka"
        result = quokka.Program.generate(
            exec_path=binary,
            output_file=output,
            disassembler=Disassembler.GHIDRA,
        )
        assert result == output
        assert output.exists()
        assert output.stat().st_size > 0

    def test_generate_output_loadable(self, root_directory, tmp_path):
        binary = root_directory / "docs" / "samples" / "qb-crackme"
        if not binary.exists():
            pytest.skip("qb-crackme binary not found")

        output = tmp_path / "qb-crackme.quokka"
        quokka.Program.generate(
            exec_path=binary,
            output_file=output,
            disassembler=Disassembler.GHIDRA,
        )
        prog = quokka.Program.open(output, binary)
        assert len(prog) > 0

    def test_from_binary_ghidra(self, root_directory, tmp_path):
        binary = root_directory / "docs" / "samples" / "qb-crackme"
        if not binary.exists():
            pytest.skip("qb-crackme binary not found")

        output = tmp_path / "qb-crackme.quokka"
        prog = quokka.Program.from_binary(
            exec_path=binary,
            output_file=output,
            disassembler=Disassembler.GHIDRA,
        )
        assert prog is not None
        assert len(prog) > 0


@requires_ghidra
class TestGhidraCli:
    """Test quokka-cli --backend ghidra."""

    def test_cli_single_binary(self, root_directory, tmp_path):
        binary = root_directory / "docs" / "samples" / "qb-crackme"
        if not binary.exists():
            pytest.skip("qb-crackme binary not found")

        # Copy binary to tmp so .quokka lands there
        target = tmp_path / "qb-crackme"
        shutil.copy2(binary, target)

        runner = CliRunner()
        result = runner.invoke(
            quokka_cli,
            ["--backend", "ghidra", str(target)],
        )
        assert result.exit_code == 0, f"CLI failed: {result.output}"

        quokka_file = tmp_path / "qb-crackme.quokka"
        assert quokka_file.exists()

        prog = quokka.Program.open(quokka_file, target)
        assert len(prog) > 0

    def test_cli_ghidra_path_option(self, root_directory, tmp_path):
        binary = root_directory / "docs" / "samples" / "qb-crackme"
        if not binary.exists():
            pytest.skip("qb-crackme binary not found")

        target = tmp_path / "qb-crackme"
        shutil.copy2(binary, target)

        runner = CliRunner()
        result = runner.invoke(
            quokka_cli,
            [
                "--backend", "ghidra",
                "--ghidra-path", str(GHIDRA_DIR),
                str(target),
            ],
        )
        assert result.exit_code == 0, f"CLI failed: {result.output}"

        quokka_file = tmp_path / "qb-crackme.quokka"
        assert quokka_file.exists()
