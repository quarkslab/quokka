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

"""IDA integration tests for commit(), regenerate(), and the quokka-apply CLI.

These tests exercise the full round-trip: export a binary with IDA, modify
the program in-memory, then apply changes via commit()/regenerate()/CLI and
verify the edits landed in a re-exported .quokka.

Auto-skipped when IDA Pro is not available.
"""

import logging
import shutil
from pathlib import Path

import idascript
import pytest
from click.testing import CliRunner

import quokka
from quokka.__main__ import apply_changes

requires_ida = pytest.mark.skipif(
    idascript.get_ida_path() is None,
    reason="IDA Pro not found (set IDA_PATH or add it to $PATH)",
)


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def sig_test_env(root_directory: Path, tmp_path: Path):
    """Export the sig_test binary into a temp directory and return context dict.

    Yields a dict with keys: binary, database, quokka_file, prog, tmp.
    """
    binary_src = root_directory / "tests" / "dataset" / "sig_test"
    if not binary_src.exists():
        pytest.skip("sig_test binary not found in tests/dataset/")

    binary = tmp_path / "sig_test"
    shutil.copy2(binary_src, binary)

    database = tmp_path / "sig_test.i64"
    quokka_file = tmp_path / "sig_test.quokka"

    prog = quokka.Program.from_binary(
        binary,
        output_file=quokka_file,
        database_file=database,
        decompiled=True,
        timeout=600,
    )

    return {
        "binary": binary,
        "database": database,
        "quokka_file": quokka_file,
        "prog": prog,
        "tmp": tmp_path,
    }


def _find_function_by_name(prog, name):
    """Find a function by its original symbol name."""
    for addr, func in prog.items():
        if func.name == name:
            return func
    pytest.skip(f"Function {name!r} not found in sig_test")


# ---------------------------------------------------------------------------
# Program.regenerate() integration test
# ---------------------------------------------------------------------------


@requires_ida
class TestRegenerateIDA:
    """Test Program.regenerate() end-to-end with IDA."""

    def test_regenerate_preserves_rename(self, sig_test_env):
        """Rename a function, call regenerate(), verify the new name persists."""
        env = sig_test_env
        prog = env["prog"]

        func = _find_function_by_name(prog, "add_two")
        original_addr = func.address
        func.name = "quokka_regen_test"

        new_prog = prog.regenerate(
            database_file=env["database"],
            overwrite=True,
            timeout=600,
        )

        new_func = new_prog[original_addr]
        assert new_func.name == "quokka_regen_test", (
            f"Expected 'quokka_regen_test', got {new_func.name!r}"
        )


# ---------------------------------------------------------------------------
# quokka-apply CLI integration tests
# ---------------------------------------------------------------------------


@requires_ida
class TestApplyChangesCLI_IDA:
    """Test the quokka-apply CLI with real IDA round-trips."""

    def test_cli_commit_applies_rename(self, sig_test_env, caplog):
        """quokka-apply --commit should apply a rename via IDA."""
        env = sig_test_env
        prog = env["prog"]

        func = _find_function_by_name(prog, "add_two")
        original_addr = func.address
        func.name = "quokka_cli_commit"

        # Write the modified protobuf so the CLI can read it
        prog.write()

        runner = CliRunner()
        with caplog.at_level(logging.INFO):
            result = runner.invoke(
                apply_changes,
                ["--commit", "--overwrite", str(env["quokka_file"]), str(env["binary"])],
            )

        assert result.exit_code == 0, (
            f"CLI failed (exit {result.exit_code}): {caplog.text}"
        )
        assert "committed" in caplog.text.lower()

        # Re-export and verify the rename landed
        reexport = env["tmp"] / "sig_test_re.quokka"
        new_prog = quokka.Program.from_binary(
            env["binary"],
            output_file=reexport,
            database_file=env["database"],
            override=False,
            timeout=600,
        )
        new_func = new_prog[original_addr]
        assert new_func.name == "quokka_cli_commit", (
            f"Expected 'quokka_cli_commit', got {new_func.name!r}"
        )

    def test_cli_regenerate_applies_rename(self, sig_test_env, caplog):
        """quokka-apply --regenerate should apply a rename and re-export."""
        env = sig_test_env
        prog = env["prog"]

        func = _find_function_by_name(prog, "compute_three")
        original_addr = func.address
        func.name = "quokka_cli_regen"

        # Write the modified protobuf so the CLI can read it
        prog.write()

        runner = CliRunner()
        with caplog.at_level(logging.INFO):
            result = runner.invoke(
                apply_changes,
                ["--regenerate", "--overwrite", str(env["quokka_file"]), str(env["binary"])],
            )

        assert result.exit_code == 0, (
            f"CLI failed (exit {result.exit_code}): {caplog.text}"
        )
        assert "regenerated" in caplog.text.lower()
