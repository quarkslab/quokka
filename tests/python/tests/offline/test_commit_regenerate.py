"""Offline tests for Program.commit(), Program.regenerate(), and the
quokka-apply CLI (apply_changes).

These tests mock the disassembler backends so they run without IDA or Ghidra.
"""

from pathlib import Path
from unittest.mock import patch, MagicMock

import logging

import pytest
from click.testing import CliRunner

import quokka
from quokka.__main__ import apply_changes
from quokka.types import Disassembler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_program(disassembler=Disassembler.IDA):
    """Return a MagicMock that behaves like a Program for commit/regenerate."""
    prog = MagicMock(spec=quokka.Program)
    prog.disassembler = disassembler
    prog.export_file = Path("/tmp/fake.quokka")
    prog.executable = MagicMock()
    prog.executable.exec_file = Path("/tmp/fake_binary")
    prog.proto = MagicMock()
    prog.logger = MagicMock()
    return prog


def _make_files(tmp_path):
    """Create dummy quokka and binary files, return (quokka_path, binary_path)."""
    qf = tmp_path / "test.quokka"
    bf = tmp_path / "test_binary"
    qf.write_bytes(b"\x00")
    bf.write_bytes(b"\x00")
    return qf, bf


# ---------------------------------------------------------------------------
# apply_changes CLI tests
# ---------------------------------------------------------------------------


class TestApplyChangesCli:
    """Test the quokka-apply CLI command."""

    @patch("quokka.__main__.Program")
    def test_commit_is_default_action(self, mock_prog_cls, tmp_path, caplog):
        """Without flags, commit is the default; exit 0 and correct method called."""
        qf, bf = _make_files(tmp_path)

        mock_prog = MagicMock()
        mock_prog.commit.return_value = 0
        mock_prog_cls.open.return_value = mock_prog

        runner = CliRunner()
        with caplog.at_level(logging.INFO):
            result = runner.invoke(apply_changes, [str(qf), str(bf)])

        assert result.exit_code == 0
        assert "committed" in caplog.text.lower()
        mock_prog.commit.assert_called_once()
        mock_prog.regenerate.assert_not_called()

    @patch("quokka.__main__.Program")
    def test_commit_failure_reports_error_count(self, mock_prog_cls, tmp_path, caplog):
        """commit() returning >0 should exit 1 and report the error count."""
        qf, bf = _make_files(tmp_path)

        mock_prog = MagicMock()
        mock_prog.commit.return_value = 3
        mock_prog_cls.open.return_value = mock_prog

        runner = CliRunner()
        result = runner.invoke(apply_changes, ["--commit", str(qf), str(bf)])

        assert result.exit_code != 0
        assert "3 error" in caplog.text

    @patch("quokka.__main__.Program")
    def test_regenerate_action(self, mock_prog_cls, tmp_path, caplog):
        """--regenerate should call regenerate() instead of commit()."""
        qf, bf = _make_files(tmp_path)

        mock_prog = MagicMock()
        mock_new_prog = MagicMock()
        mock_new_prog.export_file = Path("/tmp/new.quokka")
        mock_prog.regenerate.return_value = mock_new_prog
        mock_prog_cls.open.return_value = mock_prog

        runner = CliRunner()
        with caplog.at_level(logging.INFO):
            result = runner.invoke(apply_changes, ["--regenerate", str(qf), str(bf)])

        assert result.exit_code == 0
        assert "regenerated" in caplog.text.lower()
        mock_prog.regenerate.assert_called_once()
        mock_prog.commit.assert_not_called()

    @patch("quokka.__main__.Program")
    def test_regenerate_failure_reports_message(self, mock_prog_cls, tmp_path, caplog):
        """regenerate() raising QuokkaError should exit 1 with error message."""
        qf, bf = _make_files(tmp_path)

        mock_prog = MagicMock()
        mock_prog.regenerate.side_effect = quokka.QuokkaError("regen failed")
        mock_prog_cls.open.return_value = mock_prog

        runner = CliRunner()
        result = runner.invoke(apply_changes, ["--regenerate", str(qf), str(bf)])

        assert result.exit_code != 0
        assert "regen failed" in caplog.text

    @patch("quokka.__main__.Program")
    def test_commit_without_overwrite_reports_hint(self, mock_prog_cls, tmp_path, caplog):
        """commit() raising FileExistsError should exit 1 and suggest --overwrite."""
        qf, bf = _make_files(tmp_path)

        mock_prog = MagicMock()
        mock_prog.commit.side_effect = FileExistsError("Database already exists: db.i64")
        mock_prog_cls.open.return_value = mock_prog

        runner = CliRunner()
        result = runner.invoke(apply_changes, ["--commit", str(qf), str(bf)])

        assert result.exit_code != 0
        assert "--overwrite" in caplog.text

    @patch("quokka.__main__.Program")
    def test_regenerate_without_overwrite_reports_hint(self, mock_prog_cls, tmp_path, caplog):
        """regenerate() raising FileExistsError should exit 1 and suggest --overwrite."""
        qf, bf = _make_files(tmp_path)

        mock_prog = MagicMock()
        mock_prog.regenerate.side_effect = FileExistsError("Database already exists: db.i64")
        mock_prog_cls.open.return_value = mock_prog

        runner = CliRunner()
        result = runner.invoke(apply_changes, ["--regenerate", str(qf), str(bf)])

        assert result.exit_code != 0
        assert "--overwrite" in caplog.text

    @patch("quokka.__main__.Program")
    def test_open_failure_reports_message(self, mock_prog_cls, tmp_path, caplog):
        """If Program.open() fails, CLI should exit 1 with error message."""
        qf, bf = _make_files(tmp_path)
        mock_prog_cls.open.side_effect = quokka.QuokkaError("bad file")

        runner = CliRunner()
        result = runner.invoke(apply_changes, [str(qf), str(bf)])

        assert result.exit_code != 0
        assert "bad file" in caplog.text


# ---------------------------------------------------------------------------
# Program.commit() unit tests
# ---------------------------------------------------------------------------


class TestCommitMethod:
    """Unit tests for Program.commit()."""

    def test_commit_writes_quokka_file(self):
        """commit() should call write() to serialize the protobuf."""
        prog = _make_mock_program(Disassembler.GHIDRA)
        prog.write = MagicMock()
        prog.commit = lambda **kw: quokka.Program.commit(prog, **kw)

        result = prog.commit()
        prog.write.assert_called_once()
        assert result == 0

    def test_commit_ghidra_returns_zero(self):
        """For Ghidra programs, commit() should return 0 (no IDA apply-back)."""
        prog = _make_mock_program(Disassembler.GHIDRA)
        prog.write = MagicMock()
        prog.commit = lambda **kw: quokka.Program.commit(prog, **kw)

        assert prog.commit() == 0

    def test_commit_unknown_disassembler_raises(self):
        """commit() with BINARY_NINJA should raise NotImplementedError."""
        prog = _make_mock_program(Disassembler.BINARY_NINJA)
        prog.write = MagicMock()
        prog.commit = lambda **kw: quokka.Program.commit(prog, **kw)

        with pytest.raises(NotImplementedError):
            prog.commit()


# ---------------------------------------------------------------------------
# Program.regenerate() unit tests
# ---------------------------------------------------------------------------


class TestRegenerateMethod:
    """Unit tests for Program.regenerate()."""

    def test_regenerate_passes_disassembler_to_generate(self):
        """regenerate() must forward self.disassembler to generate()."""
        prog = _make_mock_program(Disassembler.GHIDRA)
        prog.write = MagicMock()
        prog.commit = MagicMock(return_value=0)

        mock_new_prog = MagicMock()
        with patch.object(quokka.Program, "generate", return_value=Path("/tmp/out.quokka")) as mock_gen, \
             patch.object(quokka.Program, "open", return_value=mock_new_prog):
            quokka.Program.regenerate(prog)

            mock_gen.assert_called_once()
            assert mock_gen.call_args.kwargs.get("disassembler") == Disassembler.GHIDRA, \
                f"Expected disassembler=GHIDRA in generate() call, got: {mock_gen.call_args}"

    def test_regenerate_calls_commit_then_generate(self):
        """regenerate() should call commit() first, then generate()."""
        prog = _make_mock_program(Disassembler.GHIDRA)
        prog.write = MagicMock()
        prog.commit = MagicMock(return_value=0)

        call_order = []
        prog.commit.side_effect = lambda **kw: (call_order.append("commit"), 0)[1]

        mock_new_prog = MagicMock()
        with patch.object(quokka.Program, "generate", return_value=Path("/tmp/out.quokka")) as mock_gen, \
             patch.object(quokka.Program, "open", return_value=mock_new_prog):
            mock_gen.side_effect = lambda *a, **kw: (call_order.append("generate"), Path("/tmp/out.quokka"))[1]

            quokka.Program.regenerate(prog)

            assert call_order == ["commit", "generate"]

    def test_regenerate_warns_on_commit_errors(self):
        """If commit() returns >0, regenerate() logs a warning but continues."""
        prog = _make_mock_program(Disassembler.GHIDRA)
        prog.write = MagicMock()
        prog.commit = MagicMock(return_value=2)

        mock_new_prog = MagicMock()
        with patch.object(quokka.Program, "generate", return_value=Path("/tmp/out.quokka")), \
             patch.object(quokka.Program, "open", return_value=mock_new_prog):
            result = quokka.Program.regenerate(prog)

            prog.logger.warning.assert_called_once()
            assert result is mock_new_prog
