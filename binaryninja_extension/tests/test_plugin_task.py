"""Tests for the background export task in the plugin entry point.

These run only against the conftest stub: with the real BinaryNinja API the
task state is core-backed and the message boxes are real UI.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import binaryninja  # noqa: E402  # the conftest stub when outside BinaryNinja

import binaryninja_extension as ext  # noqa: E402
from binaryninja_extension.bn_quokka.export import ExportCancelled  # noqa: E402

pytestmark = pytest.mark.skipif(
    not isinstance(binaryninja.log_info, mock.MagicMock),
    reason="exercises the plugin task against the stubbed BinaryNinja API",
)


@pytest.fixture
def dialogs(monkeypatch):
    """Run main-thread callbacks inline and capture message boxes."""
    boxes = mock.MagicMock()
    monkeypatch.setattr(ext, "execute_on_main_thread", lambda callback: callback())
    monkeypatch.setattr(ext, "show_message_box", boxes)
    return boxes


def _proto_stub() -> mock.MagicMock:
    proto = mock.MagicMock()
    proto.functions = [object()] * 3
    proto.segments = [object()] * 2
    proto.types = [object()] * 9
    return proto


def test_run_reports_success_dialog(dialogs, monkeypatch, tmp_path):
    output = tmp_path / "out.quokka"
    progress_texts = []

    def fake_export(bv, output_file, mode, *, progress=None):
        progress("exporting functions")
        progress_texts.append(task.progress)
        return _proto_stub()

    monkeypatch.setattr(ext, "export_binary_view", fake_export)
    task = ext._ExportTask(object(), output, "LIGHT")
    task.run()

    assert progress_texts == ["Quokka: exporting functions"]
    dialogs.assert_called_once()
    title, message = dialogs.call_args.args[:2]
    assert title == "Quokka export complete"
    assert "Functions: 3" in message and "Segments: 2" in message


def test_run_cancellation_skips_dialog(dialogs, monkeypatch, tmp_path):
    def fake_export(bv, output_file, mode, *, progress=None):
        task.cancelled = True
        progress("exporting references")  # raises ExportCancelled
        raise AssertionError("unreachable")

    monkeypatch.setattr(ext, "export_binary_view", fake_export)
    task = ext._ExportTask(object(), tmp_path / "out.quokka", "LIGHT")
    task.run()

    dialogs.assert_not_called()


def test_run_reports_failure_dialog(dialogs, monkeypatch, tmp_path):
    def fake_export(bv, output_file, mode, *, progress=None):
        raise ValueError("boom")

    monkeypatch.setattr(ext, "export_binary_view", fake_export)
    task = ext._ExportTask(object(), tmp_path / "out.quokka", "LIGHT")
    task.run()

    dialogs.assert_called_once()
    title, message = dialogs.call_args.args[:2]
    assert title == "Quokka export failed"
    assert "boom" in message


def test_progress_raises_when_cancelled(tmp_path):
    task = ext._ExportTask(object(), tmp_path / "out.quokka", "LIGHT")
    task._progress("exporting data")
    assert task.progress == "Quokka: exporting data"

    task.cancelled = True
    with pytest.raises(ExportCancelled):
        task._progress("exporting data")
