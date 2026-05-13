from __future__ import annotations

import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT))

import export_headless  # noqa: E402


def test_main_invokes_export_file(monkeypatch, tmp_path: Path) -> None:
    input_file = tmp_path / "sample.bin"
    output_file = tmp_path / "sample.quokka"
    input_file.write_bytes(b"sample")
    calls = []

    def fake_export_file(
        input_path: Path,
        output_path: Path | None,
        mode: str,
        *,
        compressed: bool,
        update_analysis: bool,
    ) -> Path:
        assert output_path is not None
        calls.append((input_path, output_path, mode, compressed, update_analysis))
        return output_path

    monkeypatch.setattr(export_headless, "_export_file", fake_export_file)

    result = export_headless.main(
        [
            str(input_file),
            "--out",
            str(output_file),
            "--mode",
            "SELF_CONTAINED",
            "--no-compress",
            "--skip-analysis",
        ]
    )

    assert result == 0
    assert calls == [
        (input_file, output_file, "SELF_CONTAINED", False, False),
    ]
