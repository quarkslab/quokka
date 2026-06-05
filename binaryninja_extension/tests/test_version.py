"""The extension version has one Python source; plugin.json must match."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT))

from bn_quokka.version import __version__  # noqa: E402


def test_plugin_json_version_matches_package_version():
    plugin_manifest = json.loads((PLUGIN_ROOT / "plugin.json").read_text())
    assert plugin_manifest["version"] == __version__
