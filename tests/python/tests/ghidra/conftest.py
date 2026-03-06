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

"""Ghidra export integration test fixtures.

Provides helpers to run Ghidra headlessly, export a binary to .quokka,
and load it via the Python frontend for validation.
"""

import os
import glob
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

import quokka


# ---------------------------------------------------------------------------
# Ghidra availability detection
# ---------------------------------------------------------------------------

def _find_ghidra_install() -> Path | None:
    """Return the Ghidra install directory, or None if unavailable."""
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env:
        p = Path(env)
        if (p / "support" / "analyzeHeadless").exists():
            return p
    return None


def _find_extension_jar(root: Path) -> Path | None:
    """Return the built QuokkaExporter JAR, or None if not built."""
    jar = root / "ghidra_extension" / "build" / "libs" / "QuokkaExporter.jar"
    if jar.exists():
        return jar
    return None


def _find_extension_zip(root: Path) -> Path | None:
    """Return the built Ghidra extension ZIP, or None."""
    dist_dir = root / "ghidra_extension" / "dist"
    if not dist_dir.exists():
        return None
    zips = sorted(dist_dir.glob("*.zip"))
    return zips[-1] if zips else None


GHIDRA_DIR = _find_ghidra_install()

requires_ghidra = pytest.mark.skipif(
    GHIDRA_DIR is None,
    reason=(
        "Ghidra not found (set GHIDRA_INSTALL_DIR to a Ghidra installation "
        "containing support/analyzeHeadless)"
    ),
)


# ---------------------------------------------------------------------------
# Headless export helper
# ---------------------------------------------------------------------------

def ghidra_headless_export(
    binary: Path,
    output: Path,
    root: Path,
    mode: str = "LIGHT",
    timeout: int = 600,
) -> Path:
    """Run Ghidra headless analysis and export to .quokka.

    Parameters
    ----------
    binary : Path
        Path to the binary to import and analyze.
    output : Path
        Desired output .quokka file path.
    root : Path
        Repository root (to locate the extension and scripts).
    mode : str
        Export mode ("LIGHT" or "SELF_CONTAINED").
    timeout : int
        Subprocess timeout in seconds.

    Returns
    -------
    Path
        The output .quokka file path.

    Raises
    ------
    RuntimeError
        If the export fails or the output file is not produced.
    """
    assert GHIDRA_DIR is not None, "Ghidra not available"

    jar = _find_extension_jar(root)
    if jar is None:
        raise RuntimeError(
            "QuokkaExporter.jar not found. Build the extension first: "
            "cd ghidra_extension && gradle build"
        )

    analyze_headless = GHIDRA_DIR / "support" / "analyzeHeadless"
    script_path = root / "ghidra_extension" / "src" / "script" / "ghidra_scripts"

    # Create a temporary Ghidra project directory
    proj_dir = output.parent / "ghidra_proj"
    proj_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(analyze_headless),
        str(proj_dir),
        "QuokkaTest",
        "-import", str(binary),
        "-scriptPath", str(script_path),
        "-postScript", "QuokkaExportHeadless.java",
        f"--out={output}",
        f"--mode={mode}",
        "-readOnly",
    ]

    # Add extension JAR to classpath
    env = os.environ.copy()
    existing_cp = env.get("CLASSPATH", "")
    env["CLASSPATH"] = str(jar) + (":" + existing_cp if existing_cp else "")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Ghidra headless export failed (rc={result.returncode}):\n"
            f"STDOUT:\n{result.stdout[-2000:]}\n"
            f"STDERR:\n{result.stderr[-2000:]}"
        )

    if not output.exists():
        raise RuntimeError(
            f"Ghidra export did not produce {output}.\n"
            f"STDOUT:\n{result.stdout[-2000:]}"
        )

    return output
