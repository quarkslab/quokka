#  Copyright 2022-2026 Quarkslab
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

"""BinaryNinja export integration test fixtures.

These tests drive the real Binary Ninja Python API (a commercial license is
required for headless use) and skip automatically when it is not importable.
"""

import sys
from pathlib import Path

import pytest

# Make the extension package (bn_quokka) importable.
REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT / "binaryninja_extension"))


@pytest.fixture(scope="module")
def qb_crackme(root_directory: Path) -> Path:
    sample = root_directory / "docs" / "samples" / "qb-crackme"
    if not sample.exists() or sample.stat().st_size < 1024:
        pytest.skip("docs/samples/qb-crackme fixture is unavailable")
    return sample
