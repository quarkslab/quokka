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

import pytest
from pathlib import Path

import quokka


@pytest.fixture(scope="module")
def root_directory(request) -> Path:
    """Return the
    """
    return Path(request.fspath).parent.parent.parent.parent


@pytest.fixture
def prog(root_directory: Path):
    binary_path = root_directory / "docs/samples/qb-crackme"
    return quokka.Program(binary_path.with_suffix(".quokka"), binary_path)

