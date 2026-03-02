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


@pytest.fixture
def prog(root_directory: Path):
    binary_path = root_directory / "docs/samples/qb-crackme"
    return quokka.Program(binary_path.with_suffix(".quokka"), binary_path)


@pytest.fixture
def many_types_prog(root_directory: Path):
    binary_path = root_directory / "tests/dataset/many_types_cpp"
    quokka_path = binary_path.with_suffix(".quokka")
    if not quokka_path.exists():
        pytest.skip("many_types_cpp.quokka not found")
    return quokka.Program(quokka_path, binary_path)


@pytest.fixture
def pura_update_prog(root_directory: Path):
    binary_path = root_directory / "tests/dataset/puraUpdate"
    quokka_path = binary_path.with_suffix(".quokka")
    if not quokka_path.exists():
        pytest.skip("puraUpdate.quokka not found")
    return quokka.Program(quokka_path, binary_path)
