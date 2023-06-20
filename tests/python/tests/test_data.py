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

import quokka
from quokka.types import DataType, ReferenceType


def test_data(prog: quokka.Program):
    # Get the data
    data: quokka.Data = prog.get_data(0x804b920)
    assert data.type is DataType.UNKNOWN, "Data type is not unknown"
    assert data.value is None, "Unknown data type have no value"

    data.type = DataType.BYTE
    assert data.value == 0x12, "Data should be 0x12"


def test_no_data(prog: quokka.Program):
    with pytest.raises(ValueError):
        prog.get_data(0x804B924)


def test_not_initialized(prog: quokka.Program):
    data = prog.get_data(0x804e034)

    assert data.is_initialized is False, "Data should not be initialized"
    assert data.value is None, "Data should not have a value"


def test_data_string(prog: quokka.Program):
    data = prog.get_data(0x804b08f)

    assert data.type == DataType.ASCII, "Should be a string"
    assert data.value == "What's the flag?", "Error while reading string"


def test_data_references(prog: quokka.Program):
    data_1 = prog.get_data(0x804c6e4)
    data_2 = prog.get_data(0x804813C)

    assert data_2.value == data_1.address, "Data 2 points to Data 1"
    assert data_1.references, "Missing references for Data 1"
    assert data_2.references, "Missing references for Data 2"

    ref = data_1.references[0]
    assert ref.source == data_1, "Wrong source"
    assert ref.destination == data_2, "Wrong destination"

    assert all(ref.type == ReferenceType.DATA for ref in data_1.data_references), "Ref not in data_1 references"
    assert data_2.code_references == [], "Weird code reference for data 2"
