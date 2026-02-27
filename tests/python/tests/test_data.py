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
from quokka.data_type import BaseType, StructureType


def test_data(prog: quokka.Program):
    # Get a known BaseType data and check its properties
    data: quokka.Data = prog.get_data(0x804e000)
    assert data.type is BaseType.UNKNOWN, "Data type should be UNKNOWN"
    assert data.is_initialized is True, "Data should be initialized"
    assert data.size == 4, "Wrong data size"
    assert data.name == "_GLOBAL_OFFSET_TABLE_", "Wrong data name"


def test_no_data(prog: quokka.Program):
    with pytest.raises(ValueError):
        prog.get_data(0x804B924)


def test_not_initialized(prog: quokka.Program):
    data = prog.get_data(0x804e044)

    assert data.is_initialized is False, "Data should not be initialized"
    assert data.value is None, "Data should not have a value"


def test_data_string(prog: quokka.Program):
    data = prog.get_data(0x804b08f)
    assert data.is_initialized is True, "Data should be initialized"
    assert data.size == 17
    string = prog.executable.read_string(data.file_offset, data.size)
    assert string == "What's the flag?", "Error while reading string"


def test_data_struct(prog: quokka.Program):
    data = prog.get_data(0x804df14)
    assert isinstance(data.type, StructureType), "Data type should be a StructureType"
    assert data.type.name == "Elf32_Dyn", "Wrong structure name"
    assert data.is_initialized is True, "Struct data should be initialized"
    assert isinstance(data.value, bytes), "Struct value should be bytes"


def test_data_references(prog: quokka.Program):
    data_1 = prog.get_data(0x80480fc)
    data_2 = prog.get_data(0x804df14)

    # data_1 has outgoing data references to data_2
    refs_from = data_1.data_refs_from
    refs_from_addrs = [r.address if hasattr(r, "address") else r for r in refs_from]
    assert data_2.address in refs_from_addrs, "data_1 should reference data_2"

    # data_2 has incoming data references from data_1
    refs_to = data_2.data_refs_to
    refs_to_addrs = [r.address if hasattr(r, "address") else r for r in refs_to]
    assert data_1.address in refs_to_addrs, "data_2 should be referenced by data_1"

    # data_2 should not have incoming code references
    assert data_2.code_refs_to == [], "Unexpected code reference for data_2"
