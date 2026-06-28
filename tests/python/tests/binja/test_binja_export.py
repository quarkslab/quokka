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

"""BinaryNinja export integration tests.

Export qb-crackme with the real Binary Ninja API and validate the result,
both at the protobuf level and through the Python bindings.
"""

from __future__ import annotations

import hashlib
import lzma
from pathlib import Path

import pytest

pytest.importorskip("binaryninja", reason="Binary Ninja Python API is not installed")

import quokka  # noqa: E402
from bn_quokka.export import export_file  # noqa: E402
from bn_quokka.quokka_pb2 import Quokka  # noqa: E402


def _load_proto(path: Path) -> Quokka:
    proto = Quokka()
    try:
        with lzma.open(path, "rb") as input_file:
            raw = input_file.read()
    except lzma.LZMAError:
        raw = path.read_bytes()
    proto.ParseFromString(raw)
    return proto


def test_light_export_qb_crackme(qb_crackme: Path, tmp_path: Path) -> None:
    output = tmp_path / "qb-crackme-binja-light.quokka"
    export_file(qb_crackme, output, "LIGHT")
    proto = _load_proto(output)

    assert proto.exporter_meta.mode == Quokka.ExporterMeta.MODE_LIGHT
    assert proto.meta.backend.name == Quokka.Meta.Backend.DISASS_BINARY_NINJA
    assert proto.meta.hash.hash_type == Quokka.Meta.Hash.HASH_MD5
    assert proto.meta.hash.hash_value == hashlib.md5(qb_crackme.read_bytes()).hexdigest()
    assert len(proto.segments) > 0
    assert len(proto.functions) > 0
    assert len(proto.types) >= 9
    assert any(layout.layout_type == Quokka.Layout.LAYOUT_UNK for layout in proto.layout)
    assert len(proto.instructions) == 0
    assert len(proto.operands) == 0
    assert len(proto.mnemonics) == 0
    assert len(proto.operand_strings) == 0

    blocks = [block for function in proto.functions for block in function.blocks]
    assert blocks
    assert all(len(block.instruction_index) == 0 for block in blocks)
    assert any(block.n_instr > 0 for block in blocks)

    cprintf = next((func for func in proto.functions if func.name == "cprintf"), None)
    assert cprintf is not None
    assert len(cprintf.blocks) > 1
    assert len(cprintf.edges) > 0


def test_export_loads_through_python_bindings(qb_crackme: Path, tmp_path: Path) -> None:
    """The real compatibility contract: quokka.Program must load the export."""
    output = tmp_path / "qb-crackme-binja-bindings.quokka"
    export_file(qb_crackme, output, "LIGHT")
    program = quokka.Program(output, qb_crackme)

    assert len(program.fun_names) > 0
    assert "cprintf" in program.fun_names

    # Regression: extern/imported functions must not collapse onto a single
    # reconstructed address (segment 0 + offset 0).
    segments = program.proto.segments
    addresses = [
        segments[func.segment_index].virtual_addr + func.segment_offset
        for func in program.proto.functions
    ]
    assert len(addresses) == len(set(addresses))


def test_self_contained_export_sets_mode(qb_crackme: Path, tmp_path: Path) -> None:
    output = tmp_path / "qb-crackme-binja-self-contained.quokka"
    export_file(qb_crackme, output, "SELF_CONTAINED")
    proto = _load_proto(output)

    assert proto.exporter_meta.mode == Quokka.ExporterMeta.MODE_SELF_CONTAINED
    assert proto.meta.backend.name == Quokka.Meta.Backend.DISASS_BINARY_NINJA
    assert len(proto.segments) > 0
    assert len(proto.functions) > 0
    assert len(proto.instructions) > 0
    assert len(proto.mnemonics) > 0
    assert len(proto.operands) > 0
    assert len(proto.operand_strings) > 0

    blocks = [block for function in proto.functions for block in function.blocks]
    assert blocks
    assert any(len(block.instruction_index) > 0 for block in blocks)
