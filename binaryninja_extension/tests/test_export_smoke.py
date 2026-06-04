from __future__ import annotations

import lzma
import hashlib
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PLUGIN_ROOT.parent
sys.path.insert(0, str(PLUGIN_ROOT))

from bn_quokka.export import export_file  # noqa: E402
from bn_quokka.quokka_pb2 import Quokka  # noqa: E402

pytestmark = pytest.mark.requires_binaryninja


def _load_proto(path: Path) -> Quokka:
    proto = Quokka()
    try:
        with lzma.open(path, "rb") as input_file:
            raw = input_file.read()
    except lzma.LZMAError:
        raw = path.read_bytes()
    proto.ParseFromString(raw)
    return proto


@pytest.fixture(scope="module")
def qb_crackme() -> Path:
    sample = REPO_ROOT / "docs" / "samples" / "qb-crackme"
    if not sample.exists() or sample.stat().st_size < 1024:
        pytest.skip("docs/samples/qb-crackme fixture is unavailable")
    return sample


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
