"""Tests for Program.add_type()."""

import hashlib
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import quokka
from quokka.quokka_pb2 import Quokka as Pb
from quokka.data_type import BaseType, EnumType, StructureType
from quokka.exc import QuokkaError


def _hash_name(c_str: str) -> str:
    h = hashlib.sha256(c_str.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"__user_type_{h}"


def _make_program():
    """Build a minimal mock Program with primitive types pre-populated."""
    prog = MagicMock(spec=quokka.Program)
    prog.proto = Pb()
    prog.address_size = 8

    for i in range(9):
        t = prog.proto.types.add()
        t.primitive_type = i

    prog._types = {}
    prog.get_type = lambda idx, member_index=-1: quokka.Program.get_type(prog, idx, member_index)
    prog.get_type_reference = lambda idx, member_index=-1: quokka.Program.get_type_reference(prog, idx, member_index)
    prog.add_type = lambda *args, **kwargs: quokka.Program.add_type(prog, *args, **kwargs)

    return prog


# ---------------------------------------------------------------------------
# Unit tests (mock program)
# ---------------------------------------------------------------------------

class TestAddTypeFromCStr:
    @pytest.mark.parametrize("c_str", [
        "struct foo { int x; float y; }",
        "enum color { RED=0, GREEN=1, BLUE=2 }",
        "typedef int myint",
        "union data { int i; float f; }",
        "int x",
    ])
    def test_c_str_produces_struct_with_hash_name(self, c_str):
        prog = _make_program()
        result = prog.add_type(c_str)
        assert isinstance(result, StructureType)
        assert result.name == _hash_name(c_str)
        assert result.is_new is True
        assert result.c_str == c_str

    def test_duplicate_c_str_rejected(self):
        prog = _make_program()
        prog.add_type("struct dup { int x; }")
        with pytest.raises(QuokkaError, match="already exists"):
            prog.add_type("struct dup { int x; }")

    def test_invalid_arg_type(self):
        prog = _make_program()
        with pytest.raises(AssertionError, match="Invalid type argument"):
            prog.add_type(...)


class TestAddTypeFromObject:
    def test_adopt_struct(self):
        prog = _make_program()
        ct = Pb.CompositeType()
        ct.name = "bar"
        ct.type = Pb.CompositeType.TYPE_STRUCT
        ct.c_str = "struct bar { int a; }"
        struct = StructureType(len(prog.proto.types), ct, prog, is_new=True)

        result = prog.add_type(struct)
        assert isinstance(result, StructureType)
        assert result.name == "bar"
        assert result.is_new is True

    def test_adopt_enum(self):
        prog = _make_program()
        et = Pb.EnumType()
        et.name = "myenum"
        et.c_str = "enum myenum { A=0 }"
        et.base_type = BaseType.DOUBLE_WORD
        v = et.values.add()
        v.name = "A"
        v.value = 0
        enum_obj = EnumType(len(prog.proto.types), et, prog, is_new=True)

        result = prog.add_type(enum_obj)
        assert isinstance(result, EnumType)
        assert result.name == "myenum"
        assert result.is_new is True


# ---------------------------------------------------------------------------
# Integration tests (real Program, write -> open round-trip)
# ---------------------------------------------------------------------------

class TestAddTypeRoundTrip:
    """Full integration: add_type() -> write() -> Program.open() -> verify."""

    @pytest.fixture
    def prog_and_tmpdir(self, root_directory: Path):
        binary_path = root_directory / "docs/samples/qb-crackme"
        quokka_path = binary_path.with_suffix(".quokka")
        prog = quokka.Program(quokka_path, binary_path)

        tmpdir = Path(tempfile.mkdtemp(prefix="quokka_test_add_type_"))
        tmp_binary = tmpdir / binary_path.name
        shutil.copy2(binary_path, tmp_binary)
        yield prog, tmpdir, tmp_binary
        shutil.rmtree(tmpdir, ignore_errors=True)

    def _write_and_reload(self, prog, tmpdir, tmp_binary):
        out_path = tmpdir / "out.quokka"
        prog.write(out_path)
        return quokka.Program(out_path, tmp_binary)

    @pytest.mark.parametrize("c_str", [
        "struct test_rt { int x; float y; }",
        "enum test_rt_e { A=0, B=1, C=2 }",
        "typedef int test_rt_td",
        "union test_rt_u { int i; float f; }",
    ])
    def test_c_str_roundtrip(self, prog_and_tmpdir, c_str):
        prog, tmpdir, tmp_binary = prog_and_tmpdir
        original_count = len(prog.proto.types)

        added = prog.add_type(c_str)
        assert isinstance(added, StructureType)

        reloaded = self._write_and_reload(prog, tmpdir, tmp_binary)
        assert len(reloaded.proto.types) == original_count + 1

        rt = reloaded.get_type(added.type_index)
        assert isinstance(rt, StructureType)
        assert rt.name == _hash_name(c_str)
        assert rt.is_new is True
        assert rt.c_str == c_str

    def test_existing_types_unchanged(self, prog_and_tmpdir):
        prog, tmpdir, tmp_binary = prog_and_tmpdir

        existing_samples = [
            (i, type(prog.get_type(i)), getattr(prog.get_type(i), "name", None))
            for i in range(min(20, len(prog.proto.types)))
        ]

        prog.add_type("struct no_corrupt { int z; }")
        reloaded = self._write_and_reload(prog, tmpdir, tmp_binary)

        for idx, cls, name in existing_samples:
            rt = reloaded.get_type(idx)
            assert type(rt) is cls, f"Type at index {idx} changed class"
            if name is not None:
                assert getattr(rt, "name", None) == name, f"Type at index {idx} changed name"

    def test_adopt_type_obj_roundtrip(self, prog_and_tmpdir):
        prog, tmpdir, tmp_binary = prog_and_tmpdir

        ct = Pb.CompositeType()
        ct.name = "adopted_struct"
        ct.type = Pb.CompositeType.TYPE_STRUCT
        ct.c_str = "struct adopted_struct { int a; int b; }"
        struct = StructureType(len(prog.proto.types), ct, prog, is_new=True)

        added = prog.add_type(struct)
        reloaded = self._write_and_reload(prog, tmpdir, tmp_binary)

        rt = reloaded.get_type(added.type_index)
        assert isinstance(rt, StructureType)
        assert rt.name == "adopted_struct"
        assert rt.is_new is True
        assert rt.c_str == "struct adopted_struct { int a; int b; }"
