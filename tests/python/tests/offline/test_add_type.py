"""Tests for Program.add_type()."""

import pytest
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import quokka
from quokka.quokka_pb2 import Quokka as Pb
from quokka.data_type import (
    BaseType, EnumType, StructureType, UnionType, TypedefType,
)
from quokka.exc import QuokkaError


def _make_program():
    """Build a minimal mock Program with primitive types pre-populated."""
    prog = MagicMock(spec=quokka.Program)
    prog.proto = Pb()
    prog.address_size = 8

    # Populate the 9 primitive types (indices 0-8)
    for i in range(9):
        t = prog.proto.types.add()
        t.primitive_type = i

    # Wire up real methods
    prog._types = {}
    prog.get_type = lambda idx, member_index=-1: quokka.Program.get_type(prog, idx, member_index)
    prog.get_type_reference = lambda idx, member_index=-1: quokka.Program.get_type_reference(prog, idx, member_index)
    prog.add_type = lambda *args, **kwargs: quokka.Program.add_type(prog, *args, **kwargs)

    return prog


# ---------------------------------------------------------------------------
# Unit tests (mock program)
# ---------------------------------------------------------------------------

class TestAddTypeFromCStr:
    def test_struct(self):
        prog = _make_program()
        result = prog.add_type("struct foo { int x; float y; }")
        assert isinstance(result, StructureType)
        assert result.name == "foo"
        assert result.is_new is True

    def test_enum(self):
        prog = _make_program()
        result = prog.add_type("enum color { RED=0, GREEN=1, BLUE=2 }")
        assert isinstance(result, EnumType)
        assert result.name == "color"
        assert result.is_new is True

    def test_typedef(self):
        prog = _make_program()
        result = prog.add_type("typedef int myint")
        assert isinstance(result, TypedefType)
        assert result.name == "myint"
        assert result.is_new is True

    def test_union(self):
        prog = _make_program()
        result = prog.add_type("union data { int i; float f; }")
        assert isinstance(result, UnionType)
        assert result.name == "data"
        assert result.is_new is True


class TestAddTypeFromObject:
    def test_adopt_struct(self):
        prog = _make_program()
        ct = Pb.CompositeType()
        ct.name = "bar"
        ct.type = Pb.CompositeType.TYPE_STRUCT
        ct.c_str = "struct bar { int a; }"
        idx = len(prog.proto.types)
        struct = StructureType(idx, ct, prog, is_new=True)

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

        idx = len(prog.proto.types)
        enum_obj = EnumType(idx, et, prog, is_new=True)

        result = prog.add_type(enum_obj)
        assert isinstance(result, EnumType)
        assert result.name == "myenum"
        assert result.is_new is True


class TestAddTypeErrors:
    def test_invalid_arg_type(self):
        prog = _make_program()
        with pytest.raises(AssertionError, match="Invalid type argument"):
            prog.add_type(...)

    def test_duplicate_name(self):
        prog = _make_program()
        prog.add_type("struct dup { int x; }")
        with pytest.raises(QuokkaError, match="already exists"):
            prog.add_type("struct dup { float y; }")

    def test_unsupported_decl(self):
        prog = _make_program()
        with pytest.raises(ValueError, match="Unsupported"):
            prog.add_type("int x")


class TestAddTypeUnitIntegration:
    def test_new_type_in_types_iteration(self):
        prog = _make_program()
        prog.add_type("struct iter_test { int a; }")

        found = False
        for i in range(len(prog.proto.types)):
            t = prog.get_type(i)
            if isinstance(t, StructureType) and t.name == "iter_test":
                found = True
                break
        assert found

    def test_new_type_accessible_via_get_type(self):
        prog = _make_program()
        result = prog.add_type("enum access_test { X=1 }")
        idx = result.type_index
        retrieved = prog.get_type(idx)
        assert retrieved is result

    def test_c_str_preserved(self):
        prog = _make_program()
        decl = "struct preserved { int x; }"
        result = prog.add_type(decl)
        assert result.c_str == decl


# ---------------------------------------------------------------------------
# Integration tests (real Program, write -> open round-trip)
# ---------------------------------------------------------------------------

class TestAddTypeRoundTrip:
    """Full integration: add_type() -> write() -> Program.open() -> verify."""

    @pytest.fixture
    def prog_and_tmpdir(self, root_directory: Path):
        """Load the qb-crackme program and prepare a temp dir for writes."""
        binary_path = root_directory / "docs/samples/qb-crackme"
        quokka_path = binary_path.with_suffix(".quokka")
        prog = quokka.Program(quokka_path, binary_path)

        tmpdir = Path(tempfile.mkdtemp(prefix="quokka_test_add_type_"))
        # Copy the binary so the reloaded Program can hash-check against it
        tmp_binary = tmpdir / binary_path.name
        shutil.copy2(binary_path, tmp_binary)
        yield prog, tmpdir, tmp_binary
        shutil.rmtree(tmpdir, ignore_errors=True)

    def _write_and_reload(self, prog, tmpdir, tmp_binary):
        """Write the program to a temp .quokka and reload it."""
        out_path = tmpdir / "out.quokka"
        prog.write(out_path)
        return quokka.Program(out_path, tmp_binary)

    def test_struct_roundtrip(self, prog_and_tmpdir):
        prog, tmpdir, tmp_binary = prog_and_tmpdir
        original_type_count = len(prog.proto.types)

        added = prog.add_type("struct test_rt_struct { int x; float y; }")
        assert isinstance(added, StructureType)

        reloaded = self._write_and_reload(prog, tmpdir, tmp_binary)
        assert len(reloaded.proto.types) == original_type_count + 1

        rt = reloaded.get_type(added.type_index)
        assert isinstance(rt, StructureType)
        assert rt.name == "test_rt_struct"
        assert rt.is_new is True
        assert rt.c_str == "struct test_rt_struct { int x; float y; }"

    def test_enum_roundtrip(self, prog_and_tmpdir):
        prog, tmpdir, tmp_binary = prog_and_tmpdir

        added = prog.add_type("enum test_rt_enum { A=0, B=1, C=2 }")
        assert isinstance(added, EnumType)

        reloaded = self._write_and_reload(prog, tmpdir, tmp_binary)
        rt = reloaded.get_type(added.type_index)
        assert isinstance(rt, EnumType)
        assert rt.name == "test_rt_enum"
        assert rt.is_new is True
        assert rt.c_str == "enum test_rt_enum { A=0, B=1, C=2 }"

    def test_typedef_roundtrip(self, prog_and_tmpdir):
        prog, tmpdir, tmp_binary = prog_and_tmpdir

        added = prog.add_type("typedef int test_rt_td")
        assert isinstance(added, TypedefType)

        reloaded = self._write_and_reload(prog, tmpdir, tmp_binary)
        rt = reloaded.get_type(added.type_index)
        assert isinstance(rt, TypedefType)
        assert rt.name == "test_rt_td"
        assert rt.is_new is True

    def test_union_roundtrip(self, prog_and_tmpdir):
        prog, tmpdir, tmp_binary = prog_and_tmpdir

        added = prog.add_type("union test_rt_union { int i; float f; }")
        assert isinstance(added, UnionType)

        reloaded = self._write_and_reload(prog, tmpdir, tmp_binary)
        rt = reloaded.get_type(added.type_index)
        assert isinstance(rt, UnionType)
        assert rt.name == "test_rt_union"
        assert rt.is_new is True

    def test_multiple_types_roundtrip(self, prog_and_tmpdir):
        """Add several types at once, verify all survive the round-trip."""
        prog, tmpdir, tmp_binary = prog_and_tmpdir
        original_type_count = len(prog.proto.types)

        s = prog.add_type("struct multi_s { int a; }")
        e = prog.add_type("enum multi_e { X=10, Y=20 }")
        t = prog.add_type("typedef int multi_t")

        reloaded = self._write_and_reload(prog, tmpdir, tmp_binary)
        assert len(reloaded.proto.types) == original_type_count + 3

        rs = reloaded.get_type(s.type_index)
        assert isinstance(rs, StructureType) and rs.name == "multi_s"
        re_ = reloaded.get_type(e.type_index)
        assert isinstance(re_, EnumType) and re_.name == "multi_e"
        rt = reloaded.get_type(t.type_index)
        assert isinstance(rt, TypedefType) and rt.name == "multi_t"

        # All must be is_new
        assert rs.is_new and re_.is_new and rt.is_new

    def test_existing_types_unchanged(self, prog_and_tmpdir):
        """Adding a new type must not corrupt the pre-existing types."""
        prog, tmpdir, tmp_binary = prog_and_tmpdir

        # Snapshot a few existing types before adding
        existing_samples = []
        for i in range(min(20, len(prog.proto.types))):
            t = prog.get_type(i)
            existing_samples.append((i, type(t), getattr(t, "name", None)))

        prog.add_type("struct no_corrupt { int z; }")
        reloaded = self._write_and_reload(prog, tmpdir, tmp_binary)

        for idx, cls, name in existing_samples:
            rt = reloaded.get_type(idx)
            assert type(rt) is cls, f"Type at index {idx} changed class"
            if name is not None:
                assert getattr(rt, "name", None) == name, (
                    f"Type at index {idx} changed name"
                )

    def test_new_type_visible_in_types_property(self, prog_and_tmpdir):
        """The new type must appear when iterating Program.types."""
        prog, tmpdir, tmp_binary = prog_and_tmpdir

        prog.add_type("struct visible_check { int v; }")
        reloaded = self._write_and_reload(prog, tmpdir, tmp_binary)

        names = [
            t.name for t in reloaded.types
            if hasattr(t, "name") and isinstance(t, StructureType)
        ]
        assert "visible_check" in names

    def test_adopt_type_obj_roundtrip(self, prog_and_tmpdir):
        """add_type(...) should also survive write -> open."""
        prog, tmpdir, tmp_binary = prog_and_tmpdir

        ct = Pb.CompositeType()
        ct.name = "adopted_struct"
        ct.type = Pb.CompositeType.TYPE_STRUCT
        ct.c_str = "struct adopted_struct { int a; int b; }"
        # Use a temporary index just for constructing the wrapper
        tmp_idx = len(prog.proto.types)
        struct = StructureType(tmp_idx, ct, prog, is_new=True)

        added = prog.add_type(struct)
        reloaded = self._write_and_reload(prog, tmpdir, tmp_binary)

        rt = reloaded.get_type(added.type_index)
        assert isinstance(rt, StructureType)
        assert rt.name == "adopted_struct"
        assert rt.is_new is True
        assert rt.c_str == "struct adopted_struct { int a; int b; }"
