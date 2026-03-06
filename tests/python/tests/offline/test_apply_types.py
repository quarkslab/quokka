"""Tests for apply_types() with mocked IDA APIs."""

import sys
import types
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# IDA module stubs -- these must be installed before importing ida.py
# ---------------------------------------------------------------------------

def _install_ida_stubs():
    """Create minimal IDA module stubs so the backend can be imported."""
    stubs = {}
    for mod_name in (
        "ida_name", "ida_typeinf",
        "ida_bytes", "ida_funcs", "ida_xref",
    ):
        if mod_name not in sys.modules:
            stubs[mod_name] = MagicMock()
            sys.modules[mod_name] = stubs[mod_name]
    return stubs


_stubs = _install_ida_stubs()

# Now safe to import
from quokka.backends.ida import apply_types, _apply_type
from quokka.data_type import (
    ArrayType, EnumType, PointerType, StructureType, TypedefType, UnionType, BaseType,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_program_with_types(*type_specs):
    """Build a minimal Program-like object with the given types.

    Each type_spec is a tuple (TypeClass, name, is_new, extra_kwargs).
    Returns a mock Program whose .types yields the constructed types.
    """
    from quokka.quokka_pb2 import Quokka as Pb

    q = Pb()
    py_types = []

    for cls, name, is_new, extra in type_specs:
        t = q.types.add()
        t.is_new = is_new

        if cls is EnumType:
            t.enum_type.name = name
            if "c_str" in extra:
                t.enum_type.c_str = extra["c_str"]
            for vname, vval in extra.get("values", []):
                v = t.enum_type.values.add()
                v.name = vname
                v.value = vval
        else:
            t.composite_type.name = name
            if cls is StructureType:
                t.composite_type.type = Pb.CompositeType.TYPE_STRUCT
            elif cls is UnionType:
                t.composite_type.type = Pb.CompositeType.TYPE_UNION
            elif cls is TypedefType:
                t.composite_type.type = Pb.CompositeType.TYPE_TYPEDEF
            elif cls is PointerType:
                t.composite_type.type = Pb.CompositeType.TYPE_POINTER
            elif cls is ArrayType:
                t.composite_type.type = Pb.CompositeType.TYPE_ARRAY
            t.composite_type.size = extra.get("size", 8)
            if "c_str" in extra:
                t.composite_type.c_str = extra["c_str"]

    # Build a mock program that lazily loads from this proto
    import quokka
    prog = MagicMock(spec=quokka.Program)
    prog.proto = q
    # EnumType.__init__ calls program.get_type(proto.base_type) which must
    # return a BaseType.  base_type defaults to 0 == BaseType.UNKNOWN.
    prog.get_type.return_value = BaseType.UNKNOWN

    # Build actual Python type objects
    for idx, (cls, name, is_new, extra) in enumerate(type_specs):
        pb_type = q.types[idx]
        if cls is EnumType:
            py_types.append(cls(idx, pb_type.enum_type, prog, is_new=is_new))
        else:
            py_types.append(cls(idx, pb_type.composite_type, prog, is_new=is_new))

    prog.types = py_types
    return prog


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_ida_mocks():
    """Reset all IDA stub mocks before each test."""
    for mod_name in ("ida_name", "ida_typeinf",
                     "ida_bytes", "ida_funcs", "ida_xref"):
        sys.modules[mod_name].reset_mock()
    yield


def test_apply_types_skips_non_new():
    """Types with is_new=False should not be applied."""
    prog = _make_program_with_types(
        (StructureType, "ExistingStruct", False, {"size": 16}),
    )
    errors = apply_types(prog)
    assert errors == 0


def test_apply_types_enum_with_c_str():
    """A new enum with c_str should use parse_decls into the TIL."""
    prog = _make_program_with_types(
        (EnumType, "NewEnum", True, {
            "values": [("A", 0), ("B", 1)],
            "c_str": "enum NewEnum { A = 0, B = 1 };",
        }),
    )

    ida_typeinf = sys.modules["ida_typeinf"]
    ida_typeinf.get_idati.return_value = MagicMock()
    ida_typeinf.parse_decls.return_value = 0  # success
    ida_typeinf.HTI_DCL = 0

    errors = apply_types(prog)
    assert errors == 0
    ida_typeinf.parse_decls.assert_called_once()


def test_apply_types_enum_no_c_str():
    """An enum without c_str should fail (no manual fallback for enums)."""
    prog = _make_program_with_types(
        (EnumType, "NoStrEnum", True, {"values": [("X", 0)]}),
    )

    errors = apply_types(prog)
    assert errors == 1


def test_apply_types_struct_with_c_str():
    """A new struct with c_str should use parse_decls fast path."""
    prog = _make_program_with_types(
        (StructureType, "NewStruct", True, {
            "size": 8,
            "c_str": "struct NewStruct { int x; int y; };",
        }),
    )

    ida_typeinf = sys.modules["ida_typeinf"]
    ida_typeinf.get_idati.return_value = MagicMock()
    ida_typeinf.parse_decls.return_value = 0  # success
    ida_typeinf.HTI_DCL = 0

    errors = apply_types(prog)
    assert errors == 0
    ida_typeinf.parse_decls.assert_called_once()


def test_apply_types_mixed():
    """Only is_new=True types should be applied; is_new=False skipped."""
    prog = _make_program_with_types(
        (StructureType, "Old", False, {"size": 4}),
        (EnumType, "New", True, {
            "values": [("V", 1)],
            "c_str": "enum New { V = 1 };",
        }),
    )

    ida_typeinf = sys.modules["ida_typeinf"]
    ida_typeinf.get_idati.return_value = MagicMock()
    ida_typeinf.parse_decls.return_value = 0
    ida_typeinf.HTI_DCL = 0

    errors = apply_types(prog)
    assert errors == 0
    # Only the new enum should have been created
    ida_typeinf.parse_decls.assert_called_once()


def test_apply_types_typedef_with_c_str():
    """A new typedef with c_str should use parse_decls."""
    prog = _make_program_with_types(
        (TypedefType, "MyInt", True, {"size": 4, "c_str": "typedef int MyInt;"}),
    )

    ida_typeinf = sys.modules["ida_typeinf"]
    ida_typeinf.get_idati.return_value = MagicMock()
    ida_typeinf.parse_decls.return_value = 0  # success
    ida_typeinf.HTI_DCL = 0

    errors = apply_types(prog)
    assert errors == 0
    ida_typeinf.parse_decls.assert_called_once()


def test_apply_types_pointer_with_c_str():
    """A new pointer type with c_str should use parse_decls."""
    prog = _make_program_with_types(
        (PointerType, "int_ptr", True, {"size": 8, "c_str": "typedef int *int_ptr;"}),
    )

    ida_typeinf = sys.modules["ida_typeinf"]
    ida_typeinf.get_idati.return_value = MagicMock()
    ida_typeinf.parse_decls.return_value = 0
    ida_typeinf.HTI_DCL = 0

    errors = apply_types(prog)
    assert errors == 0
    ida_typeinf.parse_decls.assert_called_once()


def test_apply_types_array_with_c_str():
    """A new array type with c_str should use parse_decls."""
    prog = _make_program_with_types(
        (ArrayType, "int_arr", True, {"size": 40, "c_str": "typedef int int_arr[10];"}),
    )

    ida_typeinf = sys.modules["ida_typeinf"]
    ida_typeinf.get_idati.return_value = MagicMock()
    ida_typeinf.parse_decls.return_value = 0
    ida_typeinf.HTI_DCL = 0

    errors = apply_types(prog)
    assert errors == 0
    ida_typeinf.parse_decls.assert_called_once()


def test_apply_types_no_c_str_error():
    """A typedef/pointer/array with no c_str should return an error."""
    prog = _make_program_with_types(
        (TypedefType, "EmptyTd", True, {"size": 4}),
    )

    errors = apply_types(prog)
    assert errors == 1
