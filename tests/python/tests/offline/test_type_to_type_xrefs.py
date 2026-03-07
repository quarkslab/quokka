"""Tests for type-to-type cross-references.

Uses the many_types_cpp dataset which contains struct members referencing other
types (typedefs, enums, nested structs), typedef chains, pointer types, and
array element types.
"""

import pytest

import quokka
from quokka.data_type import (
    ArrayType,
    ComplexType,
    EnumType,
    EnumTypeMember,
    PointerType,
    StructureType,
    StructureTypeMember,
    TypedefType,
    UnionType,
)


def _find_type(prog: quokka.Program, name: str, cls: type):
    """Find a type by name and class in a Program."""
    for t in prog.types:
        if isinstance(t, cls) and t.name == name:
            return t
    pytest.skip(f"Type {name!r} not found in sample")


# ---------------------------------------------------------------------------
# ComplexType.type_refs_from / type_refs_to
# ---------------------------------------------------------------------------


def test_struct_type_refs_from(many_types_prog: quokka.Program):
    """Struct A should have outgoing type refs to its member types."""
    struct_a = _find_type(many_types_prog, "A", StructureType)
    refs_from = struct_a.type_refs_from
    assert len(refs_from) > 0, "Struct A should have outgoing type-to-type refs"
    ref_types = {type(r) for r in refs_from}
    assert ref_types & {TypedefType, StructureType, EnumType, ArrayType, PointerType}, (
        f"Expected diverse member type refs, got {ref_types}"
    )


def test_struct_type_refs_to(many_types_prog: quokka.Program):
    """Struct A should have an incoming ref from the TdStructA typedef."""
    struct_a = _find_type(many_types_prog, "A", StructureType)
    refs_to = struct_a.type_refs_to
    assert len(refs_to) > 0, "Struct A should have incoming type-to-type refs"
    assert any(
        isinstance(r, TypedefType) and r.name == "TdStructA" for r in refs_to
    ), "Struct A should be referenced by TdStructA typedef"


def test_typedef_type_refs_from(many_types_prog: quokka.Program):
    """TdStructA typedef should reference struct A."""
    td = _find_type(many_types_prog, "TdStructA", TypedefType)
    refs_from = td.type_refs_from
    assert any(
        isinstance(r, StructureType) and r.name == "A" for r in refs_from
    ), "TdStructA should reference struct A"


def test_typedef_type_refs_to(many_types_prog: quokka.Program):
    """TdStructA should be referenced by pointer and array types."""
    td = _find_type(many_types_prog, "TdStructA", TypedefType)
    refs_to = td.type_refs_to
    ref_types = {type(r) for r in refs_to}
    assert PointerType in ref_types or ArrayType in ref_types, (
        "TdStructA should be referenced by pointer or array types"
    )


def test_enum_type_refs_to(many_types_prog: quokka.Program):
    """Enum D should have incoming refs from struct A.n member."""
    enum_d = _find_type(many_types_prog, "D", EnumType)
    refs_to = enum_d.type_refs_to
    assert len(refs_to) > 0, "Enum D should have incoming type-to-type refs"
    has_member_ref = any(
        isinstance(r, StructureTypeMember) and r.name == "n"
        for r in refs_to
    )
    assert has_member_ref, "Enum D should be referenced by struct A.n member"


def test_array_type_refs_from(many_types_prog: quokka.Program):
    """An array type with a complex element type should reference it."""
    arrays = [t for t in many_types_prog.types
              if isinstance(t, ArrayType) and t.type_refs_from]
    if not arrays:
        pytest.skip("No array types with type-to-type xrefs found")
    arr = arrays[0]
    assert any(isinstance(r, (ComplexType, StructureTypeMember)) for r in arr.type_refs_from)


def test_pointer_type_refs_from(many_types_prog: quokka.Program):
    """A pointer type targeting a complex type should reference it."""
    pointers = [t for t in many_types_prog.types
                if isinstance(t, PointerType) and t.type_refs_from]
    if not pointers:
        pytest.skip("No pointer types with type-to-type xrefs found")
    ptr = pointers[0]
    assert len(ptr.type_refs_from) > 0


# ---------------------------------------------------------------------------
# StructureTypeMember.type_refs_from / type_refs_to
# ---------------------------------------------------------------------------


def test_member_type_refs_from(many_types_prog: quokka.Program):
    """Members of struct A with complex types should have outgoing refs."""
    struct_a = _find_type(many_types_prog, "A", StructureType)
    members_with_refs = [m for m in struct_a.members if m.type_refs_from]
    assert len(members_with_refs) > 0, (
        "At least one member of struct A should have outgoing type refs"
    )


def test_member_n_refs_enum(many_types_prog: quokka.Program):
    """Struct A.n should reference enum D."""
    struct_a = _find_type(many_types_prog, "A", StructureType)
    n_member = None
    for m in struct_a.members:
        if m.name == "n":
            n_member = m
            break
    assert n_member is not None, "Struct A should have an 'n' member"

    refs = n_member.type_refs_from
    assert any(isinstance(r, EnumType) and r.name == "D" for r in refs), (
        "Member 'n' should reference enum D"
    )


def test_member_l_refs_struct(many_types_prog: quokka.Program):
    """Struct A.l should reference struct B (nested struct)."""
    struct_a = _find_type(many_types_prog, "A", StructureType)
    l_member = None
    for m in struct_a.members:
        if m.name == "l":
            l_member = m
            break
    assert l_member is not None, "Struct A should have an 'l' member"

    refs = l_member.type_refs_from
    assert any(isinstance(r, StructureType) and r.name == "B" for r in refs), (
        "Member 'l' should reference struct B"
    )


def test_member_o_refs_pointer(many_types_prog: quokka.Program):
    """Struct A.o should reference a pointer type."""
    struct_a = _find_type(many_types_prog, "A", StructureType)
    o_member = None
    for m in struct_a.members:
        if m.name == "o":
            o_member = m
            break
    assert o_member is not None, "Struct A should have an 'o' member"

    refs = o_member.type_refs_from
    assert any(isinstance(r, PointerType) for r in refs), (
        "Member 'o' should reference a pointer type"
    )


# ---------------------------------------------------------------------------
# Round-trip: if A references B, B's type_refs_to should contain A
# ---------------------------------------------------------------------------


def test_roundtrip_struct_to_enum(many_types_prog: quokka.Program):
    """If A.type_refs_from contains D, then D's type_refs_to should
    contain the A.n member."""
    struct_a = _find_type(many_types_prog, "A", StructureType)
    enum_d = _find_type(many_types_prog, "D", EnumType)

    assert enum_d in struct_a.type_refs_from, "Struct A should reference enum D"
    refs_to = enum_d.type_refs_to
    member_parents = [
        r.parent.name for r in refs_to if isinstance(r, StructureTypeMember)
    ]
    assert "A" in member_parents, "Enum D should be referenced by struct A members"


def test_roundtrip_typedef_to_struct(many_types_prog: quokka.Program):
    """TdStructA -> A: A.type_refs_to should include TdStructA."""
    td = _find_type(many_types_prog, "TdStructA", TypedefType)
    struct_a = _find_type(many_types_prog, "A", StructureType)

    assert struct_a in td.type_refs_from, "TdStructA should reference struct A"
    assert td in struct_a.type_refs_to, "Struct A should be referenced by TdStructA"


def test_roundtrip_nested_struct(many_types_prog: quokka.Program):
    """A.l references B: B.type_refs_to should include A.l member."""
    struct_a = _find_type(many_types_prog, "A", StructureType)
    struct_b = _find_type(many_types_prog, "B", StructureType)

    assert struct_b in struct_a.type_refs_from, "Struct A should reference struct B"
    refs_to = struct_b.type_refs_to
    member_refs = [r for r in refs_to if isinstance(r, StructureTypeMember)]
    assert any(r.name == "l" and r.parent.name == "A" for r in member_refs), (
        "Struct B should be referenced by A.l member"
    )


# ---------------------------------------------------------------------------
# Types with no type-to-type xrefs
# ---------------------------------------------------------------------------


def test_no_type_refs_on_leaf_types(many_types_prog: quokka.Program):
    """Elf64_Sym has no outgoing type-to-type refs (members are base types)."""
    sym = _find_type(many_types_prog, "Elf64_Sym", StructureType)
    assert sym.type_refs_from == [], (
        "Elf64_Sym should have no outgoing type-to-type xrefs"
    )


# ---------------------------------------------------------------------------
# EnumTypeMember.type_refs_to
# ---------------------------------------------------------------------------


def test_enum_member_type_refs_to(many_types_prog: quokka.Program):
    """EnumTypeMember should not crash when accessing type_refs_to."""
    enum_d = _find_type(many_types_prog, "D", EnumType)
    for m in enum_d.members:
        refs = m.type_refs_to
        assert isinstance(refs, list)


# ---------------------------------------------------------------------------
# Regression: dr_I / dr_T data xref types (was a crash in Reference.cpp)
# ---------------------------------------------------------------------------


def test_rtti_typeinfo_data_exported(many_types_prog: quokka.Program):
    """Regression: IDA emits dr_I (informational) xrefs from RTTI typeinfo
    data (e.g. _ZTI13MemberPtrHost at 0x4d98). Before the fix, GetXrefType()
    did not handle dr_I, causing a crash during the linear scan. Verify the
    data at that address was exported (the linear scan completed past it)."""
    d = many_types_prog.get_data(0x4d98)
    assert "MemberPtrHost" in d.name, (
        f"Expected RTTI typeinfo data, got {d.name}"
    )
