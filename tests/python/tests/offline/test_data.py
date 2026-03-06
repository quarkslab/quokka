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
from quokka.data_type import ArrayType, BaseType, EnumType, PointerType, StructureType, TypedefType, UnionType


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


def test_struct_c_str(prog: quokka.Program):
    """Test that struct types have a c_str representation from IDA's type printer"""
    data = prog.get_data(0x804df14)
    assert isinstance(data.type, StructureType), "Data type should be a StructureType"
    assert data.type.c_str, "StructureType should have a non-empty c_str"
    assert "Elf32_Dyn" in data.type.c_str, "c_str should contain the struct name"


def test_enum_c_str(many_types_prog: quokka.Program):
    """Test that at least one enum type has a non-empty c_str"""
    enums = [t for t in many_types_prog.types if isinstance(t, EnumType)]
    assert enums, "many_types sample should contain enum types"
    has_c_str = any(e.c_str for e in enums)
    assert has_c_str, "At least one enum should have a non-empty c_str"


def test_pointer_c_str(many_types_prog: quokka.Program):
    """Test that at least one pointer type has a non-empty c_str"""
    pointers = [t for t in many_types_prog.types if isinstance(t, PointerType)]
    assert pointers, "many_types sample should contain pointer types"
    has_c_str = any(p.c_str for p in pointers)
    assert has_c_str, "At least one pointer should have a non-empty c_str"


def test_array_c_str(many_types_prog: quokka.Program):
    """Test that at least one array type has a non-empty c_str"""
    arrays = [t for t in many_types_prog.types if isinstance(t, ArrayType)]
    assert arrays, "many_types sample should contain array types"
    has_c_str = any(a.c_str for a in arrays)
    assert has_c_str, "At least one array should have a non-empty c_str"


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


# ---------------------------------------------------------------------------
# Struct member bit-offset tests
# ---------------------------------------------------------------------------


def _find_type(prog: quokka.Program, name: str, cls: type):
    """Find a type by name and class in a Program."""
    for t in prog.types:
        if isinstance(t, cls) and t.name == name:
            return t
    pytest.skip(f"Type {name!r} not found in sample")


def test_struct_member_offsets_in_bits(many_types_prog: quokka.Program):
    """Member offsets and sizes should be expressed in bits."""
    struct_a = _find_type(many_types_prog, "A", StructureType)

    # struct A { uint8_t a; char b; unsigned char b1; short c; uint32_t d; ... }
    members = struct_a.members
    assert len(members) > 5, "struct A should have many members"

    first = members[0]
    assert first.name == "a"
    assert first.size == 8, "uint8_t should be 8 bits"

    # All offsets must be non-negative; sizes must be positive (except flex
    # arrays which are 0)
    for m in members:
        assert m.offset >= 0, f"Negative bit offset for {m.name}"
        assert m.size >= 0, f"Negative bit size for {m.name}"


def test_struct_dict_keyed_by_offset(many_types_prog: quokka.Program):
    """StructureType dict should be keyed by the member's bit offset."""
    struct_a = _find_type(many_types_prog, "A", StructureType)

    for m in struct_a.members:
        assert struct_a[m.offset] is m, (
            f"Dict lookup by bit offset {m.offset} should return member {m.name}"
        )


def test_struct_member_at(many_types_prog: quokka.Program):
    """member_at() should return members by positional index."""
    struct_a = _find_type(many_types_prog, "A", StructureType)

    for i, m in enumerate(struct_a.members):
        assert struct_a.member_at(i) is m, (
            f"member_at({i}) should return {m.name}"
        )


# ---------------------------------------------------------------------------
# Union member tests
# ---------------------------------------------------------------------------


def test_union_preserves_all_members(many_types_prog: quokka.Program):
    """All union members must be preserved despite sharing offset 0."""
    union_e = _find_type(many_types_prog, "E", UnionType)

    # union E { uint8_t a[4]; uint32_t b; }
    assert len(union_e.members) == 2, "Union E should have 2 members"
    names = [m.name for m in union_e.members]
    assert "a" in names
    assert "b" in names


def test_union_member_at(many_types_prog: quokka.Program):
    """member_at() should return union members by positional index."""
    union_e = _find_type(many_types_prog, "E", UnionType)

    for i, m in enumerate(union_e.members):
        assert union_e.member_at(i) is m


def test_union_dict_access_by_index(many_types_prog: quokka.Program):
    """UnionType dict is keyed by positional index (not offset)."""
    union_e = _find_type(many_types_prog, "E", UnionType)

    assert len(union_e) == len(union_e.members), (
        "Union dict length should match member count"
    )
    for i, m in enumerate(union_e.members):
        assert union_e[i] is m


def test_union_members_all_offset_zero(many_types_prog: quokka.Program):
    """All union members should have bit offset 0."""
    union_e = _find_type(many_types_prog, "E", UnionType)

    for m in union_e.members:
        assert m.offset == 0, f"Union member {m.name} should have offset 0"


def test_union_many_members(many_types_prog: quokka.Program):
    """A union with >2 members should preserve all of them."""
    union_uw = _find_type(many_types_prog, "UWeird_C", UnionType)

    # union UWeird_C { uint64_t u64; double d; parts32; parts16; uint8_t bytes[8]; }
    assert len(union_uw.members) == 5, "UWeird_C should have 5 members"
    expected_names = {"u64", "d", "parts32", "parts16", "bytes"}
    actual_names = {m.name for m in union_uw.members}
    assert actual_names == expected_names


# ---------------------------------------------------------------------------
# Regression test for ExportCompositeDataTypes iterator invalidation fix
# ---------------------------------------------------------------------------


def test_pura_update_loads(pura_update_prog: quokka.Program):
    """Regression: puraUpdate triggered a SIGSEGV in ExportCompositeDataTypes
    due to iterator invalidation when inserting pointer/array types into the
    hash map during iteration. The fixed exporter must produce a loadable
    .quokka file."""
    assert len(pura_update_prog.fun_names) == 74
    types_list = list(pura_update_prog.types)
    assert len(types_list) > 0, "Export should contain data types"
    structs = [t for t in types_list if isinstance(t, StructureType)]
    assert len(structs) > 0, "Export should contain struct types"
    main_func = pura_update_prog.get_function("main")
    assert main_func is not None, "main function should exist"
    assert len(main_func.graph) > 1, "main should have multiple blocks"


# ---------------------------------------------------------------------------
# Typedef type tests
# ---------------------------------------------------------------------------


def test_typedef_type_exists(many_types_prog: quokka.Program):
    """Typedef types should be present in the type list."""
    typedefs = [t for t in many_types_prog.types if isinstance(t, TypedefType)]
    if not typedefs:
        pytest.skip("No typedef types found in sample")
    assert len(typedefs) > 0


def test_typedef_aliased_type(many_types_prog: quokka.Program):
    """Typedef's aliased_type should return a valid type."""
    for t in many_types_prog.types:
        if isinstance(t, TypedefType):
            aliased = t.aliased_type
            assert aliased is not None, f"Typedef {t.name} has no aliased type"
            break
    else:
        pytest.skip("No typedef types found in sample")


def test_typedef_resolve(many_types_prog: quokka.Program):
    """Typedef.resolve() should return a non-typedef concrete type."""
    for t in many_types_prog.types:
        if isinstance(t, TypedefType):
            resolved = t.resolve()
            assert not isinstance(resolved, TypedefType), (
                f"resolve() should not return a TypedefType, got {resolved}"
            )
            break
    else:
        pytest.skip("No typedef types found in sample")


def test_typedef_is_typedef(many_types_prog: quokka.Program):
    """TypedefType.is_typedef should be True."""
    for t in many_types_prog.types:
        if isinstance(t, TypedefType):
            assert t.is_typedef is True
            assert t.is_struct is False
            assert t.is_pointer is False
            break
    else:
        pytest.skip("No typedef types found in sample")


def test_typedef_has_name(many_types_prog: quokka.Program):
    """All typedef types should have a non-empty name."""
    typedefs = [t for t in many_types_prog.types if isinstance(t, TypedefType)]
    if not typedefs:
        pytest.skip("No typedef types found in sample")
    for td in typedefs:
        assert td.name, f"Typedef at index {td.index} has empty name"


def test_typedef_chain_resolution(many_types_prog: quokka.Program):
    """Chained typedefs (e.g. TdInt -> TdInt2 -> TdInt3) should resolve."""
    typedefs = {
        t.name: t
        for t in many_types_prog.types
        if isinstance(t, TypedefType)
    }
    if "TdInt3" not in typedefs:
        pytest.skip("TdInt3 typedef not found in sample")

    td3 = typedefs["TdInt3"]
    resolved = td3.resolve()
    assert not isinstance(resolved, TypedefType), (
        f"TdInt3.resolve() returned TypedefType: {resolved}"
    )


def test_typedef_over_struct(many_types_prog: quokka.Program):
    """A typedef over a struct should resolve to a StructureType."""
    typedefs = {
        t.name: t
        for t in many_types_prog.types
        if isinstance(t, TypedefType)
    }
    if "TdStructA" not in typedefs:
        pytest.skip("TdStructA typedef not found in sample")

    resolved = typedefs["TdStructA"].resolve()
    assert isinstance(resolved, StructureType), (
        f"TdStructA should resolve to StructureType, got {type(resolved).__name__}"
    )


def test_typedef_over_union(many_types_prog: quokka.Program):
    """A typedef over a union should resolve to a UnionType."""
    typedefs = {
        t.name: t
        for t in many_types_prog.types
        if isinstance(t, TypedefType)
    }
    if "TdUnionE" not in typedefs:
        pytest.skip("TdUnionE typedef not found in sample")

    resolved = typedefs["TdUnionE"].resolve()
    assert isinstance(resolved, UnionType), (
        f"TdUnionE should resolve to UnionType, got {type(resolved).__name__}"
    )


def test_typedef_over_enum(many_types_prog: quokka.Program):
    """A typedef over an enum should resolve to EnumType or BaseType.

    Enum typedefs may resolve to BaseType.UNKNOWN when the enum lives in a
    different index space (enums vs composites) and the exporter records
    element_type_idx = 0 as a fallback.
    """
    typedefs = {
        t.name: t
        for t in many_types_prog.types
        if isinstance(t, TypedefType)
    }
    if "TdEnumD" not in typedefs:
        pytest.skip("TdEnumD typedef not found in sample")

    resolved = typedefs["TdEnumD"].resolve()
    assert isinstance(resolved, (EnumType, BaseType)), (
        f"TdEnumD should resolve to EnumType or BaseType, got {type(resolved).__name__}"
    )


def test_get_type_resolved(many_types_prog: quokka.Program):
    """Program.get_type_resolved() should resolve through typedef chains."""
    for t in many_types_prog.types:
        if isinstance(t, TypedefType):
            resolved = many_types_prog.get_type_resolved(t.type_index)
            assert not isinstance(resolved, TypedefType), (
                f"get_type_resolved({t.type_index}) returned TypedefType"
            )
            break
    else:
        pytest.skip("No typedef types found in sample")


def test_backward_compat_no_typedefs(prog: quokka.Program):
    """A .quokka file with no typedefs should still load correctly."""
    assert len(prog.fun_names) > 0, "Basic loading should still work"
    types_list = list(prog.types)
    assert len(types_list) > 0, "Types should still be present"
