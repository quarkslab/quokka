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

"""Ghidra export integration tests.

These tests exercise the full Ghidra export pipeline: they invoke Ghidra
headlessly to export a binary and then validate the resulting .quokka
through the Python frontend.  They are skipped when Ghidra is not available.

Mirrors the IDA integration tests in tests/python/tests/ida/test_ida_export.py
with strict assertions matching the types defined in many_types.cpp / many_types.c.

Known Ghidra-vs-IDA differences accounted for in these tests:
- Ghidra may miss volatile-qualified struct members (e.g. ``volatile uint32_t g``)
"""

from pathlib import Path

import pytest

import quokka
from quokka.data_type import StructureType, EnumType
from quokka import quokka_pb2 as Pb

from .conftest import requires_ghidra, ghidra_headless_export


# ---------------------------------------------------------------------------
# Shared export fixtures (class-scoped to avoid re-exporting per test)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="class")
def pura_update_ghidra_prog(root_directory: Path, tmp_path_factory):
    """Export puraUpdate through Ghidra once for the entire class."""
    binary = root_directory / "tests" / "dataset" / "puraUpdate"
    if not binary.exists():
        pytest.skip("puraUpdate binary not found in tests/dataset/")

    tmp = tmp_path_factory.mktemp("pura_update_ghidra")
    output = tmp / "puraUpdate.quokka"
    ghidra_headless_export(binary, output, root_directory)
    return quokka.Program(output, binary)


@pytest.fixture(scope="class")
def many_types_ghidra_prog(root_directory: Path, tmp_path_factory):
    """Export many_types_cpp through Ghidra once for the entire class."""
    binary = root_directory / "tests" / "dataset" / "many_types_cpp"
    if not binary.exists():
        pytest.skip("many_types_cpp binary not found in tests/dataset/")

    tmp = tmp_path_factory.mktemp("many_types_ghidra")
    output = tmp / "many_types_cpp.quokka"
    ghidra_headless_export(binary, output, root_directory)
    return quokka.Program(output, binary)


# ---------------------------------------------------------------------------
# puraUpdate: basic export validation (ARM 32-bit)
# ---------------------------------------------------------------------------


@requires_ghidra
class TestPuraUpdateGhidraExport:
    """Export the puraUpdate ARM binary through Ghidra and validate output.

    Mirrors TestPuraUpdateExport from the IDA test suite.
    """

    @pytest.fixture(autouse=True)
    def _setup(self, pura_update_ghidra_prog):
        self.prog = pura_update_ghidra_prog

    def test_export_produces_program(self):
        assert self.prog is not None

    def test_function_count(self):
        # Ghidra discovers 68 functions vs IDA's 113.
        assert len(self.prog.fun_names) == 68

    def test_has_types(self):
        types_list = list(self.prog.types)
        assert len(types_list) > 0, "Export should contain data types"

    def test_has_structs(self):
        structs = [t for t in self.prog.types if isinstance(t, StructureType)]
        assert len(structs) > 0, "Export should contain struct types"

    def test_has_segments(self):
        assert len(self.prog.segments) > 0, "Export should contain segments"

    def test_meta_is_arm_32(self):
        assert self.prog.isa == quokka.analysis.ArchEnum.ARM
        assert self.prog.address_size == 32

    def test_disassembler_is_ghidra(self):
        # DISASS_GHIDRA = 2 in the proto enum
        assert self.prog.proto.meta.backend.name == 2

    def test_has_normal_function_with_blocks(self):
        """At least one NORMAL function should have multiple blocks."""
        from quokka.types import FunctionType

        for func in self.prog.values():
            if func.type != FunctionType.NORMAL:
                continue
            if len(func.graph) > 1:
                return
        pytest.fail("No NORMAL function with >1 block found")


# ---------------------------------------------------------------------------
# many_types_cpp: comprehensive type system validation
# ---------------------------------------------------------------------------


@requires_ghidra
class TestManyTypesCppGhidraExport:
    """Export many_types_cpp through Ghidra and validate types.

    Mirrors TestManyTypesCppExport from the IDA test suite with strict
    assertions matching the types defined in many_types.cpp / many_types.c.
    """

    @pytest.fixture(autouse=True)
    def _setup(self, many_types_ghidra_prog):
        self.prog = many_types_ghidra_prog

    # -- Proto-level helpers ------------------------------------------------

    TYPE_TYPEDEF = Pb.Quokka.CompositeType.CompositeSubType.TYPE_TYPEDEF
    TYPE_STRUCT = Pb.Quokka.CompositeType.CompositeSubType.TYPE_STRUCT
    TYPE_UNION = Pb.Quokka.CompositeType.CompositeSubType.TYPE_UNION
    TYPE_POINTER = Pb.Quokka.CompositeType.CompositeSubType.TYPE_POINTER
    TYPE_ARRAY = Pb.Quokka.CompositeType.CompositeSubType.TYPE_ARRAY

    def _find_typedef(self, name):
        """Return (type_index, CompositeType) for the first typedef with *name*."""
        for i, t in enumerate(self.prog.proto.types):
            if t.WhichOneof("OneofType") == "composite_type":
                ct = t.composite_type
                if ct.type == self.TYPE_TYPEDEF and ct.name == name:
                    return i, ct
        return None, None

    def _find_composite(self, name, subtype=None):
        """Return (type_index, CompositeType) for a composite with *name*.

        If *subtype* is given, restrict to that CompositeSubType.
        """
        for i, t in enumerate(self.prog.proto.types):
            if t.WhichOneof("OneofType") == "composite_type":
                ct = t.composite_type
                if ct.name == name and (subtype is None or ct.type == subtype):
                    return i, ct
        return None, None

    def _type_at(self, idx):
        """Return the raw Type proto at *idx*."""
        return self.prog.proto.types[idx]

    def _is_composite_of(self, type_proto, subtype):
        """True when *type_proto* is a composite of the given *subtype*."""
        return (
            type_proto.WhichOneof("OneofType") == "composite_type"
            and type_proto.composite_type.type == subtype
        )

    def _is_primitive(self, type_proto, base=None):
        """True when *type_proto* is a primitive, optionally of a given BaseType."""
        if type_proto.WhichOneof("OneofType") != "primitive_type":
            return False
        if base is not None:
            return type_proto.primitive_type == base
        return True

    def _find_data_by_name(self, name):
        """Return the first Data proto whose name ends with *name*."""
        for d in self.prog.proto.data:
            if d.name == name or d.name.endswith(name):
                return d
        return None

    def _find_member(self, composite, name):
        """Return the Member proto with *name* in *composite*, or None."""
        for m in composite.members:
            if m.name == name:
                return m
        return None

    def _follow_typedef_element(self, name):
        """Return (typedef_ct, element_type_proto) for typedef *name*."""
        _, ct = self._find_typedef(name)
        if ct is None:
            pytest.fail(f"{name} typedef not found in export")
        target = self._type_at(ct.element_type_idx)
        return ct, target

    # -- Basic sanity checks -----------------------------------------------

    def test_export_produces_program(self):
        assert self.prog is not None

    def test_has_types(self):
        types_list = list(self.prog.types)
        assert len(types_list) > 0, "Export should contain data types"

    def test_has_structs(self):
        structs = [t for t in self.prog.types if isinstance(t, StructureType)]
        assert len(structs) > 0, "Export should contain struct types"

    def test_has_enums(self):
        enums = [t for t in self.prog.types if isinstance(t, EnumType)]
        assert len(enums) > 0, "Export should contain enum types"

    def test_has_segments(self):
        assert len(self.prog.segments) > 0, "Export should contain segments"

    def test_main_function_exists(self):
        main_func = self.prog.get_function("main")
        assert main_func is not None, "main function should exist"

    def test_disassembler_is_ghidra(self):
        assert self.prog.proto.meta.backend.name == 2  # DISASS_GHIDRA

    def test_mode_is_light(self):
        assert self.prog.proto.exporter_meta.mode == 0  # MODE_LIGHT

    # -- Primitive type invariants -----------------------------------------

    def test_primitive_types_at_indices_0_through_8(self):
        """Indices 0-8 must be primitive types (proto contract)."""
        types = self.prog.proto.types
        for i in range(9):
            assert types[i].HasField(
                "primitive_type"
            ), f"Type at index {i} should be primitive"

    def test_primitive_type_order(self):
        """Primitive type at index i must have enum value i."""
        types = self.prog.proto.types
        for i in range(9):
            assert (
                types[i].primitive_type == i
            ), f"Type at index {i} should have value {i}"

    # -- Segment checks ----------------------------------------------------

    def test_segments_sorted_by_va(self):
        segs = self.prog.proto.segments
        for i in range(1, len(segs)):
            assert (
                segs[i].virtual_addr >= segs[i - 1].virtual_addr
            ), "Segments must be sorted by virtual address"

    def test_segments_have_names(self):
        for seg in self.prog.proto.segments:
            assert seg.name, "Each segment must have a name"

    # -- Typedef structural invariants -------------------------------------

    def test_typedef_entries_in_proto(self):
        """Verify that TYPE_TYPEDEF entries appear in the raw protobuf."""
        typedef_count = 0
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "composite_type":
                if t.composite_type.type == self.TYPE_TYPEDEF:
                    typedef_count += 1
        assert (
            typedef_count > 0
        ), "many_types_cpp should export at least one typedef entry"

    def test_typedef_names(self):
        """Verify known typedefs from many_types.c are present."""
        known_typedefs = {
            # Original typedef chains
            "U32",
            "PU32",
            "PCU32",
            "PPCU32",
            "CPPCU32",
            # struct/union/enum alias
            "C",
            # Function-pointer typedefs
            "Fn1_C",
            "Fn2_C",
            "VoidFn_C",
            # Function-pointer array / complex declarator typedefs
            "FnArr3_C",
            "PtrToFnArr3_C",
            "FnReturningPtrArr_C",
            "FnTakesPtrToArr_C",
            # Typedef over primitive
            "TdInt",
            "TdByte",
            "TdFloat",
            "TdDouble",
            # Typedef chain over primitive
            "TdInt2",
            "TdInt3",
            # Typedef over struct/union/enum
            "TdStructA",
            "TdStructB",
            "TdUnionE",
            "TdUWeird",
            "TdEnumD",
            # Typedef over array
            "TdIntArr5",
            "TdU32Arr3",
            "TdCharBuf",
            # Typedef over array of typedef
            "TdIntArr4",
            "TdByteArr8",
            "TdStructAArr2",
            "TdUnionEArr3",
            "TdEnumDArr3",
            # Typedef chain over array
            "TdIntArr5Alias",
            # Typedef over pointer to primitive
            "TdIntPtr",
            "TdConstIntPtr",
            "TdFloatPtr",
            "TdDoublePtr",
            "TdBoolPtr",
            # Typedef over pointer to typedef
            "TdTdIntPtr",
            "TdTdFloatPtr",
            "TdTdBytePtr",
            "TdConstTdIntPtr",
            "TdTdIntPtrPtr",
            # Typedef over pointer to typedef struct/union/enum
            "TdStructAPtr",
            "TdConstStructAPtr",
            "TdUnionEPtr",
            "TdEnumDPtr",
            # Typedef over pointer to array
            "TdPtrToIntArr4",
            "TdPtrToU32Arr3",
            # Typedef over pointer to typedef-array
            "TdPtrToTdIntArr5",
            "TdPtrToTdIntArr4",
            # Typedef over pointer to pointer
            "TdIntPtrPtr",
            "TdIntPtrPtrPtr",
            "TdConstPtrConstInt",
            # Typedef over pointer to pointer to typedef
            "TdTdIntPtrPtr2",
            "TdTdIntPtrPtrPtr",
            # Typedef chain over pointer
            "TdIntPtr2",
            "TdIntPtr3",
        }
        found = set()
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "composite_type":
                ct = t.composite_type
                if ct.type == self.TYPE_TYPEDEF:
                    found.add(ct.name)
        missing = known_typedefs - found
        assert not missing, f"Expected typedefs not found: {missing}"

    def test_typedef_element_type_idx_valid(self):
        """Every typedef must have a valid element_type_idx."""
        types_count = len(self.prog.proto.types)
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "composite_type":
                ct = t.composite_type
                if ct.type == self.TYPE_TYPEDEF:
                    assert ct.HasField(
                        "element_type_idx"
                    ), f"Typedef {ct.name} missing element_type_idx"
                    assert 0 <= ct.element_type_idx < types_count, (
                        f"Typedef {ct.name} has out-of-range "
                        f"element_type_idx={ct.element_type_idx}"
                    )

    def test_no_duplicate_type_names_per_subtype(self):
        """No two typedefs should have the same name."""
        seen = set()
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "composite_type":
                ct = t.composite_type
                if ct.type == self.TYPE_TYPEDEF:
                    assert ct.name not in seen, f"Duplicate typedef name: {ct.name}"
                    seen.add(ct.name)

    # -- Simple typedef target checks --------------------------------------

    def test_typedef_u32_target_chain(self):
        """U32 = typedef uint32_t -> follow the chain to TYPE_DW."""
        _, ct = self._find_typedef("U32")
        assert ct is not None, "U32 typedef should be exported"
        assert ct.size == 4, f"U32 size should be 4, got {ct.size}"

        idx = ct.element_type_idx
        visited = set()
        chain_names = ["U32"]
        while True:
            assert idx not in visited, f"Cycle in U32 typedef chain: {chain_names}"
            visited.add(idx)
            target = self._type_at(idx)
            if self._is_primitive(target):
                assert target.primitive_type == Pb.Quokka.TYPE_DW, (
                    f"U32 chain should end at TYPE_DW, "
                    f"got base={Pb.Quokka.BaseType.Name(target.primitive_type)} "
                    f"(chain: {chain_names})"
                )
                return
            if self._is_composite_of(target, self.TYPE_TYPEDEF):
                inner = target.composite_type
                chain_names.append(inner.name)
                assert inner.HasField(
                    "element_type_idx"
                ), f"Intermediate typedef {inner.name!r} missing element_type_idx"
                idx = inner.element_type_idx
                continue
            pytest.fail(
                f"Unexpected type in U32 chain: {target.WhichOneof('OneofType')}"
            )

    def test_typedef_c_target(self):
        """C = typedef struct C_ -> target must be struct C_."""
        _, ct = self._find_typedef("C")
        if ct is None:
            pytest.fail("C typedef not found in export")
        target = self._type_at(ct.element_type_idx)
        assert self._is_composite_of(target, self.TYPE_STRUCT), (
            f"C typedef target should be struct C_, got "
            f"{target.WhichOneof('OneofType')}"
        )
        sname = target.composite_type.name
        assert sname == "C_", f"Expected struct name 'C_', got {sname!r}"

    def test_typedef_c_struct_exists_separately(self):
        """struct C_ should exist as a separate TYPE_STRUCT entry."""
        _, st = self._find_composite("C_", self.TYPE_STRUCT)
        if st is None:
            pytest.fail("struct C_ not found in export")
        member_names = [m.name for m in st.members]
        assert (
            "a" in member_names
        ), f"struct C_ should have member 'a', found {member_names}"

    def test_typedef_voidfn_c_exists(self):
        """VoidFn_C = typedef void(*)(void) should exist as a typedef."""
        _, ct = self._find_typedef("VoidFn_C")
        if ct is None:
            pytest.fail("VoidFn_C typedef not found in export")
        assert ct.HasField("element_type_idx"), "VoidFn_C must have element_type_idx"

    def test_typedef_fn1_c_exists(self):
        """Fn1_C = typedef int(*)(int) should exist as a typedef."""
        _, ct = self._find_typedef("Fn1_C")
        if ct is None:
            pytest.fail("Fn1_C typedef not found in export")
        assert ct.HasField("element_type_idx"), "Fn1_C must have element_type_idx"

    def test_typedef_fn2_c_exists(self):
        """Fn2_C = typedef int(*)(int, ...) should exist as a typedef."""
        _, ct = self._find_typedef("Fn2_C")
        if ct is None:
            pytest.fail("Fn2_C typedef not found in export")
        assert ct.HasField("element_type_idx"), "Fn2_C must have element_type_idx"

    # -- Pointer-chain typedefs --------------------------------------------

    def test_typedef_pu32_element_is_pointer(self):
        """PU32 = typedef U32* -> element must be TYPE_POINTER."""
        _, ct = self._find_typedef("PU32")
        if ct is None:
            pytest.fail("PU32 typedef not found in export")
        target = self._type_at(ct.element_type_idx)
        assert self._is_composite_of(target, self.TYPE_POINTER), (
            f"PU32 element should be TYPE_POINTER, got "
            f"{target.WhichOneof('OneofType')}"
        )

    def test_typedef_pcu32_element_is_pointer(self):
        """PCU32 = typedef const U32* -> element must be TYPE_POINTER."""
        _, ct = self._find_typedef("PCU32")
        if ct is None:
            pytest.fail("PCU32 typedef not found in export")
        target = self._type_at(ct.element_type_idx)
        assert self._is_composite_of(target, self.TYPE_POINTER), (
            f"PCU32 element should be TYPE_POINTER, got "
            f"{target.WhichOneof('OneofType')}"
        )

    def test_typedef_ppcu32_element_is_pointer(self):
        """PPCU32 = typedef PCU32* -> element must be TYPE_POINTER."""
        _, ct = self._find_typedef("PPCU32")
        if ct is None:
            pytest.fail("PPCU32 typedef not found in export")
        target = self._type_at(ct.element_type_idx)
        assert self._is_composite_of(target, self.TYPE_POINTER), (
            f"PPCU32 element should be TYPE_POINTER, got "
            f"{target.WhichOneof('OneofType')}"
        )

    def test_typedef_cppcu32_element_is_pointer(self):
        """CPPCU32 = typedef const PPCU32* -> element must be TYPE_POINTER."""
        _, ct = self._find_typedef("CPPCU32")
        if ct is None:
            pytest.fail("CPPCU32 typedef not found in export")
        target = self._type_at(ct.element_type_idx)
        assert self._is_composite_of(target, self.TYPE_POINTER), (
            f"CPPCU32 element should be TYPE_POINTER, got "
            f"{target.WhichOneof('OneofType')}"
        )

    def test_typedef_fn1_c_target_is_pointer(self):
        """Fn1_C = typedef int(*)(int) -> element must be TYPE_POINTER."""
        _, ct = self._find_typedef("Fn1_C")
        if ct is None:
            pytest.fail("Fn1_C typedef not found in export")
        target = self._type_at(ct.element_type_idx)
        assert self._is_composite_of(target, self.TYPE_POINTER), (
            f"Fn1_C element should be TYPE_POINTER, got "
            f"{target.WhichOneof('OneofType')}"
        )

    # -- Data type checks (proto level) ------------------------------------

    def test_data_g_u32_data_typed(self):
        """Global g_u32_data should be typed as U32.

        g_u32_data is declared as U32 (locally defined typedef of uint32_t).
        """
        d = self._find_data_by_name("g_u32_data")
        if d is None:
            pytest.fail("g_u32_data not found in data")
        t = self._type_at(d.type_index)
        if self._is_composite_of(t, self.TYPE_TYPEDEF):
            assert (
                t.composite_type.name == "U32"
            ), f"g_u32_data typedef should be U32, got {t.composite_type.name!r}"
        else:
            pytest.fail(f"g_u32_data unexpected type: {t.WhichOneof('OneofType')}")

    def test_data_g_pu32_data_typed(self):
        """Global g_pu32_data should be typed as PU32.

        PU32 is locally defined;
        """
        d = self._find_data_by_name("g_pu32_data")
        if d is None:
            pytest.fail("g_pu32_data not found in data")
        t = self._type_at(d.type_index)
        if self._is_composite_of(t, self.TYPE_TYPEDEF):
            assert t.composite_type.name == "PU32", (
                f"g_pu32_data typedef should be PU32, got "
                f"{t.composite_type.name!r}"
            )
        else:
            pytest.fail(
                f"g_pu32_data should be typed as PU32, got "
                f"{t.WhichOneof('OneofType')}"
            )

    def test_data_v12_typed_as_struct_a(self):
        """Global v12 should be typed as struct A."""
        d = self._find_data_by_name("v12")
        if d is None:
            pytest.fail("v12 not found in data")
        t = self._type_at(d.type_index)
        assert self._is_composite_of(t, self.TYPE_STRUCT), (
            f"v12 should be typed as a struct, got " f"{t.WhichOneof('OneofType')}"
        )
        assert (
            t.composite_type.name == "A"
        ), f"v12 struct should be named 'A', got {t.composite_type.name!r}"

    def test_data_g_pcu32_data_typed(self):
        """g_pcu32_data is declared as PCU32."""
        d = self._find_data_by_name("g_pcu32_data")
        if d is None:
            pytest.fail("g_pcu32_data not found in data")
        t = self._type_at(d.type_index)
        assert self._is_composite_of(t, self.TYPE_TYPEDEF), (
            f"g_pcu32_data should be typedef PCU32, got "
            f"{t.WhichOneof('OneofType')}"
        )
        assert t.composite_type.name == "PCU32", (
            f"g_pcu32_data should be typedef PCU32, got "
            f"{t.composite_type.name!r}"
        )

    def test_data_g_ppcu32_data_typed(self):
        """g_ppcu32_data is declared as PPCU32."""
        d = self._find_data_by_name("g_ppcu32_data")
        if d is None:
            pytest.fail("g_ppcu32_data not found in data")
        t = self._type_at(d.type_index)
        assert self._is_composite_of(t, self.TYPE_TYPEDEF), (
            f"g_ppcu32_data should be typedef PPCU32, got "
            f"{t.WhichOneof('OneofType')}"
        )
        assert t.composite_type.name == "PPCU32", (
            f"g_ppcu32_data should be typedef PPCU32, got "
            f"{t.composite_type.name!r}"
        )

    def test_data_g_cppcu32_data_typed(self):
        """g_cppcu32_data is declared as CPPCU32."""
        d = self._find_data_by_name("g_cppcu32_data")
        if d is None:
            pytest.fail("g_cppcu32_data not found in data")
        t = self._type_at(d.type_index)
        assert self._is_composite_of(t, self.TYPE_TYPEDEF), (
            f"g_cppcu32_data should be typedef CPPCU32, got "
            f"{t.WhichOneof('OneofType')}"
        )
        assert t.composite_type.name == "CPPCU32", (
            f"g_cppcu32_data should be typedef CPPCU32, got "
            f"{t.composite_type.name!r}"
        )

    def test_data_g_voidfn_c_typed(self):
        """g_voidfn_c is declared as VoidFn_C (function pointer typedef)."""
        d = self._find_data_by_name("g_voidfn_c")
        if d is None:
            pytest.fail("g_voidfn_c not found in data")
        t = self._type_at(d.type_index)
        assert self._is_composite_of(t, self.TYPE_TYPEDEF), (
            f"g_voidfn_c should be typedef VoidFn_C, got "
            f"{t.WhichOneof('OneofType')}"
        )
        assert t.composite_type.name == "VoidFn_C", (
            f"g_voidfn_c should be typedef VoidFn_C, got "
            f"{t.composite_type.name!r}"
        )

    def test_data_g_a_data_typed_as_struct_a(self):
        """g_a_data is declared as struct A; must be typed as struct A."""
        d = self._find_data_by_name("g_a_data")
        if d is None:
            pytest.fail("g_a_data not found in data")
        t = self._type_at(d.type_index)
        assert self._is_composite_of(
            t, self.TYPE_STRUCT
        ), f"g_a_data should be struct A, got {t.WhichOneof('OneofType')}"
        assert (
            t.composite_type.name == "A"
        ), f"g_a_data should be struct A, got {t.composite_type.name!r}"

    def test_data_g_uw_c_typed(self):
        """g_uw_c is declared as union UWeird_C; must be typed as union."""
        d = self._find_data_by_name("g_uw_c")
        if d is None:
            pytest.fail("g_uw_c not found in data")
        t = self._type_at(d.type_index)
        assert self._is_composite_of(t, self.TYPE_UNION), (
            f"g_uw_c should be union UWeird_C, got "
            f"{t.WhichOneof('OneofType')}"
        )
        assert t.composite_type.name == "UWeird_C", (
            f"g_uw_c should be union UWeird_C, got " f"{t.composite_type.name!r}"
        )

    def test_data_g_bfw_data_typed(self):
        """g_bfw_data is declared as BitfieldWeird_C; must be typed as struct."""
        d = self._find_data_by_name("g_bfw_data")
        if d is None:
            pytest.fail("g_bfw_data not found in data")
        t = self._type_at(d.type_index)
        assert self._is_composite_of(t, self.TYPE_STRUCT), (
            f"g_bfw_data should be BitfieldWeird_C, got "
            f"{t.WhichOneof('OneofType')}"
        )
        assert t.composite_type.name == "BitfieldWeird_C", (
            f"g_bfw_data should be BitfieldWeird_C, got "
            f"{t.composite_type.name!r}"
        )

    def test_data_g_mph_data_typed(self):
        """g_mph_data is declared as MemberPtrHost; must be typed correctly."""
        d = self._find_data_by_name("g_mph_data")
        if d is None:
            pytest.fail("g_mph_data not found in data")
        t = self._type_at(d.type_index)
        assert self._is_composite_of(t, self.TYPE_STRUCT), (
            f"g_mph_data should be MemberPtrHost, got "
            f"{t.WhichOneof('OneofType')}"
        )
        assert t.composite_type.name == "MemberPtrHost", (
            f"g_mph_data should be MemberPtrHost, got "
            f"{t.composite_type.name!r}"
        )

    # -- Pointer typedef sizes ---------------------------------------------

    def test_pointer_typedef_sizes(self):
        """All pointer typedefs must have size == address_size // 8."""
        ptr_size = self.prog.address_size // 8
        for name in ("PU32", "PCU32", "PPCU32", "CPPCU32"):
            _, ct = self._find_typedef(name)
            if ct is None:
                pytest.fail(f"{name} typedef not found")
            assert (
                ct.size == ptr_size
            ), f"{name} size should be {ptr_size}, got {ct.size}"

    # -- Struct and union structure checks ---------------------------------

    def test_struct_a_member_count(self):
        """struct A has 16-17 members.

        Ghidra may miss volatile-qualified member 'g' (volatile uint32_t),
        resulting in 16 instead of 17 members.
        """
        _, st = self._find_composite("A", self.TYPE_STRUCT)
        if st is None:
            pytest.fail("struct A not found")
        assert (
            len(st.members) >= 16
        ), f"struct A should have >= 16 members, got {len(st.members)}"

    def test_struct_a_member_names(self):
        """struct A members must include the expected names.

        Ghidra may omit 'g' (volatile uint32_t).
        """
        _, st = self._find_composite("A", self.TYPE_STRUCT)
        if st is None:
            pytest.fail("struct A not found")
        # Core members that Ghidra should always find
        expected = {
            "a",
            "b",
            "b1",
            "c",
            "d",
            "e",
            "f",
            "h",
            "i",
            "j",
            "k",
            "l",
            "m",
            "n",
            "o",
            "p",
        }
        actual = {m.name for m in st.members}
        missing = expected - actual
        assert not missing, f"struct A missing members: {missing}"

    def test_struct_a_first_member(self):
        """struct A first member 'a' is uint8_t (8 bits)."""
        _, st = self._find_composite("A", self.TYPE_STRUCT)
        if st is None:
            pytest.fail("struct A not found")
        first = st.members[0]
        assert first.name == "a", f"First member should be 'a', got {first.name!r}"
        assert first.size == 8, f"uint8_t should be 8 bits, got {first.size}"

    def test_union_e_members(self):
        """union E has 2 members: a[4] and b."""
        _, ut = self._find_composite("E", self.TYPE_UNION)
        if ut is None:
            pytest.fail("union E not found")
        assert (
            len(ut.members) == 2
        ), f"union E should have 2 members, got {len(ut.members)}"
        names = {m.name for m in ut.members}
        assert names == {"a", "b"}, f"union E members: {names}"

    def test_union_uweird_c_members(self):
        """union UWeird_C has 5 members: u64, d, parts32, parts16, bytes."""
        _, ut = self._find_composite("UWeird_C", self.TYPE_UNION)
        if ut is None:
            pytest.fail("union UWeird_C not found")
        assert (
            len(ut.members) == 5
        ), f"union UWeird_C should have 5 members, got {len(ut.members)}"
        expected = {"u64", "d", "parts32", "parts16", "bytes"}
        actual = {m.name for m in ut.members}
        assert (
            actual == expected
        ), f"union UWeird_C members mismatch: expected {expected}, got {actual}"

    def test_struct_b_nested_members(self):
        """struct B has members a, b, c (nested struct/union)."""
        _, st = self._find_composite("B", self.TYPE_STRUCT)
        if st is None:
            pytest.fail("struct B not found")
        names = {m.name for m in st.members}
        expected = {"a", "b", "c"}
        assert expected.issubset(
            names
        ), f"struct B should have members {expected}, got {names}"

    def test_enum_d_values(self):
        """enum D { FIRST, SECOND, THIRD } must exist with expected values."""
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "enum_type":
                if t.enum_type.name == "D":
                    val_names = [v.name for v in t.enum_type.values]
                    for expected in ("FIRST", "SECOND", "THIRD"):
                        found = any(
                            n == expected or n.endswith("::" + expected)
                            for n in val_names
                        )
                        assert found, (
                            f"enum D missing member {expected!r}, "
                            f"found: {val_names}"
                        )
                    return
        pytest.fail("enum D not found")

    def test_struct_selfref_c_has_next(self):
        """SelfRef_C should have 'next' member (self-referential pointer)."""
        _, st = self._find_composite("SelfRef_C", self.TYPE_STRUCT)
        if st is None:
            pytest.fail("SelfRef_C not found")
        names = {m.name for m in st.members}
        assert "next" in names, f"SelfRef_C should have 'next', got {names}"

    def test_struct_packed1_c_exists(self):
        """Packed1_C should exist as a struct with members a, b."""
        _, st = self._find_composite("Packed1_C", self.TYPE_STRUCT)
        if st is None:
            pytest.fail("Packed1_C not found")
        names = {m.name for m in st.members}
        assert "a" in names, f"Packed1_C should have 'a', got {names}"
        assert "b" in names, f"Packed1_C should have 'b', got {names}"

    def test_struct_has_anon_agg_c(self):
        """HasAnonAgg_C should exist with 'tag' and 'u' members."""
        _, st = self._find_composite("HasAnonAgg_C", self.TYPE_STRUCT)
        if st is None:
            pytest.fail("HasAnonAgg_C not found")
        names = {m.name for m in st.members}
        assert "tag" in names, f"HasAnonAgg_C should have 'tag', got {names}"
        assert "u" in names, f"HasAnonAgg_C should have 'u', got {names}"

    # -- Struct member type resolution -------------------------------------

    def test_struct_a_member_l_type_is_struct_b(self):
        """struct A member 'l' (struct B) must reference struct B."""
        _, st = self._find_composite("A", self.TYPE_STRUCT)
        if st is None:
            pytest.fail("struct A not found")
        m = self._find_member(st, "l")
        assert m is not None, "struct A should have member 'l'"
        t = self._type_at(m.type_index)
        assert self._is_composite_of(
            t, self.TYPE_STRUCT
        ), f"A.l should be struct B, got {t.WhichOneof('OneofType')}"
        assert (
            t.composite_type.name == "B"
        ), f"A.l should be struct B, got {t.composite_type.name!r}"

    def test_struct_a_member_m_type_is_c(self):
        """struct A member 'm' (C) must reference typedef C."""
        _, st = self._find_composite("A", self.TYPE_STRUCT)
        if st is None:
            pytest.fail("struct A not found")
        m = self._find_member(st, "m")
        assert m is not None, "struct A should have member 'm'"
        t = self._type_at(m.type_index)
        assert self._is_composite_of(t, self.TYPE_TYPEDEF), (
            f"A.m should be typedef C, got {t.WhichOneof('OneofType')}"
        )
        assert (
            t.composite_type.name == "C"
        ), f"A.m should be typedef C, got {t.composite_type.name!r}"

    def test_struct_a_member_n_type_is_enum_d(self):
        """struct A member 'n' (enum D) must reference enum D."""
        _, st = self._find_composite("A", self.TYPE_STRUCT)
        if st is None:
            pytest.fail("struct A not found")
        m = self._find_member(st, "n")
        assert m is not None, "struct A should have member 'n'"
        t = self._type_at(m.type_index)
        assert t.WhichOneof("OneofType") == "enum_type", (
            f"A.n should be enum D, got {t.WhichOneof('OneofType')}"
        )
        assert (
            t.enum_type.name == "D"
        ), f"A.n should be enum D, got {t.enum_type.name!r}"

    def test_struct_a_member_o_type_is_pointer(self):
        """struct A member 'o' (C*) must be a pointer type."""
        _, st = self._find_composite("A", self.TYPE_STRUCT)
        if st is None:
            pytest.fail("struct A not found")
        m = self._find_member(st, "o")
        assert m is not None, "struct A should have member 'o'"
        t = self._type_at(m.type_index)
        assert self._is_composite_of(t, self.TYPE_POINTER), (
            f"A.o should be TYPE_POINTER, got {t.WhichOneof('OneofType')}"
        )

    # -- C++ enum checks ---------------------------------------------------

    def test_cpp_enum_e8_exists(self):
        """C++ enum class E8 : uint8_t should be exported with values."""
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "enum_type":
                if t.enum_type.name == "E8":
                    val_names = [v.name for v in t.enum_type.values]
                    for expected in ("Z0", "Z1", "Z255"):
                        found = any(
                            n == expected or n.endswith("::" + expected)
                            for n in val_names
                        )
                        assert found, (
                            f"enum E8 missing member {expected!r}, "
                            f"found: {val_names}"
                        )
                    return
        pytest.fail("enum E8 not found (C++ scoped enum may not export)")

    def test_cpp_enum_eneg_exists(self):
        """C++ enum class ENeg : int32_t should be exported with values."""
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "enum_type":
                if t.enum_type.name == "ENeg":
                    val_names = [v.name for v in t.enum_type.values]
                    for expected in ("N0", "N1"):
                        found = any(
                            n == expected or n.endswith("::" + expected)
                            for n in val_names
                        )
                        assert found, (
                            f"enum ENeg missing member {expected!r}, "
                            f"found: {val_names}"
                        )
                    return
        pytest.fail("enum ENeg not found (C++ scoped enum may not export)")

    def test_cpp_enum_eu64_cpp_exists(self):
        """C++ enum EU64_CPP : uint64_t should be exported."""
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "enum_type":
                if t.enum_type.name == "EU64_CPP":
                    return
        pytest.fail("enum EU64_CPP not found")

    # -- C++ struct checks -------------------------------------------------

    def test_cpp_struct_bitfield_weird_cpp(self):
        """BitfieldWeird_CPP should exist with members ed, b, u, tc."""
        _, st = self._find_composite("BitfieldWeird_CPP", self.TYPE_STRUCT)
        if st is None:
            pytest.fail("BitfieldWeird_CPP not found")
        names = {m.name for m in st.members}
        expected = {"ed", "b", "u", "tc"}
        missing = expected - names
        assert not missing, f"BitfieldWeird_CPP missing members: {missing}, got {names}"

    def test_cpp_struct_member_ptr_host(self):
        """MemberPtrHost should exist with members x, y."""
        _, st = self._find_composite("MemberPtrHost", self.TYPE_STRUCT)
        if st is None:
            pytest.fail("MemberPtrHost not found")
        names = {m.name for m in st.members}
        assert "x" in names, f"MemberPtrHost should have 'x', got {names}"
        assert "y" in names, f"MemberPtrHost should have 'y', got {names}"

    # -- Typedef pointer chains --------------------------------------------
    #
    # When the source says ``typedef TdInt* TdTdIntPtr``, the exported
    # chain MUST be:
    #   TdTdIntPtr (TYPEDEF) -> POINTER -> TdInt (TYPEDEF) -> primitive
    # The pointer element must reference the *intermediate typedef*, not
    # the fully-resolved primitive, because the user wrote ``TdInt*``.
    # ------------------------------------------------------------------

    def test_typedef_ptr_chain_TdTdIntPtr(self):
        """TdTdIntPtr = TdInt* -> element is POINTER whose pointee is TdInt.

        Source:
            typedef int          TdInt;
            typedef TdInt*       TdTdIntPtr;
        Expected chain:
            TdTdIntPtr (TYPEDEF) -> POINTER -> TdInt (TYPEDEF) -> TYPE_DW
        """
        ct, ptr = self._follow_typedef_element("TdTdIntPtr")
        assert self._is_composite_of(ptr, self.TYPE_POINTER), (
            f"TdTdIntPtr element should be TYPE_POINTER, "
            f"got {ptr.WhichOneof('OneofType')}"
        )
        pointee = self._type_at(ptr.composite_type.element_type_idx)
        assert self._is_composite_of(pointee, self.TYPE_TYPEDEF), (
            f"TdTdIntPtr pointer pointee should be typedef TdInt, "
            f"got {pointee.WhichOneof('OneofType')}"
        )
        assert pointee.composite_type.name == "TdInt", (
            f"TdTdIntPtr pointer pointee should be TdInt, "
            f"got {pointee.composite_type.name!r}"
        )

    def test_typedef_ptr_chain_TdTdFloatPtr(self):
        """TdTdFloatPtr = TdFloat* -> POINTER -> TdFloat (TYPEDEF).

        Source:
            typedef float        TdFloat;
            typedef TdFloat*     TdTdFloatPtr;
        """
        ct, ptr = self._follow_typedef_element("TdTdFloatPtr")
        assert self._is_composite_of(ptr, self.TYPE_POINTER), (
            f"TdTdFloatPtr element should be TYPE_POINTER, "
            f"got {ptr.WhichOneof('OneofType')}"
        )
        pointee = self._type_at(ptr.composite_type.element_type_idx)
        assert self._is_composite_of(pointee, self.TYPE_TYPEDEF), (
            f"TdTdFloatPtr pointer pointee should be typedef TdFloat, "
            f"got {pointee.WhichOneof('OneofType')}"
        )
        assert pointee.composite_type.name == "TdFloat", (
            f"TdTdFloatPtr pointer pointee should be TdFloat, "
            f"got {pointee.composite_type.name!r}"
        )

    def test_typedef_ptr_chain_TdTdBytePtr(self):
        """TdTdBytePtr = TdByte* -> POINTER -> TdByte (TYPEDEF).

        Source:
            typedef unsigned char TdByte;
            typedef TdByte*       TdTdBytePtr;
        """
        ct, ptr = self._follow_typedef_element("TdTdBytePtr")
        assert self._is_composite_of(ptr, self.TYPE_POINTER), (
            f"TdTdBytePtr element should be TYPE_POINTER, "
            f"got {ptr.WhichOneof('OneofType')}"
        )
        pointee = self._type_at(ptr.composite_type.element_type_idx)
        assert self._is_composite_of(pointee, self.TYPE_TYPEDEF), (
            f"TdTdBytePtr pointer pointee should be typedef TdByte, "
            f"got {pointee.WhichOneof('OneofType')}"
        )
        assert pointee.composite_type.name == "TdByte", (
            f"TdTdBytePtr pointer pointee should be TdByte, "
            f"got {pointee.composite_type.name!r}"
        )

    def test_typedef_ptr_chain_TdStructAPtr(self):
        """TdStructAPtr = TdStructA* -> POINTER -> TdStructA (TYPEDEF).

        Source:
            typedef struct A     TdStructA;
            typedef TdStructA*   TdStructAPtr;
        """
        ct, ptr = self._follow_typedef_element("TdStructAPtr")
        assert self._is_composite_of(ptr, self.TYPE_POINTER), (
            f"TdStructAPtr element should be TYPE_POINTER, "
            f"got {ptr.WhichOneof('OneofType')}"
        )
        pointee = self._type_at(ptr.composite_type.element_type_idx)
        assert self._is_composite_of(pointee, self.TYPE_TYPEDEF), (
            f"TdStructAPtr pointer pointee should be typedef TdStructA, "
            f"got {pointee.WhichOneof('OneofType')}"
        )
        assert pointee.composite_type.name == "TdStructA", (
            f"TdStructAPtr pointer pointee should be TdStructA, "
            f"got {pointee.composite_type.name!r}"
        )

    def test_typedef_ptr_chain_TdUnionEPtr(self):
        """TdUnionEPtr = TdUnionE* -> POINTER -> TdUnionE (TYPEDEF).

        Source:
            typedef union E      TdUnionE;
            typedef TdUnionE*    TdUnionEPtr;
        """
        ct, ptr = self._follow_typedef_element("TdUnionEPtr")
        assert self._is_composite_of(ptr, self.TYPE_POINTER), (
            f"TdUnionEPtr element should be TYPE_POINTER, "
            f"got {ptr.WhichOneof('OneofType')}"
        )
        pointee = self._type_at(ptr.composite_type.element_type_idx)
        assert self._is_composite_of(pointee, self.TYPE_TYPEDEF), (
            f"TdUnionEPtr pointer pointee should be typedef TdUnionE, "
            f"got {pointee.WhichOneof('OneofType')}"
        )
        assert pointee.composite_type.name == "TdUnionE", (
            f"TdUnionEPtr pointer pointee should be TdUnionE, "
            f"got {pointee.composite_type.name!r}"
        )

    def test_typedef_ptr_chain_TdEnumDPtr(self):
        """TdEnumDPtr = TdEnumD* -> POINTER -> TdEnumD (TYPEDEF).

        Source:
            typedef enum D       TdEnumD;
            typedef TdEnumD*     TdEnumDPtr;
        """
        ct, ptr = self._follow_typedef_element("TdEnumDPtr")
        assert self._is_composite_of(ptr, self.TYPE_POINTER), (
            f"TdEnumDPtr element should be TYPE_POINTER, "
            f"got {ptr.WhichOneof('OneofType')}"
        )
        pointee = self._type_at(ptr.composite_type.element_type_idx)
        assert self._is_composite_of(pointee, self.TYPE_TYPEDEF), (
            f"TdEnumDPtr pointer pointee should be typedef TdEnumD, "
            f"got {pointee.WhichOneof('OneofType')}"
        )
        assert pointee.composite_type.name == "TdEnumD", (
            f"TdEnumDPtr pointer pointee should be TdEnumD, "
            f"got {pointee.composite_type.name!r}"
        )

    def test_typedef_ptr_chain_TdConstTdIntPtr(self):
        """TdConstTdIntPtr = const TdInt* -> POINTER -> TdInt (TYPEDEF).

        Source:
            typedef int          TdInt;
            typedef const TdInt* TdConstTdIntPtr;
        The const qualifier lives on the pointer, not on the pointee
        typedef; the pointee must still be TdInt.
        """
        ct, ptr = self._follow_typedef_element("TdConstTdIntPtr")
        assert self._is_composite_of(ptr, self.TYPE_POINTER), (
            f"TdConstTdIntPtr element should be TYPE_POINTER, "
            f"got {ptr.WhichOneof('OneofType')}"
        )
        pointee = self._type_at(ptr.composite_type.element_type_idx)
        assert self._is_composite_of(pointee, self.TYPE_TYPEDEF), (
            f"TdConstTdIntPtr pointer pointee should be typedef TdInt, "
            f"got {pointee.WhichOneof('OneofType')}"
        )
        assert pointee.composite_type.name == "TdInt", (
            f"TdConstTdIntPtr pointer pointee should be TdInt, "
            f"got {pointee.composite_type.name!r}"
        )

    def test_typedef_ptr_chain_TdTdIntPtrPtr(self):
        """TdTdIntPtrPtr = TdInt** -> POINTER -> POINTER -> TdInt.

        Source:
            typedef int          TdInt;
            typedef TdInt**      TdTdIntPtrPtr;
        The outer pointer must point to another pointer, which in turn
        must point to the TdInt typedef.
        """
        ct, ptr_outer = self._follow_typedef_element("TdTdIntPtrPtr")
        assert self._is_composite_of(ptr_outer, self.TYPE_POINTER), (
            f"TdTdIntPtrPtr element should be TYPE_POINTER, "
            f"got {ptr_outer.WhichOneof('OneofType')}"
        )
        ptr_inner = self._type_at(ptr_outer.composite_type.element_type_idx)
        assert self._is_composite_of(ptr_inner, self.TYPE_POINTER), (
            f"TdTdIntPtrPtr inner element should be TYPE_POINTER, "
            f"got {ptr_inner.WhichOneof('OneofType')}"
        )
        pointee = self._type_at(ptr_inner.composite_type.element_type_idx)
        assert self._is_composite_of(pointee, self.TYPE_TYPEDEF), (
            f"TdTdIntPtrPtr innermost pointee should be typedef TdInt, "
            f"got {pointee.WhichOneof('OneofType')}"
        )
        assert pointee.composite_type.name == "TdInt", (
            f"TdTdIntPtrPtr innermost pointee should be TdInt, "
            f"got {pointee.composite_type.name!r}"
        )

    def test_typedef_ptr_chain_TdConstStructAPtr(self):
        """TdConstStructAPtr = const TdStructA* -> POINTER -> TdStructA.

        Source:
            typedef struct A         TdStructA;
            typedef const TdStructA* TdConstStructAPtr;
        """
        ct, ptr = self._follow_typedef_element("TdConstStructAPtr")
        assert self._is_composite_of(ptr, self.TYPE_POINTER), (
            f"TdConstStructAPtr element should be TYPE_POINTER, "
            f"got {ptr.WhichOneof('OneofType')}"
        )
        pointee = self._type_at(ptr.composite_type.element_type_idx)
        assert self._is_composite_of(pointee, self.TYPE_TYPEDEF), (
            f"TdConstStructAPtr pointer pointee should be typedef TdStructA, "
            f"got {pointee.WhichOneof('OneofType')}"
        )
        assert pointee.composite_type.name == "TdStructA", (
            f"TdConstStructAPtr pointer pointee should be TdStructA, "
            f"got {pointee.composite_type.name!r}"
        )

    # -- Typedef array chains ----------------------------------------------
    #
    # When the source says ``typedef TdInt TdIntArr4[4]``, the exported
    # chain MUST be:
    #   TdIntArr4 (TYPEDEF) -> ARRAY -> TdInt (TYPEDEF) -> primitive
    # The array element must reference the *intermediate typedef*, not
    # the fully-resolved primitive, because the user wrote ``TdInt[4]``.
    # ------------------------------------------------------------------

    def test_typedef_arr_chain_TdIntArr4(self):
        """TdIntArr4 = TdInt[4] -> ARRAY whose element is TdInt (TYPEDEF).

        Source:
            typedef int    TdInt;
            typedef TdInt  TdIntArr4[4];
        Expected chain:
            TdIntArr4 (TYPEDEF, size=16) -> ARRAY -> TdInt (TYPEDEF) -> TYPE_DW
        """
        ct, arr = self._follow_typedef_element("TdIntArr4")
        assert ct.size == 16, f"TdIntArr4 size should be 16, got {ct.size}"
        assert self._is_composite_of(arr, self.TYPE_ARRAY), (
            f"TdIntArr4 element should be TYPE_ARRAY, "
            f"got {arr.WhichOneof('OneofType')}"
        )
        elem = self._type_at(arr.composite_type.element_type_idx)
        assert self._is_composite_of(elem, self.TYPE_TYPEDEF), (
            f"TdIntArr4 array element should be typedef TdInt, "
            f"got {elem.WhichOneof('OneofType')}"
        )
        assert elem.composite_type.name == "TdInt", (
            f"TdIntArr4 array element should be TdInt, "
            f"got {elem.composite_type.name!r}"
        )

    def test_typedef_arr_chain_TdByteArr8(self):
        """TdByteArr8 = TdByte[8] -> ARRAY whose element is TdByte.

        Source:
            typedef unsigned char TdByte;
            typedef TdByte        TdByteArr8[8];
        """
        ct, arr = self._follow_typedef_element("TdByteArr8")
        assert ct.size == 8, f"TdByteArr8 size should be 8, got {ct.size}"
        assert self._is_composite_of(arr, self.TYPE_ARRAY), (
            f"TdByteArr8 element should be TYPE_ARRAY, "
            f"got {arr.WhichOneof('OneofType')}"
        )
        elem = self._type_at(arr.composite_type.element_type_idx)
        assert self._is_composite_of(elem, self.TYPE_TYPEDEF), (
            f"TdByteArr8 array element should be typedef TdByte, "
            f"got {elem.WhichOneof('OneofType')}"
        )
        assert elem.composite_type.name == "TdByte", (
            f"TdByteArr8 array element should be TdByte, "
            f"got {elem.composite_type.name!r}"
        )

    def test_typedef_arr_chain_TdStructAArr2(self):
        """TdStructAArr2 = TdStructA[2] -> ARRAY whose element is TdStructA.

        Source:
            typedef struct A   TdStructA;
            typedef TdStructA  TdStructAArr2[2];
        """
        ct, arr = self._follow_typedef_element("TdStructAArr2")
        assert self._is_composite_of(arr, self.TYPE_ARRAY), (
            f"TdStructAArr2 element should be TYPE_ARRAY, "
            f"got {arr.WhichOneof('OneofType')}"
        )
        elem = self._type_at(arr.composite_type.element_type_idx)
        assert self._is_composite_of(elem, self.TYPE_TYPEDEF), (
            f"TdStructAArr2 array element should be typedef TdStructA, "
            f"got {elem.WhichOneof('OneofType')}"
        )
        assert elem.composite_type.name == "TdStructA", (
            f"TdStructAArr2 array element should be TdStructA, "
            f"got {elem.composite_type.name!r}"
        )

    def test_typedef_arr_chain_TdUnionEArr3(self):
        """TdUnionEArr3 = TdUnionE[3] -> ARRAY whose element is TdUnionE.

        Source:
            typedef union E    TdUnionE;
            typedef TdUnionE   TdUnionEArr3[3];
        """
        ct, arr = self._follow_typedef_element("TdUnionEArr3")
        assert ct.size == 12, f"TdUnionEArr3 size should be 12, got {ct.size}"
        assert self._is_composite_of(arr, self.TYPE_ARRAY), (
            f"TdUnionEArr3 element should be TYPE_ARRAY, "
            f"got {arr.WhichOneof('OneofType')}"
        )
        elem = self._type_at(arr.composite_type.element_type_idx)
        assert self._is_composite_of(elem, self.TYPE_TYPEDEF), (
            f"TdUnionEArr3 array element should be typedef TdUnionE, "
            f"got {elem.WhichOneof('OneofType')}"
        )
        assert elem.composite_type.name == "TdUnionE", (
            f"TdUnionEArr3 array element should be TdUnionE, "
            f"got {elem.composite_type.name!r}"
        )

    def test_typedef_arr_chain_TdEnumDArr3(self):
        """TdEnumDArr3 = TdEnumD[3] -> ARRAY whose element is TdEnumD.

        Source:
            typedef enum D     TdEnumD;
            typedef TdEnumD    TdEnumDArr3[3];
        """
        ct, arr = self._follow_typedef_element("TdEnumDArr3")
        assert ct.size == 12, f"TdEnumDArr3 size should be 12, got {ct.size}"
        assert self._is_composite_of(arr, self.TYPE_ARRAY), (
            f"TdEnumDArr3 element should be TYPE_ARRAY, "
            f"got {arr.WhichOneof('OneofType')}"
        )
        elem = self._type_at(arr.composite_type.element_type_idx)
        assert self._is_composite_of(elem, self.TYPE_TYPEDEF), (
            f"TdEnumDArr3 array element should be typedef TdEnumD, "
            f"got {elem.WhichOneof('OneofType')}"
        )
        assert elem.composite_type.name == "TdEnumD", (
            f"TdEnumDArr3 array element should be TdEnumD, "
            f"got {elem.composite_type.name!r}"
        )

    # -- C type declarations (c_str / headers) -----------------------------

    def test_headers_non_empty(self):
        """The headers field must be a non-empty C header string."""
        h = self.prog.proto.headers
        assert h, "headers field should be non-empty"
        assert len(h) > 100, "headers should contain substantial type declarations"

    def test_headers_contains_struct_keyword(self):
        """headers should contain at least one 'struct' C declaration."""
        assert "struct " in self.prog.proto.headers

    def test_headers_no_ghidra_debug_format(self):
        """headers must not contain Ghidra's internal debug format artifacts."""
        h = self.prog.proto.headers
        # DataType.toString() produces lines like "Length: 64 Alignment: 1"
        assert "Length:" not in h, "headers contains Ghidra debug 'Length:' artifact"
        assert "Alignment:" not in h, "headers contains Ghidra debug 'Alignment:' artifact"

    def test_enum_d_c_str(self):
        """enum D c_str must be a valid C enum declaration."""
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "enum_type":
                if t.enum_type.name == "D":
                    c = t.enum_type.c_str
                    assert c, "enum D c_str should be non-empty"
                    assert "typedef enum" in c, (
                        f"enum D c_str should start with typedef enum, got: {c!r}"
                    )
                    assert "FIRST" in c, f"enum D c_str should contain FIRST: {c!r}"
                    assert "SECOND" in c, f"enum D c_str should contain SECOND: {c!r}"
                    assert "THIRD" in c, f"enum D c_str should contain THIRD: {c!r}"
                    # Must NOT contain Ghidra debug artifacts
                    assert "Length:" not in c
                    return
        pytest.fail("enum D not found")

    def test_struct_a_c_str(self):
        """struct A c_str must be a valid C struct declaration."""
        _, st = self._find_composite("A", self.TYPE_STRUCT)
        if st is None:
            pytest.fail("struct A not found")
        c = st.c_str
        assert c, "struct A c_str should be non-empty"
        assert c.startswith("struct A {"), (
            f"struct A c_str should start with 'struct A {{', got: {c[:40]!r}"
        )
        assert c.rstrip().endswith("};"), (
            f"struct A c_str should end with '}};\', got: {c[-20:]!r}"
        )
        # Should contain field names, not Ghidra debug format
        assert "Length:" not in c
        assert "Alignment:" not in c

    def test_union_e_c_str(self):
        """union E c_str must be a valid C union declaration."""
        _, ut = self._find_composite("E", self.TYPE_UNION)
        if ut is None:
            pytest.fail("union E not found")
        c = ut.c_str
        assert c, "union E c_str should be non-empty"
        assert c.startswith("union E {"), (
            f"union E c_str should start with 'union E {{', got: {c[:40]!r}"
        )
        assert c.rstrip().endswith("};"), (
            f"union E c_str should end with '}};\', got: {c[-20:]!r}"
        )

    def test_typedef_u32_c_str(self):
        """typedef U32 c_str must be a valid C typedef declaration."""
        _, ct = self._find_typedef("U32")
        if ct is None:
            pytest.fail("typedef U32 not found")
        c = ct.c_str
        assert c, "U32 c_str should be non-empty"
        assert "typedef" in c, f"U32 c_str should contain 'typedef': {c!r}"
        assert "U32" in c, f"U32 c_str should contain 'U32': {c!r}"

    def test_pointer_type_c_str_set(self):
        """At least one TYPE_POINTER should have a non-empty c_str."""
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "composite_type":
                ct = t.composite_type
                if ct.type == self.TYPE_POINTER and ct.c_str:
                    # Must not contain Ghidra debug format
                    assert "Length:" not in ct.c_str
                    return
        pytest.fail("No TYPE_POINTER with non-empty c_str found")

    def test_array_type_c_str_set(self):
        """At least one TYPE_ARRAY should have a non-empty c_str."""
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "composite_type":
                ct = t.composite_type
                if ct.type == self.TYPE_ARRAY and ct.c_str:
                    assert "[" in ct.c_str, (
                        f"Array c_str should contain '[': {ct.c_str!r}"
                    )
                    assert "Length:" not in ct.c_str
                    return
        pytest.fail("No TYPE_ARRAY with non-empty c_str found")
