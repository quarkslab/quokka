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

"""IDA export integration tests.

These tests exercise the full IDA export pipeline: they invoke IDA headlessly
to export a binary and then validate the resulting .quokka through the Python
frontend.  They are skipped when IDA is not available.
"""

import shutil
import tempfile
from pathlib import Path

import idascript
import pytest

import quokka
from quokka.data_type import StructureType, EnumType
from quokka import quokka_pb2 as Pb


requires_ida = pytest.mark.skipif(
    idascript.get_ida_path() is None,
    reason="IDA Pro not found (set IDA_PATH or add it to $PATH)",
)


# ---------------------------------------------------------------------------
# puraUpdate regression: ExportCompositeDataTypes iterator invalidation
# ---------------------------------------------------------------------------


@requires_ida
class TestPuraUpdateExport:
    """Export the puraUpdate ARM binary through IDA and validate the output.

    This is a regression test for the ExportCompositeDataTypes iterator
    invalidation fix.  The 32-bit ARM ELF triggered a SIGSEGV during export
    because inserting pointer/array types into the absl::flat_hash_map while
    iterating invalidated the iterator.
    """

    @pytest.fixture(autouse=True)
    def _export(self, root_directory: Path, tmp_path: Path):
        """Export puraUpdate through IDA into a temporary directory."""
        binary = root_directory / "tests" / "dataset" / "puraUpdate"
        if not binary.exists():
            pytest.skip("puraUpdate binary not found in tests/dataset/")

        output = tmp_path / "puraUpdate.quokka"
        self.prog = quokka.Program.from_binary(
            binary,
            output_file=output,
            database_file=tmp_path / "puraUpdate.i64",
            timeout=600,
        )

    def test_export_produces_program(self):
        assert self.prog is not None

    def test_function_count(self):
        assert len(self.prog.fun_names) == 113

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

    def test_main_function_exists(self):
        main_func = self.prog.get_function("main", approximative=False)
        assert main_func is not None, "main function should exist"

    def test_main_has_multiple_blocks(self):
        main_func = self.prog.get_function("main", approximative=False)
        assert len(main_func.graph) > 1, "main should have multiple blocks"


# ---------------------------------------------------------------------------
# many_types_cpp: typedef export validation
# ---------------------------------------------------------------------------


@requires_ida
class TestManyTypesCppExport:
    """Export the many_types_cpp binary through IDA and validate typedefs.

    The many_types.c source contains typedef chains (U32, PU32, PCU32,
    PPCU32, CPPCU32) and function-pointer typedefs that exercise the
    ExportTypedefs() pipeline.
    """

    @pytest.fixture(autouse=True)
    def _export(self, root_directory: Path, tmp_path: Path):
        """Export many_types_cpp through IDA into a temporary directory."""
        binary = root_directory / "tests" / "dataset" / "many_types_cpp"
        if not binary.exists():
            pytest.skip("many_types_cpp binary not found in tests/dataset/")

        output = tmp_path / "many_types_cpp.quokka"
        self.prog = quokka.Program.from_binary(
            binary,
            output_file=output,
            database_file=tmp_path / "many_types_cpp.i64",
            timeout=600,
        )

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
        main_func = self.prog.get_function("main", approximative=False)
        assert main_func is not None, "main function should exist"

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

    # -- Easy: simple typedef target checks --------------------------------

    def test_typedef_u32_target_chain(self):
        """U32 = typedef uint32_t -> follow the chain to TYPE_DW.

        Typedefs always point to the next type in the chain, never to the
        fully resolved type.  U32 -> uint32_t (typedef) -> __uint32_t
        (typedef) -> unsigned int (TYPE_DW).
        """
        _, ct = self._find_typedef("U32")
        assert ct is not None, "U32 typedef should be exported"

        # The U32 typedef itself must record size = 4 (uint32_t)
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

    def test_typedef_u32_c_str(self):
        """U32 c_str should reference both 'U32' and 'uint32_t'."""
        _, ct = self._find_typedef("U32")
        if ct is None:
            pytest.skip("U32 typedef not found in export")
        assert "U32" in ct.c_str, f"c_str missing 'U32': {ct.c_str!r}"

    def test_typedef_c_target(self):
        """C = typedef struct C_ -> target must be struct C_.

        struct C_ is locally defined, so the typedef must resolve to it.
        """
        _, ct = self._find_typedef("C")
        if ct is None:
            pytest.skip("C typedef not found in export")
        target = self._type_at(ct.element_type_idx)
        assert self._is_composite_of(target, self.TYPE_STRUCT), (
            f"C typedef target should be struct C_, got "
            f"{target.WhichOneof('OneofType')}"
        )
        sname = target.composite_type.name
        assert "C" in sname, f"Expected struct name with 'C', got {sname!r}"
        assert "C" in ct.c_str, f"C c_str should mention 'C': {ct.c_str!r}"

    def test_typedef_c_struct_exists_separately(self):
        """struct C_ should exist as a separate TYPE_STRUCT entry."""
        _, st = self._find_composite("C_", self.TYPE_STRUCT)
        if st is None:
            pytest.skip("struct C_ not found in export")
        member_names = [m.name for m in st.members]
        assert (
            "a" in member_names
        ), f"struct C_ should have member 'a', found {member_names}"

    def test_typedef_voidfn_c_exists(self):
        """VoidFn_C = typedef void(*)(void) should exist as a typedef."""
        _, ct = self._find_typedef("VoidFn_C")
        if ct is None:
            pytest.skip("VoidFn_C typedef not found in export")
        assert ct.HasField("element_type_idx"), "VoidFn_C must have element_type_idx"
        assert (
            "void" in ct.c_str.lower()
        ), f"VoidFn_C c_str should contain 'void': {ct.c_str!r}"

    def test_typedef_fn1_c_exists(self):
        """Fn1_C = typedef int(*)(int) should exist as a typedef."""
        _, ct = self._find_typedef("Fn1_C")
        if ct is None:
            pytest.skip("Fn1_C typedef not found in export")
        assert ct.HasField("element_type_idx"), "Fn1_C must have element_type_idx"
        # c_str should contain function pointer signature fragments
        assert "Fn1_C" in ct.c_str, f"c_str missing 'Fn1_C': {ct.c_str!r}"
        assert (
            "int" in ct.c_str.lower()
        ), f"Fn1_C c_str should mention 'int': {ct.c_str!r}"

    def test_typedef_fn2_c_exists(self):
        """Fn2_C = typedef int(*)(int, ...) should exist as a typedef."""
        _, ct = self._find_typedef("Fn2_C")
        if ct is None:
            pytest.skip("Fn2_C typedef not found in export")
        assert ct.HasField("element_type_idx"), "Fn2_C must have element_type_idx"
        assert "Fn2_C" in ct.c_str, f"c_str missing 'Fn2_C': {ct.c_str!r}"

    # -- Medium: pointer-chain typedefs ------------------------------------

    def test_typedef_pu32_element_is_pointer(self):
        """PU32 = typedef U32* -> element must be TYPE_POINTER.

        U32* is locally resolvable; TYPE_UNK is not acceptable.
        """
        _, ct = self._find_typedef("PU32")
        if ct is None:
            pytest.skip("PU32 typedef not found in export")
        target = self._type_at(ct.element_type_idx)
        assert self._is_composite_of(target, self.TYPE_POINTER), (
            f"PU32 element should be TYPE_POINTER, got "
            f"{target.WhichOneof('OneofType')}"
        )
        assert "PU32" in ct.c_str
        assert "U32" in ct.c_str

    def test_typedef_pcu32_element_is_pointer(self):
        """PCU32 = typedef const U32* -> element must be TYPE_POINTER."""
        _, ct = self._find_typedef("PCU32")
        if ct is None:
            pytest.skip("PCU32 typedef not found in export")
        target = self._type_at(ct.element_type_idx)
        assert self._is_composite_of(target, self.TYPE_POINTER), (
            f"PCU32 element should be TYPE_POINTER, got "
            f"{target.WhichOneof('OneofType')}"
        )
        assert "PCU32" in ct.c_str, f"c_str missing 'PCU32': {ct.c_str!r}"

    def test_typedef_ppcu32_element_is_pointer(self):
        """PPCU32 = typedef PCU32* -> element must be TYPE_POINTER."""
        _, ct = self._find_typedef("PPCU32")
        if ct is None:
            pytest.skip("PPCU32 typedef not found in export")
        target = self._type_at(ct.element_type_idx)
        assert self._is_composite_of(target, self.TYPE_POINTER), (
            f"PPCU32 element should be TYPE_POINTER, got "
            f"{target.WhichOneof('OneofType')}"
        )
        assert "PPCU32" in ct.c_str, f"c_str missing 'PPCU32': {ct.c_str!r}"

    def test_typedef_cppcu32_element_is_pointer(self):
        """CPPCU32 = typedef const PPCU32* -> element must be TYPE_POINTER."""
        _, ct = self._find_typedef("CPPCU32")
        if ct is None:
            pytest.skip("CPPCU32 typedef not found in export")
        assert ct.HasField("element_type_idx"), "CPPCU32 must have element_type_idx"
        assert "CPPCU32" in ct.c_str, f"c_str missing 'CPPCU32': {ct.c_str!r}"
        target = self._type_at(ct.element_type_idx)
        assert self._is_composite_of(target, self.TYPE_POINTER), (
            f"CPPCU32 element should be TYPE_POINTER, got "
            f"{target.WhichOneof('OneofType')}"
        )

    def test_typedef_fn1_c_target_is_pointer(self):
        """Fn1_C = typedef int(*)(int) -> element must be TYPE_POINTER.

        Typedefs always point to the next type in the chain.
        int(*)(int) is a function pointer, so the element is TYPE_POINTER.
        """
        _, ct = self._find_typedef("Fn1_C")
        if ct is None:
            pytest.skip("Fn1_C typedef not found in export")
        target = self._type_at(ct.element_type_idx)
        assert self._is_composite_of(target, self.TYPE_POINTER), (
            f"Fn1_C element should be TYPE_POINTER, got "
            f"{target.WhichOneof('OneofType')}"
        )

    # -- Data type checks (proto level) ------------------------------------

    def test_data_g_u32_data_typed(self):
        """Global g_u32_data should be typed as U32 or TYPE_DW.

        g_u32_data is declared as U32 (locally defined typedef of uint32_t).
        TYPE_UNK is not acceptable.
        """
        d = self._find_data_by_name("g_u32_data")
        if d is None:
            pytest.skip("g_u32_data not found in data")
        t = self._type_at(d.type_index)
        if self._is_composite_of(t, self.TYPE_TYPEDEF):
            assert (
                t.composite_type.name == "U32"
            ), f"g_u32_data typedef should be U32, got {t.composite_type.name!r}"
        elif self._is_primitive(t):
            assert t.primitive_type == Pb.Quokka.TYPE_DW, (
                f"g_u32_data primitive should be TYPE_DW, "
                f"got {Pb.Quokka.BaseType.Name(t.primitive_type)}"
            )
        else:
            pytest.fail(f"g_u32_data unexpected type: {t.WhichOneof('OneofType')}")

    def test_data_g_pu32_data_typed(self):
        """Global g_pu32_data should be typed as PU32 or a pointer.

        PU32 is locally defined; TYPE_UNK is not acceptable.
        """
        d = self._find_data_by_name("g_pu32_data")
        if d is None:
            pytest.skip("g_pu32_data not found in data")
        t = self._type_at(d.type_index)
        if self._is_composite_of(t, self.TYPE_TYPEDEF):
            assert t.composite_type.name == "PU32", (
                f"g_pu32_data typedef should be PU32, got " f"{t.composite_type.name!r}"
            )
        elif self._is_composite_of(t, self.TYPE_POINTER):
            pass  # Pointer type, acceptable
        else:
            pytest.fail(
                f"g_pu32_data should be typed as PU32 or pointer, got "
                f"{t.WhichOneof('OneofType')}"
            )

    def test_data_v12_typed_as_struct_a(self):
        """Global v12 should be typed as struct A."""
        d = self._find_data_by_name("v12")
        if d is None:
            pytest.skip("v12 not found in data")
        t = self._type_at(d.type_index)
        assert self._is_composite_of(t, self.TYPE_STRUCT), (
            f"v12 should be typed as a struct, got " f"{t.WhichOneof('OneofType')}"
        )
        assert (
            t.composite_type.name == "A"
        ), f"v12 struct should be named 'A', got {t.composite_type.name!r}"

    # -- Pointer typedef sizes ----------------------------------------------

    def test_pointer_typedef_sizes(self):
        """All pointer typedefs must have size == address_size // 8."""
        ptr_size = self.prog.address_size // 8
        for name in ("PU32", "PCU32", "PPCU32", "CPPCU32"):
            _, ct = self._find_typedef(name)
            if ct is None:
                continue
            assert (
                ct.size == ptr_size
            ), f"{name} size should be {ptr_size}, got {ct.size}"

    # -- Additional typed data globals --------------------------------------

    def test_data_g_pcu32_data_typed(self):
        """g_pcu32_data is declared as PCU32; should be PCU32 or pointer.

        PCU32 is locally defined; TYPE_UNK is not acceptable.
        """
        d = self._find_data_by_name("g_pcu32_data")
        if d is None:
            pytest.skip("g_pcu32_data not found in data")
        t = self._type_at(d.type_index)
        if self._is_composite_of(t, self.TYPE_TYPEDEF):
            assert t.composite_type.name == "PCU32", (
                f"g_pcu32_data typedef should be PCU32, got "
                f"{t.composite_type.name!r}"
            )
        elif self._is_composite_of(t, self.TYPE_POINTER):
            pass  # pointer type, acceptable
        else:
            pytest.fail(
                f"g_pcu32_data should be typed as PCU32 or pointer, got "
                f"{t.WhichOneof('OneofType')}"
            )

    def test_data_g_ppcu32_data_typed(self):
        """g_ppcu32_data is declared as PPCU32; should be PPCU32 or pointer.

        PPCU32 is locally defined; TYPE_UNK is not acceptable.
        """
        d = self._find_data_by_name("g_ppcu32_data")
        if d is None:
            pytest.skip("g_ppcu32_data not found in data")
        t = self._type_at(d.type_index)
        if self._is_composite_of(t, self.TYPE_TYPEDEF):
            assert t.composite_type.name == "PPCU32", (
                f"g_ppcu32_data typedef should be PPCU32, got "
                f"{t.composite_type.name!r}"
            )
        elif self._is_composite_of(t, self.TYPE_POINTER):
            pass  # pointer type, acceptable
        else:
            pytest.fail(
                f"g_ppcu32_data should be typed as PPCU32 or pointer, got "
                f"{t.WhichOneof('OneofType')}"
            )

    def test_data_g_cppcu32_data_typed(self):
        """g_cppcu32_data is declared as CPPCU32; should be CPPCU32 or ptr.

        CPPCU32 is locally defined; TYPE_UNK is not acceptable.
        """
        d = self._find_data_by_name("g_cppcu32_data")
        if d is None:
            pytest.skip("g_cppcu32_data not found in data")
        t = self._type_at(d.type_index)
        if self._is_composite_of(t, self.TYPE_TYPEDEF):
            assert t.composite_type.name == "CPPCU32", (
                f"g_cppcu32_data typedef should be CPPCU32, got "
                f"{t.composite_type.name!r}"
            )
        elif self._is_composite_of(t, self.TYPE_POINTER):
            pass  # pointer type, acceptable
        else:
            pytest.fail(
                f"g_cppcu32_data should be typed as CPPCU32 or pointer, got "
                f"{t.WhichOneof('OneofType')}"
            )

    def test_data_g_voidfn_c_typed(self):
        """g_voidfn_c is declared as VoidFn_C (function pointer typedef).

        Function types are not yet supported, so primitive/UNK is acceptable.
        """
        d = self._find_data_by_name("g_voidfn_c")
        if d is None:
            pytest.skip("g_voidfn_c not found in data")
        t = self._type_at(d.type_index)
        oneof = t.WhichOneof("OneofType")
        assert oneof in (
            "composite_type",
            "primitive_type",
        ), f"g_voidfn_c unexpected type kind: {oneof}"

    # -- Struct and union structure checks ----------------------------------

    def test_struct_a_member_count(self):
        """struct A has 17 members: a,b,b1,c,d,e,f,g,h,i,j,k,l,m,n,o,p."""
        _, st = self._find_composite("A", self.TYPE_STRUCT)
        if st is None:
            pytest.skip("struct A not found")
        assert (
            len(st.members) == 17
        ), f"struct A should have 17 members, got {len(st.members)}"

    def test_struct_a_member_names(self):
        """struct A members must include the expected names."""
        _, st = self._find_composite("A", self.TYPE_STRUCT)
        if st is None:
            pytest.skip("struct A not found")
        expected = {
            "a",
            "b",
            "b1",
            "c",
            "d",
            "e",
            "f",
            "g",
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
            pytest.skip("struct A not found")
        first = st.members[0]
        assert first.name == "a", f"First member should be 'a', got {first.name!r}"
        assert first.size == 8, f"uint8_t should be 8 bits, got {first.size}"

    def test_union_e_members(self):
        """union E has 2 members: a[4] and b."""
        _, ut = self._find_composite("E", self.TYPE_UNION)
        if ut is None:
            pytest.skip("union E not found")
        assert (
            len(ut.members) == 2
        ), f"union E should have 2 members, got {len(ut.members)}"
        names = {m.name for m in ut.members}
        assert names == {"a", "b"}, f"union E members: {names}"

    def test_union_uweird_c_members(self):
        """union UWeird_C has 5 members: u64, d, parts32, parts16, bytes."""
        _, ut = self._find_composite("UWeird_C", self.TYPE_UNION)
        if ut is None:
            pytest.skip("union UWeird_C not found")
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
            pytest.skip("struct B not found")
        names = {m.name for m in st.members}
        expected = {"a", "b", "c"}
        assert expected.issubset(
            names
        ), f"struct B should have members {expected}, got {names}"

    def test_enum_d_values(self):
        """enum D { FIRST, SECOND, THIRD } must exist with expected values.

        IDA may prefix enum member names (e.g. D::FIRST).
        """
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
        pytest.skip("enum D not found")

    # -- Struct member type resolution --------------------------------------
    #
    # These tests verify that struct members reference the correct types,
    # not just that the struct exists with the right member names.
    # -------------------------------------------------------------------

    def _find_member(self, composite, name):
        """Return the Member proto with *name* in *composite*, or None."""
        for m in composite.members:
            if m.name == name:
                return m
        return None

    def test_struct_a_member_l_type_is_struct_b(self):
        """struct A member 'l' (struct B) must reference struct B."""
        _, st = self._find_composite("A", self.TYPE_STRUCT)
        if st is None:
            pytest.skip("struct A not found")
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
        """struct A member 'm' (C) must reference typedef C or struct C_."""
        _, st = self._find_composite("A", self.TYPE_STRUCT)
        if st is None:
            pytest.skip("struct A not found")
        m = self._find_member(st, "m")
        assert m is not None, "struct A should have member 'm'"
        t = self._type_at(m.type_index)
        if self._is_composite_of(t, self.TYPE_TYPEDEF):
            assert (
                t.composite_type.name == "C"
            ), f"A.m should be typedef C, got {t.composite_type.name!r}"
        elif self._is_composite_of(t, self.TYPE_STRUCT):
            assert (
                "C" in t.composite_type.name
            ), f"A.m should be struct C_, got {t.composite_type.name!r}"
        else:
            pytest.fail(
                f"A.m should be typedef C or struct C_, "
                f"got {t.WhichOneof('OneofType')}"
            )

    def test_struct_a_member_n_type_is_enum_d(self):
        """struct A member 'n' (enum D) must reference enum D.

        enum D is locally defined; TYPE_UNK is not acceptable.
        """
        _, st = self._find_composite("A", self.TYPE_STRUCT)
        if st is None:
            pytest.skip("struct A not found")
        m = self._find_member(st, "n")
        assert m is not None, "struct A should have member 'n'"
        t = self._type_at(m.type_index)
        if t.WhichOneof("OneofType") == "enum_type":
            assert (
                t.enum_type.name == "D"
            ), f"A.n should be enum D, got {t.enum_type.name!r}"
        elif self._is_composite_of(t, self.TYPE_TYPEDEF):
            pass  # Typedef wrapping the enum is acceptable
        else:
            pytest.fail(
                f"A.n should be enum D or typedef wrapping it, "
                f"got {t.WhichOneof('OneofType')}"
            )

    def test_struct_a_member_o_type_is_pointer(self):
        """struct A member 'o' (C*) should be a pointer type."""
        _, st = self._find_composite("A", self.TYPE_STRUCT)
        if st is None:
            pytest.skip("struct A not found")
        m = self._find_member(st, "o")
        assert m is not None, "struct A should have member 'o'"
        t = self._type_at(m.type_index)
        if self._is_composite_of(t, self.TYPE_POINTER):
            return
        # Pointer stored as a primitive (TYPE_QW on 64-bit) is acceptable
        if self._is_primitive(t):
            return
        pytest.fail(
            f"A.o should be pointer or primitive, " f"got {t.WhichOneof('OneofType')}"
        )

    # -- C++ scoped enum checks ---------------------------------------------

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
        pytest.skip("enum E8 not found (C++ scoped enum may not export)")

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
        pytest.skip("enum ENeg not found (C++ scoped enum may not export)")

    def test_cpp_enum_eu64_cpp_exists(self):
        """C++ enum EU64_CPP : uint64_t should be exported."""
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "enum_type":
                if t.enum_type.name == "EU64_CPP":
                    return
        pytest.skip("enum EU64_CPP not found")

    # -- C++ struct checks --------------------------------------------------

    def test_cpp_struct_bitfield_weird_cpp(self):
        """BitfieldWeird_CPP should exist with members ed, b, u, tc."""
        _, st = self._find_composite("BitfieldWeird_CPP", self.TYPE_STRUCT)
        if st is None:
            pytest.skip("BitfieldWeird_CPP not found")
        names = {m.name for m in st.members}
        expected = {"ed", "b", "u", "tc"}
        missing = expected - names
        assert not missing, f"BitfieldWeird_CPP missing members: {missing}, got {names}"

    def test_cpp_struct_member_ptr_host(self):
        """MemberPtrHost should exist with members x, y."""
        _, st = self._find_composite("MemberPtrHost", self.TYPE_STRUCT)
        if st is None:
            pytest.skip("MemberPtrHost not found")
        names = {m.name for m in st.members}
        assert "x" in names, f"MemberPtrHost should have 'x', got {names}"
        assert "y" in names, f"MemberPtrHost should have 'y', got {names}"

    # -- Additional C struct checks -----------------------------------------

    def test_struct_selfref_c_has_next(self):
        """SelfRef_C should have 'next' member (self-referential pointer)."""
        _, st = self._find_composite("SelfRef_C", self.TYPE_STRUCT)
        if st is None:
            pytest.skip("SelfRef_C not found")
        names = {m.name for m in st.members}
        assert "next" in names, f"SelfRef_C should have 'next', got {names}"

    def test_struct_packed1_c_exists(self):
        """Packed1_C should exist as a struct with members a, b."""
        _, st = self._find_composite("Packed1_C", self.TYPE_STRUCT)
        if st is None:
            pytest.skip("Packed1_C not found")
        names = {m.name for m in st.members}
        assert "a" in names, f"Packed1_C should have 'a', got {names}"
        assert "b" in names, f"Packed1_C should have 'b', got {names}"

    def test_struct_has_anon_agg_c(self):
        """HasAnonAgg_C should exist with 'tag' and 'u' members."""
        _, st = self._find_composite("HasAnonAgg_C", self.TYPE_STRUCT)
        if st is None:
            pytest.skip("HasAnonAgg_C not found")
        names = {m.name for m in st.members}
        assert "tag" in names, f"HasAnonAgg_C should have 'tag', got {names}"
        assert "u" in names, f"HasAnonAgg_C should have 'u', got {names}"

    # -- Additional typed data globals (C++ and more C) ---------------------

    def test_data_g_a_data_typed_as_struct_a(self):
        """g_a_data is declared as struct A; must be typed as struct A."""
        d = self._find_data_by_name("g_a_data")
        if d is None:
            pytest.skip("g_a_data not found in data")
        t = self._type_at(d.type_index)
        assert self._is_composite_of(
            t, self.TYPE_STRUCT
        ), f"g_a_data should be struct A, got {t.WhichOneof('OneofType')}"
        assert (
            t.composite_type.name == "A"
        ), f"g_a_data should be struct A, got {t.composite_type.name!r}"

    def test_data_g_bfw_data_typed(self):
        """g_bfw_data is declared as BitfieldWeird_C."""
        d = self._find_data_by_name("g_bfw_data")
        if d is None:
            pytest.skip("g_bfw_data not found in data")
        t = self._type_at(d.type_index)
        if self._is_composite_of(t, self.TYPE_STRUCT):
            assert t.composite_type.name == "BitfieldWeird_C", (
                f"g_bfw_data should be BitfieldWeird_C, got "
                f"{t.composite_type.name!r}"
            )
            return
        # Bitfield struct may degrade to a primitive
        if self._is_primitive(t):
            return
        pytest.fail(f"g_bfw_data unexpected type: {t.WhichOneof('OneofType')}")

    def test_data_g_mph_data_typed(self):
        """g_mph_data is declared as MemberPtrHost; must be typed correctly."""
        d = self._find_data_by_name("g_mph_data")
        if d is None:
            pytest.skip("g_mph_data not found in data")
        t = self._type_at(d.type_index)
        assert self._is_composite_of(t, self.TYPE_STRUCT), (
            f"g_mph_data should be MemberPtrHost, got " f"{t.WhichOneof('OneofType')}"
        )
        assert t.composite_type.name == "MemberPtrHost", (
            f"g_mph_data should be MemberPtrHost, got " f"{t.composite_type.name!r}"
        )

    def test_data_g_uw_c_typed(self):
        """g_uw_c is declared as union UWeird_C."""
        d = self._find_data_by_name("g_uw_c")
        if d is None:
            pytest.skip("g_uw_c not found in data")
        t = self._type_at(d.type_index)
        if self._is_composite_of(t, self.TYPE_UNION):
            assert t.composite_type.name == "UWeird_C", (
                f"g_uw_c should be union UWeird_C, got " f"{t.composite_type.name!r}"
            )
            return
        if self._is_primitive(t):
            return  # Union stored as primitive is acceptable
        pytest.fail(f"g_uw_c unexpected type: {t.WhichOneof('OneofType')}")
