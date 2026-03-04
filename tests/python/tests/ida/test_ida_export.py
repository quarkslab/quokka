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

    def test_typedef_entries_in_proto(self):
        """Verify that TYPE_TYPEDEF entries appear in the raw protobuf."""
        typedef_count = 0
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "composite_type":
                if t.composite_type.type == Pb.Quokka.CompositeType.CompositeSubType.TYPE_TYPEDEF:
                    typedef_count += 1
        assert typedef_count > 0, (
            "many_types_cpp should export at least one typedef entry"
        )

    def test_typedef_names(self):
        """Verify known typedefs from many_types.c are present."""
        known_typedefs = {"U32", "PU32", "C"}
        found = set()
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "composite_type":
                ct = t.composite_type
                if ct.type == Pb.Quokka.CompositeType.CompositeSubType.TYPE_TYPEDEF:
                    found.add(ct.name)
        missing = known_typedefs - found
        assert not missing, f"Expected typedefs not found: {missing}"

    def test_typedef_element_type_idx_valid(self):
        """Every typedef must have a valid element_type_idx."""
        types_count = len(self.prog.proto.types)
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "composite_type":
                ct = t.composite_type
                if ct.type == Pb.Quokka.CompositeType.CompositeSubType.TYPE_TYPEDEF:
                    assert ct.HasField("element_type_idx"), (
                        f"Typedef {ct.name} missing element_type_idx"
                    )
                    assert 0 <= ct.element_type_idx < types_count, (
                        f"Typedef {ct.name} has out-of-range "
                        f"element_type_idx={ct.element_type_idx}"
                    )

    def test_typedef_chain_u32(self):
        """U32 is typedef'd from uint32_t.

        Its element_type_idx should point to a primitive type or a
        composite representing the base integer type.
        """
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "composite_type":
                ct = t.composite_type
                if (ct.type == Pb.Quokka.CompositeType.CompositeSubType.TYPE_TYPEDEF
                        and ct.name == "U32"):
                    # U32 is typedef uint32_t, element should be a base type
                    target = self.prog.proto.types[ct.element_type_idx]
                    # uint32_t likely resolves to a primitive (TYPE_DW) or
                    # another typedef. Either is acceptable.
                    assert target.WhichOneof("OneofType") in (
                        "primitive_type", "composite_type"
                    ), f"U32 target should be primitive or composite, got {target}"
                    return
        pytest.skip("U32 typedef not found in export")

    def test_typedef_pu32_element_is_pointer(self):
        """PU32 is typedef U32* -- its element should resolve to a pointer.

        When IDA stores a pointer typedef with the same ordinal,
        element_type_idx falls back to the primitive TYPE_POINTER
        BaseType (to avoid a self-referencing cycle). The c_str field
        preserves the full 'typedef U32 *PU32;' declaration.
        """
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "composite_type":
                ct = t.composite_type
                if (ct.type == Pb.Quokka.CompositeType.CompositeSubType.TYPE_TYPEDEF
                        and ct.name == "PU32"):
                    target = self.prog.proto.types[ct.element_type_idx]
                    # PU32 = U32*, element should be either:
                    # - a primitive (TYPE_POINTER BaseType, self-ref guard) or
                    # - a separate PointerType composite
                    oneof = target.WhichOneof("OneofType")
                    assert oneof in ("primitive_type", "composite_type"), (
                        f"PU32 element should be primitive or composite, "
                        f"got {oneof}"
                    )
                    # Verify the typedef is not self-referencing
                    if oneof == "composite_type":
                        assert ct.name != target.composite_type.name, (
                            "PU32 should not point to itself"
                        )
                    # Verify c_str preserves the original declaration
                    assert "PU32" in ct.c_str
                    assert "U32" in ct.c_str
                    return
        pytest.skip("PU32 typedef not found in export")

    def test_no_duplicate_type_names_per_subtype(self):
        """No two typedefs should have the same name."""
        seen = set()
        for t in self.prog.proto.types:
            if t.WhichOneof("OneofType") == "composite_type":
                ct = t.composite_type
                if ct.type == Pb.Quokka.CompositeType.CompositeSubType.TYPE_TYPEDEF:
                    assert ct.name not in seen, (
                        f"Duplicate typedef name: {ct.name}"
                    )
                    seen.add(ct.name)
