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
from quokka.data_type import StructureType


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
