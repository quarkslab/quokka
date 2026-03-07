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

"""IDA apply-back integration tests.

These tests exercise the apply-back feature: modifying a .quokka in-memory,
applying the changes to the IDA database, and re-exporting to verify that the
whole signature (name, return type, param types, param names, param count) is
correctly reflected in both the stored prototype and the Hex-Rays decompiled
output.
"""

import re
import shutil
from pathlib import Path

import idascript
import pytest

import quokka

requires_ida = pytest.mark.skipif(
    idascript.get_ida_path() is None,
    reason="IDA Pro not found (set IDA_PATH or add it to $PATH)",
)


# ---------------------------------------------------------------------------
# Helpers for parsing C prototypes from IDA-exported strings
# ---------------------------------------------------------------------------

def _parse_prototype(proto_str):
    """Parse a C prototype string into (return_type, name, params_list).

    Each element of params_list is (type_str, name_str).
    Handles prototypes like:
        __int64 __fastcall quokka_sig(unsigned int alpha, char beta);
    """
    proto_str = proto_str.rstrip(";").strip()
    # Match: <return_type> [calling_conv] <name>(<params>)
    m = re.match(r"^(.+?)\s+(\w+)\s*\(([^)]*)\)\s*$", proto_str)
    if not m:
        return None, None, []
    ret_and_cc = m.group(1).strip()
    name = m.group(2).strip()
    params_str = m.group(3).strip()

    # Strip calling convention from return type
    for cc in ("__cdecl", "__fastcall", "__stdcall", "__thiscall"):
        ret_and_cc = ret_and_cc.replace(cc, "").strip()
    ret_type = ret_and_cc

    # Parse params
    params = []
    if params_str and params_str != "void":
        for p in params_str.split(","):
            p = p.strip()
            # Last token is the param name, everything before is the type
            parts = p.rsplit(None, 1)
            if len(parts) == 2:
                ptype, pname = parts
                # Handle pointer types where * is attached to name
                if pname.startswith("*"):
                    ptype = ptype + " *"
                    pname = pname[1:]
                params.append((ptype.strip(), pname.strip()))
            else:
                params.append((p, ""))

    return ret_type, name, params


# ---------------------------------------------------------------------------
# Full signature change tests (sig_test binary)
# ---------------------------------------------------------------------------


@requires_ida
class TestApplyBackFullSignature:
    """Apply full signature changes to an IDA database and verify every aspect.

    Uses the sig_test binary which has functions with clear, simple
    prototypes (int params, non-variadic) that IDA will faithfully
    reproduce and accept changes to.

    Verifies: function name, return type, parameter types, parameter names,
    and parameter count -- in both the stored prototype and Hex-Rays
    decompiled output.
    """

    @pytest.fixture(autouse=True)
    def _setup(self, root_directory: Path, tmp_path: Path):
        """Export sig_test with decompilation into a temp directory."""
        binary_src = root_directory / "tests" / "dataset" / "sig_test"
        if not binary_src.exists():
            pytest.skip("sig_test binary not found in tests/dataset/")

        self.tmp = tmp_path
        self.binary = tmp_path / "sig_test"
        shutil.copy2(binary_src, self.binary)

        self.database = tmp_path / "sig_test.i64"
        self.quokka_file = tmp_path / "sig_test.quokka"

        self.prog = quokka.Program.from_binary(
            self.binary,
            output_file=self.quokka_file,
            database_file=self.database,
            decompiled=True,
            timeout=600,
        )

    def _find_function_by_name(self, name):
        """Find a function by its original symbol name."""
        for addr, func in self.prog.items():
            if func.name == name:
                return func
        pytest.skip(f"Function {name!r} not found in sig_test")

    def _apply_and_reexport(self):
        """Apply edits via commit(), then re-export and return new Program."""
        errors = self.prog.commit(
            database_file=self.database,
            overwrite=True,
            timeout=600,
        )
        assert errors == 0, f"commit() returned {errors} errors"

        reexport = self.tmp / "sig_test_re.quokka"
        new_prog = quokka.Program.from_binary(
            self.binary,
            output_file=reexport,
            database_file=self.database,
            decompiled=True,
            override=False,
            timeout=600,
        )
        return new_prog

    # -- tests -------------------------------------------------------------

    def test_full_signature_change(self):
        """Change name, return type, param types, param names, and param
        count on add_two, then verify all five aspects in the re-exported
        prototype and decompiled code."""
        func = self._find_function_by_name("add_two")
        original_addr = func.address

        # Original: int add_two(int x, int y) -- 2 params
        # New:      __int64 quokka_sig(unsigned int quokka_alpha,
        #                              unsigned int quokka_beta,
        #                              char quokka_gamma) -- 3 params
        new_name = "quokka_sig"
        new_proto = (
            "__int64 __cdecl quokka_sig"
            "(unsigned int quokka_alpha, unsigned int quokka_beta, "
            "char quokka_gamma);"
        )
        func.name = new_name
        func.prototype = new_proto

        new_prog = self._apply_and_reexport()
        new_func = new_prog[original_addr]

        # --- Verify stored prototype ---
        proto = new_func.prototype
        assert proto, "Re-exported prototype is empty"
        ret_type, parsed_name, params = _parse_prototype(proto)

        # 1. Name
        assert parsed_name == new_name, (
            f"Prototype name mismatch: expected {new_name!r}, "
            f"got {parsed_name!r} in {proto!r}"
        )

        # 2. Return type
        assert "__int64" in ret_type or "long long" in ret_type, (
            f"Return type mismatch: expected '__int64', "
            f"got {ret_type!r} in {proto!r}"
        )

        # 3. Param count (2 -> 3)
        assert len(params) == 3, (
            f"Param count mismatch: expected 3, "
            f"got {len(params)} in {proto!r}"
        )

        # 4. Param names
        param_names = [p[1] for p in params]
        assert param_names == ["quokka_alpha", "quokka_beta", "quokka_gamma"], (
            f"Param names mismatch: expected "
            f"['quokka_alpha', 'quokka_beta', 'quokka_gamma'], "
            f"got {param_names} in {proto!r}"
        )

        # 5. Param types
        assert "unsigned int" in params[0][0], (
            f"Param 0 type mismatch: expected 'unsigned int', "
            f"got {params[0][0]!r} in {proto!r}"
        )
        assert "unsigned int" in params[1][0], (
            f"Param 1 type mismatch: expected 'unsigned int', "
            f"got {params[1][0]!r} in {proto!r}"
        )
        assert "char" in params[2][0], (
            f"Param 2 type mismatch: expected 'char', "
            f"got {params[2][0]!r} in {proto!r}"
        )

        # --- Verify decompiled code reflects changes ---
        decomp = new_func.decompiled_code
        assert decomp, "Decompiled code is empty"

        sig_line = decomp.split("\n")[0]
        assert new_name in sig_line, (
            f"Decompiled sig does not contain name {new_name!r}: {sig_line!r}"
        )
        assert "quokka_alpha" in sig_line, (
            f"Decompiled sig does not contain param name 'quokka_alpha': "
            f"{sig_line!r}"
        )
        assert "quokka_beta" in sig_line, (
            f"Decompiled sig does not contain param name 'quokka_beta': "
            f"{sig_line!r}"
        )
        assert "quokka_gamma" in sig_line, (
            f"Decompiled sig does not contain param name 'quokka_gamma': "
            f"{sig_line!r}"
        )

    def test_return_type_change(self):
        """Change only the return type and verify it is reflected."""
        func = self._find_function_by_name("compute_three")
        original_addr = func.address

        # Keep original name and params but change return type
        new_proto = (
            "unsigned int __cdecl compute_three"
            "(long a, long b, long c);"
        )
        func.prototype = new_proto

        new_prog = self._apply_and_reexport()
        new_func = new_prog[original_addr]

        proto = new_func.prototype
        ret_type, _, _ = _parse_prototype(proto)
        assert "unsigned int" in ret_type or "unsigned __int32" in ret_type, (
            f"Return type not changed: got {ret_type!r} in {proto!r}"
        )

    def test_param_count_decrease(self):
        """Reduce param count and verify it in the stored prototype."""
        func = self._find_function_by_name("compute_three")
        original_addr = func.address

        # Original: long compute_three(long a, long b, long c) -- 3 params
        # New: int compute_three(int quokka_only) -- 1 param
        new_proto = "int __cdecl compute_three(int quokka_only);"
        func.prototype = new_proto

        new_prog = self._apply_and_reexport()
        new_func = new_prog[original_addr]

        proto = new_func.prototype
        _, _, params = _parse_prototype(proto)
        assert len(params) == 1, (
            f"Param count not reduced: expected 1, "
            f"got {len(params)} in {proto!r}"
        )
        assert params[0][1] == "quokka_only", (
            f"Param name mismatch: expected 'quokka_only', "
            f"got {params[0][1]!r} in {proto!r}"
        )

    def test_rename_reflected_in_decompiled_code(self):
        """After renaming a function, decompiled code uses the new name."""
        func = self._find_function_by_name("use_char_ptr")
        original_addr = func.address
        new_name = "quokka_renamed"

        func.name = new_name

        new_prog = self._apply_and_reexport()
        new_func = new_prog[original_addr]

        assert new_func.name == new_name, (
            f"Name not updated: expected {new_name!r}, got {new_func.name!r}"
        )
        assert new_name in new_func.decompiled_code, (
            f"Decompiled code does not contain new name {new_name!r}.\n"
            f"Snippet: {new_func.decompiled_code[:200]!r}"
        )
