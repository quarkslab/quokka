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

"""
Feature Extractor

This snippet uses Quokka to extract features from the every function (and block) of the program.

Usage:
    python ./script <binary_path>

Author:
    Written by dm (Alexis Challande) in 2022.
"""

from __future__ import annotations

import json
import sys
from typing import Dict, Union, List
import quokka

# Use the code from arch.py in this repo
# Originally
# https://github.com/Cisco-Talos/binary_function_similarity/blob/main/IDA_scripts/IDA_acfg_features/core/architecture.py
ARCH_MNEM = ...

FeaturesDict = Dict[str, Union[int, List[str], List[int], "FeaturesDict"]]


def get_bb_features(block: quokka.Block) -> FeaturesDict:
    """Extract features from a Basic Block"""

    mnemonics = [inst.cs_inst.mnemonic for inst in block.instructions]
    arch = block.program.isa.name

    return {
        "bb_len": block.size,
        # List features
        "bb_numerics": block.constants,
        "bb_strings": block.strings,
        # Numeric features
        "n_numeric_consts": len(block.constants),
        "n_string_consts": len(block.strings),
        "n_instructions": len(mnemonics),
        "n_arith_instrs": sum(
            1 for m in mnemonics if m in ARCH_MNEM[arch]["arithmetic"]
        ),
        "n_call_instrs": sum(1 for m in mnemonics if m in ARCH_MNEM[arch]["call"]),
        "n_logic_instrs": sum(1 for m in mnemonics if m in ARCH_MNEM[arch]["logic"]),
        "n_transfer_instrs": sum(
            1 for m in mnemonics if m in ARCH_MNEM[arch]["transfer"]
        ),
        "n_redirect_instrs": sum(
            1
            for m in mnemonics
            if (m in ARCH_MNEM[arch]["unconditional"])
            or (m in ARCH_MNEM[arch]["conditional"])
            or (m in ARCH_MNEM[arch]["call"])
        ),
    }


def sum_block_features(bb_features: FeaturesDict, feature: str) -> int:
    """Sum the values for every basic block in the function"""
    assert feature.startswith("n_"), "Only numeric values can be summed"
    return sum(basic_block[feature] for basic_block in bb_features.values())


def get_func_features(func: quokka.Function) -> FeaturesDict:
    """Extracts features from a Function"""
    bb_features = {}
    for block_start in func.graph:
        block = func.get_block(block_start)
        bb_features[block_start] = get_bb_features(block)

    return {
        "n_func_calls": sum_block_features(bb_features, "n_call_instrs"),
        "n_logic_instrs": sum_block_features(bb_features, "n_logic_instrs"),
        "n_redirections": sum_block_features(bb_features, "n_redirect_instrs"),
        "n_transfer_instrs": sum_block_features(bb_features, "n_transfer_instrs"),
        "size_local_variables": ...,  # Not possible with Quokka
        "n_bb": len(bb_features),
        "n_edges": len(func.graph.edges),
        "n_incoming_calls": len(func.callers),
        "n_instructions": sum(1 for _ in func.instructions),
        "basic_blocks": bb_features,
    }


def export_binary(binary: quokka.Program) -> None:
    """Export features from a Program"""

    prog_features: FeaturesDict = {}
    for func in binary.values():
        prog_features[func.start] = get_func_features(func)

    with open(f"{binary.name}.json", "w") as fp:
        json.dump(prog_features, fp, indent=True)


if __name__ == "main":
    program: quokka.Program = quokka.Program.from_binary(sys.argv[1])
    export_binary(program)
