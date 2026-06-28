"""Tests for CFG edge export fidelity.

Pure logic over _ExportBlock and real protobuf messages; runs against the
conftest BinaryNinja stub (BranchType members are stable sentinel objects).
"""

from __future__ import annotations

import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT))

from binaryninja import BranchType  # noqa: E402

from bn_quokka.exporters.cfg import (  # noqa: E402
    FunctionExporter,
    _ExportBlock,
    _map_edge_type,
)
from bn_quokka.quokka_pb2 import Quokka  # noqa: E402


def block(start: int, outgoing_edges: list) -> _ExportBlock:
    return _ExportBlock(
        start=start,
        instructions=[],
        outgoing_edges=outgoing_edges,
        source_block=None,
    )


def test_map_edge_type_covers_branch_kinds():
    assert _map_edge_type(BranchType.TrueBranch) == Quokka.EDGE_JUMP_COND
    assert _map_edge_type(BranchType.FalseBranch) == Quokka.EDGE_JUMP_COND
    assert _map_edge_type(BranchType.UnconditionalBranch) == Quokka.EDGE_JUMP_UNCOND
    assert _map_edge_type(BranchType.IndirectBranch) == Quokka.EDGE_JUMP_INDIR
    assert _map_edge_type(BranchType.UnresolvedBranch) == Quokka.EDGE_JUMP_INDIR
    assert _map_edge_type(BranchType.CallDestination) == Quokka.EDGE_CALL
    assert _map_edge_type(object()) == Quokka.EDGE_UNKNOWN


def test_export_block_derived_views():
    edges = [(0x10, BranchType.TrueBranch), (0x20, BranchType.FalseBranch)]
    sample = block(0x0, edges)

    assert sample.outgoing_targets == [0x10, 0x20]
    assert sample.outgoing_edge_types == {
        BranchType.TrueBranch,
        BranchType.FalseBranch,
    }


def test_edges_carry_per_edge_branch_types():
    function = Quokka.Function()
    blocks = [
        # Conditional with both targets in-function: COND + COND, not a
        # function of the out-degree.
        block(0x0, [(0x10, BranchType.TrueBranch), (0x20, BranchType.FalseBranch)]),
        # Three-way jump table: every edge INDIR.
        block(
            0x10,
            [
                (0x0, BranchType.IndirectBranch),
                (0x10, BranchType.IndirectBranch),
                (0x20, BranchType.IndirectBranch),
            ],
        ),
        block(0x20, []),
    ]
    indices = {0x0: 0, 0x10: 1, 0x20: 2}

    FunctionExporter._export_edges(function, blocks, indices)

    assert [edge.edge_type for edge in function.edges] == [
        Quokka.EDGE_JUMP_COND,
        Quokka.EDGE_JUMP_COND,
        Quokka.EDGE_JUMP_INDIR,
        Quokka.EDGE_JUMP_INDIR,
        Quokka.EDGE_JUMP_INDIR,
    ]
    assert [(edge.source, edge.destination) for edge in function.edges] == [
        (0, 1),
        (0, 2),
        (1, 0),
        (1, 1),
        (1, 2),
    ]


def test_single_surviving_conditional_edge_stays_conditional():
    # A conditional jump whose other target falls outside the function must
    # not degrade to "unconditional" just because only one edge survives.
    function = Quokka.Function()
    blocks = [
        block(0x0, [(0x10, BranchType.TrueBranch), (0x999, BranchType.FalseBranch)]),
        block(0x10, []),
    ]

    FunctionExporter._export_edges(function, blocks, {0x0: 0, 0x10: 1})

    assert len(function.edges) == 1
    assert function.edges[0].edge_type == Quokka.EDGE_JUMP_COND
