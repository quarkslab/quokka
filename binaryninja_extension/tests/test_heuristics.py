"""Tests for the structural (non-heuristic) classification paths.

These run only against the conftest stub: they build synthetic views,
tokens, and LLIL nodes.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT))

import binaryninja  # noqa: E402  # the conftest stub when outside BinaryNinja
from binaryninja import (  # noqa: E402
    BranchType,
    InstructionTextTokenType,
    LowLevelILOperation,
)

from bn_quokka.context import ExportContext  # noqa: E402
from bn_quokka.exporters import references as refs  # noqa: E402
from bn_quokka.exporters.cfg import FunctionExporter, _ExportBlock  # noqa: E402
from bn_quokka.exporters.instructions import (  # noqa: E402
    ACCESS_UNKNOWN,
    export_instruction,
)
from bn_quokka.quokka_pb2 import Quokka  # noqa: E402
from bn_quokka.util import SegmentInfo  # noqa: E402

pytestmark = pytest.mark.skipif(
    not isinstance(binaryninja.log_info, mock.MagicMock),
    reason="builds synthetic objects against the stubbed BinaryNinja API",
)


def make_context(view=None) -> ExportContext:
    return ExportContext(view, 0)


# --- instruction_branches cache -------------------------------------------


class FakeArch:
    def __init__(self):
        self.calls = 0

    def get_instruction_info(self, data, addr):
        self.calls += 1
        return SimpleNamespace(
            length=4,
            branches=[
                SimpleNamespace(type=BranchType.UnconditionalBranch, target=0x1234)
            ],
        )


class FakeBranchView:
    def __init__(self):
        self.arch = FakeArch()

    def read(self, addr, size):
        return b"\x90" * size


def test_instruction_branches_decodes_once():
    view = FakeBranchView()
    ctx = make_context(view)

    first = ctx.instruction_branches(0x10)
    second = ctx.instruction_branches(0x10)

    assert view.arch.calls == 1
    assert first is second
    assert first == (4, ((BranchType.UnconditionalBranch, 0x1234),))


# --- conditional-return block typing ---------------------------------------


def make_block(start: int, edges: list) -> _ExportBlock:
    return _ExportBlock(
        start=start,
        instructions=[([], 4)],
        outgoing_edges=edges,
        source_block=SimpleNamespace(
            has_invalid_instructions=False,
            has_undetermined_outgoing_edges=False,
            can_exit=True,
        ),
    )


def test_block_type_conditional_return_from_branch_info():
    ctx = make_context()
    ctx.segments = [SegmentInfo(name="seg", start_offset=0x1000, size=0x100)]
    ctx._instruction_branch_cache[0x1000] = (
        4,
        ((BranchType.FunctionReturn, None),),
    )
    block = make_block(0x1000, [(0x1100, BranchType.FalseBranch)])

    assert FunctionExporter._block_type(ctx, block) == Quokka.Block.BLOCK_TYPE_CNDRET


def test_block_type_plain_conditional_is_not_cndret():
    # A conditional branch over a symbol containing "ret" must not be CNDRET.
    ctx = make_context()
    ctx.segments = [SegmentInfo(name="seg", start_offset=0x1000, size=0x100)]
    ctx._instruction_branch_cache[0x1000] = (4, ())
    block = make_block(0x1000, [(0x1100, BranchType.FalseBranch)])

    assert FunctionExporter._block_type(ctx, block) == Quokka.Block.BLOCK_TYPE_NORMAL


# --- call-site detection ----------------------------------------------------


def fake_func_with_llil(operation):
    llil = SimpleNamespace(operation=operation, operands=[])
    return SimpleNamespace(get_llil_at=lambda addr: llil)


def test_is_call_site_from_branch_info():
    ctx = make_context()
    ctx._instruction_branch_cache[0x10] = (4, ((BranchType.CallDestination, 0x99),))

    assert FunctionExporter._is_call_site(ctx, fake_func_with_llil(None), 0x10)


def test_is_call_site_indirect_call_via_llil():
    ctx = make_context()
    ctx._instruction_branch_cache[0x10] = (4, ())
    func = fake_func_with_llil(LowLevelILOperation.LLIL_CALL)

    assert FunctionExporter._is_call_site(ctx, func, 0x10)


def test_is_call_site_negative():
    ctx = make_context()
    ctx._instruction_branch_cache[0x10] = (4, ())
    func = fake_func_with_llil(LowLevelILOperation.LLIL_ADD)

    assert not FunctionExporter._is_call_site(ctx, func, 0x10)


# --- operand access ----------------------------------------------------------


class FakeToken:
    def __init__(self, token_type, text, value=None):
        self.type = token_type
        self.text = text
        if value is not None:
            self.value = value


def test_operand_access_is_unknown():
    ctx = make_context()
    builder = Quokka()
    tokens = [
        FakeToken(InstructionTextTokenType.InstructionToken, "mov"),
        FakeToken(InstructionTextTokenType.RegisterToken, "rax"),
    ]

    export_instruction(ctx, builder, tokens, 3, False)

    assert len(builder.operands) == 1
    assert builder.operands[0].access == ACCESS_UNKNOWN == 0


# --- structural LLIL reference classification --------------------------------


class LL:
    """Minimal LLIL expression node."""

    def __init__(self, operation, operands=(), constant=None, dest=None, src=None):
        self.operation = operation
        self.operands = list(operands)
        if constant is not None:
            self.constant = constant
        if dest is not None:
            self.dest = dest
            self.operands.append(dest)
        if src is not None:
            self.src = src
            self.operands.append(src)


def const_ptr(value):
    return LL(LowLevelILOperation.LLIL_CONST_PTR, constant=value)


def test_llil_store_destination_is_write():
    # [0x2000] = rax
    store = LL(
        LowLevelILOperation.LLIL_STORE,
        dest=const_ptr(0x2000),
        src=LL(LowLevelILOperation.LLIL_REG),
    )
    assert refs._classify_llil_reference(store, 0x2000) == Quokka.EDGE_DATA_WRITE


def test_llil_load_source_is_read():
    # rax = [0x2000]
    load = LL(LowLevelILOperation.LLIL_LOAD, src=const_ptr(0x2000))
    set_reg = LL(LowLevelILOperation.LLIL_SET_REG, operands=[load])
    assert refs._classify_llil_reference(set_reg, 0x2000) == Quokka.EDGE_DATA_READ


def test_llil_stored_value_is_not_a_write():
    # [rax] = 0x2000: the constant is the stored value, not the destination.
    store = LL(
        LowLevelILOperation.LLIL_STORE,
        dest=LL(LowLevelILOperation.LLIL_REG),
        src=const_ptr(0x2000),
    )
    assert refs._classify_llil_reference(store, 0x2000) != Quokka.EDGE_DATA_WRITE


def test_llil_call_target_is_read():
    call = LL(LowLevelILOperation.LLIL_CALL, operands=[const_ptr(0x2000)])
    assert refs._classify_llil_reference(call, 0x2000) == Quokka.EDGE_DATA_READ


def test_llil_unrelated_constant_is_unclassified():
    store = LL(
        LowLevelILOperation.LLIL_STORE,
        dest=const_ptr(0x1111),
        src=LL(LowLevelILOperation.LLIL_REG),
    )
    assert refs._classify_llil_reference(store, 0x2000) is None


# --- token reference classification ------------------------------------------


def test_token_memory_operand_is_read():
    tokens = [
        FakeToken(InstructionTextTokenType.InstructionToken, "mov"),
        FakeToken(InstructionTextTokenType.BeginMemoryOperandToken, "["),
        FakeToken(InstructionTextTokenType.PossibleAddressToken, "0x2000", 0x2000),
        FakeToken(InstructionTextTokenType.EndMemoryOperandToken, "]"),
    ]
    assert refs._classify_token_reference(tokens, 0x2000) == Quokka.EDGE_DATA_READ


def test_token_immediate_operand_is_indirect():
    tokens = [
        FakeToken(InstructionTextTokenType.InstructionToken, "mov"),
        FakeToken(InstructionTextTokenType.PossibleAddressToken, "0x2000", 0x2000),
    ]
    assert refs._classify_token_reference(tokens, 0x2000) == Quokka.EDGE_DATA_INDIR
