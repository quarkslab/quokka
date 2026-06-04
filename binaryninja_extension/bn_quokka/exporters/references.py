"""Cross-reference export and read/write/call classification."""

from __future__ import annotations

from typing import Any

from binaryninja import BranchType, LowLevelILOperation  # type: ignore

from ..context import ExportContext
from ..quokka_pb2 import Quokka
from .instructions import (
    CALL_LLIL_OPERATIONS,
    extract_mnemonic,
    llil_at,
    operand_token_groups,
    token_value,
    tokens_are_memory,
)


_LOAD_OPERATIONS = (
    LowLevelILOperation.LLIL_LOAD,
    LowLevelILOperation.LLIL_LOAD_SSA,
)
_STORE_OPERATIONS = (
    LowLevelILOperation.LLIL_STORE,
    LowLevelILOperation.LLIL_STORE_SSA,
)
_CONST_OPERATIONS = (
    LowLevelILOperation.LLIL_CONST,
    LowLevelILOperation.LLIL_CONST_PTR,
    LowLevelILOperation.LLIL_EXTERN_PTR,
)


class ReferenceExporter:
    @staticmethod
    def export(ctx: ExportContext, builder: Quokka) -> None:
        view = ctx.view
        records: set[tuple[int, int, int]] = set()

        for func in view.functions:
            for tokens, addr in func.instructions:
                branch_targets = ReferenceExporter._branch_targets(ctx, addr)
                fallthrough = _instruction_fallthrough(ctx, addr)
                for dest, edge_type in branch_targets.items():
                    records.add((addr, dest, edge_type))

                refs = set(view.get_code_refs_from(addr, func=func))
                refs.update(view.get_data_refs_from(addr))
                for dest in refs:
                    if dest in branch_targets or dest == fallthrough:
                        continue
                    edge_type = ReferenceExporter._classify_nonbranch_reference(
                        ctx, func, addr, tokens, dest
                    )
                    records.add((addr, dest, edge_type))

        for addr, data_var in view.data_vars.items():
            for dest in view.get_data_refs_from(addr, max(1, len(data_var))):
                records.add((addr, dest, Quokka.EDGE_DATA_INDIR))

        for source, destination, edge_type in sorted(records):
            ref_index = len(builder.references)
            reference = builder.references.add()
            reference.source.address = source
            reference.destination.address = destination
            reference.reference_type = edge_type
            ReferenceExporter._record_instruction_xrefs(
                ctx, builder, ref_index, source, destination
            )

    @staticmethod
    def _branch_targets(ctx: ExportContext, addr: int) -> dict[int, int]:
        info = ctx.instruction_branches(addr)
        if info is None:
            return {}

        length, branches = info
        result: dict[int, int] = {}
        fallthrough = addr + length
        for branch_type, target in branches:
            if target is None or target == fallthrough:
                continue
            if branch_type == BranchType.UnresolvedBranch and target == 0:
                continue
            if branch_type == BranchType.CallDestination:
                result[target] = Quokka.EDGE_CALL
            elif branch_type in (BranchType.TrueBranch, BranchType.FalseBranch):
                result[target] = Quokka.EDGE_JUMP_COND
            elif branch_type == BranchType.UnconditionalBranch:
                result[target] = Quokka.EDGE_JUMP_UNCOND
            elif branch_type in (BranchType.IndirectBranch, BranchType.UnresolvedBranch):
                result[target] = Quokka.EDGE_JUMP_INDIR
        return result

    @staticmethod
    def _classify_nonbranch_reference(
        ctx: ExportContext, func: Any, addr: int, tokens: list[Any], dest: int
    ) -> int:
        # The lifted IL is the most precise signal: it shows structurally
        # whether the constant is a store destination or a load source.
        llil = llil_at(func, addr)
        if llil is not None:
            edge = _classify_llil_reference(llil, dest)
            if edge is not None:
                return edge

        token_edge = _classify_token_reference(tokens, dest)
        if token_edge is not None:
            return token_edge

        # Coarse fallback when the constant is not visible in the IL: the
        # instruction's top-level operation still hints at the access kind.
        llil_op = getattr(llil, "operation", None)
        if llil_op in _LOAD_OPERATIONS:
            return Quokka.EDGE_DATA_READ
        if llil_op in _STORE_OPERATIONS:
            return Quokka.EDGE_DATA_WRITE
        if llil_op in CALL_LLIL_OPERATIONS:
            return Quokka.EDGE_DATA_READ

        return Quokka.EDGE_DATA_INDIR

    @staticmethod
    def _record_instruction_xrefs(
        ctx: ExportContext,
        builder: Quokka,
        ref_index: int,
        source: int,
        destination: int,
    ) -> None:
        source_loc = ctx.instruction_locations.get(source)
        if source_loc is not None:
            func_idx, block_idx, instr_idx = source_loc
            xref = builder.functions[func_idx].blocks[block_idx].instructions_xref_from.add()
            xref.instr_bb_idx = instr_idx
            xref.xref_index = ref_index

        dest_loc = ctx.instruction_locations.get(destination)
        if dest_loc is not None:
            func_idx, block_idx, instr_idx = dest_loc
            xref = builder.functions[func_idx].blocks[block_idx].instructions_xref_to.add()
            xref.instr_bb_idx = instr_idx
            xref.xref_index = ref_index


def _walk_llil(node: Any) -> Any:
    """Yield node and every nested LLIL expression below it."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        for operand in getattr(current, "operands", []):
            if hasattr(operand, "operation"):
                stack.append(operand)
            elif isinstance(operand, list):
                stack.extend(
                    item for item in operand if hasattr(item, "operation")
                )


def _llil_mentions_constant(node: Any, value: int) -> bool:
    return any(
        sub.operation in _CONST_OPERATIONS
        and getattr(sub, "constant", None) == value
        for sub in _walk_llil(node)
    )


def _classify_llil_reference(llil: Any, dest: int) -> int | None:
    """Classify how the IL instruction accesses the dest constant.

    Walks the expression tree structurally instead of matching the IL's
    string rendering: a constant inside a store destination is a write, one
    inside a load source is a read, and one feeding a call is a read.
    """
    for node in _walk_llil(llil):
        if node.operation in _STORE_OPERATIONS and _llil_mentions_constant(
            node.dest, dest
        ):
            return Quokka.EDGE_DATA_WRITE
    for node in _walk_llil(llil):
        if node.operation in _LOAD_OPERATIONS and _llil_mentions_constant(
            node.src, dest
        ):
            return Quokka.EDGE_DATA_READ
    if llil.operation in CALL_LLIL_OPERATIONS and _llil_mentions_constant(llil, dest):
        return Quokka.EDGE_DATA_READ
    return None


def _classify_token_reference(tokens: list[Any], destination: int) -> int | None:
    for operand_tokens in operand_token_groups(tokens):
        if not any(token_value(token) == destination for token in operand_tokens):
            continue
        if (
            tokens_are_memory(operand_tokens)
            and extract_mnemonic(tokens).lower() != "lea"
        ):
            # Without structural IL information the access direction is
            # unknowable from tokens alone; READ is the conservative default
            # (writes are normally caught by the LLIL pass first).
            return Quokka.EDGE_DATA_READ
        return Quokka.EDGE_DATA_INDIR
    return None


def _instruction_fallthrough(ctx: ExportContext, addr: int) -> int | None:
    try:
        length = ctx.view.get_instruction_length(addr)
    except Exception:
        length = 0
    if length <= 0:
        return None
    return addr + length


__all__ = [
    "ReferenceExporter",
]
