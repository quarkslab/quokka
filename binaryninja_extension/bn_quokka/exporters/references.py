"""Cross-reference export and read/write/call classification."""

from __future__ import annotations

from typing import Any

from binaryninja import BranchType, LowLevelILOperation  # type: ignore

from ..context import ExportContext
from ..quokka_pb2 import Quokka
from .instructions import (
    extract_mnemonic,
    infer_operand_access,
    operand_token_groups,
    token_value,
    tokens_are_memory,
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
        data = ctx.view.read(addr, 16)
        try:
            info = ctx.view.arch.get_instruction_info(data, addr)
        except Exception:
            return {}

        result: dict[int, int] = {}
        fallthrough = addr + getattr(info, "length", 0)
        for branch in getattr(info, "branches", []):
            target = getattr(branch, "target", None)
            branch_type = branch.type
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
        token_edge = _classify_token_reference(tokens, dest)
        if token_edge is not None:
            return token_edge

        llil_text = _llil_text(func, addr)
        if f"{{0x{dest:x}}}" in llil_text or f"[0x{dest:x}" in llil_text:
            lhs = llil_text.split("=", 1)[0]
            if f"0x{dest:x}" in lhs:
                return Quokka.EDGE_DATA_WRITE
            return Quokka.EDGE_DATA_READ

        llil_op = _llil_operation(func, addr)
        if llil_op in (LowLevelILOperation.LLIL_LOAD, LowLevelILOperation.LLIL_LOAD_SSA):
            return Quokka.EDGE_DATA_READ
        if llil_op in (LowLevelILOperation.LLIL_STORE, LowLevelILOperation.LLIL_STORE_SSA):
            return Quokka.EDGE_DATA_WRITE
        if llil_op in (
            LowLevelILOperation.LLIL_CALL,
            LowLevelILOperation.LLIL_CALL_SSA,
            LowLevelILOperation.LLIL_TAILCALL,
            LowLevelILOperation.LLIL_TAILCALL_SSA,
        ):
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


def _classify_token_reference(tokens: list[Any], destination: int) -> int | None:
    mnemonic = extract_mnemonic(tokens).lower()
    for operand_idx, operand_tokens in enumerate(operand_token_groups(tokens)):
        if not any(token_value(token) == destination for token in operand_tokens):
            continue
        if tokens_are_memory(operand_tokens) and mnemonic != "lea":
            if operand_idx == 0 and infer_operand_access(mnemonic, operand_idx) in (2, 3):
                return Quokka.EDGE_DATA_WRITE
            return Quokka.EDGE_DATA_READ
        return Quokka.EDGE_DATA_INDIR
    return None


def _llil_operation(func: Any, addr: int) -> Any | None:
    try:
        llil = func.get_llil_at(addr)
    except Exception:
        return None
    return getattr(llil, "operation", None)


def _llil_text(func: Any, addr: int) -> str:
    try:
        return str(func.get_llil_at(addr))
    except Exception:
        return ""


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
