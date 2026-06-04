"""Function, basic-block, and edge export, including call-site block splitting."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from binaryninja import BranchType, SymbolType  # type: ignore

from ..context import ExportContext
from ..quokka_pb2 import Quokka
from ..util import map_calling_convention
from .instructions import export_instruction, extract_mnemonic


LOGGER = logging.getLogger(__name__)


@dataclass
class _ExportBlock:
    """A Quokka block synthesized from one BinaryNinja basic block."""

    start: int
    instructions: list[tuple[list[Any], int]]
    outgoing_edges: list[tuple[int, Any]]  # (target address, BranchType)
    source_block: Any
    is_synthetic_split: bool = False

    @property
    def length(self) -> int:
        return sum(length for _, length in self.instructions)

    @property
    def outgoing_targets(self) -> list[int]:
        return [target for target, _ in self.outgoing_edges]

    @property
    def outgoing_edge_types(self) -> set[Any]:
        return {branch_type for _, branch_type in self.outgoing_edges}


def _map_edge_type(branch_type: Any) -> int:
    """Map a BinaryNinja BranchType to the Quokka edge type."""
    if branch_type in (BranchType.TrueBranch, BranchType.FalseBranch):
        return Quokka.EDGE_JUMP_COND
    if branch_type == BranchType.UnconditionalBranch:
        return Quokka.EDGE_JUMP_UNCOND
    if branch_type in (BranchType.IndirectBranch, BranchType.UnresolvedBranch):
        return Quokka.EDGE_JUMP_INDIR
    if branch_type in (BranchType.CallDestination, BranchType.SystemCall):
        return Quokka.EDGE_CALL
    return Quokka.EDGE_UNKNOWN


class FunctionExporter:
    @staticmethod
    def export(ctx: ExportContext, builder: Quokka) -> None:
        functions = sorted(ctx.view.functions, key=lambda func: func.start)
        function_starts = {func.start for func in functions}

        for func in functions:
            function_index = len(builder.functions)
            function = builder.functions.add()
            _set_address_fields(ctx, function, func.start)
            symbol_type = func.symbol.type
            if func.is_thunk:
                function.function_type = Quokka.Function.TYPE_THUNK
            elif symbol_type in (
                SymbolType.ImportedFunctionSymbol,
                SymbolType.ImportAddressSymbol,
                SymbolType.ExternalSymbol,
            ):
                function.function_type = Quokka.Function.TYPE_IMPORTED
            elif symbol_type == SymbolType.LibraryFunctionSymbol:
                function.function_type = Quokka.Function.TYPE_LIBRARY
            else:
                function.function_type = Quokka.Function.TYPE_NORMAL
            function.name = func.name or ""

            symbol = func.symbol
            if symbol is not None and symbol.raw_name != function.name:
                function.mangled_name = symbol.raw_name

            function.prototype = str(func.type)
            function.is_exported = bool(func.is_exported)
            if func.calling_convention is not None:
                function.calling_convention = map_calling_convention(
                    func.calling_convention.name or ""
                )
            FunctionExporter._export_blocks_and_edges(
                ctx, builder, function, function_index, func, function_starts
            )

        FunctionExporter._export_external_functions(ctx, builder, function_starts)

    @staticmethod
    def _export_blocks_and_edges(
        ctx: ExportContext,
        builder: Quokka,
        function_proto: Any,
        function_index: int,
        func: Any,
        function_starts: set[int],
    ) -> None:
        blocks = FunctionExporter._split_blocks(ctx, func)
        block_indices = {block.start: idx for idx, block in enumerate(blocks)}

        for block_idx, block in enumerate(blocks):
            block_proto = function_proto.blocks.add()
            _set_address_fields(ctx, block_proto, block.start)
            block_proto.block_type = FunctionExporter._block_type(ctx, block)
            block_proto.size = block.length
            block_proto.n_instr = len(block.instructions)
            block_proto.is_thumb = (
                block.source_block.arch is not None
                and "thumb" in block.source_block.arch.name.lower()
            )
            FunctionExporter._record_block_instructions(
                ctx,
                builder,
                block_proto,
                function_index,
                block_idx,
                block.start,
                block.instructions,
                block_proto.is_thumb,
            )

        FunctionExporter._export_edges(function_proto, blocks, block_indices)

    @staticmethod
    def _export_edges(
        function_proto: Any,
        blocks: list[_ExportBlock],
        block_indices: dict[int, int],
    ) -> None:
        for src_idx, block in enumerate(blocks):
            for target, branch_type in block.outgoing_edges:
                dst_idx = block_indices.get(target)
                if dst_idx is None:
                    # Target outside this function (e.g. tail call): not an
                    # intra-function CFG edge.
                    continue
                edge = function_proto.edges.add()
                edge.edge_type = _map_edge_type(branch_type)
                edge.source = src_idx
                edge.destination = dst_idx
                edge.user_defined = False

    @staticmethod
    def _split_blocks(ctx: ExportContext, func: Any) -> list[_ExportBlock]:
        blocks = sorted(
            func.basic_blocks,
            key=lambda block: (
                ctx.resolve_segment_index(block.start),
                ctx.resolve_segment_offset(block.start),
            ),
        )
        split_blocks: list[_ExportBlock] = []

        for block in blocks:
            instructions = list(block)
            if not instructions:
                split_blocks.append(
                    _ExportBlock(
                        start=block.start,
                        instructions=[],
                        outgoing_edges=[
                            (edge.target.start, edge.type)
                            for edge in block.outgoing_edges
                        ],
                        source_block=block,
                    )
                )
                continue

            indexed_instructions: list[tuple[int, list[Any], int]] = []
            addr = block.start
            for tokens, length in instructions:
                indexed_instructions.append((addr, tokens, length))
                addr += length

            start_index = 0
            for instr_index, (addr, tokens, _length) in enumerate(indexed_instructions[:-1]):
                if not FunctionExporter._is_call_site(ctx, addr, tokens):
                    continue

                next_start = indexed_instructions[instr_index + 1][0]
                split_blocks.append(
                    _ExportBlock(
                        start=indexed_instructions[start_index][0],
                        instructions=[
                            (tokens, length)
                            for _, tokens, length in indexed_instructions[
                                start_index : instr_index + 1
                            ]
                        ],
                        outgoing_edges=[(next_start, BranchType.UnconditionalBranch)],
                        source_block=block,
                        is_synthetic_split=True,
                    )
                )
                start_index = instr_index + 1

            terminal_fallthrough = FunctionExporter._terminal_call_fallthrough(
                ctx, block, indexed_instructions
            )
            outgoing_edges = [
                (edge.target.start, edge.type) for edge in block.outgoing_edges
            ]
            if terminal_fallthrough is not None:
                outgoing_edges = [
                    (terminal_fallthrough[0], BranchType.UnconditionalBranch)
                ]

            split_blocks.append(
                _ExportBlock(
                    start=indexed_instructions[start_index][0],
                    instructions=[
                        (tokens, length)
                        for _, tokens, length in indexed_instructions[start_index:]
                    ],
                    outgoing_edges=outgoing_edges,
                    source_block=block,
                    is_synthetic_split=terminal_fallthrough is not None,
                )
            )

            if terminal_fallthrough is not None:
                fallthrough_addr, fallthrough_tokens, fallthrough_length = terminal_fallthrough
                split_blocks.append(
                    _ExportBlock(
                        start=fallthrough_addr,
                        instructions=[(fallthrough_tokens, fallthrough_length)],
                        outgoing_edges=[],
                        source_block=block,
                        is_synthetic_split=True,
                    )
                )

        return split_blocks

    @staticmethod
    def _terminal_call_fallthrough(
        ctx: ExportContext,
        block: Any,
        indexed_instructions: list[tuple[int, list[Any], int]],
    ) -> tuple[int, list[Any], int] | None:
        if block.outgoing_edges:
            return None
        if not indexed_instructions:
            return None

        last_addr, last_tokens, last_length = indexed_instructions[-1]
        if not FunctionExporter._is_call_site(ctx, last_addr, last_tokens):
            return None

        fallthrough_addr = last_addr + last_length
        if ctx.resolve_segment_index(fallthrough_addr) < 0:
            return None
        if ctx.view.get_function_at(fallthrough_addr) is not None:
            return None

        arch = getattr(block, "arch", None) or ctx.view.arch
        if arch is None:
            return None

        try:
            tokens, length = arch.get_instruction_text(
                ctx.view.read(fallthrough_addr, 16), fallthrough_addr
            )
        except Exception:
            return None
        if length <= 0:
            return None

        mnemonic = extract_mnemonic(tokens).lower()
        if mnemonic not in {"hlt", "ud2", "int3", "brk", "bkpt", "trap"}:
            return None

        return fallthrough_addr, tokens, length

    @staticmethod
    def _is_call_site(ctx: ExportContext, addr: int, tokens: list[Any]) -> bool:
        try:
            info = ctx.view.arch.get_instruction_info(ctx.view.read(addr, 16), addr)
        except Exception:
            info = None

        if any(
            branch.type in (BranchType.CallDestination, BranchType.SystemCall)
            for branch in getattr(info, "branches", [])
        ):
            return True

        mnemonic = extract_mnemonic(tokens).lower()
        return mnemonic in {"call", "callq", "bl", "blx", "jal", "jalr"}

    @staticmethod
    def _block_type(ctx: ExportContext, block: _ExportBlock) -> int:
        edge_types = block.outgoing_edge_types
        normal_flow_edges = {
            BranchType.UnconditionalBranch,
            BranchType.TrueBranch,
            BranchType.FalseBranch,
        }

        last_text = ""
        if block.instructions:
            last_tokens = block.instructions[-1][0]
            last_text = "".join(str(token) for token in last_tokens).lower()
        compact_last_text = last_text.replace(" ", "")
        has_conditional_flow = bool(
            edge_types & {BranchType.TrueBranch, BranchType.FalseBranch}
        )
        looks_like_conditional_return = has_conditional_flow and (
            "ret" in last_text
            or " lr" in last_text
            or " pc" in last_text
            or ",pc" in compact_last_text
            or "{pc" in compact_last_text
        )

        if ctx.resolve_segment_index(block.start) < 0:
            return Quokka.Block.BLOCK_TYPE_EXTERN
        if block.source_block.has_invalid_instructions:
            return Quokka.Block.BLOCK_TYPE_ERROR
        if looks_like_conditional_return:
            return Quokka.Block.BLOCK_TYPE_CNDRET
        if BranchType.ExceptionBranch in edge_types:
            return Quokka.Block.BLOCK_TYPE_ENORET
        if (
            not block.is_synthetic_split
            and block.source_block.has_undetermined_outgoing_edges
        ):
            return Quokka.Block.BLOCK_TYPE_INDJUMP
        if edge_types & {BranchType.IndirectBranch, BranchType.UnresolvedBranch}:
            return Quokka.Block.BLOCK_TYPE_INDJUMP
        if BranchType.SystemCall in edge_types and not edge_types & normal_flow_edges:
            return Quokka.Block.BLOCK_TYPE_NORET
        if BranchType.FunctionReturn in edge_types:
            return Quokka.Block.BLOCK_TYPE_RET
        if not block.is_synthetic_split and not block.source_block.can_exit:
            return Quokka.Block.BLOCK_TYPE_NORET
        if not block.outgoing_targets:
            return Quokka.Block.BLOCK_TYPE_RET
        return Quokka.Block.BLOCK_TYPE_NORMAL

    @staticmethod
    def _record_block_instructions(
        ctx: ExportContext,
        builder: Quokka,
        block_proto: Any,
        function_index: int,
        block_index: int,
        block_start: int,
        instructions: list[tuple[list[Any], int]],
        is_thumb: bool,
    ) -> None:
        addr = block_start
        for instr_idx, (tokens, length) in enumerate(instructions):
            ctx.instruction_locations[addr] = (function_index, block_index, instr_idx)
            if ctx.mode == Quokka.ExporterMeta.MODE_SELF_CONTAINED:
                instruction_index = export_instruction(ctx, builder, tokens, length, is_thumb)
                block_proto.instruction_index.append(instruction_index)
            addr += length

    @staticmethod
    def _export_external_functions(
        ctx: ExportContext, builder: Quokka, known_starts: set[int]
    ) -> None:
        candidates: dict[tuple[int, str], Any] = {}
        candidate_names: set[str] = set()
        for symbol_type in (SymbolType.ExternalSymbol, SymbolType.ImportedFunctionSymbol):
            for symbol in ctx.view.get_symbols_of_type(symbol_type):
                if symbol.address in known_starts or ctx.view.get_function_at(symbol.address):
                    continue
                if not symbol.name:
                    continue
                candidates[(symbol.address, symbol.raw_name or symbol.name)] = symbol
                candidate_names.add(symbol.name)

        for symbol_type in (SymbolType.ImportAddressSymbol, SymbolType.LibraryFunctionSymbol):
            for symbol in ctx.view.get_symbols_of_type(symbol_type):
                if symbol.address in known_starts or ctx.view.get_function_at(symbol.address):
                    continue
                if not symbol.name or symbol.name in candidate_names:
                    continue
                candidates[(symbol.address, symbol.raw_name or symbol.name)] = symbol
                candidate_names.add(symbol.name)

        skipped = 0
        for _, symbol in sorted(candidates.items(), key=lambda item: (item[0][0], item[0][1])):
            # SegmentExporter synthesizes extern pseudo-segments for unmapped
            # symbol addresses; anything still unresolved cannot be encoded
            # faithfully, and emitting it would collide on segment 0.
            if ctx.resolve_segment_index(symbol.address) < 0:
                skipped += 1
                continue
            function = builder.functions.add()
            _set_address_fields(ctx, function, symbol.address)
            if symbol.type == SymbolType.LibraryFunctionSymbol:
                function.function_type = Quokka.Function.TYPE_LIBRARY
            else:
                function.function_type = Quokka.Function.TYPE_IMPORTED
            function.name = symbol.name or ""
            if symbol.raw_name and symbol.raw_name != function.name:
                function.mangled_name = symbol.raw_name

        if skipped:
            LOGGER.warning(
                "Skipped %d external symbol(s) outside any exported segment", skipped
            )


def _set_address_fields(ctx: ExportContext, proto: Any, addr: int) -> None:
    seg_idx = ctx.resolve_segment_index(addr)
    if seg_idx < 0:
        # Should not happen for function/block starts; consumers reconstruct
        # the address as segment[0].base + 0, so make the loss visible.
        LOGGER.warning(
            "Address 0x%x is outside any exported segment; encoding as segment 0",
            addr,
        )
        proto.segment_index = 0
        proto.segment_offset = 0
        proto.file_offset = -1
        return

    proto.segment_index = seg_idx
    proto.segment_offset = ctx.resolve_segment_offset(addr)
    proto.file_offset = ctx.resolve_file_offset(addr)


__all__ = [
    "FunctionExporter",
]
