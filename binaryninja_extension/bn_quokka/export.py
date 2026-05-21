from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import io
import logging
import lzma
import os
from pathlib import Path
import re
from typing import Any, Iterable, Optional, Union

try:
    import binaryninja  # type: ignore
    from binaryninja import (  # type: ignore
        BinaryView,
        BranchType,
        Endianness,
        InstructionTextTokenType,
        LowLevelILOperation,
        SymbolType,
        Type,
        TypeClass,
    )
except ImportError:  # Allows tests to import this module outside BinaryNinja.
    binaryninja = None  # type: ignore
    BinaryView = Any  # type: ignore
    BranchType = None  # type: ignore
    Endianness = None  # type: ignore
    InstructionTextTokenType = None  # type: ignore
    LowLevelILOperation = None  # type: ignore
    SymbolType = None  # type: ignore
    Type = Any  # type: ignore
    TypeClass = None  # type: ignore

try:
    from .quokka_pb2 import Quokka
except ImportError:
    try:
        from quokka_pb2 import Quokka
    except ImportError as exc:
        raise ImportError(
            "Generated protobuf support file not found. "
            "Run generate_proto.py to generate required supporting files."
        ) from exc

try:
    from .util import (
        PRIMITIVE_TYPE_COUNT,
        TYPE_UNK,
        SegmentInfo,
        TypeKind,
        address_offset,
        address_size_to_proto,
        classify_type,
        find_segment_index,
        inner_type,
        map_by_size,
        map_primitive_type,
        segment_offset,
        type_class_name,
        type_key,
        type_name,
    )
except ImportError:
    from util import (  # type: ignore
        PRIMITIVE_TYPE_COUNT,
        TYPE_UNK,
        SegmentInfo,
        TypeKind,
        address_offset,
        address_size_to_proto,
        classify_type,
        find_segment_index,
        inner_type,
        map_by_size,
        map_primitive_type,
        segment_offset,
        type_class_name,
        type_key,
        type_name,
    )


LOGGER = logging.getLogger(__name__)

ModeInput = Union[int, str]


@dataclass
class _ExportBlock:
    """A Quokka block synthesized from one BinaryNinja basic block."""

    start: int
    instructions: list[tuple[list[Any], int]]
    outgoing_targets: list[int]
    outgoing_edge_types: set[Any]
    source_block: Any
    is_synthetic_split: bool = False

    @property
    def length(self) -> int:
        return sum(length for _, length in self.instructions)


class ExportContext:
    """Shared export state passed through BinaryNinja export phases."""

    def __init__(self, bv: BinaryView, file: io.BufferedWriter, mode: int):
        self.view: BinaryView = bv
        self.output_file: io.BufferedWriter = file
        self.file: io.BufferedWriter = file
        self.mode: int = mode

        self.segments: list[SegmentInfo] = []

        self.next_type_index: int = PRIMITIVE_TYPE_COUNT
        self.enum_type_indices: "OrderedDict[str, int]" = OrderedDict()
        self.composite_type_indices: "OrderedDict[str, int]" = OrderedDict()
        self.mnemonic_indices: dict[str, int] = {}
        self.operand_string_indices: dict[str, int] = {}
        self.register_indices: dict[str, int] = {}
        self.instruction_locations: dict[int, tuple[int, int, int]] = {}

    def resolveSegmentIndex(self, addr: int) -> int:
        return find_segment_index(self.segments, address_offset(addr))

    def resolveSegmentOffset(self, addr: int) -> int:
        offset = address_offset(addr)
        idx = find_segment_index(self.segments, offset)
        if idx < 0:
            return 0
        return segment_offset(offset, self.segments[idx])

    def resolveFileOffset(self, addr: int) -> int:
        offset = address_offset(addr)

        if self.view is not None:
            view_offset = self.view.get_data_offset_for_address(offset)
            if view_offset is not None:
                return view_offset

        idx = find_segment_index(self.segments, offset)
        segment = self.segments[idx] if idx >= 0 else None
        if segment is None:
            return -1

        offset_in_segment = segment_offset(offset, segment)
        data_size = segment.size if segment.data_size is None else segment.data_size
        if segment.file_offset < 0 or data_size <= 0:
            return -1
        if offset_in_segment < 0 or offset_in_segment >= data_size:
            return -1
        return segment.file_offset + offset_in_segment

    def isAddressInitialized(self, addr: int) -> bool:
        offset = address_offset(addr)
        idx = find_segment_index(self.segments, offset)
        if idx < 0:
            return False

        segment = self.segments[idx]
        offset_in_segment = segment_offset(offset, segment)
        data_size = segment.size if segment.data_size is None else segment.data_size
        return data_size > 0 and 0 <= offset_in_segment < data_size

    def resolveTypeIndex(self, dtype: Optional[Type]) -> int:
        if dtype is None:
            return TYPE_UNK

        base_type = map_primitive_type(dtype)
        if base_type is not None:
            return int(base_type)

        kind = classify_type(dtype)
        if kind == TypeKind.FUNC_DEF:
            return TYPE_UNK
        if kind == TypeKind.ENUM:
            existing = self.enum_type_indices.get(type_name(dtype))
            if existing is not None:
                return existing
        elif kind not in (TypeKind.FUNC_DEF, TypeKind.PRIMITIVE, TypeKind.UNKNOWN):
            existing = self.composite_type_indices.get(type_key(dtype, kind))
            if existing is not None:
                return existing

        LOGGER.warning(
            "Cannot resolve type index for: %s (%s), using TYPE_UNK",
            type_name(dtype),
            type_class_name(dtype),
        )
        return TYPE_UNK


class MetaExporter:
    @staticmethod
    def export(ctx: ExportContext, builder: Quokka) -> None:
        view = ctx.view

        builder.exporter_meta.mode = ctx.mode
        builder.exporter_meta.version = "1.0.0"

        meta = builder.meta
        path = view.file.original_filename or view.file.filename
        meta.executable_name = os.path.basename(path) if path else ""

        arch_name = view.arch.name.lower() if view.arch is not None else ""
        if "x86" in arch_name or "amd64" in arch_name:
            meta.isa = Quokka.Meta.PROC_INTEL
        elif "arm" in arch_name or "aarch64" in arch_name or "thumb" in arch_name:
            meta.isa = Quokka.Meta.PROC_ARM
        elif "mips" in arch_name:
            meta.isa = Quokka.Meta.PROC_MIPS
        elif "ppc" in arch_name or "powerpc" in arch_name:
            meta.isa = Quokka.Meta.PROC_PPC
        elif "dalvik" in arch_name:
            meta.isa = Quokka.Meta.PROC_DALVIK
        else:
            meta.isa = Quokka.Meta.PROC_UNK

        meta.endianess = (
            Quokka.Meta.END_BE
            if view.endianness == Endianness.BigEndian
            else Quokka.Meta.END_LE
        )
        meta.address_size = address_size_to_proto(view.address_size)
        hash_type, hash_value = _hash_for_view(view)
        meta.hash.hash_type = hash_type
        meta.hash.hash_value = hash_value
        meta.backend.name = Quokka.Meta.Backend.DISASS_BINARY_NINJA
        if binaryninja is not None:
            version = getattr(binaryninja, "__version__", "")
            meta.backend.version = (
                str(version) if version else str(binaryninja.core_version())
            )

        cc_name = ""
        platform = view.platform
        if platform is not None and platform.default_calling_convention is not None:
            cc_name = platform.default_calling_convention.name or ""
        meta.calling_convention = _map_calling_convention(cc_name)


class SegmentExporter:
    @staticmethod
    def export(ctx: ExportContext, builder: Quokka) -> None:
        segments = SegmentExporter._collect_segment_infos(ctx)
        ctx.segments = segments

        for info in segments:
            segment = builder.segments.add()
            segment.name = info.name
            segment.virtual_addr = info.start_offset
            segment.size = info.size
            segment.permissions = info.permissions
            segment.type = info.proto_seg_type
            segment.address_size = info.proto_addr_size
            segment.file_offset = info.file_offset

    @staticmethod
    def _collect_segment_infos(ctx: ExportContext) -> list[SegmentInfo]:
        view = ctx.view
        sections = sorted(view.sections.values(), key=lambda item: (item.start, item.end))
        emitted_sections: set[int] = set()
        infos: list[SegmentInfo] = []

        for segment in sorted(view.segments, key=lambda item: item.start):
            cursor = segment.start
            segment_sections = [
                section
                for section in sections
                if segment.start <= section.start < segment.end and section.end > section.start
            ]

            for section in segment_sections:
                if section.start > cursor:
                    infos.append(
                        SegmentInfo.from_range(
                            view,
                            segment,
                            cursor,
                            section.start,
                            f"segment_{cursor:x}",
                        )
                    )
                infos.append(SegmentInfo.from_binaryninja_section(view, section))
                emitted_sections.add(id(section))
                cursor = max(cursor, section.end)

            if cursor < segment.end:
                infos.append(
                    SegmentInfo.from_range(
                        view,
                        segment,
                        cursor,
                        segment.end,
                        f"segment_{cursor:x}",
                    )
                )

        for section in sections:
            if id(section) in emitted_sections or section.end <= section.start:
                continue
            infos.append(SegmentInfo.from_binaryninja_section(view, section))

        infos.sort(key=lambda item: (item.start_offset, item.size, item.name))
        return [info for info in infos if info.size > 0]


class TypeExporter:
    WHOLE_TYPE = -1

    @staticmethod
    def export(ctx: ExportContext, builder: Quokka) -> None:
        for primitive_type in range(PRIMITIVE_TYPE_COUNT):
            builder.types.add().primitive_type = primitive_type

        collected: list[tuple[Type, TypeKind]] = []
        skipped_duplicates = 0
        skipped_func_defs = 0
        unhandled_types: set[str] = set()

        def register_type(dtype: Optional[Type]) -> None:
            nonlocal skipped_duplicates, skipped_func_defs

            if dtype is None:
                return

            kind = classify_type(dtype)

            # BinaryNinja stores named aliases as ordinary registered types in many cases.
            if kind == TypeKind.PRIMITIVE and dtype.registered_name is not None:
                kind = TypeKind.TYPEDEF

            if kind == TypeKind.ENUM:
                name = type_name(dtype)
                if name in ctx.enum_type_indices:
                    skipped_duplicates += 1
                    return
                ctx.enum_type_indices[name] = ctx.next_type_index
                ctx.next_type_index += 1
                collected.append((dtype, kind))
            elif kind in (
                TypeKind.STRUCT,
                TypeKind.UNION,
                TypeKind.POINTER,
                TypeKind.ARRAY,
                TypeKind.TYPEDEF,
            ):
                key = type_key(dtype, kind)
                if key in ctx.composite_type_indices:
                    skipped_duplicates += 1
                    return
                ctx.composite_type_indices[key] = ctx.next_type_index
                ctx.next_type_index += 1
                collected.append((dtype, kind))
                for child_type in TypeExporter._child_types(ctx, dtype, kind):
                    register_type(child_type)
            elif kind == TypeKind.FUNC_DEF:
                skipped_func_defs += 1
            elif kind != TypeKind.PRIMITIVE:
                unhandled_types.add(f"{type_name(dtype)} ({type_class_name(dtype)})")

        for _, dtype in sorted(ctx.view.types.items(), key=lambda item: str(item[0])):
            register_type(dtype)

        for _, data_var in sorted(ctx.view.data_vars.items(), key=lambda item: item[0]):
            register_type(data_var.type)

        if skipped_duplicates:
            LOGGER.info("Skipped %d duplicate type definitions", skipped_duplicates)
        if skipped_func_defs:
            LOGGER.info("Skipped %d Function types (not representable in proto)", skipped_func_defs)
        if unhandled_types:
            LOGGER.warning(
                "Skipped %d unrepresentable types: %s",
                len(unhandled_types),
                sorted(unhandled_types),
            )

        for dtype, kind in collected:
            TypeExporter._build_type(ctx, builder.types.add(), dtype, kind)

    @staticmethod
    def _child_types(
        ctx: ExportContext, dtype: Type, kind: TypeKind
    ) -> Iterable[Optional[Type]]:
        if kind in (TypeKind.STRUCT, TypeKind.UNION):
            composite_type = _resolve_named_type(ctx, dtype)
            for member in getattr(composite_type, "members", []):
                yield member.type
        elif kind in (TypeKind.POINTER, TypeKind.ARRAY):
            yield inner_type(dtype)
        elif kind == TypeKind.TYPEDEF:
            if dtype.type_class == TypeClass.NamedTypeReferenceClass:
                yield dtype.target(ctx.view)

    @staticmethod
    def exportTypeToTypeRefs(ctx: ExportContext, builder: Quokka) -> int:
        emitted = 0
        for type_idx in range(PRIMITIVE_TYPE_COUNT, len(builder.types)):
            proto_type = builder.types[type_idx]
            if not proto_type.HasField("composite_type"):
                continue

            composite = proto_type.composite_type
            if composite.type in (
                Quokka.CompositeType.TYPE_STRUCT,
                Quokka.CompositeType.TYPE_UNION,
            ):
                for member_idx, member in enumerate(composite.members):
                    if member.type_index >= PRIMITIVE_TYPE_COUNT:
                        ref_idx = TypeExporter._emit_type_ref(
                            builder, type_idx, member_idx, member.type_index
                        )
                        composite.xref_from.append(ref_idx)
                        member.xref_from.append(ref_idx)
                        TypeExporter._add_xref_to(builder, member.type_index, ref_idx)
                        emitted += 1
            elif composite.type in (
                Quokka.CompositeType.TYPE_POINTER,
                Quokka.CompositeType.TYPE_ARRAY,
                Quokka.CompositeType.TYPE_TYPEDEF,
            ):
                if (
                    composite.HasField("element_type_idx")
                    and composite.element_type_idx >= PRIMITIVE_TYPE_COUNT
                ):
                    ref_idx = TypeExporter._emit_type_ref(
                        builder, type_idx, TypeExporter.WHOLE_TYPE, composite.element_type_idx
                    )
                    composite.xref_from.append(ref_idx)
                    TypeExporter._add_xref_to(builder, composite.element_type_idx, ref_idx)
                    emitted += 1

        return emitted

    @staticmethod
    def _build_type(ctx: ExportContext, proto_type: Any, dtype: Type, kind: TypeKind) -> None:
        if kind == TypeKind.ENUM:
            TypeExporter._build_enum(ctx, proto_type.enum_type, dtype)
        elif kind in (TypeKind.STRUCT, TypeKind.UNION):
            TypeExporter._build_struct_or_union(ctx, proto_type.composite_type, dtype, kind)
        elif kind == TypeKind.POINTER:
            TypeExporter._build_reference_composite(
                ctx,
                proto_type.composite_type,
                dtype,
                Quokka.CompositeType.TYPE_POINTER,
                inner_type(dtype),
            )
        elif kind == TypeKind.ARRAY:
            TypeExporter._build_reference_composite(
                ctx,
                proto_type.composite_type,
                dtype,
                Quokka.CompositeType.TYPE_ARRAY,
                inner_type(dtype),
            )
        elif kind == TypeKind.TYPEDEF:
            element_type = (
                dtype.target(ctx.view)
                if dtype.type_class == TypeClass.NamedTypeReferenceClass
                else dtype
            )
            TypeExporter._build_reference_composite(
                ctx,
                proto_type.composite_type,
                dtype,
                Quokka.CompositeType.TYPE_TYPEDEF,
                element_type,
            )

    @staticmethod
    def _build_enum(ctx: ExportContext, enum_proto: Any, dtype: Type) -> None:
        enum_type = _resolve_named_type(ctx, dtype)
        enum_proto.name = type_name(dtype)
        enum_proto.base_type = map_by_size(enum_type.width)
        enum_proto.c_str = enum_type.get_string()

        for member in getattr(enum_type, "members", []):
            value = enum_proto.values.add()
            value.name = member.name
            value.value = TypeExporter._enum_value_to_int64(member.value)

    @staticmethod
    def _enum_value_to_int64(raw_value: Optional[int]) -> int:
        if raw_value is None:
            return 0

        value = int(raw_value)
        int64_min = -(1 << 63)
        int64_max = (1 << 63) - 1
        if int64_min <= value <= int64_max:
            return value

        # The protobuf stores enum values as signed int64, while BinaryNinja may
        # expose unsigned 64-bit enum values such as 0xffffffffffffffff.
        value &= (1 << 64) - 1
        if value > int64_max:
            value -= 1 << 64
        return value

    @staticmethod
    def _build_struct_or_union(
        ctx: ExportContext, composite: Any, dtype: Type, kind: TypeKind
    ) -> None:
        struct_type = _resolve_named_type(ctx, dtype)
        is_union = kind == TypeKind.UNION
        composite.name = type_name(dtype)
        composite.type = (
            Quokka.CompositeType.TYPE_UNION
            if is_union
            else Quokka.CompositeType.TYPE_STRUCT
        )
        composite.size = max(0, struct_type.width)
        composite.c_str = struct_type.get_string()

        used_member_names: set[str] = set()
        for member_idx, member in enumerate(getattr(struct_type, "members", [])):
            member_offset = 0 if is_union else int(member.offset)
            member_proto = composite.members.add()
            member_proto.offset = member_offset * 8
            member_proto.name = _member_name_or_default(
                member.name, member_offset, member_idx, used_member_names
            )
            member_proto.type_index = ctx.resolveTypeIndex(member.type)
            member_proto.size = max(0, len(member.type)) * 8

    @staticmethod
    def _build_reference_composite(
        ctx: ExportContext,
        composite: Any,
        dtype: Type,
        subtype: int,
        element_type: Optional[Type],
    ) -> None:
        composite.name = type_name(dtype)
        composite.type = subtype
        composite.size = max(0, dtype.width)
        composite.c_str = dtype.get_string()
        if element_type is not None:
            composite.element_type_idx = ctx.resolveTypeIndex(element_type)

    @staticmethod
    def _emit_type_ref(
        builder: Quokka, src_type_idx: int, src_member_idx: int, dst_type_idx: int
    ) -> int:
        ref_idx = len(builder.references)
        reference = builder.references.add()
        reference.source.data_type_identifier.type_index = src_type_idx
        reference.source.data_type_identifier.member_index = src_member_idx
        reference.destination.data_type_identifier.type_index = dst_type_idx
        reference.destination.data_type_identifier.member_index = TypeExporter.WHOLE_TYPE
        reference.reference_type = Quokka.EDGE_DATA_READ
        return ref_idx

    @staticmethod
    def _add_xref_to(builder: Quokka, type_idx: int, ref_idx: int) -> None:
        dest_type = builder.types[type_idx]
        if dest_type.HasField("composite_type"):
            dest_type.composite_type.xref_to.append(ref_idx)
        elif dest_type.HasField("enum_type"):
            dest_type.enum_type.xref_to.append(ref_idx)


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
                function.calling_convention = _map_calling_convention(
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

        for src_idx, block in enumerate(blocks):
            pending_edges: list[tuple[int, int]] = []
            for target in block.outgoing_targets:
                dst_idx = block_indices.get(target)
                if dst_idx is not None:
                    pending_edges.append((src_idx, dst_idx))

            out_degree = len(pending_edges)
            if out_degree == 0:
                edge_type = Quokka.EDGE_UNKNOWN
            elif out_degree == 1:
                edge_type = Quokka.EDGE_JUMP_UNCOND
            elif out_degree == 2:
                edge_type = Quokka.EDGE_JUMP_COND
            else:
                edge_type = Quokka.EDGE_JUMP_INDIR
            for source, destination in pending_edges:
                edge = function_proto.edges.add()
                edge.edge_type = edge_type
                edge.source = source
                edge.destination = destination
                edge.user_defined = False

    @staticmethod
    def _split_blocks(ctx: ExportContext, func: Any) -> list[_ExportBlock]:
        blocks = sorted(
            func.basic_blocks,
            key=lambda block: (
                ctx.resolveSegmentIndex(block.start),
                ctx.resolveSegmentOffset(block.start),
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
                        outgoing_targets=[edge.target.start for edge in block.outgoing_edges],
                        outgoing_edge_types={edge.type for edge in block.outgoing_edges},
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
                        outgoing_targets=[next_start],
                        outgoing_edge_types={BranchType.UnconditionalBranch},
                        source_block=block,
                        is_synthetic_split=True,
                    )
                )
                start_index = instr_index + 1

            terminal_fallthrough = FunctionExporter._terminal_call_fallthrough(
                ctx, block, indexed_instructions
            )
            outgoing_targets = [edge.target.start for edge in block.outgoing_edges]
            outgoing_edge_types = {edge.type for edge in block.outgoing_edges}
            if terminal_fallthrough is not None:
                outgoing_targets = [terminal_fallthrough[0]]
                outgoing_edge_types = {BranchType.UnconditionalBranch}

            split_blocks.append(
                _ExportBlock(
                    start=indexed_instructions[start_index][0],
                    instructions=[
                        (tokens, length)
                        for _, tokens, length in indexed_instructions[start_index:]
                    ],
                    outgoing_targets=outgoing_targets,
                    outgoing_edge_types=outgoing_edge_types,
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
                        outgoing_targets=[],
                        outgoing_edge_types=set(),
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
    ) -> Optional[tuple[int, list[Any], int]]:
        if block.outgoing_edges:
            return None
        if not indexed_instructions:
            return None

        last_addr, last_tokens, last_length = indexed_instructions[-1]
        if not FunctionExporter._is_call_site(ctx, last_addr, last_tokens):
            return None

        fallthrough_addr = last_addr + last_length
        if ctx.resolveSegmentIndex(fallthrough_addr) < 0:
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

        mnemonic = _extract_mnemonic(tokens).lower()
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

        mnemonic = _extract_mnemonic(tokens).lower()
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

        if ctx.resolveSegmentIndex(block.start) < 0:
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
                instruction_index = _export_instruction(ctx, builder, tokens, length, is_thumb)
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

        for _, symbol in sorted(candidates.items(), key=lambda item: (item[0][0], item[0][1])):
            function = builder.functions.add()
            _set_address_fields(ctx, function, symbol.address)
            if symbol.type == SymbolType.LibraryFunctionSymbol:
                function.function_type = Quokka.Function.TYPE_LIBRARY
            else:
                function.function_type = Quokka.Function.TYPE_IMPORTED
            function.name = symbol.name or ""
            if symbol.raw_name and symbol.raw_name != function.name:
                function.mangled_name = symbol.raw_name


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


class LayoutExporter:
    @staticmethod
    def export(ctx: ExportContext, builder: Quokka) -> None:
        view = ctx.view
        code_ranges = _merged_ranges(
            (block.start, block.end)
            for func in view.functions
            for block in func.basic_blocks
        )
        data_ranges = _merged_ranges(
            (data_var.address, data_var.address + max(1, len(data_var)))
            for data_var in view.data_vars.values()
        )

        for segment in ctx.segments:
            if not (segment.permissions & 0x5):
                continue
            if segment.data_size == 0:
                _add_layout(
                    builder, segment.start_offset, segment.size, Quokka.Layout.LAYOUT_DATA
                )
                continue
            LayoutExporter._walk_segment(builder, segment, code_ranges, data_ranges)

    @staticmethod
    def _walk_segment(
        builder: Quokka,
        segment: SegmentInfo,
        code_ranges: list[tuple[int, int]],
        data_ranges: list[tuple[int, int]],
    ) -> None:
        start = segment.start_offset
        end = segment.start_offset + segment.size
        ranges: list[tuple[int, int, int]] = []

        for range_start, range_end in _intersect_ranges(code_ranges, start, end):
            ranges.append((range_start, range_end, Quokka.Layout.LAYOUT_CODE))
        for range_start, range_end in _intersect_ranges(data_ranges, start, end):
            ranges.append((range_start, range_end, Quokka.Layout.LAYOUT_DATA))

        ranges.sort(key=lambda item: (item[0], item[1], item[2]))
        cursor = start
        for range_start, range_end, layout_type in ranges:
            if range_end <= cursor:
                continue
            if range_start > cursor:
                _add_layout(builder, cursor, range_start - cursor, Quokka.Layout.LAYOUT_UNK)
            clipped_start = max(cursor, range_start)
            _add_layout(builder, clipped_start, range_end - clipped_start, layout_type)
            cursor = range_end

        if cursor < end:
            _add_layout(builder, cursor, end - cursor, Quokka.Layout.LAYOUT_UNK)


class DataExporter:
    @staticmethod
    def export(ctx: ExportContext, builder: Quokka) -> None:
        records: dict[int, tuple[int, int, int, int, int, str, bool]] = {}

        def add_record(
            addr: int,
            dtype: Optional[Type],
            size: int,
            name: str = "",
        ) -> None:
            seg_idx = ctx.resolveSegmentIndex(addr)
            if seg_idx < 0:
                return
            symbol_name = _symbol_name_at(ctx.view, addr)
            chosen_name = symbol_name or name
            current = records.get(addr)
            record = (
                seg_idx,
                ctx.resolveSegmentOffset(addr),
                ctx.resolveFileOffset(addr),
                ctx.resolveTypeIndex(dtype),
                max(1, size),
                chosen_name,
                not ctx.isAddressInitialized(addr),
            )
            if current is None or (not current[5] and chosen_name):
                records[addr] = record

        for addr, data_var in ctx.view.data_vars.items():
            symbol = data_var.symbol
            add_record(addr, data_var.type, len(data_var), symbol.name if symbol else "")

        for string_ref in ctx.view.strings:
            add_record(
                string_ref.start,
                getattr(ctx.view.get_data_var_at(string_ref.start), "type", None),
                string_ref.length + 1,
                _string_symbol_name(string_ref),
            )

        for symbol in ctx.view.get_symbols():
            if symbol.type not in (
                SymbolType.DataSymbol,
                SymbolType.ImportAddressSymbol,
                SymbolType.ImportedDataSymbol,
                SymbolType.ExternalSymbol,
            ):
                continue
            data_var = ctx.view.get_data_var_at(symbol.address)
            dtype = data_var.type if data_var is not None else None
            size = len(data_var) if data_var is not None else ctx.view.address_size
            add_record(symbol.address, dtype, size, symbol.name or "")

        for addr, (
            seg_idx,
            seg_off,
            file_off,
            type_idx,
            size,
            name,
            not_initialized,
        ) in sorted(
            records.items(), key=lambda item: item[1]
        ):
            data = builder.data.add()
            data.segment_index = seg_idx
            data.segment_offset = seg_off
            data.file_offset = file_off
            data.type_index = type_idx
            data.size = size
            data.not_initialized = not_initialized
            if name:
                data.name = name
            _populate_data_xrefs(builder, data, addr, size)


def _export_instruction(
    ctx: ExportContext,
    builder: Quokka,
    tokens: list[Any],
    size: int,
    is_thumb: bool,
) -> int:
    instruction_index = len(builder.instructions)
    instruction = builder.instructions.add()
    instruction.size = max(0, size)
    instruction.mnemonic_index = _intern_string(
        ctx.mnemonic_indices, builder.mnemonics, _extract_mnemonic(tokens)
    )
    instruction.is_thumb = is_thumb

    operands = _operand_token_groups(tokens)
    mnemonic = _extract_mnemonic(tokens).lower()
    for operand_idx, operand_tokens in enumerate(operands):
        instruction.operand_index.append(
            _export_operand(ctx, builder, mnemonic, operand_idx, operand_tokens)
        )

    return instruction_index


def _export_operand(
    ctx: ExportContext,
    builder: Quokka,
    mnemonic: str,
    operand_idx: int,
    tokens: list[Any],
) -> int:
    operand_index = len(builder.operands)
    operand = builder.operands.add()
    operand_text = _operand_text(tokens)
    operand.operand_string_index = _intern_string(
        ctx.operand_string_indices, builder.operand_strings, operand_text
    )
    operand.access = _infer_operand_access(mnemonic, operand_idx)

    if _tokens_are_memory(tokens):
        operand.type = Quokka.Operand.OPERAND_MEMORY
        address = _first_resolved_address(ctx, tokens)
        if address is not None:
            operand.address = address
    elif _tokens_are_register(tokens):
        operand.type = Quokka.Operand.OPERAND_REGISTER
        register_name = next(
            (token.text for token in tokens if token.type == InstructionTextTokenType.RegisterToken),
            operand_text,
        )
        operand.register_index = str(
            _intern_string(ctx.register_indices, builder.register_table, register_name)
        )
    else:
        value = _last_token_value(tokens)
        if value is not None:
            operand.type = Quokka.Operand.OPERAND_IMMEDIATE
            operand.value = value
        else:
            operand.type = Quokka.Operand.OPERAND_OTHER
            operand.other = operand_text

    return operand_index


def _intern_string(indexes: dict[str, int], values: Any, value: str) -> int:
    existing = indexes.get(value)
    if existing is not None:
        return existing
    index = len(values)
    values.append(value)
    indexes[value] = index
    return index


def _extract_mnemonic(tokens: list[Any]) -> str:
    for token in tokens:
        if token.type == InstructionTextTokenType.InstructionToken:
            return token.text
    for token in tokens:
        text = token.text.strip()
        if text:
            return text
    return ""


def _operand_token_groups(tokens: list[Any]) -> list[list[Any]]:
    groups: list[list[Any]] = []
    current: list[Any] = []
    seen_mnemonic = False

    for token in tokens:
        if not seen_mnemonic:
            if token.type == InstructionTextTokenType.InstructionToken:
                seen_mnemonic = True
            continue

        if token.type == InstructionTextTokenType.OperandSeparatorToken:
            if _operand_text(current):
                groups.append(current)
            current = []
            continue

        if token.type == InstructionTextTokenType.TextToken and not token.text.strip():
            if current:
                current.append(token)
            continue

        current.append(token)

    if _operand_text(current):
        groups.append(current)

    return groups


def _operand_text(tokens: list[Any]) -> str:
    return "".join(token.text for token in tokens).strip()


def _tokens_are_memory(tokens: list[Any]) -> bool:
    return any(
        token.type
        in (
            InstructionTextTokenType.BeginMemoryOperandToken,
            InstructionTextTokenType.EndMemoryOperandToken,
        )
        or token.text in ("[", "]")
        for token in tokens
    )


def _tokens_are_register(tokens: list[Any]) -> bool:
    meaningful = [token for token in tokens if token.text.strip()]
    return bool(meaningful) and all(
        token.type == InstructionTextTokenType.RegisterToken for token in meaningful
    )


def _first_resolved_address(ctx: ExportContext, tokens: list[Any]) -> Optional[int]:
    for token in tokens:
        value = _token_value(token)
        if value is not None and ctx.resolveSegmentIndex(value) >= 0:
            return value
    return None


def _last_token_value(tokens: list[Any]) -> Optional[int]:
    for token in reversed(tokens):
        value = _token_value(token)
        if value is not None:
            return value
    return None


def _token_value(token: Any) -> Optional[int]:
    if token.type not in (
        InstructionTextTokenType.IntegerToken,
        InstructionTextTokenType.PossibleAddressToken,
        InstructionTextTokenType.CodeRelativeAddressToken,
        InstructionTextTokenType.CodeSymbolToken,
        InstructionTextTokenType.DataSymbolToken,
        InstructionTextTokenType.ExternalSymbolToken,
        InstructionTextTokenType.ImportToken,
        InstructionTextTokenType.IndirectImportToken,
        InstructionTextTokenType.PossibleValueToken,
    ):
        return None
    value = getattr(token, "value", 0)
    if value is None:
        return None
    value = int(value)
    if value > 0x7FFFFFFFFFFFFFFF:
        value -= 1 << 64
    return value


def _infer_operand_access(mnemonic: str, operand_idx: int) -> int:
    if operand_idx != 0:
        return 1
    if mnemonic in {"add", "sub", "xor", "or", "and", "adc", "sbb", "inc", "dec"}:
        return 3
    if mnemonic in {"mov", "lea", "pop", "xchg", "imul", "shl", "shr", "sar", "sal"}:
        return 2
    return 1


def _classify_token_reference(tokens: list[Any], destination: int) -> Optional[int]:
    mnemonic = _extract_mnemonic(tokens).lower()
    for operand_idx, operand_tokens in enumerate(_operand_token_groups(tokens)):
        if not any(_token_value(token) == destination for token in operand_tokens):
            continue
        if _tokens_are_memory(operand_tokens) and mnemonic != "lea":
            if operand_idx == 0 and _infer_operand_access(mnemonic, operand_idx) in (2, 3):
                return Quokka.EDGE_DATA_WRITE
            return Quokka.EDGE_DATA_READ
        return Quokka.EDGE_DATA_INDIR
    return None


def _llil_operation(func: Any, addr: int) -> Optional[Any]:
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


def _instruction_fallthrough(ctx: ExportContext, addr: int) -> Optional[int]:
    try:
        length = ctx.view.get_instruction_length(addr)
    except Exception:
        length = 0
    if length <= 0:
        return None
    return addr + length


def _symbol_name_at(view: BinaryView, addr: int) -> str:
    symbol = view.get_symbol_at(addr)
    return symbol.name if symbol is not None and symbol.name else ""


def _string_symbol_name(string_ref: Any) -> str:
    value = str(string_ref.value)
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")[:32]
    if not cleaned:
        cleaned = "string"
    return f"s_{cleaned}_{string_ref.start:08x}"


def _type_declaration(dtype: Optional[Type]) -> str:
    if dtype is None:
        return ""
    try:
        return dtype.get_string()
    except Exception:
        return str(dtype)


def _populate_data_xrefs(builder: Quokka, data: Any, addr: int, size: int) -> None:
    end = addr + max(1, size)
    for ref_idx, reference in enumerate(builder.references):
        if reference.destination.WhichOneof("Type") == "address":
            destination = reference.destination.address
            if addr <= destination < end:
                data.xref_to.append(ref_idx)
        if reference.source.WhichOneof("Type") == "address":
            source = reference.source.address
            if addr <= source < end:
                data.xref_from.append(ref_idx)


def run_export_pipeline(ctx: ExportContext, builder: Quokka) -> Quokka:
    MetaExporter.export(ctx, builder)
    SegmentExporter.export(ctx, builder)
    TypeExporter.export(ctx, builder)
    TypeExporter.exportTypeToTypeRefs(ctx, builder)
    FunctionExporter.export(ctx, builder)
    ReferenceExporter.export(ctx, builder)
    LayoutExporter.export(ctx, builder)
    DataExporter.export(ctx, builder)
    builder.headers = collect_headers(ctx.view)
    return builder


def export_binary_view(
    bv: BinaryView,
    output_file: Union[Path, str],
    mode: ModeInput = Quokka.ExporterMeta.MODE_LIGHT,
    *,
    compressed: bool = True,
    update_analysis: bool = True,
) -> Quokka:
    if update_analysis:
        bv.update_analysis_and_wait()

    output_path = Path(output_file)
    builder = Quokka()
    ctx = ExportContext(bv, io.BytesIO(), _normalize_mode(mode))
    run_export_pipeline(ctx, builder)

    raw_proto = builder.SerializeToString()
    if compressed:
        with lzma.open(output_path, "wb", format=lzma.FORMAT_XZ) as output:
            output.write(raw_proto)
    else:
        with output_path.open("wb") as output:
            output.write(raw_proto)
    return builder


def export_file(
    input_file: Union[Path, str],
    output_file: Optional[Union[Path, str]] = None,
    mode: ModeInput = Quokka.ExporterMeta.MODE_LIGHT,
    *,
    compressed: bool = True,
    update_analysis: bool = True,
) -> Path:
    if binaryninja is None:
        raise RuntimeError("BinaryNinja Python API is required for export")

    input_path = Path(input_file)
    output_path = Path(output_file) if output_file is not None else input_path.with_name(
        f"{input_path.name}.quokka"
    )

    view = binaryninja.load(str(input_path))
    if view is None:
        raise RuntimeError(f"BinaryNinja could not load {input_path}")

    export_binary_view(
        view,
        output_path,
        mode,
        compressed=compressed,
        update_analysis=update_analysis,
    )
    return output_path


def collect_headers(view: BinaryView) -> str:
    declarations: set[str] = set()
    for _, dtype in sorted(view.types.items(), key=lambda item: str(item[0])):
        declaration = _type_declaration(dtype)
        if declaration:
            declarations.add(declaration)

    for _, data_var in sorted(view.data_vars.items(), key=lambda item: item[0]):
        declaration = _type_declaration(data_var.type)
        if declaration:
            declarations.add(declaration)

    for func in sorted(view.functions, key=lambda item: item.start):
        if func.type is not None:
            declaration = _type_declaration(func.type)
            if declaration:
                declarations.add(declaration)

    return "\n".join(sorted(declarations)) + ("\n" if declarations else "")


def _normalize_mode(mode: ModeInput) -> int:
    if isinstance(mode, int):
        if mode in (
            Quokka.ExporterMeta.MODE_LIGHT,
            Quokka.ExporterMeta.MODE_SELF_CONTAINED,
        ):
            return mode
        raise ValueError(f"Unsupported Quokka export mode: {mode}")

    normalized = mode.strip().upper().replace("-", "_")
    if normalized == "LIGHT":
        return int(Quokka.ExporterMeta.MODE_LIGHT)
    if normalized in ("FULL", "SELF_CONTAINED"):
        return int(Quokka.ExporterMeta.MODE_SELF_CONTAINED)
    raise ValueError(f"Unsupported Quokka export mode: {mode}")


def _set_address_fields(ctx: ExportContext, proto: Any, addr: int) -> None:
    seg_idx = ctx.resolveSegmentIndex(addr)
    if seg_idx < 0:
        proto.segment_index = 0
        proto.segment_offset = 0
        proto.file_offset = -1
        return

    proto.segment_index = seg_idx
    proto.segment_offset = ctx.resolveSegmentOffset(addr)
    proto.file_offset = ctx.resolveFileOffset(addr)


def _hash_for_view(view: BinaryView) -> tuple[int, str]:
    for algorithm, hash_type in (
        ("md5", Quokka.Meta.Hash.HASH_MD5),
        ("sha256", Quokka.Meta.Hash.HASH_SHA256),
    ):
        try:
            return hash_type, _digest_for_view(view, algorithm)
        except Exception as exc:
            LOGGER.warning("Cannot compute %s for input binary: %s", algorithm, exc)

    return Quokka.Meta.Hash.HASH_NONE, ""


def _digest_for_view(view: BinaryView, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    path = view.file.original_filename or view.file.filename
    if path and os.path.isfile(path):
        with open(path, "rb") as input_file:
            for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    for segment in view.segments:
        data = view.read(segment.start, segment.data_length)
        digest.update(data)
    return digest.hexdigest()


def _member_name_or_default(
    name: str,
    offset: int,
    member_idx: int,
    used_names: set[str],
) -> str:
    candidate = name or f"field_{offset}"
    if candidate in used_names:
        candidate = f"{candidate}_{member_idx}"
    used_names.add(candidate)
    return candidate


def _map_calling_convention(cc_name: str) -> int:
    normalized = cc_name.lower().replace("_", "")
    if "cdecl" in normalized:
        return Quokka.CC_CDECL
    if "stdcall" in normalized:
        return Quokka.CC_STDCALL
    if "fastcall" in normalized:
        return Quokka.CC_FASTCALL
    if "thiscall" in normalized:
        return Quokka.CC_THISCALL
    if "pascal" in normalized:
        return Quokka.CC_PASCAL
    if "ellipsis" in normalized:
        return Quokka.CC_ELLIPSIS
    if "swift" in normalized:
        return Quokka.CC_SWIFT
    if "go" in normalized or "golang" in normalized:
        return Quokka.CC_GOLANG
    return Quokka.CC_UNK


def _resolve_named_type(ctx: ExportContext, dtype: Type) -> Type:
    if dtype.type_class == TypeClass.NamedTypeReferenceClass:
        target = dtype.target(ctx.view)
        return target if target is not None else dtype
    return dtype


def _merged_ranges(ranges: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted((start, end) for start, end in ranges if end > start):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged


def _intersect_ranges(
    ranges: Iterable[tuple[int, int]], start: int, end: int
) -> Iterable[tuple[int, int]]:
    for range_start, range_end in ranges:
        clipped_start = max(start, range_start)
        clipped_end = min(end, range_end)
        if clipped_end > clipped_start:
            yield clipped_start, clipped_end


def _add_layout(builder: Quokka, start_addr: int, size: int, layout_type: int) -> None:
    if size <= 0:
        return
    layout = builder.layout.add()
    layout.address_range.start_address = start_addr
    layout.address_range.size = size
    layout.layout_type = layout_type


__all__ = [
    "collect_headers",
    "DataExporter",
    "ExportContext",
    "export_binary_view",
    "export_file",
    "FunctionExporter",
    "LayoutExporter",
    "MetaExporter",
    "ReferenceExporter",
    "run_export_pipeline",
    "SegmentInfo",
    "SegmentExporter",
    "TypeExporter",
    "TypeKind",
    "classify_type",
    "map_primitive_type",
    "type_key",
]
