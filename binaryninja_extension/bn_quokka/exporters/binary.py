"""Program-image export phases: metadata, segments, layout, and data items."""

from __future__ import annotations

import hashlib
import logging
import os
import re
from typing import TYPE_CHECKING, Any, Iterable

if TYPE_CHECKING:
    from binaryninja import BinaryView, Type

import binaryninja  # type: ignore
from binaryninja import Endianness, SymbolType  # type: ignore

from ..context import ExportContext
from ..quokka_pb2 import Quokka
from ..util import (
    SegmentInfo,
    address_size_to_proto,
    build_extern_segments,
    map_calling_convention,
)


LOGGER = logging.getLogger(__name__)

# Symbol kinds whose addresses are synthetic in BinaryNinja and may lie
# outside every mapped segment.
_EXTERN_SYMBOL_TYPES = (
    SymbolType.ExternalSymbol,
    SymbolType.ImportedFunctionSymbol,
    SymbolType.ImportAddressSymbol,
    SymbolType.LibraryFunctionSymbol,
    SymbolType.ImportedDataSymbol,
)


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
        version = getattr(binaryninja, "__version__", "")
        meta.backend.version = (
            str(version) if version else str(binaryninja.core_version())
        )

        cc_name = ""
        platform = view.platform
        if platform is not None and platform.default_calling_convention is not None:
            cc_name = platform.default_calling_convention.name or ""
        meta.calling_convention = map_calling_convention(cc_name)


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
        infos = [info for info in infos if info.size > 0]

        # External/imported symbols may live at synthetic addresses outside
        # every mapped segment; give them SEGMENT_EXTERN pseudo-segments so
        # their addresses survive the (segment_index, segment_offset)
        # encoding instead of collapsing onto segment 0.
        extern_infos = build_extern_segments(
            SegmentExporter._extern_symbol_addresses(view), infos, view.address_size
        )
        if extern_infos:
            LOGGER.info(
                "Synthesized %d extern segment(s) for unmapped symbols",
                len(extern_infos),
            )
            infos.extend(extern_infos)
            infos.sort(key=lambda item: (item.start_offset, item.size, item.name))
        return infos

    @staticmethod
    def _extern_symbol_addresses(view: BinaryView) -> list[int]:
        addresses: list[int] = []
        for symbol_type in _EXTERN_SYMBOL_TYPES:
            addresses.extend(
                symbol.address for symbol in view.get_symbols_of_type(symbol_type)
            )
        return addresses


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
            dtype: Type | None,
            size: int,
            name: str = "",
        ) -> None:
            seg_idx = ctx.resolve_segment_index(addr)
            if seg_idx < 0:
                return
            symbol_name = _symbol_name_at(ctx.view, addr)
            chosen_name = symbol_name or name
            current = records.get(addr)
            record = (
                seg_idx,
                ctx.resolve_segment_offset(addr),
                ctx.resolve_file_offset(addr),
                ctx.resolve_type_index(dtype),
                max(1, size),
                chosen_name,
                not ctx.is_address_initialized(addr),
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


def _symbol_name_at(view: BinaryView, addr: int) -> str:
    symbol = view.get_symbol_at(addr)
    return symbol.name if symbol is not None and symbol.name else ""


def _string_symbol_name(string_ref: Any) -> str:
    value = str(string_ref.value)
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")[:32]
    if not cleaned:
        cleaned = "string"
    return f"s_{cleaned}_{string_ref.start:08x}"


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
    "DataExporter",
    "LayoutExporter",
    "MetaExporter",
    "SegmentExporter",
]
