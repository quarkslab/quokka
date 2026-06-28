"""Shared state threaded through the export pipeline phases."""

from __future__ import annotations

import logging
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from binaryninja import BinaryView, Type

from .util import (
    PRIMITIVE_TYPE_COUNT,
    TYPE_UNK,
    SegmentInfo,
    TypeKind,
    address_offset,
    classify_type,
    find_segment_index,
    is_named_primitive_alias,
    map_primitive_type,
    segment_offset,
    type_class_name,
    type_key,
    type_name,
)


LOGGER = logging.getLogger(__name__)


class ExportCancelled(Exception):
    """Raised by a progress callback to abort an export in flight."""


class ExportContext:
    """Shared export state passed through BinaryNinja export phases."""

    def __init__(self, bv: BinaryView, mode: int):
        self.view: BinaryView = bv
        self.mode: int = mode

        self.segments: list[SegmentInfo] = []

        self.next_type_index: int = PRIMITIVE_TYPE_COUNT
        self.enum_type_indices: OrderedDict[str, int] = OrderedDict()
        self.composite_type_indices: OrderedDict[str, int] = OrderedDict()
        self.mnemonic_indices: dict[str, int] = {}
        self.operand_string_indices: dict[str, int] = {}
        self.register_indices: dict[str, int] = {}
        self.instruction_locations: dict[int, tuple[int, int, int]] = {}
        self._instruction_branch_cache: dict[
            int, tuple[int, tuple[tuple[Any, int | None], ...]] | None
        ] = {}

    def instruction_branches(
        self, addr: int
    ) -> tuple[int, tuple[tuple[Any, int | None], ...]] | None:
        """Decoded branch info for the instruction at addr, cached.

        Returns (length, ((branch_type, target_or_None), ...)) or None when
        the instruction cannot be decoded. Several export phases need this
        for every instruction; caching avoids re-reading and re-decoding the
        same bytes once per phase.
        """
        if addr in self._instruction_branch_cache:
            return self._instruction_branch_cache[addr]

        info = None
        if self.view is not None and self.view.arch is not None:
            try:
                raw = self.view.arch.get_instruction_info(
                    self.view.read(addr, 16), addr
                )
            except Exception:
                raw = None
            if raw is not None:
                info = (
                    getattr(raw, "length", 0),
                    tuple(
                        (branch.type, getattr(branch, "target", None))
                        for branch in getattr(raw, "branches", [])
                    ),
                )

        self._instruction_branch_cache[addr] = info
        return info

    def resolve_segment_index(self, addr: int) -> int:
        return find_segment_index(self.segments, address_offset(addr))

    def resolve_segment_offset(self, addr: int) -> int:
        offset = address_offset(addr)
        idx = find_segment_index(self.segments, offset)
        if idx < 0:
            return 0
        return segment_offset(offset, self.segments[idx])

    def resolve_file_offset(self, addr: int) -> int:
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

    def is_address_initialized(self, addr: int) -> bool:
        offset = address_offset(addr)
        idx = find_segment_index(self.segments, offset)
        if idx < 0:
            return False

        segment = self.segments[idx]
        offset_in_segment = segment_offset(offset, segment)
        data_size = segment.size if segment.data_size is None else segment.data_size
        return data_size > 0 and 0 <= offset_in_segment < data_size

    def resolve_type_index(self, dtype: Type | None, *, unaliased: bool = False) -> int:
        """Resolve a BinaryNinja type to its index in the exported type table.

        Named primitive aliases are exported as TYPEDEF entries (see
        TypeExporter), so uses of the alias resolve to that entry rather than
        to the raw primitive. Pass unaliased=True to resolve through to the
        underlying primitive instead - used for the typedef's own element
        type, which must not point back at itself.
        """
        if dtype is None:
            return TYPE_UNK

        base_type = map_primitive_type(dtype)
        if base_type is not None:
            if not unaliased and is_named_primitive_alias(dtype):
                existing = self.composite_type_indices.get(
                    type_key(dtype, TypeKind.TYPEDEF)
                )
                if existing is not None:
                    return existing
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


__all__ = [
    "ExportCancelled",
    "ExportContext",
]
