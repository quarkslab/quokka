from __future__ import annotations

import bisect
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Iterable, Sequence

if TYPE_CHECKING:
    from binaryninja import BinaryView

from binaryninja import (  # type: ignore
    NamedTypeReferenceClass,
    Section,
    SectionSemantics,
    Segment,
    StructureVariant,
    Type,
    TypeClass,
)

from .quokka_pb2 import Quokka


PRIMITIVE_TYPE_COUNT = 9
TYPE_UNK = int(Quokka.TYPE_UNK)


class TypeKind(Enum):
    ENUM = auto()
    STRUCT = auto()
    UNION = auto()
    POINTER = auto()
    ARRAY = auto()
    TYPEDEF = auto()
    FUNC_DEF = auto()
    PRIMITIVE = auto()
    UNKNOWN = auto()


@dataclass(frozen=True)
class SegmentInfo:
    """BinaryNinja segment metadata used for Quokka address resolution."""

    name: str
    start_offset: int
    size: int
    permissions: int = 0
    proto_seg_type: int = int(Quokka.Segment.SEGMENT_UNK)
    proto_addr_size: int = int(Quokka.ADDR_UNK)
    file_offset: int = -1
    data_size: int | None = None
    segment: Segment | None = None

    @classmethod
    def from_binaryninja(
        cls, view: BinaryView, segment: Segment, name: str | None = None
    ) -> SegmentInfo:
        _require_segment(segment)

        sections = view.get_sections_at(segment.start)
        if name is None:
            name = sections[0].name if sections else f"segment_{segment.start:x}"

        permissions = 0
        if segment.readable:
            permissions |= 4
        if segment.writable:
            permissions |= 2
        if segment.executable:
            permissions |= 1

        proto_seg_type = int(Quokka.Segment.SEGMENT_NORMAL)
        for section in sections:
            if section.semantics == SectionSemantics.ReadOnlyCodeSectionSemantics:
                proto_seg_type = int(Quokka.Segment.SEGMENT_CODE)
                break
            if section.semantics in (
                SectionSemantics.ReadOnlyDataSectionSemantics,
                SectionSemantics.ReadWriteDataSectionSemantics,
            ):
                proto_seg_type = int(Quokka.Segment.SEGMENT_DATA)
                break
            if section.semantics == SectionSemantics.ExternalSectionSemantics:
                proto_seg_type = int(Quokka.Segment.SEGMENT_EXTERN)
                break
        else:
            if segment.executable:
                proto_seg_type = int(Quokka.Segment.SEGMENT_CODE)
            elif segment.data_length == 0:
                proto_seg_type = int(Quokka.Segment.SEGMENT_BSS)
            elif segment.readable or segment.writable:
                proto_seg_type = int(Quokka.Segment.SEGMENT_DATA)

        return cls(
            name=name,
            start_offset=segment.start,
            size=segment.length,
            permissions=permissions,
            proto_seg_type=proto_seg_type,
            proto_addr_size=address_size_to_proto(view.address_size),
            file_offset=segment.data_offset if segment.data_length > 0 else -1,
            data_size=segment.data_length,
            segment=segment,
        )

    @classmethod
    def from_binaryninja_section(
        cls, view: BinaryView, section: Section, name: str | None = None
    ) -> SegmentInfo:
        """Build segment metadata from a BinaryNinja section."""

        if not isinstance(section, Section):
            raise TypeError(f"Expected binaryninja.Section, got {type(section).__name__}")

        backing_segment = view.get_segment_at(section.start)
        return cls.from_range(
            view,
            backing_segment,
            section.start,
            section.end,
            name or section.name,
            section.semantics,
        )

    @classmethod
    def from_range(
        cls,
        view: BinaryView,
        segment: Segment | None,
        start: int,
        end: int,
        name: str,
        semantics: Any | None = None,
    ) -> SegmentInfo:
        """Build segment metadata for a non-overlapping virtual address range."""

        size = max(0, end - start)
        permissions = _permissions_from_segment(segment, semantics)
        proto_seg_type = _segment_type_from_semantics(segment, semantics, name)
        file_offset = view.get_data_offset_for_address(start)
        if file_offset is None:
            data_size = 0
        elif segment is not None:
            data_end = segment.start + segment.data_length
            data_size = max(0, min(end, data_end) - start)
        else:
            data_size = size

        return cls(
            name=name,
            start_offset=start,
            size=size,
            permissions=permissions,
            proto_seg_type=proto_seg_type,
            proto_addr_size=address_size_to_proto(view.address_size),
            file_offset=file_offset if file_offset is not None else -1,
            data_size=data_size,
            segment=segment,
        )


def _require_type(dtype: Type) -> Type:
    if not isinstance(dtype, Type):
        raise TypeError(f"Expected binaryninja.Type, got {type(dtype).__name__}")
    return dtype


def _require_segment(segment: Segment) -> Segment:
    if not isinstance(segment, Segment):
        raise TypeError(f"Expected binaryninja.Segment, got {type(segment).__name__}")
    return segment


def _permissions_from_segment(
    segment: Segment | None, semantics: Any | None
) -> int:
    permissions = 0
    if segment is not None:
        if segment.readable:
            permissions |= 4
        if segment.writable:
            permissions |= 2
        if segment.executable:
            permissions |= 1
        return permissions

    if semantics == SectionSemantics.ReadOnlyCodeSectionSemantics:
        return 5
    if semantics == SectionSemantics.ReadWriteDataSectionSemantics:
        return 6
    if semantics == SectionSemantics.ReadOnlyDataSectionSemantics:
        return 4
    return permissions


def _segment_type_from_semantics(
    segment: Segment | None, semantics: Any | None, name: str
) -> int:
    lowered_name = name.lower()
    if semantics == SectionSemantics.ExternalSectionSemantics or "extern" in lowered_name:
        return int(Quokka.Segment.SEGMENT_EXTERN)
    if semantics == SectionSemantics.ReadOnlyCodeSectionSemantics:
        return int(Quokka.Segment.SEGMENT_CODE)
    if semantics in (
        SectionSemantics.ReadOnlyDataSectionSemantics,
        SectionSemantics.ReadWriteDataSectionSemantics,
    ):
        if segment is not None and segment.data_length == 0:
            return int(Quokka.Segment.SEGMENT_BSS)
        return int(Quokka.Segment.SEGMENT_DATA)

    if segment is None:
        return int(Quokka.Segment.SEGMENT_UNK)
    if segment.executable:
        return int(Quokka.Segment.SEGMENT_CODE)
    if segment.data_length == 0:
        return int(Quokka.Segment.SEGMENT_BSS)
    if segment.readable or segment.writable:
        return int(Quokka.Segment.SEGMENT_DATA)
    return int(Quokka.Segment.SEGMENT_NORMAL)


def address_offset(addr: int) -> int:
    """BinaryNinja addresses are integer virtual addresses."""

    if not isinstance(addr, int):
        raise TypeError(f"Expected integer BinaryNinja address, got {type(addr).__name__}")
    return addr


def address_size_to_proto(address_size: int) -> int:
    if address_size == 4:
        return int(Quokka.ADDR_32)
    if address_size == 8:
        return int(Quokka.ADDR_64)
    return int(Quokka.ADDR_UNK)


def find_segment_index(segments: Sequence[SegmentInfo], addr: int) -> int:
    offset = address_offset(addr)
    lo = 0
    hi = len(segments) - 1
    result = -1

    while lo <= hi:
        mid = (lo + hi) >> 1
        if segments[mid].start_offset <= offset:
            result = mid
            lo = mid + 1
        else:
            hi = mid - 1

    if result < 0:
        return -1

    segment = segments[result]
    if segment.start_offset <= offset < segment.start_offset + segment.size:
        return result
    return -1


def segment_offset(addr: int, segment: SegmentInfo) -> int:
    return address_offset(addr) - segment.start_offset


def build_extern_segments(
    addresses: Iterable[int],
    segments: Sequence[SegmentInfo],
    address_size: int,
) -> list[SegmentInfo]:
    """Synthesize SEGMENT_EXTERN pseudo-segments for unmapped addresses.

    BinaryNinja assigns external and imported symbols synthetic addresses
    that may lie outside every mapped segment. Without a backing segment such
    addresses cannot be encoded as (segment_index, segment_offset) pairs and
    would all collapse onto segment 0. One pseudo-segment is emitted per gap
    between existing segments that contains unmapped addresses, clamped so it
    never overlaps a real segment.

    The segments sequence must be sorted by start_offset and non-overlapping.
    """
    unmapped = sorted(
        {addr for addr in addresses if find_segment_index(segments, addr) < 0}
    )
    if not unmapped:
        return []

    starts = [segment.start_offset for segment in segments]

    clusters: list[list[int]] = []
    for addr in unmapped:
        gap = bisect.bisect_right(starts, addr)
        if clusters and bisect.bisect_right(starts, clusters[-1][-1]) == gap:
            clusters[-1].append(addr)
        else:
            clusters.append([addr])

    width = max(1, address_size)
    extern_segments: list[SegmentInfo] = []
    for index, cluster in enumerate(clusters):
        start = cluster[0]
        end = cluster[-1] + width
        gap = bisect.bisect_right(starts, cluster[-1])
        if gap < len(segments):
            end = min(end, segments[gap].start_offset)
        end = max(end, cluster[-1] + 1)
        extern_segments.append(
            SegmentInfo(
                name="extern" if index == 0 else f"extern_{index}",
                start_offset=start,
                size=end - start,
                permissions=0,
                proto_seg_type=int(Quokka.Segment.SEGMENT_EXTERN),
                proto_addr_size=address_size_to_proto(address_size),
                file_offset=-1,
                data_size=0,
                segment=None,
            )
        )
    return extern_segments


def type_name(dtype: Type) -> str:
    dtype = _require_type(dtype)
    if dtype.type_class == TypeClass.NamedTypeReferenceClass:
        return str(dtype.name)

    registered_name = dtype.registered_name
    if registered_name is not None:
        return str(registered_name.name)

    return dtype.get_string()


def type_class_name(dtype: Type) -> str:
    return _require_type(dtype).type_class.name


def map_by_size(byte_size: int | None) -> int:
    return {
        1: int(Quokka.TYPE_B),
        2: int(Quokka.TYPE_W),
        4: int(Quokka.TYPE_DW),
        8: int(Quokka.TYPE_QW),
        16: int(Quokka.TYPE_OW),
    }.get(byte_size, TYPE_UNK)


def map_calling_convention(cc_name: str) -> int:
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


def map_primitive_type(dtype: Type) -> int | None:
    dtype = _require_type(dtype)

    if dtype.type_class == TypeClass.VoidTypeClass:
        return int(Quokka.TYPE_VOID)
    if dtype.type_class == TypeClass.BoolTypeClass:
        return int(Quokka.TYPE_B)
    if dtype.type_class in (TypeClass.IntegerTypeClass, TypeClass.WideCharTypeClass):
        return map_by_size(dtype.width)
    if dtype.type_class == TypeClass.FloatTypeClass:
        if dtype.width == 4:
            return int(Quokka.TYPE_FLOAT)
        if dtype.width == 8:
            return int(Quokka.TYPE_DOUBLE)
        return TYPE_UNK

    return None


def classify_type(dtype: Type) -> TypeKind:
    dtype = _require_type(dtype)

    if dtype.type_class == TypeClass.NamedTypeReferenceClass:
        named_type_class = dtype.named_type_class
        if named_type_class == NamedTypeReferenceClass.EnumNamedTypeClass:
            return TypeKind.ENUM
        if named_type_class == NamedTypeReferenceClass.UnionNamedTypeClass:
            return TypeKind.UNION
        if named_type_class in (
            NamedTypeReferenceClass.StructNamedTypeClass,
            NamedTypeReferenceClass.ClassNamedTypeClass,
        ):
            return TypeKind.STRUCT
        if named_type_class == NamedTypeReferenceClass.TypedefNamedTypeClass:
            return TypeKind.TYPEDEF
        return TypeKind.UNKNOWN

    if dtype.type_class == TypeClass.EnumerationTypeClass:
        return TypeKind.ENUM
    if dtype.type_class == TypeClass.StructureTypeClass:
        return (
            TypeKind.UNION
            if dtype.type == StructureVariant.UnionStructureType
            else TypeKind.STRUCT
        )
    if dtype.type_class == TypeClass.PointerTypeClass:
        return TypeKind.POINTER
    if dtype.type_class == TypeClass.ArrayTypeClass:
        return TypeKind.ARRAY
    if dtype.type_class == TypeClass.FunctionTypeClass:
        return TypeKind.FUNC_DEF
    if map_primitive_type(dtype) is not None:
        return TypeKind.PRIMITIVE
    return TypeKind.UNKNOWN


def type_key(dtype: Type, kind: TypeKind) -> str:
    suffix = {
        TypeKind.STRUCT: "STRUCT",
        TypeKind.UNION: "UNION",
        TypeKind.POINTER: "POINTER",
        TypeKind.ARRAY: "ARRAY",
        TypeKind.TYPEDEF: "TYPEDEF",
    }.get(kind)
    if suffix is None:
        raise ValueError(f"No type key for kind: {kind.name}")
    return f"{type_name(dtype)}:{suffix}"


def inner_type(dtype: Type) -> Type | None:
    dtype = _require_type(dtype)
    if dtype.type_class == TypeClass.PointerTypeClass:
        return dtype.target
    if dtype.type_class == TypeClass.ArrayTypeClass:
        return dtype.element_type
    return None


__all__ = [
    "PRIMITIVE_TYPE_COUNT",
    "TYPE_UNK",
    "SegmentInfo",
    "TypeKind",
    "address_offset",
    "address_size_to_proto",
    "build_extern_segments",
    "classify_type",
    "find_segment_index",
    "inner_type",
    "map_by_size",
    "map_calling_convention",
    "map_primitive_type",
    "segment_offset",
    "type_class_name",
    "type_key",
    "type_name",
]
