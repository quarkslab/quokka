"""Type table export: enums, composites, type cross-references, and headers."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Iterable

if TYPE_CHECKING:
    from binaryninja import BinaryView, Type

import binaryninja  # type: ignore
from binaryninja import TypeClass  # type: ignore

from ..context import ExportContext
from ..quokka_pb2 import Quokka
from ..util import (
    PRIMITIVE_TYPE_COUNT,
    TypeKind,
    classify_type,
    inner_type,
    is_named_primitive_alias,
    map_by_size,
    type_class_name,
    type_key,
    type_name,
)


LOGGER = logging.getLogger(__name__)


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

        def register_type(dtype: Type | None) -> None:
            nonlocal skipped_duplicates, skipped_func_defs

            if dtype is None:
                return

            kind = classify_type(dtype)

            # Shared promotion rule: resolve_type_index applies the same one.
            if is_named_primitive_alias(dtype):
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
    ) -> Iterable[Type | None]:
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
    def export_type_to_type_refs(ctx: ExportContext, builder: Quokka) -> int:
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
            if dtype.type_class == TypeClass.NamedTypeReferenceClass:
                element_type = dtype.target(ctx.view)
                unaliased = False
            else:
                # Promoted named primitive alias: its element is the
                # underlying primitive, not the alias entry itself.
                element_type = dtype
                unaliased = True
            TypeExporter._build_reference_composite(
                ctx,
                proto_type.composite_type,
                dtype,
                Quokka.CompositeType.TYPE_TYPEDEF,
                element_type,
                unaliased=unaliased,
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
    def _enum_value_to_int64(raw_value: int | None) -> int:
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
            member_proto.type_index = ctx.resolve_type_index(member.type)
            member_proto.size = max(0, len(member.type)) * 8

    @staticmethod
    def _build_reference_composite(
        ctx: ExportContext,
        composite: Any,
        dtype: Type,
        subtype: int,
        element_type: Type | None,
        *,
        unaliased: bool = False,
    ) -> None:
        composite.name = type_name(dtype)
        composite.type = subtype
        composite.size = max(0, dtype.width)
        composite.c_str = dtype.get_string()
        if element_type is not None:
            composite.element_type_idx = ctx.resolve_type_index(
                element_type, unaliased=unaliased
            )

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


def collect_headers(view: BinaryView) -> str:
    """Produce C declarations for the binary's types.

    The primary path uses BinaryNinja's TypePrinter (the same machinery as
    the UI's Export Header feature), which emits forward declarations and
    orders definitions by dependency, so the result parses as a unit. When
    TypePrinter is unavailable or fails, fall back to alphabetically sorted
    per-type strings; that fallback loses dependency order and is not
    guaranteed to compile.
    """
    named_types = sorted(view.types.items(), key=lambda item: str(item[0]))

    printer = getattr(getattr(binaryninja, "TypePrinter", None), "default", None)
    if printer is not None and named_types:
        try:
            header = printer.print_all_types(named_types, view)
        except Exception as exc:
            LOGGER.warning(
                "TypePrinter failed (%s); emitting unordered declarations", exc
            )
        else:
            if isinstance(header, str) and header:
                return header if header.endswith("\n") else header + "\n"
            LOGGER.warning(
                "TypePrinter produced no header; emitting unordered declarations"
            )

    return _collect_headers_unordered(view)


def _collect_headers_unordered(view: BinaryView) -> str:
    """Alphabetically sorted type strings; loses dependency order."""
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


def _type_declaration(dtype: Type | None) -> str:
    if dtype is None:
        return ""
    try:
        return dtype.get_string()
    except Exception:
        return str(dtype)


def _resolve_named_type(ctx: ExportContext, dtype: Type) -> Type:
    if dtype.type_class == TypeClass.NamedTypeReferenceClass:
        target = dtype.target(ctx.view)
        return target if target is not None else dtype
    return dtype


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


__all__ = [
    "TypeExporter",
    "collect_headers",
]
