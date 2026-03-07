"""Minimal C type declaration classifier.

Determines the kind (struct, union, enum, typedef) and name from a C
declaration string, then builds a minimal proto message with ``c_str`` set.
The backend reconstructs the full type from ``c_str`` alone -- proto fields
like members/size are left at defaults.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from quokka.quokka_pb2 import Quokka as Pb  # pyright: ignore[reportMissingImports]
from quokka.data_type import BaseType

if TYPE_CHECKING:
    from quokka.program import Program


def parse_c_type(c_str: str, program: Program) -> tuple[str, Pb.Type]:
    """Classify a C declaration and build a proto Type with ``c_str`` set.

    Args:
        c_str: C declaration string
        program: Program context (unused for now, reserved for future use)

    Returns:
        Tuple of (type_name, Type proto message).

    Raises:
        ValueError: If the declaration cannot be classified.
    """
    cleaned = re.sub(r'/\*.*?\*/', '', c_str, flags=re.DOTALL)
    cleaned = re.sub(r'//[^\n]*', '', cleaned)
    cleaned = cleaned.strip().rstrip(";").strip()

    if cleaned.startswith("struct "):
        return _make_composite(cleaned, c_str, "struct", Pb.CompositeType.TYPE_STRUCT)
    elif cleaned.startswith("union "):
        return _make_composite(cleaned, c_str, "union", Pb.CompositeType.TYPE_UNION)
    elif cleaned.startswith("enum "):
        return _make_enum(cleaned, c_str)
    elif cleaned.startswith("typedef "):
        return _make_typedef(cleaned, c_str)
    else:
        raise ValueError(f"Unsupported C type declaration: {c_str!r}")


def _extract_name(cleaned: str, keyword: str) -> str:
    """Extract the type name after a keyword (struct/union/enum)."""
    rest = cleaned[len(keyword):].strip()
    # Name is everything before { or end of string
    m = re.match(r'(\w+)', rest)
    if not m:
        raise ValueError(f"Cannot extract name from: {cleaned!r}")
    return m.group(1)


def _make_composite(
    cleaned: str,
    c_str: str,
    keyword: str,
    sub_type: "Pb.CompositeType.CompositeSubType",
) -> tuple[str, Pb.Type]:
    name = _extract_name(cleaned, keyword + " ")
    pb_type = Pb.Type()
    ct = pb_type.composite_type
    ct.name = name
    ct.type = sub_type
    ct.c_str = c_str
    return name, pb_type


def _make_enum(cleaned: str, c_str: str) -> tuple[str, Pb.Type]:
    name = _extract_name(cleaned, "enum ")
    pb_type = Pb.Type()
    et = pb_type.enum_type
    et.name = name
    et.c_str = c_str
    et.base_type = BaseType.DOUBLE_WORD
    return name, pb_type


def _make_typedef(cleaned: str, c_str: str) -> tuple[str, Pb.Type]:
    """Classify a typedef -- the new name is the last identifier."""
    rest = cleaned[len("typedef "):].strip()

    # Handle array: typedef int arr[10]
    arr_m = re.match(r'.+?\s+(\w+)\s*\[\d+\]\s*$', rest)
    if arr_m:
        name = arr_m.group(1)
        pb_type = Pb.Type()
        ct = pb_type.composite_type
        ct.name = name
        ct.type = Pb.CompositeType.TYPE_TYPEDEF
        ct.c_str = c_str
        return name, pb_type

    # Handle pointer: typedef int *intptr
    ptr_m = re.match(r'.+?\s*\*\s*(\w+)\s*$', rest)
    if ptr_m:
        name = ptr_m.group(1)
        pb_type = Pb.Type()
        ct = pb_type.composite_type
        ct.name = name
        ct.type = Pb.CompositeType.TYPE_TYPEDEF
        ct.c_str = c_str
        return name, pb_type

    # Simple: typedef <type> <name>
    parts = rest.rsplit(None, 1)
    if len(parts) != 2:
        raise ValueError(f"Cannot parse typedef: {cleaned!r}")
    name = parts[1].strip()
    pb_type = Pb.Type()
    ct = pb_type.composite_type
    ct.name = name
    ct.type = Pb.CompositeType.TYPE_TYPEDEF
    ct.c_str = c_str
    return name, pb_type
