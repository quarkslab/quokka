"""Tests for named-primitive-alias handling in type registration/resolution.

These run only against the conftest stub: real BinaryNinja Type objects
cannot be constructed with hand-picked attributes.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
from unittest import mock

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT))

import binaryninja  # noqa: E402  # the conftest stub when outside BinaryNinja
from binaryninja import TypeClass  # noqa: E402

from bn_quokka.context import ExportContext  # noqa: E402
from bn_quokka.quokka_pb2 import Quokka  # noqa: E402
from bn_quokka.util import is_named_primitive_alias, type_key, TypeKind  # noqa: E402

pytestmark = pytest.mark.skipif(
    not isinstance(binaryninja.log_info, mock.MagicMock),
    reason="builds synthetic Type objects against the stubbed BinaryNinja API",
)


class FakeRegisteredName:
    def __init__(self, name: str):
        self.name = name


class FakeType(binaryninja.Type):
    def __init__(self, type_class, width: int = 4, registered_name=None):
        self.type_class = type_class
        self.width = width
        self.registered_name = registered_name


def plain_uint32() -> FakeType:
    return FakeType(TypeClass.IntegerTypeClass, width=4)


def dword_alias() -> FakeType:
    return FakeType(
        TypeClass.IntegerTypeClass,
        width=4,
        registered_name=FakeRegisteredName("DWORD"),
    )


def make_context() -> ExportContext:
    return ExportContext(None, io.BytesIO(), 0)


def test_is_named_primitive_alias():
    assert is_named_primitive_alias(dword_alias())
    assert not is_named_primitive_alias(plain_uint32())


def test_plain_primitive_resolves_to_primitive_index():
    ctx = make_context()
    assert ctx.resolve_type_index(plain_uint32()) == int(Quokka.TYPE_DW)


def test_alias_use_resolves_to_typedef_entry():
    ctx = make_context()
    alias = dword_alias()
    ctx.composite_type_indices[type_key(alias, TypeKind.TYPEDEF)] = 12

    assert ctx.resolve_type_index(alias) == 12


def test_alias_element_resolves_through_to_primitive():
    # The typedef's own element type must not point back at the alias entry.
    ctx = make_context()
    alias = dword_alias()
    ctx.composite_type_indices[type_key(alias, TypeKind.TYPEDEF)] = 12

    assert ctx.resolve_type_index(alias, unaliased=True) == int(Quokka.TYPE_DW)


def test_unregistered_alias_falls_back_to_primitive():
    ctx = make_context()
    assert ctx.resolve_type_index(dword_alias()) == int(Quokka.TYPE_DW)
