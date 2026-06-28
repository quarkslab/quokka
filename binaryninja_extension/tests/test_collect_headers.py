"""Tests for header collection ordering.

These run only against the conftest stub: they monkeypatch module attributes
of the binaryninja module and build synthetic views/types.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT))

import binaryninja  # noqa: E402  # the conftest stub when outside BinaryNinja

from bn_quokka.exporters import types as types_module  # noqa: E402
from bn_quokka.exporters.types import collect_headers  # noqa: E402

pytestmark = pytest.mark.skipif(
    not isinstance(binaryninja.log_info, mock.MagicMock),
    reason="monkeypatches the stubbed BinaryNinja API",
)


class FakeNamedType:
    def __init__(self, declaration: str):
        self._declaration = declaration

    def get_string(self) -> str:
        return self._declaration


class FakeView:
    def __init__(self, types: dict):
        self.types = types
        self.data_vars: dict = {}
        self.functions: list = []


@pytest.fixture
def view() -> FakeView:
    return FakeView(
        {
            "A": FakeNamedType("struct A { struct B b; };"),
            "B": FakeNamedType("struct B { int x; };"),
        }
    )


def test_headers_use_type_printer_ordering(monkeypatch, view):
    # Dependency order: B must precede A even though "A" sorts first.
    ordered_header = "struct B { int x; };\nstruct A { struct B b; };\n"
    seen = {}

    class FakePrinter:
        def print_all_types(self, named_types, data):
            seen["types"] = named_types
            seen["view"] = data
            return ordered_header

    monkeypatch.setattr(
        types_module.binaryninja,
        "TypePrinter",
        mock.MagicMock(default=FakePrinter()),
        raising=False,
    )

    assert collect_headers(view) == ordered_header
    assert seen["view"] is view
    assert [name for name, _ in seen["types"]] == ["A", "B"]


def test_headers_fall_back_without_type_printer(monkeypatch, view):
    monkeypatch.delattr(types_module.binaryninja, "TypePrinter", raising=False)

    header = collect_headers(view)

    # Fallback is alphabetical: A's declaration precedes B's.
    assert header == "struct A { struct B b; };\nstruct B { int x; };\n"


def test_headers_fall_back_when_printer_fails(monkeypatch, view):
    class BrokenPrinter:
        def print_all_types(self, named_types, data):
            raise RuntimeError("boom")

    monkeypatch.setattr(
        types_module.binaryninja,
        "TypePrinter",
        mock.MagicMock(default=BrokenPrinter()),
        raising=False,
    )

    header = collect_headers(view)
    assert header == "struct A { struct B b; };\nstruct B { int x; };\n"


def test_headers_empty_view(monkeypatch):
    monkeypatch.delattr(types_module.binaryninja, "TypePrinter", raising=False)
    assert collect_headers(FakeView({})) == ""
