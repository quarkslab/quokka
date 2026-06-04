"""Shared test setup for the BinaryNinja extension.

The real binaryninja package only ships with Binary Ninja itself, so it is
absent from regular development and CI environments. To keep the extension
modules importable there, a strict stub is installed in sys.modules before
collection. Tests that need the real API must be marked with
@pytest.mark.requires_binaryninja; they are skipped when only the stub is
available.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from unittest import mock

import pytest

HAS_BINARYNINJA = importlib.util.find_spec("binaryninja") is not None

# Only the names the extension imports at module level are stubbed, so any
# unexpected API use fails loudly instead of being absorbed by a permissive
# mock.
_STUB_ATTRIBUTES = {
    "binaryninja": (
        "BinaryView",
        "BranchType",
        "Endianness",
        "InstructionTextTokenType",
        "LowLevelILOperation",
        "NamedTypeReferenceClass",
        "PluginCommand",
        "Section",
        "SectionSemantics",
        "Segment",
        "StructureVariant",
        "SymbolType",
        "Type",
        "TypeClass",
        "log_error",
        "log_info",
    ),
    "binaryninja.enums": ("MessageBoxIcon",),
    "binaryninja.interaction": (
        "SaveFileNameField",
        "get_form_input",
        "show_message_box",
    ),
}


def _install_binaryninja_stub() -> None:
    for module_name, attributes in _STUB_ATTRIBUTES.items():
        module = types.ModuleType(module_name)
        for attribute in attributes:
            setattr(
                module, attribute, mock.MagicMock(name=f"{module_name}.{attribute}")
            )
        sys.modules[module_name] = module
        parent_name, _, child_name = module_name.rpartition(".")
        if parent_name:
            setattr(sys.modules[parent_name], child_name, module)


if not HAS_BINARYNINJA:
    _install_binaryninja_stub()


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "requires_binaryninja: test needs the real BinaryNinja Python API",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if HAS_BINARYNINJA:
        return
    skip_marker = pytest.mark.skip(reason="BinaryNinja Python API is not installed")
    for item in items:
        if "requires_binaryninja" in item.keywords:
            item.add_marker(skip_marker)
