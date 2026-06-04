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
from pathlib import Path
from unittest import mock

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
_PB2_FILE = PLUGIN_ROOT / "bn_quokka" / "quokka_pb2.py"

HAS_BINARYNINJA = importlib.util.find_spec("binaryninja") is not None


def _ensure_quokka_pb2() -> bool:
    """Generate bn_quokka/quokka_pb2.py if missing, like the package build.

    The generated protobuf module is not checked in (same convention as the
    Python bindings); generate it on demand when grpcio-tools is available.
    """
    if _PB2_FILE.is_file():
        return True
    if importlib.util.find_spec("grpc_tools") is None:
        return False

    spec = importlib.util.spec_from_file_location(
        "bn_generate_proto", PLUGIN_ROOT / "generate_proto.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main()
    return _PB2_FILE.is_file()


# Running any test in this directory makes pytest import the extension
# package __init__, whose import chain requires the generated protobuf
# module. Without it (and without the tooling to generate it), nothing here
# can run.
if not _ensure_quokka_pb2():
    import warnings

    warnings.warn(
        "bn_quokka/quokka_pb2.py is missing and grpcio-tools is not "
        "installed; skipping the BinaryNinja extension tests. "
        "Run: pip install grpcio-tools",
        stacklevel=1,
    )
    collect_ignore_glob = ["test_*.py"]

# Only the names the extension imports at module level are stubbed, so any
# unexpected API use fails loudly instead of being absorbed by a permissive
# mock.
_STUB_ATTRIBUTES = {
    "binaryninja": (
        "BinaryView",
        "execute_on_main_thread",
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
        "core_ui_enabled",
        "log_debug",
        "log_error",
        "log_info",
        "log_warn",
    ),
    "binaryninja.enums": ("MessageBoxIcon",),
    "binaryninja.interaction": (
        "SaveFileNameField",
        "get_form_input",
        "show_message_box",
    ),
}


class _StubBackgroundTaskThread:
    """Minimal stand-in: the plugin entry point subclasses it at import time,
    which a MagicMock instance cannot support."""

    def __init__(self, initial_progress_text: str = "", can_cancel: bool = False):
        self.progress = initial_progress_text
        self.can_cancel = can_cancel
        self.cancelled = False

    def start(self) -> None:
        pass

    def finish(self) -> None:
        pass


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

    sys.modules["binaryninja"].BackgroundTaskThread = _StubBackgroundTaskThread


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
