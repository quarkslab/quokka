from __future__ import annotations

import sys
from pathlib import Path

from binaryninja import PluginCommand, log_error, log_info  # type: ignore
from binaryninja.enums import MessageBoxIcon  # type: ignore
from binaryninja.interaction import (  # type: ignore
    SaveFileNameField,
    get_form_input,
    show_message_box,
)

PLUGIN_ROOT = Path(__file__).resolve().parent
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from bn_quokka.export import export_binary_view  # noqa: E402


def _default_output_path(bv) -> Path:
    source = bv.file.original_filename or bv.file.filename or "binary"
    return Path(source).with_name(f"{Path(source).name}.quokka")


def _export_with_dialog(bv, mode: str) -> None:
    default_output = _default_output_path(bv)
    output_field = SaveFileNameField(
        "Output file",
        "Quokka files (*.quokka)",
        str(default_output),
    )

    if not get_form_input([output_field], f"Quokka Export ({mode})"):
        return

    output_path = Path(output_field.result or default_output)
    try:
        proto = export_binary_view(bv, output_path, mode)
    except Exception as exc:
        message = f"Failed to export {output_path}: {exc}"
        log_error(message)
        show_message_box("Quokka export failed", message, icon=MessageBoxIcon.ErrorIcon)
        return

    message = (
        f"Exported {output_path}\n"
        f"Functions: {len(proto.functions)}\n"
        f"Segments: {len(proto.segments)}\n"
        f"Types: {len(proto.types)}"
    )
    log_info(message)
    show_message_box("Quokka export complete", message, icon=MessageBoxIcon.InformationIcon)


def export_light(bv) -> None:
    _export_with_dialog(bv, "LIGHT")


def export_self_contained(bv) -> None:
    _export_with_dialog(bv, "SELF_CONTAINED")


PluginCommand.register(
    "Quokka\\Export LIGHT",
    "Export this binary to a light-mode Quokka protobuf",
    export_light,
)
#
# PluginCommand.register(
#     "Quokka\\Export SELF_CONTAINED",
#     "Export this binary to a self-contained Quokka protobuf",
#     export_self_contained,
# )
