from __future__ import annotations

import logging
from pathlib import Path

from binaryninja import (  # type: ignore
    BackgroundTaskThread,
    PluginCommand,
    core_ui_enabled,
    execute_on_main_thread,
    log_debug,
    log_error,
    log_info,
    log_warn,
)
from binaryninja.enums import MessageBoxIcon  # type: ignore
from binaryninja.interaction import (  # type: ignore
    SaveFileNameField,
    get_form_input,
    show_message_box,
)

from .bn_quokka.export import ExportCancelled, export_binary_view


class _BinaryNinjaLogHandler(logging.Handler):
    """Forward stdlib logging records to the BinaryNinja log.

    bn_quokka deliberately uses Python's logging (so headless runs can
    configure it normally); inside the UI those records would otherwise never
    reach the BinaryNinja log pane.
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
            if record.levelno >= logging.ERROR:
                log_error(message)
            elif record.levelno >= logging.WARNING:
                log_warn(message)
            elif record.levelno >= logging.INFO:
                log_info(message)
            else:
                log_debug(message)
        except Exception:
            self.handleError(record)


def _install_log_forwarder() -> None:
    """Route this package's loggers to the BinaryNinja log pane (UI only)."""
    if not core_ui_enabled():
        return

    logger = logging.getLogger(__name__)
    if any(isinstance(handler, _BinaryNinjaLogHandler) for handler in logger.handlers):
        return

    handler = _BinaryNinjaLogHandler()
    handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    logger.addHandler(handler)
    # Surface INFO diagnostics (skipped types, ...) in the log pane; the pane
    # has its own per-level filtering.
    logger.setLevel(logging.INFO)


def _default_output_path(bv) -> Path:
    source = bv.file.original_filename or bv.file.filename or "binary"
    return Path(source).with_name(f"{Path(source).name}.quokka")


class _ExportTask(BackgroundTaskThread):
    """Run the export off the UI thread, with progress text and cancellation."""

    def __init__(self, bv, output_path: Path, mode: str):
        super().__init__(f"Quokka: exporting {output_path.name} ({mode})", True)
        self.bv = bv
        self.output_path = output_path
        self.mode = mode

    def _progress(self, text: str) -> None:
        if self.cancelled:
            raise ExportCancelled(f"Quokka export of {self.output_path} cancelled")
        self.progress = f"Quokka: {text}"

    def run(self) -> None:
        try:
            proto = export_binary_view(
                self.bv, self.output_path, self.mode, progress=self._progress
            )
        except ExportCancelled as exc:
            log_info(str(exc))
            return
        except Exception as exc:
            message = f"Failed to export {self.output_path}: {exc}"
            log_error(message)
            execute_on_main_thread(
                lambda: show_message_box(
                    "Quokka export failed", message, icon=MessageBoxIcon.ErrorIcon
                )
            )
            return

        message = (
            f"Exported {self.output_path}\n"
            f"Functions: {len(proto.functions)}\n"
            f"Segments: {len(proto.segments)}\n"
            f"Types: {len(proto.types)}"
        )
        log_info(message)
        execute_on_main_thread(
            lambda: show_message_box(
                "Quokka export complete", message, icon=MessageBoxIcon.InformationIcon
            )
        )


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
    _ExportTask(bv, output_path, mode).start()


def export_light(bv) -> None:
    _export_with_dialog(bv, "LIGHT")


def export_self_contained(bv) -> None:
    _export_with_dialog(bv, "SELF_CONTAINED")


_install_log_forwarder()

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
