"""Public export API: pipeline orchestration and file-level entry points.

The heavy lifting lives in the phase modules under exporters/; this module
wires them together and remains the stable import surface of the package.
"""

from __future__ import annotations

import lzma
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from binaryninja import BinaryView

import binaryninja  # type: ignore

from .context import ExportCancelled, ExportContext
from .exporters import (
    DataExporter,
    FunctionExporter,
    LayoutExporter,
    MetaExporter,
    ReferenceExporter,
    SegmentExporter,
    TypeExporter,
    collect_headers,
)
from .quokka_pb2 import Quokka
from .util import SegmentInfo, TypeKind, classify_type, map_primitive_type, type_key


_PIPELINE_PHASES: tuple[tuple[str, Callable[[ExportContext, Quokka], Any]], ...] = (
    ("exporting metadata", MetaExporter.export),
    ("exporting segments", SegmentExporter.export),
    ("exporting types", TypeExporter.export),
    ("exporting type references", TypeExporter.export_type_to_type_refs),
    ("exporting functions", FunctionExporter.export),
    ("exporting references", ReferenceExporter.export),
    ("exporting layout", LayoutExporter.export),
    ("exporting data", DataExporter.export),
)


def run_export_pipeline(
    ctx: ExportContext,
    builder: Quokka,
    progress: Callable[[str], None] | None = None,
) -> Quokka:
    """Run all export phases on the builder.

    The optional progress callback is invoked with a short description before
    each phase; it may raise (e.g. ExportCancelled) to abort the export.
    """
    for label, phase in _PIPELINE_PHASES:
        if progress is not None:
            progress(label)
        phase(ctx, builder)

    if progress is not None:
        progress("collecting headers")
    builder.headers = collect_headers(ctx.view)
    return builder


def export_binary_view(
    bv: BinaryView,
    output_file: Path | str,
    mode: int | str = Quokka.ExporterMeta.MODE_LIGHT,
    *,
    compressed: bool = True,
    update_analysis: bool = True,
    progress: Callable[[str], None] | None = None,
) -> Quokka:
    if update_analysis:
        if progress is not None:
            progress("waiting for analysis to complete")
        bv.update_analysis_and_wait()

    output_path = Path(output_file)
    builder = Quokka()
    ctx = ExportContext(bv, _normalize_mode(mode))
    run_export_pipeline(ctx, builder, progress=progress)

    if progress is not None:
        progress(f"writing {output_path.name}")
    raw_proto = builder.SerializeToString()
    if compressed:
        with lzma.open(output_path, "wb", format=lzma.FORMAT_XZ) as output:
            output.write(raw_proto)
    else:
        with output_path.open("wb") as output:
            output.write(raw_proto)
    return builder


def export_file(
    input_file: Path | str,
    output_file: Path | str | None = None,
    mode: int | str = Quokka.ExporterMeta.MODE_LIGHT,
    *,
    compressed: bool = True,
    update_analysis: bool = True,
) -> Path:
    input_path = Path(input_file)
    output_path = Path(output_file) if output_file is not None else input_path.with_name(
        f"{input_path.name}.quokka"
    )

    view = binaryninja.load(str(input_path))
    if view is None:
        raise RuntimeError(f"BinaryNinja could not load {input_path}")

    export_binary_view(
        view,
        output_path,
        mode,
        compressed=compressed,
        update_analysis=update_analysis,
    )
    return output_path


def _normalize_mode(mode: int | str) -> int:
    if isinstance(mode, int):
        if mode in (
            Quokka.ExporterMeta.MODE_LIGHT,
            Quokka.ExporterMeta.MODE_SELF_CONTAINED,
        ):
            return mode
        raise ValueError(f"Unsupported Quokka export mode: {mode}")

    normalized = mode.strip().upper().replace("-", "_")
    if normalized == "LIGHT":
        return int(Quokka.ExporterMeta.MODE_LIGHT)
    if normalized in ("FULL", "SELF_CONTAINED"):
        return int(Quokka.ExporterMeta.MODE_SELF_CONTAINED)
    raise ValueError(f"Unsupported Quokka export mode: {mode}")


__all__ = [
    "collect_headers",
    "DataExporter",
    "ExportCancelled",
    "ExportContext",
    "export_binary_view",
    "export_file",
    "FunctionExporter",
    "LayoutExporter",
    "MetaExporter",
    "ReferenceExporter",
    "run_export_pipeline",
    "SegmentInfo",
    "SegmentExporter",
    "TypeExporter",
    "TypeKind",
    "classify_type",
    "map_primitive_type",
    "type_key",
]
