#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import logging
import sys
from pathlib import Path
from typing import Callable, Sequence


LOGGER = logging.getLogger("bn_quokka.export_headless")


def _load_export_file() -> Callable[..., Path]:
    """Import bn_quokka.export.export_file for any invocation style.

    When this module is imported as part of the plugin package, the relative
    import resolves directly. When executed as a standalone script there is no
    parent package, so make the plugin package importable under its on-disk
    name instead of exposing its internals (bn_quokka, quokka_pb2, ...) as
    top-level modules.
    """
    if __package__:
        from .bn_quokka.export import export_file

        return export_file

    plugin_root = Path(__file__).resolve().parent
    parent_dir = str(plugin_root.parent)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    module = importlib.import_module(f"{plugin_root.name}.bn_quokka.export")
    return module.export_file


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export a binary to a Quokka protobuf using Binary Ninja headlessly.",
    )
    parser.add_argument(
        "input_file",
        type=Path,
        help="Binary file to analyze and export.",
    )
    parser.add_argument(
        "-o",
        "--output",
        "--out",
        dest="output_file",
        type=Path,
        help="Output file path. Defaults to <input>.quokka.",
    )
    parser.add_argument(
        "-m",
        "--mode",
        default="LIGHT",
        help="Export mode: LIGHT, SELF_CONTAINED, or FULL. Defaults to LIGHT.",
    )
    parser.add_argument(
        "--no-compress",
        action="store_true",
        help="Write a raw protobuf instead of the default XZ-compressed output.",
    )
    parser.add_argument(
        "--skip-analysis",
        action="store_true",
        help="Do not wait for Binary Ninja analysis before exporting.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase logging verbosity.",
    )
    return parser


def _configure_logging(verbose: int) -> None:
    logging.basicConfig(
        format="%(levelname)s: %(message)s" if verbose else "%(message)s",
        level=logging.DEBUG if verbose > 1 else logging.INFO,
    )


def _export_file(
    input_file: Path,
    output_file: Path | None,
    mode: str,
    *,
    compressed: bool,
    update_analysis: bool,
) -> Path:
    export_file = _load_export_file()

    return export_file(
        input_file,
        output_file,
        mode,
        compressed=compressed,
        update_analysis=update_analysis,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.verbose)

    if not args.input_file.is_file():
        parser.error(f"input file does not exist: {args.input_file}")

    try:
        output_path = _export_file(
            args.input_file,
            args.output_file,
            args.mode,
            compressed=not args.no_compress,
            update_analysis=not args.skip_analysis,
        )
    except Exception as exc:
        LOGGER.error("Export failed: %s", exc)
        return 1

    LOGGER.info("Exported %s", output_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
