#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


DEFAULT_LINK_NAME = "quokka_exporter"


def binaryninja_plugin_dir() -> Path:
    try:
        import binaryninja  # type: ignore

        plugin_dir = binaryninja.user_plugin_path()
        if plugin_dir:
            return Path(plugin_dir)
    except Exception:
        pass

    home = Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Binary Ninja" / "plugins"
    if sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "Binary Ninja" / "plugins"
        return home / "AppData" / "Roaming" / "Binary Ninja" / "plugins"
    return home / ".binaryninja" / "plugins"


def generate_protobuf(dry_run: bool) -> None:
    """Generate bn_quokka/quokka_pb2.py from the shared schema.

    Mirrors the Python bindings, where setup.py generates the protobuf module
    at build time instead of checking it into the repository.
    """
    if dry_run:
        print("Would generate bn_quokka/quokka_pb2.py from the shared schema")
        return

    try:
        import generate_proto
    except ImportError as exc:
        raise SystemExit(
            f"Cannot generate bn_quokka/quokka_pb2.py: {exc}\n"
            "Install the generator dependency with: pip install grpcio-tools"
        ) from exc

    generate_proto.main()


def install_symlink(plugin_dir: Path, link_name: str, dry_run: bool) -> Path:
    source = Path(__file__).resolve().parent
    destination = plugin_dir / link_name

    if destination.is_symlink():
        current_target = destination.resolve(strict=False)
        if current_target == source:
            print(f"Already installed: {destination} -> {source}")
            return destination
        print(f"Replacing existing symlink: {destination} -> {current_target}")
        if not dry_run:
            destination.unlink()
    elif destination.exists():
        raise SystemExit(
            f"Refusing to replace non-symlink path: {destination}\n"
            "Remove it manually or choose a different --name."
        )

    print(f"Installing: {destination} -> {source}")
    if not dry_run:
        plugin_dir.mkdir(parents=True, exist_ok=True)
        destination.symlink_to(source, target_is_directory=True)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Symlink this checkout into the BinaryNinja user plugin directory."
    )
    parser.add_argument(
        "--plugin-dir",
        type=Path,
        default=None,
        help="BinaryNinja plugin directory; auto-detected by default",
    )
    parser.add_argument(
        "--name",
        default=DEFAULT_LINK_NAME,
        help=f"Symlink name inside the plugin directory (default: {DEFAULT_LINK_NAME})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the install action without changing the filesystem",
    )

    args = parser.parse_args()
    plugin_dir = args.plugin_dir or binaryninja_plugin_dir()
    generate_protobuf(args.dry_run)
    install_symlink(plugin_dir.expanduser(), args.name, args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
