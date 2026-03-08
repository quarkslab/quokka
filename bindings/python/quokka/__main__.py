#!/usr/bin/env python3
# coding: utf-8

import logging
import os
import os.path
from pathlib import Path
from typing import Generator
import sys

import magic
import click
from multiprocessing import Pool, Queue, Manager
import queue

# local imports
from quokka import Program, QuokkaError, StaleIDBError
from quokka.types import Disassembler, ExporterMode


BINARY_FORMAT = {
    "application/x-dosexec",
    "application/x-sharedlib",
    "application/x-mach-binary",
    "application/x-executable",
    "application/x-pie-executable",
    "application/x-object", #.ko files
}

EXTENSIONS_WHITELIST = {"application/octet-stream": [".dex"]}

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], max_content_width=300)

class Bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'




def recursive_file_iter(p: Path) -> Generator[Path, None, None]:
    if p.is_file() and not p.is_symlink():
        mime_type = magic.from_file(p, mime=True)
        if mime_type not in BINARY_FORMAT and p.suffix not in EXTENSIONS_WHITELIST.get(
            mime_type, []
        ):
            pass
        else:
            yield p
    elif p.is_dir() and not p.is_symlink():
        for f in p.iterdir():
            yield from recursive_file_iter(f)


def do_quokka(
    exec_path: Path,
    mode: ExporterMode,
    decompiled: bool,
    timeout: int,
    override: bool,
    disassembler: Disassembler = Disassembler.UNKNOWN,
) -> bool:

    try:
        Program.generate(
            exec_path=exec_path,
            mode=mode,
            decompiled=decompiled,
            timeout=timeout,
            override=override,
            disassembler=disassembler,
        )
        return True
    except StaleIDBError as e:
        logging.error(
            f"\n{Bcolors.FAIL}{Bcolors.BOLD}"
            f"{'=' * 60}\n"
            f"  ERROR: Stale IDA database files detected!\n"
            f"{'=' * 60}\n\n"
            f"  {e}\n\n"
            f"  Remove the .id0, .id1, .id2, .til, and .nam files\n"
            f"  next to '{exec_path.name}' before running quokka again.\n"
            f"{'=' * 60}"
            f"{Bcolors.ENDC}"
        )
        return False
    except QuokkaError as e:
        logging.error(f"Failed to export the binary {exec_path}. Error: {str(e)}")
        return False


def export_job(
    ingress,
    egress,
    mode: ExporterMode,
    decompiled: bool,
    timeout: int,
    override: bool,
    disassembler: Disassembler = Disassembler.UNKNOWN,
) -> None:
    while True:
        try:
            file = ingress.get(timeout=0.5)
            res = do_quokka(file, mode, decompiled, timeout, override, disassembler)
            egress.put((file, res))
        except queue.Empty:
            pass
        except KeyboardInterrupt:
            break


def run_async(
    root_path: Path,
    threads: int,
    mode: ExporterMode,
    decompiled: bool,
    timeout: int,
    override: bool,
    disassembler: Disassembler = Disassembler.UNKNOWN,
) -> None:
    manager = Manager()
    ingress = manager.Queue()
    egress = manager.Queue()
    pool = Pool(threads)

    # Launch all workers
    for _ in range(threads):
        pool.apply_async(
            export_job,
            (ingress, egress, mode, decompiled, timeout, override, disassembler),
        )

    # Pre-fill ingress queue
    total = 0
    for file in recursive_file_iter(root_path):
        ingress.put(file)
        total += 1

    logging.info(f"Start exporting {total} binaries")

    i = 0
    while True:
        item = egress.get()
        i += 1
        path, res = item
        if res:
            pp_res = Bcolors.OKGREEN + "OK" + Bcolors.ENDC
        else:
            pp_res = Bcolors.FAIL + "KO" + Bcolors.ENDC
        logging.info(f"[{i}/{total}] {str(path) + '.quokka'} [{pp_res}]")
        if i == total:
            break

    pool.terminate()

def run_sequential(
    root_path: Path,
    mode: ExporterMode,
    decompiled: bool,
    timeout: int,
    override: bool,
    disassembler: Disassembler = Disassembler.UNKNOWN,
) -> None:
    # Pre-fill ingress queue
    total_files = list(recursive_file_iter(root_path))
    total = len(total_files)

    logging.info(f"Start exporting {total} binaries")

    for i, exe_path in enumerate(total_files):
        if do_quokka(exe_path, mode, decompiled, timeout, override, disassembler):
            pp_res = Bcolors.OKGREEN + "OK" + Bcolors.ENDC
        else:
            pp_res = Bcolors.FAIL + "KO" + Bcolors.ENDC
        logging.info(f"[{i+1}/{total}] {str(exe_path) + '.quokka'} [{pp_res}]")


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option(
    "-b",
    "--backend",
    type=click.Choice(["ida", "ghidra", "auto"], case_sensitive=False),
    default="auto",
    help="Disassembler backend (default: auto-detect)",
)
@click.option(
    "-i",
    "--ida-path",
    type=click.Path(exists=True),
    default=None,
    help="IDA Pro headless executable path",
)
@click.option(
    "--ghidra-path",
    type=click.Path(exists=True),
    default=None,
    help="Ghidra installation directory (overrides GHIDRA_INSTALL_DIR)",
)
@click.option("--timeout", type=int, default=0, help="Timeout for each export in seconds")
@click.option("--override", is_flag=True, default=False, help="Override existing .quokka files")
@click.option("-t", "--threads", type=int, default=1, help="Thread number to use")
@click.option("-v", "--verbose", count=True, help="To activate or not the verbosity")
@click.option("-m", "--mode", type=click.Choice([x.name for x in ExporterMode], case_sensitive=False), default=ExporterMode.LIGHT.name, help="Export mode (LIGHT or FULL)")
@click.option("--decompiled", is_flag=True, default=False, help="Export decompiled code")
@click.argument("input_file", type=click.Path(exists=True), metavar="<binary file|directory>")
def main(
    backend: str,
    ida_path: str,
    ghidra_path: str,
    input_file: str,
    threads: int,
    verbose: bool,
    mode: str,
    decompiled: bool,
    timeout: int,
    override: bool,
) -> None:
    """
    quokka-cli is a very simple utility to generate a .Quokka file
    for a given binary or a directory. It will open the binary file and export
    files seamlessly.

    Supports both IDA Pro and Ghidra backends. Use --backend to choose, or
    let auto-detection pick whichever is available.
    """

    logging.basicConfig(
        format="%(message)s", level=logging.DEBUG if verbose else logging.INFO
    )

    # Resolve the disassembler backend
    disassembler: Disassembler = Disassembler.UNKNOWN

    if backend == "ida":
        disassembler = Disassembler.IDA
        if ida_path:
            os.environ["IDA_PATH"] = ida_path
        try:
            import idascript
        except ImportError:
            logging.error("idascript is not installed. Install it to use the IDA backend.")
            exit(1)
        if not idascript.get_ida_path():
            logging.error("Can't find IDA Pro executable. Try setting IDA_PATH or use -i option")
            exit(1)
    elif backend == "ghidra":
        disassembler = Disassembler.GHIDRA
        if ghidra_path:
            os.environ["GHIDRA_INSTALL_DIR"] = ghidra_path
        if not os.environ.get("GHIDRA_INSTALL_DIR"):
            logging.error(
                "Ghidra not found. Set GHIDRA_INSTALL_DIR or use --ghidra-path"
            )
            exit(1)
        if decompiled:
            logging.warning(
                "Ghidra export does not support decompilation yet; "
                "ignoring --decompiled flag."
            )
    else:  # auto
        if ida_path:
            os.environ["IDA_PATH"] = ida_path
        if ghidra_path:
            os.environ["GHIDRA_INSTALL_DIR"] = ghidra_path
        # Let Program._detect_disassembler() choose at export time
        disassembler = Disassembler.UNKNOWN

    root_path = Path(input_file)

    export_mode = ExporterMode[mode.upper()]

    if threads > 1:
        run_async(root_path, threads, export_mode, decompiled, timeout, override, disassembler)
    else:
        run_sequential(root_path, export_mode, decompiled, timeout, override, disassembler)



@click.command(context_settings=CONTEXT_SETTINGS)
@click.option(
    "--commit",
    "action",
    flag_value="commit",
    default=True,
    help="Write .quokka and apply edits to the disassembler (default)",
)
@click.option(
    "--regenerate",
    "action",
    flag_value="regenerate",
    help="commit() then re-export a fresh .quokka from IDA (slower)",
)
@click.option("-v", "--verbose", count=True, help="Increase logging verbosity")
@click.argument("quokka_file", type=click.Path(exists=True, dir_okay=False))
@click.argument("binary_file", type=click.Path(exists=True, dir_okay=False))
def apply_changes(
    action: str, verbose: int, quokka_file: str, binary_file: str
) -> None:
    """Apply pre-recorded edits from a .quokka file back to the disassembler.

    QUOKKA_FILE is the .quokka file containing pending edits.
    BINARY_FILE is the corresponding binary executable.

    Use --commit (default) to write the .quokka and push edits to the IDA
    database.  Use --regenerate to also trigger a fresh re-export from IDA.
    """
    logging.basicConfig(
        format="%(message)s", level=logging.DEBUG if verbose else logging.INFO
    )

    try:
        program = Program.open(quokka_file, binary_file)
    except QuokkaError as e:
        logging.error(f"Failed to open {quokka_file}: {e}")
        sys.exit(1)

    if action == "commit":
        success = program.commit()
        if success:
            logging.info(f"Edits committed to {quokka_file}")
        else:
            logging.error("commit() failed")
            sys.exit(1)
    else:  # regenerate
        try:
            new_program = program.regenerate()
            logging.info(f"Regenerated: {new_program.export_file}")
        except QuokkaError as e:
            logging.error(f"regenerate() failed: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
