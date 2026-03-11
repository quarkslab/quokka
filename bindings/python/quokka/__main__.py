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

_TEMPLATE_SPECIFIERS = {
    "f": lambda p: p.stem,
    "F": lambda p: p.name,
    "P": lambda p: str(p.resolve()),
    "p": lambda p: str(p.resolve().parent),
    "e": lambda p: p.suffix.lstrip("."),
}


def _template_has_specifiers(template: str) -> bool:
    """Return True if *template* contains at least one %f/%F/%P/%p/%e specifier."""
    i = 0
    while i < len(template):
        if template[i] == "%" and i + 1 < len(template):
            if template[i + 1] in _TEMPLATE_SPECIFIERS:
                return True
            i += 2  # skip %% or unknown
        else:
            i += 1
    return False


def expand_output_template(template: str, exec_path: Path) -> Path:
    """Expand output template specifiers against the input binary path.

    Specifiers: %f (stem), %F (name), %P (full path), %p (parent), %e (ext), %% (literal %).
    """
    result = []
    i = 0
    while i < len(template):
        if template[i] == "%":
            if i + 1 >= len(template):
                raise click.BadParameter(
                    "Trailing '%' at end of template. "
                    "Use '%%' for a literal percent sign.",
                    param_hint="'-o'",
                )
            c = template[i + 1]
            if c == "%":
                result.append("%")
            elif c in _TEMPLATE_SPECIFIERS:
                result.append(_TEMPLATE_SPECIFIERS[c](exec_path))
            else:
                raise click.BadParameter(
                    f"Unknown specifier '%{c}' in output template. "
                    f"Supported: %f (stem), %F (filename), %p (parent dir), "
                    f"%P (full path), %e (extension), %% (literal %).",
                    param_hint="'-o'",
                )
            i += 2
        else:
            result.append(template[i])
            i += 1
    expanded = Path("".join(result))
    if not expanded.is_absolute():
        expanded = exec_path.resolve().parent / expanded
    return expanded

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
    output_template: str = "%F.quokka",
) -> bool:

    try:
        output_file = expand_output_template(output_template, exec_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        Program.generate(
            exec_path=exec_path,
            output_file=output_file,
            mode=mode,
            decompiled=decompiled,
            timeout=timeout,
            override=override,
            disassembler=disassembler,
        )
        return True
    except StaleIDBError as e:
        indented_err = str(e).replace('\n', '\n  ')
        logging.error(
            f"\n{Bcolors.FAIL}{Bcolors.BOLD}"
            f"{'=' * 60}\n"
            f"  ERROR: Stale IDA database files detected!\n"
            f"{'=' * 60}\n\n"
            f"  {indented_err}\n\n"
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
    output_template: str = "%F.quokka",
) -> None:
    while True:
        try:
            file = ingress.get(timeout=0.5)
            res = do_quokka(file, mode, decompiled, timeout, override, disassembler, output_template)
            egress.put((file, res))
        except queue.Empty:
            pass
        except KeyboardInterrupt:
            break


def run_async(
    paths: list,
    threads: int,
    mode: ExporterMode,
    decompiled: bool,
    timeout: int,
    override: bool,
    disassembler: Disassembler = Disassembler.UNKNOWN,
    output_template: str = "%F.quokka",
) -> None:
    manager = Manager()
    ingress = manager.Queue()
    egress = manager.Queue()
    pool = Pool(threads)

    # Launch all workers
    for _ in range(threads):
        pool.apply_async(
            export_job,
            (ingress, egress, mode, decompiled, timeout, override, disassembler, output_template),
        )

    # Pre-fill ingress queue
    total = 0
    for p in paths:
        for file in recursive_file_iter(p):
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
    paths: list,
    mode: ExporterMode,
    decompiled: bool,
    timeout: int,
    override: bool,
    disassembler: Disassembler = Disassembler.UNKNOWN,
    output_template: str = "%F.quokka",
) -> None:
    # Collect all binaries from every input path
    total_files = []
    for p in paths:
        total_files.extend(recursive_file_iter(p))
    total = len(total_files)

    logging.info(f"Start exporting {total} binaries")

    for i, exe_path in enumerate(total_files):
        if do_quokka(exe_path, mode, decompiled, timeout, override, disassembler, output_template):
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
@click.option("-o", "--output", "output_template", type=str, default="%F.quokka", help=r"Output path or template (specifiers: %f stem, %F name, %P full path, %p parent, %e ext, %% literal %)")
@click.argument("input_files", type=click.Path(exists=True), nargs=-1, required=True, metavar="<file|directory>")
def main(
    backend: str,
    ida_path: str,
    ghidra_path: str,
    input_files: tuple,
    threads: int,
    verbose: bool,
    mode: str,
    decompiled: bool,
    timeout: int,
    override: bool,
    output_template: str,
) -> None:
    """
    quokka-cli is a very simple utility to generate a .Quokka file
    for one or more binaries and/or directories. It will open every binary
    file and export files seamlessly.

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

    paths = [Path(f) for f in input_files]

    multiple_outputs = len(paths) > 1 or any(p.is_dir() for p in paths)
    if multiple_outputs and not _template_has_specifiers(output_template):
        raise click.UsageError(
            "The -o/--output name has no specifiers, so multiple binaries "
            "would be exported to the same file. "
            "Use a template with specifiers (e.g. '%f', '%F') to "
            "differentiate output paths, or export a single file instead."
        )

    export_mode = ExporterMode[mode.upper()]

    if threads > 1:
        run_async(paths, threads, export_mode, decompiled, timeout, override, disassembler, output_template)
    else:
        run_sequential(paths, export_mode, decompiled, timeout, override, disassembler, output_template)



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
@click.option("--overwrite", is_flag=True, default=False, help="Allow overwriting an existing disassembler database")
@click.option("-v", "--verbose", count=True, help="Increase logging verbosity")
@click.argument("quokka_file", type=click.Path(exists=True, dir_okay=False))
@click.argument("binary_file", type=click.Path(exists=True, dir_okay=False))
def apply_changes(
    action: str, overwrite: bool, verbose: int, quokka_file: str, binary_file: str
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
        try:
            errors = program.commit(overwrite=overwrite)
        except FileExistsError as e:
            logging.error(f"{e}\nUse --overwrite to allow modifying an existing database.")
            sys.exit(1)
        if errors == 0:
            logging.info(f"Edits committed to {quokka_file}")
        else:
            logging.error(f"commit() reported {errors} error(s)")
            sys.exit(1)
    else:  # regenerate
        try:
            new_program = program.regenerate(overwrite=overwrite)
            logging.info(f"Regenerated: {new_program.export_file}")
        except FileExistsError as e:
            logging.error(f"{e}\nUse --overwrite to allow modifying an existing database.")
            sys.exit(1)
        except QuokkaError as e:
            logging.error(f"regenerate() failed: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
