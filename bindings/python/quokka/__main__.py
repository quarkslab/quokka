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
import idascript
from multiprocessing import Pool, Queue, Manager
import queue


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


def do_quokka(exec_path: Path) -> bool:
    output_file = Path(str(exec_path)+".quokka")

    if output_file.is_file():
        return True

    database_file = exec_path.parent / f"{exec_path.name}.i64"
    if not database_file.is_file():
        database_path = database_file.with_suffix("")
    else:
        exec_path = database_file
        database_path = None

    ida = idascript.IDA(
        exec_path,
        script_file=None,
        script_params=["QuokkaAuto:true", f"QuokkaFile:{output_file}"],
        database_path=database_path,
    )

    ida.start()
    if (ret_code := ida.wait()) == 0:
        return True

    logging.error(
        f"Failed to export the binary {exec_path}. IDA returned code {ret_code}."
    )
    return False

def export_job(ingress, egress) -> bool:
    while True:
        try:
            file = ingress.get(timeout=0.5)
            res = do_quokka(file)
            egress.put((file, res))
        except queue.Empty:
            pass
        except KeyboardInterrupt:
            break


def run_async(root_path: Path, threads: int) -> None:
    manager = Manager()
    ingress = manager.Queue()
    egress = manager.Queue()
    pool = Pool(threads)

    # Launch all workers
    for _ in range(threads):
        pool.apply_async(export_job, (ingress, egress))

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

def run_sequential(root_path: Path) -> None:
    # Pre-fill ingress queue
    total_files = list(recursive_file_iter(root_path))
    total = len(total_files)

    logging.info(f"Start exporting {total} binaries")

    for i, exe_path in enumerate(total_files):
        if do_quokka(exe_path):
            pp_res = Bcolors.OKGREEN + "OK" + Bcolors.ENDC
        else:
            pp_res = Bcolors.FAIL + "KO" + Bcolors.ENDC
        logging.info(f"[{i+1}/{total}] {str(exe_path) + '.quokka'} [{pp_res}]")


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option(
    "-i",
    "--ida-path",
    type=click.Path(exists=True),
    default=None,
    help="IDA Pro headless executable path",
)
@click.option("-t", "--threads", type=int, default=1, help="Thread number to use")
@click.option("-v", "--verbose", count=True, help="To activate or not the verbosity")
@click.argument("input_file", type=click.Path(exists=True), metavar="<binary file|directory>")
def main(ida_path: str, input_file: str, threads: int, verbose: bool) -> None:
    """
    quokka-cli is a very simple utility to generate a .Quokka file
    for a given binary or a directory. It all open the binary file and export files
    seamlessly.

    :param ida_path: Path to the IDA Pro headless executable (idat or idat64)
    :param input_file: Path of the binary to export
    :param threads: number of threads to use
    :param verbose: To activate or not the verbosity
    :return: None
    """

    logging.basicConfig(
        format="%(message)s", level=logging.DEBUG if verbose else logging.INFO
    )

    if ida_path:
        os.environ["IDA_PATH"] = ida_path
    if not idascript.get_ida_path():
        logging.error("Can't find IDA Pro executable. Try setting IDA_PATH or use -i option")
        exit(1)

    root_path = Path(input_file)

    if threads > 1:
        run_async(root_path, threads)
    else:
        run_sequential(root_path)



if __name__ == "__main__":
    main()
