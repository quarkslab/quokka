#!/usr/bin/env python3
# coding: utf-8

import logging
import os.path
from pathlib import Path
from typing import Generator

import magic
import click
import subprocess
from multiprocessing import Pool, Queue, Manager
import queue

BINARY_FORMAT = {
    "application/x-dosexec",
    "application/x-sharedlib",
    "application/x-mach-binary",
    "application/x-executable",
    "application/x-pie-executable",
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
    if p.is_file():
        mime_type = magic.from_file(p, mime=True)
        if mime_type not in BINARY_FORMAT and p.suffix not in EXTENSIONS_WHITELIST.get(
            mime_type, []
        ):
            pass
        else:
            yield p
    elif p.is_dir():
        for f in p.iterdir():
            yield from recursive_file_iter(f)


def do_quokka(exec_path: Path) -> bool:
    output_file = Path(str(exec_path)+".quokka")

    if output_file.is_file():
        return True

    database_file = exec_path.parent / f"{exec_path.name}.i64"

    additional_options = []
    if not database_file.is_file():
        additional_options.append(f'-o{database_file.with_suffix("")}')
    else:
        exec_path = database_file

    ida_path = os.environ.get("IDA_PATH", "idat64")
    try:
        cmd = [ida_path, "-OQuokkaAuto:true", f"-OQuokkaFile:{output_file}"] + additional_options + ["-A", f"{exec_path!s}"]

        result = subprocess.run(
            cmd,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            env={
                "TVHEADLESS": "1",
                "HOME": os.environ["HOME"],
                "PATH": os.environ.get("PATH", ""),
                "TERM": "xterm",  # problem with libcurses
            },
            check=True,
        )
    except subprocess.CalledProcessError:
        return False

    if output_file.is_file():
        return True
    else:
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


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option(
    "-i",
    "--ida-path",
    type=click.Path(exists=True),
    default=None,
    help="IDA Pro installation directory",
)
@click.option("-t", "--threads", type=int, default=1, help="Thread number to use")
@click.option("-v", "--verbose", count=True, help="To activate or not the verbosity")
@click.argument("input_file", type=click.Path(exists=True), metavar="<binary file|directory>")
def main(ida_path: str, input_file: str, threads: int, verbose: bool) -> None:
    """
    quokka-cli is a very simple utility to generate a .Quokka file
    for a given binary or a directory. It all open the binary file and export files
    seamlessly.

    :param ida_path: Path to the IDA Pro installation directory
    :param input_file: Path of the binary to export
    :param threads: number of threads to use
    :param verbose: To activate or not the verbosity
    :return: None
    """

    logging.basicConfig(
        format="%(message)s", level=logging.DEBUG if verbose else logging.INFO
    )

    if ida_path:
        os.environ["IDA_PATH"] = Path(ida_path).absolute().as_posix()

    root_path = Path(input_file)

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



if __name__ == "__main__":
    main()
