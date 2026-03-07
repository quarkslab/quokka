"""IDAPython entry point for headless apply-back.

Run by IDA via ``-S`` (see ``Program._commit_edits_ida``).
Expected ``idc.ARGV``: ``[script_path, quokka_file, binary_path]``

This file lives in ``backends/ida/`` (its own sub-package) so that IDA's
automatic sys.path insertion does not put ``backends/capstone.py`` on the
path, which would shadow the real ``capstone`` package.
"""

import idc  # type: ignore[import-unresolved]
import ida_auto  # type: ignore[import-unresolved]
import ida_pro  # type: ignore[import-unresolved]

from quokka import Program
from quokka.backends.ida import apply_quokka

ida_auto.auto_wait()

quokka_file = idc.ARGV[1]
binary_path = idc.ARGV[2]

prog = Program(quokka_file, binary_path)
errors = apply_quokka(prog)
ida_pro.qexit(errors)
