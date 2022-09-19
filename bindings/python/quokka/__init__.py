"""Quokka : A pythonic program manipulation tool

Quokka is a module designed to help using an exported program from a Python(ic) API.
It must be used with the exported version of a file (a Quokka file) and the binary
itself.
"""

#  Copyright 2022 Quarkslab
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

__version__ = "1.0.3"
__quokka_version__ = "0.0.3"

import quokka.analysis
import quokka.backends
import quokka.quokka_pb2 as pb

from quokka.addresser import Addresser

from quokka.block import Block

from quokka.data import Data, DataHolder

from quokka.exc import (
    QuokkaError,
    NotInFileError,
    ChunkMissingError,
    FunctionMissingError,
    ThunkMissingError,
    InstructionError,
    CapstoneError,
    PypcodeError,
)

from quokka.executable import Executable

from quokka.function import (
    dereference_thunk,
    get_degrees,
    Chunk,
    SuperChunk,
    Function,
)

from quokka.instruction import Operand, Instruction

from quokka.program import Program

from quokka.reference import Reference, ReferencesLocation, References

from quokka.segment import Segment

from quokka.structure import Structure, StructureMember

from quokka.utils import (
    md5_file,
    sha256_file,
    check_hash,
    get_isa,
    convert_address_size,
    get_arch,
)

__all__ = [
    # From addresser.py
    "Addresser",
    # From block.py
    "Block",
    # From data.py
    "Data",
    "DataHolder",
    # From exc.py
    "QuokkaError",
    "NotInFileError",
    "ChunkMissingError",
    "FunctionMissingError",
    "ThunkMissingError",
    "InstructionError",
    "CapstoneError",
    "PypcodeError",
    # From executable.py
    "Executable",
    # From functions.py
    "dereference_thunk",
    "get_degrees",
    "Chunk",
    "SuperChunk",
    "Function",
    # From instructions;py
    "Operand",
    "Instruction",
    # From program.py
    "Program",
    # From reference.py
    "Reference",
    "References",
    "ReferencesLocation",
    # From segment.py
    "Segment",
    # From structure.py
    "Structure",
    "StructureMember",
    # From utils.py
    "md5_file",
    "sha256_file",
    "check_hash",
    "get_isa",
    "convert_address_size",
    "get_arch",
]
