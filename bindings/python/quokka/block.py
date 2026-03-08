"""Methods to use and deal with blocks in a binary."""

#  Copyright 2022-2023 Quarkslab
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

from __future__ import annotations
import logging
import collections
from functools import cached_property
from typing import TYPE_CHECKING, MutableMapping

import quokka
from quokka.types import (
    AddressT,
    BlockType,
    ExporterMode,
    Index
)

if TYPE_CHECKING:
    import pypcode
    from quokka.instruction import Instruction
    from typing import Iterator

logger: logging.Logger = logging.getLogger(__name__)


class Block(MutableMapping):
    """Basic Block class

    A basic block is a sequence of instructions without any (basic) incoming flows
    disrupting it (except calls returns).

    While blocks may be serialized in the exported file, a new instance of this class is
    created for each block in the program (so they all have an unique address).

    Arguments:
        block_idx: Index in the protobuf file of the block
        start_address: Starting address of the block
        function: Parent function of the block.

    Attributes:
        proto: Protobuf object
        parent: A reference to the parent Function
        program: A reference to the parent Program
        start: Start address
        type: Block type
        address_to_index: A mapping of addresses to instruction indexes
        end: End address
        comments: List of comments attached to the block
    """

    def __init__(
        self,
        block_idx: Index,
        start_address: AddressT,
        function: quokka.Function,
    ):
        """Constructor"""
        self._proto_index: Index = block_idx
        self.parent: quokka.Function = function

        self.proto = function.proto.blocks[block_idx]

        self.start: int = start_address
        self.type: BlockType = BlockType.from_proto(self.proto.block_type)
        self.size: int = self.proto.size
        self.file_offset = self.proto.file_offset

        self.is_thumb = self.proto.is_thumb

        self.address_to_index: dict[AddressT, Index] = {}
        self._raw_dict: dict[AddressT, quokka.Instruction] = {}

        if self.program.mode == ExporterMode.FULL:
            current_address: AddressT = self.start
            for inst_idx, inst_pb_idx in enumerate(self.proto.instructions_index):
                ins =  quokka.Instruction(inst_pb_idx, inst_idx, current_address, self)
                self._raw_dict[current_address] = ins
                current_address += ins.size

        elif self.program.mode == ExporterMode.LIGHT:
            insts = quokka.backends.capstone.capstone_decode_block(self)
            if len(insts) != self.proto.n_instr:
                logger.debug(
                    f"Decoded {len(insts)} instructions for block at 0x{self.start:x} but expected {self.proto.n_instr}."
                )
            for i, inst in enumerate(insts):  
                ins = quokka.Instruction(-1, i, inst.address, self, backend_inst=inst)
                self._raw_dict[ins.address] = ins
        else:
            assert False, "Unknown exporter mode"

        self.comments: dict[AddressT, str] = {}

    @property
    def address(self) -> AddressT:
        """Direct accessor of the block address"""
        return self.start

    @property
    def program(self) -> quokka.Program:
        """Return the parent program"""
        return self.parent.program

    def __setitem__(self, k: AddressT, ins: Instruction) -> None:
        """Update the instructions mapping"""
        self._raw_dict.__setitem__(k, ins)

    def __delitem__(self, v: AddressT) -> None:
        """Remove an instruction from the mapping"""
        self._raw_dict.__delitem__(v)

    def add_comment(self, addr: AddressT, value: str) -> None:
        """Set the comment at `addr`.

        Arguments:
            addr: Comment address
            value: Comment value
        """
        self.comments[addr] = value

    def __getitem__(self, address: AddressT) -> quokka.Instruction:
        """Retrieve an instruction at `address`."""
        return self._raw_dict.__getitem__(address)

    def __len__(self) -> int:
        """Number of instruction in the block"""
        return len(self._raw_dict)

    def __iter__(self) -> Iterator:
        """Return an iterator over the instruction list"""
        return iter(self._raw_dict)

    @property
    def end(self) -> int:
        """Size of the block.

        This number is the number of instruction * the size of an instruction for
        architecture with fixed length instructions (e.g. ARM).
        """
        return self.start + self.size

    @cached_property
    def constants(self) -> list[int]:
        """Constants used by the block"""
        constants: list[int] = []
        for instruction in self.values():
            constants.extend(instruction.constants)

        return constants

    @cached_property
    def strings(self) -> list[str]:
        """Strings used by the block"""
        strings: list[str] = []
        for instruction in self.values():
            strings.extend(instruction.strings)

        return strings

    @property
    def instructions(self) -> Iterator[Instruction]:
        """Accessor of the block instructions"""
        return iter(self.values())

    def __repr__(self) -> str:
        """Block Representation"""
        return (
            f"<Block at 0x{self.start:x} ({self.type}) with {len(self)} instructions>"
        )

    def __hash__(self) -> int:
        """Hash of the block.

        The proto index is guaranteed to be unique so we can use it as an hash and
        forget about un-hashable types.

        TODO(dm):
            Check this
        """
        return self._proto_index

    @property
    def successors(self) -> Iterator[AddressT]:
        """(Addresses of the) Successors of the current block."""
        return self.parent.graph.successors(self.start)

    @property
    def predecessors(self) -> Iterator[AddressT]:
        """(Addresses of) Predecessors of the current block"""
        return self.parent.graph.predecessors(self.start)

    @property
    def last_instruction(self) -> quokka.Instruction:
        """Direct accessor of the last instruction in the block"""
        deque = collections.deque(self.instructions, maxlen=1)
        return deque.pop()

    @cached_property
    def bytes(self) -> bytes:
        """Retrieve the block bytes

        All bytes for the block are read at once in the file but the result is not
        cached.
        """
        if self.file_offset is None:
            logger.warning("Trying to get the bytes for a block not in file.")
            return b""

        # Read the whole block at once
        block_bytes = self.program.executable.read_bytes(
            offset=self.file_offset,
            size=self.size,
        )

        return block_bytes

    @property
    def pp_str(self) -> str:
        """Pretty print the block as a string"""
        return "\n".join(
            f"{inst.address:#x}: {str(inst)}"
            for inst in self.instructions
        )

    @cached_property
    def pcode_insts(self) -> list[pypcode.PcodeOp]:
        """Generate PCode instructions for the block

        This method will call the backend Pypcode and generate the instruction for the
        whole block, updating all the instruction inside the block as well.

        However, all instructions will from now be attached to the block itself, and not
        the instructions so the list may differ after some optimizations (e.g.
        len(self.pcode_insts) != sum(len(inst.pcode_insts) for inst in block.values()) )

        Returns:
            A list of PCode instructions

        """
        from quokka.backends.pypcode import pypcode_decode_block

        return pypcode_decode_block(self)
