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

import pypcode

import quokka
from quokka.types import (
    AddressT,
    BlockType,
    DataType,
    Dict,
    Index,
    Iterator,
    List,
    MutableMapping,
    ReferenceType,
    Set,
)


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
        chunk: Parent chunk (e.g. function) of the block.

    Attributes:
        proto_index: Index inside the protobuf
        parent: A reference to the parent Chunk
        program: A reference to the parent Program
        start: Start address
        fake: Is it a fake block (e.g. belongs to a fake chunk)
        type: Block type
        address_to_index: A mapping of addresses to instruction indexes
        end: End address
        comments: List of comments attached to the block
        references: References mapping attached to the block (TODO(dm): remove me?)
    """

    def __init__(
        self,
        block_idx: Index,
        start_address: AddressT,
        chunk: quokka.Chunk,
    ):
        """Constructor"""
        self.proto_index: Index = block_idx
        self.parent: quokka.Chunk = chunk
        self.program: quokka.Program = chunk.program

        block: "quokka.pb.Quokka.FunctionChunk.Block"
        block = self.program.proto.function_chunks[chunk.proto_index].blocks[block_idx]

        self.start: int = start_address
        self.fake: bool = block.is_fake
        self.type: BlockType = BlockType.from_proto(block.block_type)

        self.address_to_index: Dict[AddressT, Index] = {}
        self._raw_dict: Dict[AddressT, Index] = {}

        current_address: AddressT = self.start
        for instruction_index, instruction_proto_index in enumerate(
            block.instructions_index
        ):
            self.address_to_index[current_address] = instruction_index
            self._raw_dict[current_address] = instruction_proto_index
            current_address += self.program.proto.instructions[
                instruction_proto_index
            ].size

        self.end: int = current_address

        self.comments: Dict[AddressT, str] = {}
        self.references: Dict[str, List[int]] = {"src": [], "dst": []}

    def __setitem__(self, k: AddressT, v: Index) -> None:
        """Update the instructions mapping"""
        self._raw_dict.__setitem__(k, v)

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

    @cached_property
    def strings(self) -> List[str]:
        """Compute the list of strings used in this block."""

        strings: Set[str] = set()

        for reference in self.program.references.resolve_block_references(
            self.parent.proto_index,
            self.proto_index,
            ReferenceType.DATA,
            towards=True,
        ):
            reference_source = reference.source
            if (
                isinstance(reference_source, quokka.data.Data)
                and reference_source.type == DataType.ASCII
            ):
                strings.add(reference_source.value)

        return list(strings)

    def __getitem__(self, address: AddressT) -> quokka.Instruction:
        """Retrieve an instruction at `address`."""
        item = self._raw_dict.__getitem__(address)
        return quokka.Instruction(
            proto_index=item,
            inst_index=self.address_to_index[address],
            address=address,
            block=self,
        )

    def __len__(self) -> int:
        """Number of instruction in the block"""
        return len(self._raw_dict)

    def __iter__(self) -> Iterator:
        """Return an iterator over the instruction list"""
        return iter(self._raw_dict)

    @property
    def data_references(self):
        """Return (and compute if needed) the data referenced by this block."""
        data_references: List[quokka.Data] = []
        for instruction in self.values():
            data_references.extend(instruction.data_references)

        return data_references

    @property
    def size(self) -> int:
        """Size of the block.

        This number is the number of instruction * the size of an instruction for
        architecture with fixed length instructions (e.g. ARM).
        """
        return self.end - self.start

    @cached_property
    def constants(self) -> List[int]:
        """Constants used by the block"""
        constants: List[int] = []
        for instruction in self.values():
            constants.extend(instruction.constants)

        return constants

    @property
    def instructions(self):
        """Accessor of the block instructions"""
        return self.values()

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
        return self.proto_index

    def successors(self) -> Iterator[AddressT]:
        """(Addresses of the) Successors of the current block."""
        return self.parent.graph.successors(self.start)

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
        try:
            file_offset: int = self.program.addresser.file(self.start)
        except quokka.NotInFileError:
            logger.warning("Trying to get the bytes for a block not in file.")
            return b""

        # Read all block at once
        block_bytes = self.program.executable.read_byte(
            offset=file_offset,
            size=self.size,
        )

        return block_bytes

    @property
    def pcode_insts(self) -> List[pypcode.PcodeOp]:
        """Generate PCode instructions for the block

        This method will call the backend Pypcode and generate the instruction for the
        whole block, updating all the instruction inside the block as well.

        However, all instructions will from now be attached to the block itself, and not
        the instructions so the list may differ after some optimizations (e.g.
        len(self.pcode_insts) != sum(len(inst.pcode_insts) for inst in block.values()) )

        Returns:
            A list of PCode instructions

        """
        return quokka.backends.pypcode_decode_block(self)
