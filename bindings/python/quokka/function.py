"""Functions management"""

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
from functools import cached_property
from typing import Tuple, TYPE_CHECKING
import networkx

from collections import UserList
import quokka
from quokka.quokka_pb2 import Quokka as Pb # pyright: ignore[reportMissingImports]
from quokka import Block, FunctionMissingError
from quokka.types import (
    AddressT,
    RefType,
    FunctionType,
    Index,
    SegmentType
)

logger = logging.getLogger(__name__)


def dereference_thunk(item: Function, caller: bool = False) -> Function:
    """Dereference a thunk

    This method is used to resolve a thunk calls / callers. As thunk function only have
    1 relation : FUNC (call x) -> THUNK X -> X , it disrupts the call graph and
    heuristics based on graph degrees.

    Arguments:
        item: A function
        caller: True if we want to find the callers (e.g. the functions that call item)
                False if we want to find the callee (e.g. function that are called by
                item)

    Raises:
        ThunkMissingError: When no thunk has been found
        FunctionMissingError: When no function has been found
    """
    function = item

    # Do not try to (de)reference if we do not meet the prerequisites
    if caller is False and function.type != FunctionType.THUNK:
        # Only dereference THUNK function
        return function

    if caller is True and function.in_degree != 1:
        # Only try to reference function with in_degree == 1
        return function

    reference = function.callees if caller is False else function.callers

    try:
        candidate = reference[0]
    except IndexError as exc:
        raise FunctionMissingError("Missing func referenced by thunk") from exc

    if candidate.type == FunctionType.THUNK and caller is not True:
        # Recursive call for multi layered THUNK
        return dereference_thunk(candidate, caller)

    if caller and candidate.type != FunctionType.THUNK:
        return function

    return candidate


def resolve_effective_degrees(item: Function) -> Tuple[int, int]:
    """Compute a Function {in, out} degrees by resolving thunks"""
    in_degree = item.in_degree
    try:
        in_func = dereference_thunk(item, True)
        in_degree = in_func.in_degree
    except FunctionMissingError:
        pass

    try:
        out_func: Function = dereference_thunk(item, False)
    except FunctionMissingError:
        out_func = item

    return in_degree, out_func.out_degree


class Function(dict):
    """Function object

    This class represents a binary function within the Program.

    Arguments:
        proto_index: Protobuf index of the function
        func: Protobuf data
        program: Program reference

    Attributes:
        start: Start address
        name: Function name
        mangled_name: Function mangled name (it might be equal to the function name)
        program: Program reference
        type: Function type
        func: Protobuf data
    """

    def __init__(self, proto_index: Index, func: "Pb.Function", program: quokka.Program):
        """Constructor"""
        super(dict, self).__init__()
        self.start: int = program.virtual_address(func.segment_index, func.segment_offset)
        self.proto = func
        self.proto_index = proto_index
        self.mangled_name: str = func.mangled_name or func.name
        self.decompiled_code: str = func.decompiled_code or ""

        self.program: quokka.Program = program

        self.type: "FunctionType" = FunctionType.from_proto(func.function_type)
        if self.type == FunctionType.NORMAL:
            segment = self.program.get_segment(self.start)
            if segment and segment.type == SegmentType.EXTERN:
                self.type = FunctionType.EXTERN

        # Fill the dict with block addresses and their corresponding index
        self._block_data: dict[AddressT, Tuple[Index, int]] = {}
        for block_index, block in enumerate(func.blocks):  # iterate over the block protobuf objects
            block_address: int = program.virtual_address(block.segment_index, block.segment_offset)
            self._block_data[block_address] = (block_index, block.size)
        self._index_to_address = {idx: addr for addr, (idx, _) in self._block_data.items()}
 
        self._data_references: list[quokka.Data] = []

        # Continuous chunks of code in the function
        block_ranges = sorted((addr, addr+size) for addr, (idx, size) in self._block_data.items())
        self._chunks: list[tuple[AddressT, AddressT]] = self.coalesce_block_ranges(block_ranges)
        
        # TODO: Retrieving calling convention

    @property
    def has_body(self) -> bool:
        """Check if the function has a body (e.g. at least one block)"""
        return len(self._block_data) > 0

    def __getitem__(self, address: AddressT) -> Block:
        """Lazy loader for blocks within the function"""
        if address not in self._block_data:
            raise IndexError(f"Unable to find the block at 0x{address:x} in function {self.name}")
        else:
            if address in self:  # already loaded
                return super().__getitem__(address)
            else:
                block_index, block_size = self._block_data[address]
                block = Block(block_index, address, self)
                super().__setitem__(address, block)
                return block

    def values(self):
        """Return the blocks of the function"""
        for address in self._block_data.keys():
            yield self[address]

    def keys(self):
        """Return the block addresses of the function"""
        return self._block_data.keys()
    
    def items(self):
        """Return the block addresses and blocks of the function"""
        for address in self._block_data.keys():
            yield address, self[address]

    @cached_property
    def size(self) -> int:
        """Return the function size"""
        return self.end - self.start

    @property
    def comments(self) -> list[str]:
        """Return the function comments"""
        return self.proto.comments

    def add_comment(self, comment: str) -> None:
        """Add a comment to the function"""
        self.proto.comments.append(comment)
        self.proto.edits.comments.append(len(self.proto.comments) - 1)

    def add_edge(self, source: Block, destination: Block, type: EdgeType) -> None:
        """Add an edge to the function CFG"""
        assert source in self.blocks and destination in self.blocks, "Both source and destination blocks must belong to the function"
        edge = self.proto.edges.add()
        edge.source = source._proto_index
        edge.destination = destination._proto_index
        edge.edge_type = type.to_proto()
        edge.user_defined = True
        self.proto.edits.edges.append(len(self.proto.edges) - 1)

    @cached_property
    def strings(self) -> list[str]:
        """Return the list of strings referenced by the function"""
        strings = []
        for block in self.values():
            strings.extend(block.strings)
        return strings

    @property
    def name(self) -> str:
        """Return the function name"""
        return self.proto.name
    
    @name.setter
    def name(self, value: str) -> None:
        """Set the function name"""
        self.proto.name = value
        self.proto.edits.name_set = True

    @property
    def prototype(self) -> str:
        """Return the function prototype if any"""
        return self.proto.prototype

    @prototype.setter
    def prototype(self, value: str) -> None:
        """Set the function prototype"""
        self.proto.prototype = value
        self.proto.edits.prototype_set = True

    @cached_property
    def constants(self) -> list[int]:
        """Lists constants used in the function"""
        constants: list[int] = []
        for block in self.values():
            constants.extend(block.constants)

        return constants

    @cached_property
    def graph(self) -> "networkx.DiGraph":
        """Return the CFG of the function as DiGraph object"""
        graph = networkx.DiGraph()
        graph.add_nodes_from(n for n in self.keys())

        for edge in self.proto.edges:
            if (edge.source not in self._index_to_address
                or edge.destination not in self._index_to_address):
                continue
            graph.add_edge(
                self._index_to_address[edge.source],
                self._index_to_address[edge.destination],
                condition=RefType.from_proto(edge.edge_type),
            )

        return graph

    def in_function(self, address: AddressT) -> bool:
        """Check if an address belongs to the function."""
        if len(self._chunks) == 0:
            return False

        if address < min(self._chunks)[0] or address > max(self._chunks)[1]:
            return False

        for start, end in self._chunks:
            if start <= address < end:
                return True

        return False

    def get_instruction(self, address: AddressT) -> quokka.Instruction:
        """Get the instruction at `address`"""
        if not self.in_function(address):
            raise IndexError(f"Unable to find the instruction at 0x{address:x}")

        for block in self.values():  # TODO: Improve complexity
            if block.start <= address < block.end:
                return block[address]

        raise IndexError(f"Unable to find the instruction at 0x{address:x}")

    @cached_property
    def end(self) -> int:
        """Get the last address of the function"""
        try:
            max_block = max(self.keys())
            return self[max_block].end
        except ValueError:
            return self.start + 1

    @cached_property
    def callees(self) -> list['Function']:
        """Return the list of calls made by this function.
        The semantic of a "call" is to jump or call to the **starting** of a function.
        Beware that this might lead to different results than the program call graph.

        Note: The list is not deduplicated so a target may occur multiple time.
        """
        calls = set()
        # Iterate all basic blocks references to find calls to other functions
        # Note do not use basic block object thus does not requires loading them.
        for block in self.proto.blocks:
            for inst_xref in block.instructions_xrefs_from:
                xref = self.program.proto.references[inst_xref.xref_index]
                if xref.type == Pb.Reference.REF_CODE:
                    if xref.destination.address in self.program:  # Pointing on a function head
                        calls.add(self.program[xref.destination.address])
                # In all other else cases we are not on a call edge
        return list(calls)

    @cached_property
    def callers(self) -> list['Function']:
        """Retrieve the function callers (the ones calling this function)"""
        callers = []
        if self.has_body:
            block_idx, _ = self._block_data[self.start]
            block = self.proto.blocks[block_idx]
            for inst_xref in (x for x in block.instructions_xrefs_to if x.instr_bb_idx == 0):
                xref = self.program.proto.references[inst_xref.xref_index]
                if xref.type == Pb.Reference.REF_CODE:
                    if f := self.program.find_function_by_address(xref.source.address):
                        callers.append(f)
        return callers

    @property
    def instructions(self):
        """Yields the function instruction"""
        return (inst for block in self.values() for inst in block.instructions)

    @cached_property
    def out_degree(self) -> int:
        """Function out degree"""
        return len(set(self.callees))

    @cached_property
    def in_degree(self) -> int:
        """Function in degree"""
        return len(set(self.callers))

    @property
    def blocks(self) -> dict[AddressT, Block]:
        """Returns a dictionary which is used to reference all basic blocks
        by their address.
        """
        return {addr: self[addr] for addr in self.keys()}

    def __hash__(self) -> int:  # type: ignore
        """Hash value"""
        return self.start

    def __str__(self) -> str:
        """Function representation"""
        return f"<Function {self.name} at 0x{self.start:x}>"

    def __repr__(self) -> str:
        """Function representation"""
        return self.__str__()

    @staticmethod
    def coalesce_block_ranges(block_ranges: list[tuple[int, int]]) -> list[tuple[AddressT, AddressT]]:
        """Merge adjacent or overlapping block ranges into a reduced list.

        Arguments:
            block_ranges: Sorted list of (start, end) tuples.

        Returns:
            A list of merged (start, end) tuples.
        """
        if not block_ranges:
            return []

        merged = [block_ranges[0]]
        for start, end in block_ranges[1:]:
            prev_start, prev_end = merged[-1]
            if start == prev_end:  # Adjacent
                merged[-1] = (prev_start, end)  # keep current end
            else:
                merged.append((start, end))

        return merged