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

import quokka
from quokka import Block, FunctionMissingError
from quokka.types import (
    AddressT,
    EdgeType,
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

    reference = function.calls if caller is False else function.callers

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

    def __init__(self, proto_index: Index, func: "quokka.pb.Quokka.Function", program: quokka.Program):
        """Constructor"""
        super(dict, self).__init__()
        self.start: int = program.addresser.absolute(func.offset)  # TODO(Robin): Use segment_index+offset
        self.name: str = func.name
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
        for block_index, block in enumerate(func.blocks):
            block_address: int = self.start + block.offset_start  # TODO: Check with Riccardo
            self[block_address] = block_index
        self._index_to_address = {v: k for k, v in self.items()}
 
        self._data_references: list[quokka.Data] = []

    def __getitem__(self, address: AddressT) -> Block:
        """Lazy loader for blocks within the function"""
        block_index: Index = dict.__getitem__(self, address)
        return Block(block_index, address, self)

    @cached_property
    def strings(self) -> list[str]:
        """Return the strings used in the Function"""

        strings = set()
        for block in self.values():
            strings.update(block.strings)

        return list(strings)


    @cached_property
    def size(self) -> int:
        """Return the function size"""
        return self.end - self.start

    @property
    def data_references(self):
        """Lists data references used in the function"""
        data_references: list[quokka.Data] = []
        for block in self.values():
            data_references.extend(block.data_references)

        return data_references

    @cached_property
    def constants(self) -> list[int]:
        """Lists constants used in the function"""
        constants: list[int] = []
        for block in self.values():
            constants.extend(block.constants)

        return constants

    @property
    def block_ranges(self) -> list[Tuple[AddressT, AddressT]]:
        """Returns the sorted list of block ranges.

        A block range is a tuple (block.start, block.end).
        """
        block_ranges = []
        for block in self.values():
            block_ranges.append((block.start, block.end))

        block_ranges = sorted(block_ranges)
        return block_ranges

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
                condition=EdgeType.from_proto(edge.edge_type),
            )

        return graph

    def in_function(self, address: AddressT) -> bool:
        """Check if an address belongs to the function."""
        if len(self.block_ranges) == 0:
            return False

        if address < min(self.block_ranges)[0] or address > max(self.block_ranges)[1]:
            return False

        for start, end in self.block_ranges:
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

    @property
    def calls(self) -> list['Function']:
        """Return the list of calls made by this function.
        The semantic of a "call" is to jump or call to the **starting** of a function.
        Beware that this might lead to different results than the program call graph.

        Note: The list is not deduplicated so a target may occur multiple time.
        """

        calls = []
        for inst_instance in self.program.references.resolve_calls(self, towards=False):
            fun = (
                inst_instance[0] if isinstance(inst_instance, tuple) else inst_instance
            )
            # Check that the address is the **starting** of a function
            if fun.start in self.program:
                calls.append(fun)

        return calls

    @property
    def callers(self) -> list['Function']:
        """Retrieve the function callers (the ones calling this function)"""
        callers = []
        for inst_instance in self.program.references.resolve_calls(self, towards=True):
            if isinstance(inst_instance, tuple):
                callers.append(inst_instance[0])
            else:
                callers.append(inst_instance)

        return callers

    @property
    def instructions(self):
        """Yields the function instruction"""
        return (inst for block in self.values() for inst in block.instructions)

    @cached_property
    def out_degree(self) -> int:
        """Function out degree"""
        return len(set(self.calls))

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
