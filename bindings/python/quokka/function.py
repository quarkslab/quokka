"""Functions and chunk management"""

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

from __future__ import annotations
import logging
import itertools
import networkx
from functools import cached_property

import quokka
from quokka.types import (
    AddressT,
    Dict,
    EdgeType,
    FunctionType,
    Generator,
    Iterable,
    Iterator,
    Index,
    List,
    MutableMapping,
    Optional,
    SegmentType,
    Tuple,
    Union,
)

logger = logging.getLogger(__name__)


def dereference_thunk(item: Union[Function, Chunk], caller: bool = False) -> Function:
    """Dereference a thunk

    This method is used to resolve a thunk calls / callers. As thunk function only have
    1 relation : FUNC (call x) -> THUNK X -> X , it disrupts the call graph and
    heuristics based on graph degrees.

    Arguments:
        item: Either a function or a chunk
        caller: True if we want to find the callers (e.g. the functions that call item)
                False if we want to find the callee (e.g. function that are called by
                item)

    Raises:
        ThunkMissingError: When no thunk has been found
        FunctionMissingError: When no function has been found
    """
    if isinstance(item, quokka.function.Chunk):
        function = item.program.get_first_function_by_chunk(item)
    else:
        function = item

    # Do not try to (de)reference if we do not meet the prerequistes
    if caller is False and function.type != FunctionType.THUNK:
        # Only dereference THUNK function
        return function
    elif caller is True and function.in_degree != 1:
        # Only try to reference function with in_degree == 1
        return function

    target = "calls" if caller is False else "callers"
    reference = getattr(function, target)

    try:
        candidate = function.program.get_first_function_by_chunk(reference[0])
    except (IndexError, quokka.exc.FunctionMissingError):
        if caller is True and reference[0].in_degree == 0:
            raise quokka.exc.ThunkMissingError("Error while finding thunk")

        # This will appears when the referenced target is a chunk coming from a
        # fake chunk for instance
        # logger.debug("Unable to find the (de)reference of the thunk function")
        raise quokka.exc.FunctionMissingError("Missing func referenced by thunk")

    if candidate.type == FunctionType.THUNK and caller is not True:
        # Recursive call for multi layered THUNK
        return dereference_thunk(candidate, caller)
    elif caller and candidate.type != FunctionType.THUNK:
        return function

    return candidate


def get_degrees(item: Union[Chunk, Function]) -> Tuple[int, int]:
    """Compute the {in, out} degrees of an item (Function/Chunk)"""
    in_degree = item.in_degree
    try:
        in_func = quokka.function.dereference_thunk(item, True)
        in_degree = in_func.in_degree
    except quokka.exc.ThunkMissingError:
        in_degree = 0
    except quokka.exc.FunctionMissingError:
        pass

    try:
        out_func: Union[Function, Chunk] = quokka.function.dereference_thunk(
            item, False
        )
    except quokka.exc.FunctionMissingError:
        out_func = item

    return in_degree, out_func.out_degree


class Chunk(MutableMapping, Iterable):
    """Chunk object

    A chunk is an IDA specific item that is used for code reuse across functions.

    Arguments:
        chunk_idx: Index of the chunk in the protobuf
        program: Backref to the program
        accepted_addresses: A list of address for blocks heads. Used only
            for fake chunks.

    Attributes:
        program: Program reference
        proto_index: Index inside the protobuf
        start: Start address
        fake: Is the chunk fake?
        index_to_address: Mapping from index to block starting address
        chunk_type: Chunk type
        chunk: Proto information
    """

    def __init__(
        self,
        chunk_idx: Index,
        program: quokka.Program,
        accepted_addresses: List[AddressT] = None,
    ):
        """Constructor"""
        self.program: quokka.Program = program

        self.proto_index: Index = chunk_idx
        chunk = self.program.proto.function_chunks[chunk_idx]

        self.start: AddressT = self.program.addresser.absolute(chunk.offset_start)

        self.fake: bool = chunk.is_fake
        self._raw_dict: Dict[AddressT, Index] = {}

        self._graph: Optional["networkx.DiGraph"] = None

        self.index_to_address: Dict[int, int] = {}
        self.chunk = chunk

        self.chunk_type: FunctionType = FunctionType.NORMAL

        for block_index, block in enumerate(self.chunk.blocks):
            block_address: int = self.start + block.offset_start

            if (
                accepted_addresses is not None
                and block_address not in accepted_addresses
            ):
                continue

            self.index_to_address[block_index] = block_address
            self._raw_dict[block_address] = block_index

        if self.index_to_address:
            # We only update the start when we have a fake chunk (because it may have
            # been split out)
            if chunk.is_fake:
                self.start = min(self.index_to_address.values())

            assert self.start == min(
                self.index_to_address.values()
            ), "Wrong start of Chunk"

    def __len__(self) -> int:
        """Number of blocks in the chunk"""
        return len(self._raw_dict)

    def __iter__(self) -> Iterator:
        """Iterator over the blocks"""
        return self._raw_dict.__iter__()

    def __setitem__(self, k: AddressT, v: Index) -> None:
        """Set block"""
        self._raw_dict.__setitem__(k, v)

    def __delitem__(self, k: int) -> None:
        """Remove a block"""
        self._raw_dict.__delitem__(k)

    def __getitem__(self, address: AddressT) -> quokka.Block:
        """Lazy loader for blocks"""
        index: Index = self._raw_dict.__getitem__(address)
        return quokka.block.Block(index, address, self)

    def __str__(self) -> str:
        """Chunk representation"""
        return f"<Chunk at 0x{self.start:x} with {len(self)} block(s)>"

    @property
    def block_ranges(self) -> List[Tuple[AddressT, AddressT]]:
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
        """Return the CFG of the chunk as DiGraph object"""
        graph = networkx.DiGraph()
        graph.add_nodes_from(n for n in self._raw_dict.keys())

        for edge in self.program.proto.function_chunks[self.proto_index].edges:
            if (
                edge.source.block_id not in self.index_to_address
                or edge.destination.block_id not in self.index_to_address
            ):
                continue
            graph.add_edge(
                self.index_to_address[edge.source.block_id],
                self.index_to_address[edge.destination.block_id],
                condition=EdgeType.from_proto(edge.edge_type),
            )

        return graph

    @cached_property
    def strings(self) -> List[str]:
        """Return the strings used in the chunk"""

        strings = set()
        for block in self.values():
            strings.update(block.strings)

        return list(strings)

    @cached_property
    def constants(self) -> List[int]:
        """Return the constants used in the chunk"""
        constants = []
        for block in self.values():
            constants.extend(block.constants)

        return constants

    @property
    def data_references(self) -> List[quokka.Data]:
        """Returns the data reference in the chunk"""
        data_references: List[quokka.Data] = []
        for instruction in self.values():
            data_references.extend(instruction.data_references)

        return data_references

    @cached_property
    def end(self) -> AddressT:
        """Compute the end address of a chunk"""
        try:
            max_block = max(self.keys())
            return self[max_block].end
        except ValueError:
            return self.start + 1

    @cached_property
    def size(self) -> int:
        """Return the size of a chunk"""
        return self.end - self.start

    @property
    def calls(self) -> List[quokka.Chunk]:
        """Return the list of calls made by this chunk.

        Note: The list is not deduplicated so a target may occur multiple time.
        """

        calls = []
        for inst_instance in self.program.references.resolve_calls(self, towards=False):
            if isinstance(inst_instance, tuple):
                calls.append(inst_instance[0])
            else:
                calls.append(inst_instance)

        return calls

    @property
    def callers(self) -> List[Chunk]:
        """Return the list of callers of this chunk."""

        callers = []
        for inst_instance in self.program.references.resolve_calls(self, towards=True):
            if isinstance(inst_instance, tuple):
                callers.append(inst_instance[0])
            else:
                callers.append(inst_instance)

        return callers

    @cached_property
    def out_degree(self) -> int:
        """Compute the chunk out degree

        Get the out degree of a chunk (e.g. the number of distinct chunks called by
        this one).

        Returns:
            Number of distinct out edges
        """
        return len(set(self.calls))

    @cached_property
    def in_degree(self) -> int:
        """Compute the chunk in degree

        Get the in-degree of a chunk. This is the number of distinct incoming edges.

        returns:
            Chunk in-degree
        """
        return len(set(self.callers))

    @property
    def instructions(self) -> Generator:
        """Iterator over instructions in the chunk"""
        return (inst for block in self.values() for inst in block.instructions)

    def in_chunk(self, address: AddressT) -> bool:
        """Check if an address belongs to the chunk."""
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
        if not self.in_chunk(address):
            raise IndexError(f"Unable to find the instruction at 0x{address:x}")

        for block_addr, block in self.items():
            if block.start <= address < block.end:
                return block[address]

        raise IndexError(f"Unable to find the instruction at 0x{address:x}")

    def get_block(self, address: AddressT) -> quokka.Block:
        """Get the block at `address`"""
        return self.__getitem__(address)

    def __hash__(self) -> int:
        """Override hash method to return an unique index"""
        return self.start

    @cached_property
    def name(self) -> str:
        """Chunk name.

        The chunk name is the one of its parent if it exists or is empty otherwise.

        Returns:
            Chunk name
        """
        try:
            return self.program.get_first_function_by_chunk(self).name
        except quokka.exc.FunctionMissingError:
            return ""


class SuperChunk(MutableMapping):
    """SuperChunk: fake functions

    A SuperChunk is an abstract construction that has no other meaning that serve as
    a candidate (or fake) function.

    Indeed, super chunks are created when a chunk (or a fake chunk) have multiple
    non-connected components.

    A superchunk keeps a mapping of chunk index to chunk instance and implements most
    of a function interface.

    Arguments:
        initial_chunk: The chunk to split
        components: The various non-connected components

    Attributes:
        proto_idx: Initial chunk proto index
        addresses: All addresses belonging to the chunk with the instruction index
        chunks: Mapping of chunks within the SuperChunk
        starts: Mapping of chunk starts to chunks
    """

    def __init__(self, initial_chunk: Chunk, components: Generator):
        """Init method

        Arguments:
            initial_chunk: Original chunk to split
            components: A generator of sets for each component of the graph
        """
        self.proto_idx: Index = initial_chunk.proto_index
        self.addresses: Dict[AddressT, int] = {}

        self.chunks: Dict[Index, Chunk] = {}
        self.starts: Dict[AddressT, Chunk] = {}

        for index, component in enumerate(components):
            self.addresses.update({block_addr: index for block_addr in component})
            chunk = Chunk(initial_chunk.proto_index, initial_chunk.program, component)
            self.chunks[index] = chunk
            self.starts[min(component)] = chunk

        # We need to keep this mapping sorted to improve efficiency
        self.addresses = {k: self.addresses[k] for k in sorted(self.addresses)}

    def __setitem__(self, k: Index, v: Chunk) -> None:
        """Set a chunk"""
        self.chunks.__setitem__(k, v)

    def __delitem__(self, v: Index) -> None:
        """Delete a chunk"""
        self.chunks.__delitem__(v)

    def __getitem__(self, k: Index) -> Chunk:
        """Get a chunk"""
        return self.chunks.__getitem__(k)

    def __len__(self) -> int:
        """Number of chunk"""
        return self.chunks.__len__()

    def __iter__(self) -> Iterator[Index]:
        """Iterator over chunk"""
        return self.chunks.__iter__()

    def __str__(self) -> str:
        """SuperChunk representation"""
        return f"<SuperChunk with {len(self.starts)} chunks(s)>"

    def get_chunk(self, address: AddressT) -> Chunk:
        """Return a chunk by an address.

        To resolve an address and retrieve the appropriate chunk, we enumerate the
        chunks and look within the blocks.

        Arguments:
            address: Address to query

        Raises:
            IndexError: When no chunk is found

        """
        if address in self.addresses:
            return self.chunks[self.addresses[address]]

        if address < min(self.addresses):
            raise IndexError("Address is before the chunk")

        # TODO(dm) CHECK OR FIXME
        chunk_index = self.addresses[min(self.addresses)]
        for blocks_head, chunk_index in self.addresses.items():
            if blocks_head > address:
                break

        candidate_chunk = self.chunks[chunk_index]
        if candidate_chunk.in_chunk(address):
            return candidate_chunk

        raise IndexError("Address does not belong in this SuperChunk")

    def get_chunk_by_index(self, chunk_index: Index, block_index: Index) -> Chunk:
        """Return a chunk by its index

        This must be reimplemented because the chunk_index is unique for the proto but
        there are multiple chunks existing with the same index because of a SuperChunk.

        Arguments:
            chunk_index: Chunk index
            block_index: Block index

        Raises:
            ChunkMissingError: if the chunk is not found

        """
        if chunk_index != self.proto_idx:
            raise quokka.exc.ChunkMissingError("Wrong chunk index")

        for chunk in self.chunks.values():
            if chunk.index_to_address.get(block_index, None) is not None:
                return chunk

        raise quokka.exc.ChunkMissingError(
            "Unable to find the correct chunk for this block"
        )

    def in_chunk(self, address: AddressT) -> bool:
        """Check if address belongs to this SuperChunk"""
        if address < min(self.starts):
            return False

        for chunk in self.chunks.values():
            if chunk.in_chunk(address):
                return True

        return False

    def get_instruction(self, address: AddressT) -> quokka.Instruction:
        """Get the instruction at `address`"""
        for chunk in self.chunks.values():
            if chunk.in_chunk(address):
                return chunk.get_instruction(address)

        raise IndexError(f"Unable to find the instruction at 0x{address:x}")


class Function(dict):
    """Function object

    This class represents a binary function within the Program.

    Arguments:
        func: Protobuf data
        program: Program reference

    Attributes:
        start: Start address
        name: Function name
        program: Program reference
        type: Function type
        index_to_address: Mapping of Chunks to Protobuf indexes
        func: Protobuf data
    """

    def __init__(self, func: "quokka.pb.Quokka.Function", program: quokka.Program):
        """Constructor"""
        super(dict, self).__init__()
        self.start: int = program.addresser.absolute(func.offset)
        self.name: str = func.name

        self.program: quokka.Program = program

        self.type: "FunctionType" = FunctionType.from_proto(func.function_type)
        if self.type == FunctionType.NORMAL:
            segment = self.program.get_segment(self.start)
            if segment and segment.type == SegmentType.EXTERN:
                self.type = FunctionType.EXTERN

        self.index_to_address: Dict[int, int] = dict()
        for chunk_index in func.function_chunks_index:
            chunk = self.program.get_chunk(chunk_index)

            if not isinstance(chunk, quokka.function.Chunk):
                logger.error("Found a super chunk in a function which is not possible")
                continue

            if (
                chunk.chunk_type != FunctionType.NORMAL
                and chunk.chunk_type != self.type
            ):
                logger.error(
                    "All the chunks of the function are supposed to have the same "
                    "type. It is not the case here."
                )

            chunk.chunk_type = self.type
            self[chunk.start] = chunk

            self.index_to_address[chunk_index] = chunk.start

        self.func = func

        self._data_references: List[quokka.Data] = None

    def get_block(self, address: AddressT) -> quokka.Block:
        """Get the block at `address`"""
        for chunk in self.values():
            try:
                return chunk[address]
            except KeyError:
                pass

        raise KeyError(f"Unable to find the block at address 0x{address:x}")

    def get_instruction(self, address: AddressT) -> quokka.Instruction:
        """Get the instruction at `address`"""
        for chunk in self.values():
            if chunk.in_chunk(address):
                return chunk.get_instruction(address)

        raise IndexError(f"Unable to find the instruction at 0x{address:x}")

    @cached_property
    def strings(self) -> List[str]:
        strings = set()
        for chunk in self.values():
            strings.update(chunk.strings)

        return list(strings)

    @property
    def data_references(self):
        """Lists data references used in the function"""
        data_references: List[quokka.Data] = []
        for instruction in self.values():
            data_references.extend(instruction.data_references)

        return data_references

    @cached_property
    def constants(self) -> List[int]:
        """Lists constants used in the function"""
        constants: List[int] = []
        for chunk in self.values():
            constants.extend(chunk.constants)

        return constants

    @cached_property
    def graph(self) -> "networkx.DiGraph":

        graph = networkx.DiGraph()
        for chunk in self.values():
            graph = networkx.algorithms.operators.compose(graph, chunk.graph)

        for edge in self.func.chunk_edges:
            source_chunk = self.program.get_chunk(
                edge.source.chunk_id, edge.source.block_id
            )
            dest_chunk = self.program.get_chunk(
                edge.destination.chunk_id, edge.destination.block_id
            )

            graph.add_edge(
                source_chunk.index_to_address[edge.source.block_id],
                dest_chunk.index_to_address[edge.destination.block_id],
                condition=EdgeType.from_proto(edge.edge_type),
            )

        return graph

    @cached_property
    def end(self) -> int:
        max_chunk = max(self.keys())
        return self[max_chunk].end

    @property
    def calls(self) -> List[Chunk]:
        """Retrieve the function calls (the ones called by the function)"""
        targets = []
        for chunk in self.values():
            targets.extend(chunk.calls)

        return targets

    @property
    def callers(self) -> List[Chunk]:
        """Retrieve the function callers (the ones calling this function)"""
        sources = []
        for chunk in self.values():
            sources.extend(chunk.callers)

        return sources

    @property
    def instructions(self):
        """Yields the function instruction"""
        return itertools.chain.from_iterable(
            chunk.instructions for chunk in self.values()
        )

    def in_func(self, address: AddressT) -> bool:
        """Check if the `address` belongs to this function."""
        for chunk in self.values():
            if chunk.in_chunk(address):
                return True

        return False

    @cached_property
    def out_degree(self) -> int:
        """Function out degree"""
        return len(set(self.calls))

    @cached_property
    def in_degree(self) -> int:
        """Function in degree"""
        return self[self.start].in_degree

    def __hash__(self) -> int:  # type: ignore
        """Hash value"""
        return self.start

    def __str__(self) -> str:
        """Function representation"""
        return f"<Function {self.name} at 0x{self.start:x}>"

    def __repr__(self) -> str:
        """Function representation"""
        return self.__str__()
