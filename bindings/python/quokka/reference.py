"""References Management

This module deals with all references between different objects in the code.

A reference is an object with the following attributes:
    - A Source
    - A Destination
    - A Type

As they are stored in a complex manner, this module deals with their resolution,
i.e. how to resolve the pointed object.

There is room for improvement here. ;)
"""
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
import collections
import enum

import quokka
from quokka.types import (
    AddressT,
    DefaultDict,
    Dict,
    Index,
    Iterator,
    List,
    LocationValueType,
    Mapping,
    MutableMapping,
    Optional,
    ReferenceTarget,
    ReferenceType,
    Tuple,
    Union,
)


class Reference:
    """Reference: a link between a source and a destination

    Arguments:
        source: Source of the reference
        destination: Destination (target) of the reference
        type_: Type of the reference

    Attributes:
        source: Source of the reference
        destination: Destination (target) of the reference
        type: Type of the reference
    """

    def __init__(
        self,
        source: ReferenceTarget,
        destination: ReferenceTarget,
        type_: ReferenceType,
    ) -> None:
        """Constructor"""
        self.source: ReferenceTarget = source
        self.destination: ReferenceTarget = destination
        self.type: ReferenceType = type_


class ReferencesLocation(enum.Enum):
    """Reference location

    A reference may be attached to one of the following :
        * an instruction index (that means every instance of the instruction)
        * a data index
        * a structure position (e.g. a structure or a member inside a structure)
        * an instruction : a tuple with (chunk, block, inst_index) identifying precisely
            one instruction
        * a function
        * a chunk
    """

    INSTRUCTION = "inst_idx"
    DATA = "data_idx"
    STRUCTURE = "struct_position"
    INST_INSTANCE = "instruction_position"
    FUNCTION = "function_idx"
    CHUNK = "chunk_idx"

    @staticmethod
    def from_proto(location_type: str) -> ReferencesLocation:
        """Convert reference location from proto"""
        # These are the name of the fields in the protobuf
        mapping = {
            "inst_idx": ReferencesLocation.INSTRUCTION,
            "data_idx": ReferencesLocation.DATA,
            "struct_position": ReferencesLocation.STRUCTURE,
            "instruction_position": ReferencesLocation.INST_INSTANCE,
            "function_idx": ReferencesLocation.FUNCTION,
            "chunk_idx": ReferencesLocation.CHUNK,
        }

        try:
            return mapping[location_type]
        except IndexError as exc:
            raise ValueError("Unknown location type") from exc


class References(Mapping):
    """References bucket : maintain the list of all references inside the program

    The instantiation of the class will create a mapping for every reference but not
    resolve them yet.

    This class is probably the most messy one in Quokka and needs a global refactoring.
    However, since it's somehow working, let's try to not break it yet.

    Arguments:
        program: Reference to the program

    Attributes:
        program: Reference to the program
        proto_ref: Protobuf data
        references_category: A mapping that contains every reference for each direction.
            For instance, a ref X from inst a to struct b will be stored in both the
            structure key and the instruction key

    """

    SOURCE = "source"
    DESTINATION = "destination"

    def __init__(self, program: quokka.Program) -> None:
        """Init method

        Arguments:
            program: A backref to program
        """

        # Define the update method
        def update(
            mapping: Mapping,  # type: ignore
            key: Union[Tuple[int], LocationValueType],
            value: Index,
        ) -> None:
            """Recursive method to update the `self.references_category` mapping"""
            if isinstance(key, int):
                mapping[key].append(value)
                return

            current_key: int = key[0]
            sub_key: Union[Tuple[()], Tuple[int], Tuple[int, int]] = key[1:]
            if sub_key:
                update(mapping[current_key], sub_key, value)
            elif not isinstance(mapping.get(current_key), MutableMapping):
                mapping[current_key].append(value)

        self.program: quokka.Program = program
        self.proto_ref = program.proto.references

        # Init the references mapping
        self.references_category: Dict[ReferencesLocation, DefaultDict] = {  # type: ignore
            ReferencesLocation.INSTRUCTION: collections.defaultdict(list),
            ReferencesLocation.DATA: collections.defaultdict(list),
            ReferencesLocation.STRUCTURE: collections.defaultdict(
                lambda: collections.defaultdict(list)
            ),
            ReferencesLocation.INST_INSTANCE: collections.defaultdict(
                lambda: collections.defaultdict(lambda: collections.defaultdict(list))
            ),
            ReferencesLocation.FUNCTION: collections.defaultdict(list),
            ReferencesLocation.CHUNK: collections.defaultdict(list),
        }

        reference: quokka.pb.Quokka.Reference
        for index, reference in enumerate(self.proto_ref):
            source_ref = self.references_category[self.location_type(reference.source)]
            update(source_ref, self.get_location_value(reference.source), index)

            destination_ref = self.references_category[
                self.location_type(reference.destination)
            ]
            update(
                destination_ref, self.get_location_value(reference.destination), index
            )

    @staticmethod
    def location_type(
        location: quokka.pb.Quokka.Location,
    ) -> ReferencesLocation:
        """Convert the proto location type"""
        return ReferencesLocation.from_proto(location.WhichOneof("LocationType"))

    def get_location_value(
        self, location: quokka.pb.Quokka.Location
    ) -> LocationValueType:
        """Resolve a location

        This method resolves a location for quokka.

        Arguments:
            location: Reference location

        Returns:
            A LocationTypeValue
        """
        location_type: ReferencesLocation = self.location_type(location)
        location_value: LocationValueType = getattr(location, location_type.value)

        if location_type in (
            ReferencesLocation.INSTRUCTION,
            ReferencesLocation.DATA,
            ReferencesLocation.FUNCTION,
            ReferencesLocation.CHUNK,
        ):
            return location_value

        elif location_type == ReferencesLocation.STRUCTURE:
            structure_idx: int = getattr(location_value, "structure_idx")

            if getattr(location_value, "no_member") is False:
                return structure_idx, getattr(location_value, "member_idx")

            return structure_idx, -1

        elif location_type == ReferencesLocation.INST_INSTANCE:
            return (
                getattr(location_value, "func_chunk_idx"),
                getattr(location_value, "block_idx"),
                getattr(location_value, "instruction_idx"),
            )

        raise ValueError

    def __getitem__(self, k: Index) -> Reference:
        """Lazy loading for references"""
        return self.create_reference(self.proto_ref[k])

    def __len__(self) -> int:
        """References count"""
        return len(self.proto_ref)

    def __iter__(self) -> Iterator[Dict[AddressT, Reference]]:
        """Iterator over references"""
        raise NotImplementedError

    @property
    def structures(self) -> List[quokka.Structure]:
        """Accessor to the program structures"""
        return self.program.structures

    @property
    def data(self):
        """Accessor to the program PROTO data"""
        return self.program.proto.data

    @property
    def instructions(self):
        """Accessor to the program proto instruction"""
        return self.program.proto.instructions

    def create_reference(self, reference: quokka.pb.Quokka.Reference) -> "Reference":
        """Create a reference

        Start with resolving both the source and the destination.

        Arguments:
            reference: A protobuf reference object

        Returns:
            A python reference with both source and destination resolved
        """
        source: ReferenceTarget = self.resolve_location(reference.source)
        destination: ReferenceTarget = self.resolve_location(reference.destination)

        return Reference(
            source, destination, ReferenceType.from_proto(reference.reference_type)
        )

    def find_instruction(
        self,
        instruction_identifier: "quokka.pb.Quokka.Location.InstructionIdentifier",
    ) -> Tuple[quokka.Chunk, quokka.Block, Index]:
        """Search an instruction from an instruction identifier.

        The parameters are a chunk index, a block index, and an inst index inside the
        block.

        Arguments:
            instruction_identifier: Protobuf instruction identifier

        Returns:
            A instruction tuple (Chunk, Block, Instruction Index)
        """
        chunk = self.program.get_chunk(
            instruction_identifier.func_chunk_idx, instruction_identifier.block_idx
        )
        block = chunk[chunk.index_to_address[instruction_identifier.block_idx]]
        return chunk, block, instruction_identifier.instruction_idx

    def resolve_location(self, location: quokka.pb.Quokka.Location) -> ReferenceTarget:
        """Resolve a location

        This convert a proto location to the actual instance of the object.

        Arguments:
            location: A protobuf Location (sigh) object

        Returns:
            A ReferenceTarget

        Raises:
            ValueError: When no appropriate location has been found.
        """
        location_type: ReferencesLocation = self.location_type(location)
        if location_type == ReferencesLocation.INSTRUCTION:
            raise DeprecationWarning("Not used anymore")

        elif location_type == ReferencesLocation.DATA:
            return self.program.data_holder[location.data_idx]

        elif location_type == ReferencesLocation.STRUCTURE:
            structure: quokka.Structure = self.structures[
                location.struct_position.structure_idx
            ]
            if location.struct_position.no_member is False:
                return structure[
                    structure.index_to_offset[location.struct_position.member_idx]
                ]
            return structure

        elif location_type == ReferencesLocation.INST_INSTANCE:
            return self.find_instruction(location.instruction_position)

        elif location_type == ReferencesLocation.CHUNK:
            return self.program.chunks[location.chunk_idx]

        raise ValueError("No location found")

    @staticmethod
    def get_direction(towards: bool = True) -> Tuple[str, str]:
        """Helper method to analyze if we take the reference or unwind it"""
        target = "destination" if towards else "source"
        wanted = "destination" if not towards else "source"

        return target, wanted

    def resolve_block_references(
        self,
        chunk_index: Index,
        block_index: Index,
        reference_type: ReferenceType,
        towards: bool = True,
    ) -> List[Reference]:
        """Return a list of references from/towards a block.

        Arguments:
            chunk_index: Index of the chunk
            block_index: Index of the block
            reference_type: TYpe of reference wanted (e.g. Data)
            towards: True if we want the reference *to* this block.
                False if we want the references *from* the block.

        Returns:
            A List of references matching the criteria
        """
        target, _ = self.get_direction(towards)

        return_list = []
        for reference_ids in self.references_category[ReferencesLocation.INST_INSTANCE][
            chunk_index
        ][block_index].values():
            for reference_id in reference_ids:
                reference: Reference = self[reference_id]
                if reference.type == reference_type and isinstance(
                    getattr(reference, target), tuple
                ):
                    target_loc = getattr(reference, target)
                    if (target_loc[0].proto_index, target_loc[1].proto_index) == (
                        chunk_index,
                        block_index,
                    ):
                        return_list.append(reference)

        return return_list

    def resolve_inst_instance(
        self,
        inst_tuple: Tuple[int, int, int],
        reference_type: Optional[ReferenceType] = None,
        towards: bool = True,
    ) -> List[Reference]:
        """Resolve instruction references

        Return a list of references from/towards an instruction.
        If a reference_type is specified the references will be filtered by their type

        Arguments:
            inst_tuple: A tuple (Chunk Index, Block Index, Instruction Index)
            reference_type: Reference type to consider (filter result)
            towards: In which sense to search the reference?

        Returns:
            A list of reference matching the criteria
        """
        return_list = []
        target, _ = self.get_direction(towards)

        for reference_idx in self.references_category[ReferencesLocation.INST_INSTANCE][
            inst_tuple[0]
        ][inst_tuple[1]][inst_tuple[2]]:
            reference: "Reference" = self[reference_idx]
            if (not reference_type or reference.type == reference_type) and isinstance(
                getattr(reference, target), tuple
            ):
                target_loc = getattr(reference, target)
                if (
                    target_loc[0].proto_index,
                    target_loc[1].proto_index,
                    target_loc[2],
                ) == inst_tuple:
                    return_list.append(reference)

        return return_list

    def resolve_calls(
        self, chunk: quokka.Chunk, towards: bool = True
    ) -> List[Union[Tuple[quokka.Chunk, quokka.Block, int], quokka.Chunk]]:
        """Resolve calls to a chunk

        This method resolves calls initiated or received from every instruction in a
        chunk. Of note, a call must be from an Instruction Tuple to another.

        Arguments:
            chunk: Target chunk
            towards: Do we look at calls towards this chunk {X,Y,Z} -> Chunk or at calls
                from this chunk Chunk -> {X,Y,Z} ?

        Returns:
            A list of objects that are either tuple (Chunk, Block, Instruction Index) or
            Chunk (only for fake chunks that are created from an imported function)
        """
        return_list = []
        target, wanted = self.get_direction(towards)

        for block_index in self.references_category[ReferencesLocation.INST_INSTANCE][
            chunk.proto_index
        ]:
            # For super-chunks, filter out block that do not belong to this chunk
            # anymore
            if block_index not in chunk.index_to_address:
                continue

            block_references = self.references_category[
                ReferencesLocation.INST_INSTANCE
            ][chunk.proto_index][block_index]
            for references in block_references.values():
                for reference_idx in references:
                    reference: "Reference" = self[reference_idx]
                    if reference.type == ReferenceType.CALL and isinstance(
                        getattr(reference, target), tuple
                    ):
                        target_loc = getattr(reference, target)
                        if target_loc[0].proto_index == chunk.proto_index:
                            location = getattr(reference, wanted)
                            # Fix: Only returns valid tuple
                            # TODO(dm): check why sometimes a Data might be returned
                            if isinstance(location, (tuple, quokka.Chunk)):
                                return_list.append(location)

        return return_list

    def resolve_data(
        self,
        data_index: Index,
        reference_type: Union[ReferenceType, None] = None,
    ) -> List[Reference]:
        """Resolve data references

        Returns a list of reference towards a data
        If a reference_type is specified the references will be filtered by their type

        Arguments:
            data_index: Index of the data in the protobuf
            reference_type: Type of reference

        Returns:
            A list of reference matching the criteria
        """

        references: List[Reference] = []
        for reference_idx in self.references_category[ReferencesLocation.DATA][
            data_index
        ]:
            reference = self[reference_idx]

            if reference_type is not None and reference_type != reference.type:
                continue

            references.append(reference)

        return references
