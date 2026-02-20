"""Structure management"""
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
import weakref
import quokka

import quokka.pb.Quokka as Pb # pyright: ignore[reportMissingImports]
from quokka.types import (
    BaseType,
    Dict,
    List,
    Optional,
    AddressT
)
from quokka.data_type import ComplexType


class StructureMember:
    """StructureMember

    This class represents structure members (fields).

    Arguments:
        member: Protobuf data
        structure: Reference to the parent structure

    Attributes:
        name: Member name
        size: Member size (if known)
        type: Member data type
        value: Member value
        comments: Member comments
    """

    def __init__(
        self,
        member: "Pb.CompositeType.Member",
        structure: Structure,
    ) -> None:
        """Constructor"""
        self.name: str = member.name
        self.type: BaseType = BaseType.from_proto(member.type)
        self.size: int = member.size
        self.value: Optional[int] = member.value if member.value != 0 else None
        self._structure: weakref.ref[Structure] = weakref.ref(structure)
        self._xrefs_to = [structure._program.proto.references[x] for x in member.xref_to]

        self.comments: List[str] = []

    @property
    def parent(self) -> Structure:
        """Back reference to the parent structure"""
        return self._structure()

    @property
    def data_refs_to(self) -> list[AddressT]:
        """Returns all data reference to this type"""
        # Get protobuf type ids
        return [xref.source.address for xref in self._xrefs_to if xref.reference_type == quokka.pb.Quokka.Reference.REF_DATA]

    @property
    def code_refs_to(self) -> list[AddressT]:
        """Returns all code reference to this type"""
        # Get protobuf type ids
        return [xref.source.address for xref in self._xrefs_to if xref.reference_type == quokka.pb.Quokka.Reference.REF_CODE]


class Structure(dict, ComplexType):
    """Structure

    Arguments:
        structure: Structure protobuf data
        program: Program back reference

    Attributes:
        program: Program backreference
        name: Structure name
        size: Structure size (if known)
        type: Structure type
        index_to_offset: Mapping from offsets to structure members
        comments: Structure comments
    """

    def __init__(self, proto: "Pb.CompositeType", program: quokka.Program) -> None:
        """Constructor"""
        dict.__init__(self)
        ComplexType.__init__(self, proto, program)

        self.index_to_offset: Dict[int, int] = {}
        for index, member in enumerate(proto.members):
            self[member.offset] = StructureMember(member, self)
            self.index_to_offset[index] = member.offset

        self.comments: List[str] = []

    def is_variable_size(self) -> bool:
        """Is the structure of variable size?"""
        return self.size <= 0


class Union(Structure):
    """Union

    This class represents a union. It is a special case of structure where all members are at the same offset.

     Arguments:
        structure: Structure protobuf data
        program: Program back reference
    """
    pass
