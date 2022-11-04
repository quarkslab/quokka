"""Structure management"""
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
import weakref
import quokka

from quokka.types import (
    DataType,
    Dict,
    List,
    Optional,
    StructureType,
)


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
        member: "quokka.pb.Quokka.Structure.Member",
        structure: Structure,
    ) -> None:
        """Constructor"""
        self.name: str = member.name
        self.type: DataType = DataType.from_proto(member.type)
        self.size: int = member.size
        self.value: Optional[int] = member.value if member.value != 0 else None
        self._structure: weakref.ref[Structure] = weakref.ref(structure)

        self.comments: List[str] = []

    @property
    def structure(self) -> Structure:
        """Back reference to the parent structure"""
        return self._structure()


class Structure(dict):
    """Structure

    All IDA structure are merged inside this class (Enum, Structure, Union).

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

    def __init__(
        self,
        structure: "quokka.pb.Quokka.Structure",
        program: quokka.Program,
    ) -> None:
        """Constructor"""
        super(dict, self).__init__()
        self.program: quokka.Program = program
        self.name: str = structure.name
        self.size: Optional[int] = (
            structure.size if structure.variable_size is False else 0
        )
        self.type = StructureType.from_proto(structure.type)

        self.index_to_offset: Dict[int, int] = {}
        for index, member in enumerate(structure.members):
            self[member.offset] = StructureMember(member, self)
            self.index_to_offset[index] = member.offset

        self.comments: List[str] = []
