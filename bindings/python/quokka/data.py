"""Data management.

A data is a piece of information that isn't code.
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
import logging
from typing import Mapping, TYPE_CHECKING

import quokka
from quokka.quokka_pb2 import Quokka as Pb # pyright: ignore[reportMissingImports]

from quokka.types import AddressT, Index, RefType
from quokka.data_type import EnumType, TypeReference, TypeT, TypeValue

if TYPE_CHECKING:
    from quokka import Program, Function



logger = logging.getLogger(__name__)


def _get_item(program: 'Program', addr: AddressT) -> 'Data | Function | AddressT':
    """Get the data at the given address

    Arguments:
        addr: Address to get the data from
    Returns:
        The data at the given address
    """
    try:
        return program.data_holder[addr]  # try getting data
    except ValueError:
        try:
            return program[addr]  # try getting function
        except KeyError:
            return addr  # Otherwise returns plain address


class Data:
    """Base class for data.

    All data have at least a type and a value.
    They are referenced inside the program by and to other data and code.

    Parameters:
        proto_index: Index in the protobuf
        data: Protobuf value of the data.
        program: Program backref

    Attributes:
        proto_index: Index in the protobuf
        address: Data address
        type: Data type
        program: Reference to the Program
        is_initialized: Is the data initialized?
        size: Data size (depends on the type usually)
        name: Data name (if any)
    """

    def __init__(
        self, proto_index: Index, data: "Pb.Data", program: quokka.Program
    ):
        """Constructor"""
        self.proto: "Pb.Data" = program.proto.data[proto_index]
        self.address: AddressT = program.virtual_address(data.segment_index, data.segment_offset)
        self.program: quokka.Program = program
        self.file_offset: int = data.file_offset
        self.is_initialized: bool = not data.not_initialized
        self.size: int = self.proto.size

        # Retrieve xrefs (for the data)
        self._xrefs_from = [self.program.proto.references[x] for x in self.proto.xref_from]
        self._xrefs_from = [(RefType(ref.reference_type), ref) for ref in self._xrefs_from]
        
        self._xrefs_to = [self.program.proto.references[x] for x in self.proto.xref_to]
        self._xrefs_to = [(RefType(ref.reference_type), ref) for ref in self._xrefs_to]

    def __str__(self) -> str:
        """Data representation"""
        return f"<Data {self.name} at {self.address:#x}>"

    def __eq__(self, other: "Pb.Data") -> bool:
        """Check equality between two Data instances"""
        return id(self.proto) == id(other.proto)

    @property
    def name(self) -> str:
        """Data name"""
        return self.proto.name
    
    @name.setter
    def name(self, value: str) -> None:
        """Set the data name and mark it as edited in the protobuf"""
        self.proto.edits.name_set = True
        self.proto.name = value

    @property
    def comments(self) -> list[str]:
        """Return the data comments"""
        return self.proto.comments

    @property
    def value(self) -> TypeValue | None:
        """Data value.

        The value is read in the program binary file.
        """

        if not self.is_initialized:
            return None  # Uninitialized memory has no value
        if self.proto.file_offset <= 0:
            return None  # Not mapped in the file
        
        if self.type.size <= 0 and self.size:  # Variable size data with a known size (e.g., string)
            return self.program.read_bytes(self.file_offset, self.size)
        else:  # Try reading the value as a type
            return self.program.executable.read_type_value(self.file_offset, self.type)

    def is_variable_size(self) -> bool:
        """Is the data of variable size?"""
        return self.size == -1
    
    @property
    def type(self) -> TypeT:
        """Data type. Assume one exists for each data"""
        return self.program.get_type(self.proto.type_index)

    @type.setter
    def type(self, typ: TypeT|str) -> None:
        """Set the data type and mark it as edited in the protobuf.
        
        The final type will only be applied when quokka file regenerated.
        """
        if isinstance(typ, str):
            self.proto.edits.type_str = typ
        elif isinstance(typ, TypeT):
            self.proto.edits.type_str = typ.c_str
        else:
            assert False, "Invalid type"

    @property
    def data_refs_to(self) -> list['Data | Function | AddressT']:
        """Returns all data reference to this data"""
        # If querying refs_to get the source address
        return [_get_item(self.program, xref.source.address) for t, xref in self._xrefs_to if t.is_data]

    @property
    def data_read_refs_to(self) -> list['Data | Function | AddressT']:
        """Returns all data read reference to this data"""
        return [_get_item(self.program, xref.source.address) for t, xref in self._xrefs_to if t in [RefType.DATA_READ, RefType.DATA_INDIR]]

    @property
    def data_write_refs_to(self) -> list['Data | Function | AddressT']:
        """Returns all data write reference to this data"""
        return [_get_item(self.program, xref.source.address) for t, xref in self._xrefs_to if t == RefType.DATA_WRITE]

    @property
    def data_refs_from(self) -> list['Data | Function | AddressT']:
        """Returns all data reference from this data"""
        # If querying refs_from get the destination address
        return [_get_item(self.program, xref.destination.address) for t, xref in self._xrefs_from if t.is_data]

    @property
    def data_read_refs_from(self) -> list['Data | Function | AddressT']:
        """Returns all data read reference from this data"""
        # FIXME: Right now consider DATA_INDIR reference as read references (do we want to distinguish R/W ?)
        return [_get_item(self.program, xref.destination.address) for t, xref in self._xrefs_from if t in [RefType.DATA_READ, RefType.DATA_INDIR]]

    @property
    def data_write_refs_from(self) -> list['Data | Function | AddressT']:
        """Returns all data write reference from this data"""
        return [_get_item(self.program, xref.destination.address) for t, xref in self._xrefs_from if t == RefType.DATA_WRITE]


    @property
    def code_refs_to(self) -> list[AddressT]:
        """Returns all code reference to this data"""
        # If querying refs_to get the source address
        return [xref.source.address for t, xref in self._xrefs_to if t.is_code]

    @property
    def type_refs_from(self) -> list[TypeReference]:
        """Returns all type reference from this data"""
        # Get protobuf type ids
        type_ids = [xref.destination.data_type_identifier for t, xref in self._xrefs_from
                    if t.is_data and xref.destination.HasField("data_type_identifier")]  # Note: do not use SYMBOL enum
        # Resolve type ids to actual types
        return [self.program.get_type_reference(t.type_index, t.member_index) for t in type_ids]
    

class DataHolder(Mapping):
    """Data bucket

    All the data of the program are referenced in this bucket and allow to store them
    only once.

    Attributes:
        proto: The protobuf data themselves
        program: A reference to the Program

    Arguments:
        proto: The protobuf data
        program: The program
    """

    def __init__(self, proto, program: quokka.Program):
        """Init method

        Arguments:
            proto: List of data in the protobuf
            program: Backref to the program
        """
        self.proto = proto.data
        self.program: quokka.Program = program
        self._addr_to_idx: dict[AddressT, Index] = {
            program.virtual_address(data.segment_index, data.segment_offset): index 
            for index, data in enumerate(proto.data)
        }

    def __setitem__(self, key: Index, value: Data) -> None:
        """Set a data"""
        raise ValueError("Should not be accessed")

    def __delitem__(self, value: Index) -> None:
        """Remove a data from the bucket"""
        raise ValueError("Should not be accessed")

    def __getitem__(self, address: AddressT) -> Data:
        """Get a data from the bucket.

        Arguments:
            address: Data address
        Returns:
            A Data
        """
        key = self._addr_to_idx.get(address)
        if key is None:
            raise ValueError(f"No data at address 0x{address:x}")
        # Right now we create a new Data object each time, but we could cache them if needed
        return Data(key, self.proto[key], self.program)

    def __len__(self) -> int:
        """Number of data in the program"""
        return len(self._addr_to_idx)

    def __iter__(self):
        """Do not allow the iteration over the data"""
        for addr, idx in self._addr_to_idx.items():
            yield self[addr]
