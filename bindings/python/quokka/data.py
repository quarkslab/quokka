"""Data management.

A data is a piece of information that isn't code.
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

from __future__ import annotations
import logging

import quokka

from quokka.types import (
    AddressT,
    Any,
    DataType,
    Index,
    List,
    Mapping,
    Optional,
)

logger = logging.getLogger(__name__)


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

    def __init__(self, proto_index: Index, data: "quokka.pb.Quokka.Data", program: quokka.Program):
        """Constructor"""
        self.proto_index: Index = proto_index
        self.address: AddressT = program.addresser.absolute(data.offset)
        self.type: "DataType" = DataType.from_proto(data.type)
        self.program: quokka.Program = program

        self.is_initialized: bool = not data.not_initialized

        self.size: Optional[int] = (
            data.size if data.WhichOneof("DataSize") != "no_size" else None
        )
        self._value: Optional[str] = (
            self.program.proto.string_table[data.value_index]
            if data.value_index > 0
            else None
        )
        self.name: Optional[str] = (
            self.program.proto.string_table[data.name_index]
            if data.name_index > 0
            else None
        )

    def __eq__(self, other: Any) -> bool:
        """Check equality between two Data instances"""
        return type(other) is type(self) and other.proto_index == self.proto_index

    @property
    def value(self) -> Any:
        """Data value.

        The value is read in the program binary file.
        """

        # Uninitialized memory
        if not self.is_initialized:
            return None

        address = self.program.addresser.file(self.address)

        if self.type in (
            DataType.ALIGN,
            DataType.POINTER,
            DataType.STRUCT,
            DataType.UNKNOWN,
        ):
            return self._value
        elif self.type == DataType.ASCII:
            try:
                return self.program.executable.read_data(
                    address, self.type, size=self.size
                )
            except quokka.exc.NotInFileError:
                logger.error("Try to read a string which is not in file")
                return ""
        else:
            return self.program.executable.read_data(address, self.type)

    @property
    def references(self) -> List[quokka.Reference]:
        """References to/from this data"""
        return self.program.references.resolve_data(self.proto_index)

    @property
    def code_references(self) -> List[quokka.Reference]:
        """Returns code referencing this Data"""
        return [ref for ref in self.references if isinstance(ref.destination, tuple)]
    
    @property
    def data_references(self) -> List[quokka.Reference]:
        """Returns data references to/from this Data"""
        return [ref for ref in self.references if isinstance(ref.destination, Data)]


class DataHolder(Mapping):
    """Data bucket

    All the data of the program are referenced in this bucket and allow to store them
    only once.

    Attributes:
        proto_data: The protobuf data themselves
        program: A reference to the Program

    Arguments:
        proto: The protobuf data
        program: The program

    TODO:
        Type hinting for proto parameter (RepeatedCompositeFieldContainer)
    """

    def __init__(self, proto, program: quokka.Program):
        """Init method

        Arguments:
            proto: List of data in the protobuf
            program: Backref to the program
        """
        self.proto_data = proto.data
        self.program: quokka.Program = program

    def __setitem__(self, k: Index, v: Data) -> None:
        """Set a data"""
        raise ValueError("Should not be accessed")

    def __delitem__(self, v: Index) -> None:
        """Remove a data from the bucket"""
        raise ValueError("Should not be accessed")

    def __getitem__(self, k: Index) -> Data:
        """Get a data from the bucket.

        Arguments:
            k: Data Index
        
        Returns:
            A Data
        """
        return Data(k, self.proto_data[k], self.program)

    def get_data(self, address: AddressT) -> Data:
        """Find a data by address

        Iterates over the data to find the one at a specified offset

        Arguments:
            address: Offset to query
        
        Returns:
            A Data
        
        Raises:
            ValueError if no data is found
        """

        # We have to iterate over every data because they are not sorted by offset
        for index, data_proto in enumerate(self.proto_data):
            if data_proto.offset + self.program.base_address == address:
                return self[index]
        else:
            raise ValueError(f"No data at offset 0x{address:x}")

    def __len__(self) -> int:
        """Number of data in the program"""
        return len(self.proto_data)

    def __iter__(self):
        """Do not allow the iteration over the data"""
        raise ValueError("Should not be accessed")
