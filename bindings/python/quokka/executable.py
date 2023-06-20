"""Executable: management of the binary file in itself."""

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

import pathlib
import struct

from quokka.types import DataType, Endianness, Literal, Optional, Union


class Executable:
    """The executable class is used to interact with the binary file.

    It handles access to the binary file itself (not the exported) for reads.

    Note: The binary is read only once and stored in memory. This is done for
    performance purposes but does not cope well with low RAM systems and/or huge
    binaries.

    Arguments:
        path: Path towards the executable file
        endianness: How are stored the data

    Attributes:
        exec_file: Path towards the executable file
        endianness: Binary endianness
        content: Bytes of the binary

    Raises:
        ValueError: If the file is not found
    """

    def __init__(self, path: Union[str, pathlib.Path], endianness: Endianness):
        """Constructor"""
        try:
            with open(path, "rb") as file:
                self.content: bytes = file.read()

        except FileNotFoundError:
            raise ValueError("File not found")

        self.exec_file: pathlib.Path = pathlib.Path(path)
        self.endianness: Endianness = endianness

    def read(self, offset: int, size: int) -> bytes:
        """Read `size` at `offset` in the file.

        This method should not be used directly and considered as part of a private API.
        The preferred method are read_byte / read_string .

        Arguments:
            offset: File offset
            size: Read size

        Returns:
            The content that has been read

        Raises:
            ValueError: when the value is not in the file
        """
        try:
            return self.content[offset : offset + size]
        except IndexError as exc:
            raise ValueError(f"Content not found at offset {offset}") from exc

    def read_string(self, offset: int, size: Optional[int] = None) -> str:
        """Read a string in the file.
        
        If the size is not given, Quokka will try to read the string until the
        first null byte. That works only for null-terminated strings.

        If the string is null terminated, remove the trailing 0.

        Arguments:
            offset: String file offset 
            size: String size if known.

        Returns:
            The decoded string

        Raises:
          ValueError: If the string is not found nor decoded.
        """

        if size is not None:
            try:
                string = self.read(offset, size).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("Unable to read or decode the string.") from exc
        
        else:
            try:
                null_byte = self.content.index(b"\x00", offset)
            except ValueError as exc:
                raise ValueError("String is not null-terminated and size was not given") from exc

            string = self.content[offset: null_byte].decode("utf-8")

        # FIX: When returning a single character string, it does not end with a '\0'
        if len(string) > 1 and string.endswith("\x00"):
            return string[:-1]

        return string

    def read_data(
        self, offset: int, data_type: DataType, size: Optional[int] = None
    ) -> Union[int, float, str]:
        """Read the data value.

        If the size is not specified, it is inferred from the data type.

        Arguments:
            offset: Data file offset
            data_type: Data type
            size: Read size

        Returns:
            The data value
        """
        # Read an int of size `read_size`
        def read_int(read_size: int) -> int:
            """Read an integer from the binary"""
            return int.from_bytes(self.read_byte(offset, read_size), endianness)

        endianness: Literal["big", "little"]
        if self.endianness == Endianness.BIG_ENDIAN:
            endianness = "big"
            endianness_sign = ">"
        else:
            endianness = "little"
            endianness_sign = "<"

        if data_type == DataType.ASCII:
            if size is None:
                raise ValueError("No size specified when reading a DataType.ASCII")
            return self.read_string(offset, size)
        elif data_type == DataType.BYTE:
            return read_int(1 if size is None else size)
        elif data_type == DataType.WORD:
            return read_int(2 if size is None else size)
        elif data_type == DataType.DOUBLE_WORD:
            return read_int(4 if size is None else size)
        elif data_type == DataType.QUAD_WORD:
            return read_int(8 if size is None else size)
        elif data_type == DataType.OCTO_WORD:
            return read_int(16 if size is None else size)
        elif data_type == DataType.FLOAT:
            s = 4 if size is None else size
            return struct.unpack(f"{endianness_sign}f", self.read_byte(offset, s))
        elif data_type == DataType.DOUBLE:
            s = 8 if size is None else size
            return struct.unpack(f"{endianness_sign}d", self.read_byte(offset, s))
        else:
            raise NotImplementedError(
                f"Cannot read {data_type}. DataType not implemented."
            )

    def read_byte(self, offset: int, size: int) -> bytes:
        """Read one (or more) byte(s) in the file at `offset`.

        This is mostly used to read instructions.

        Arguments:
            offset: File offset to read
            size: Number of bytes to read

        Returns:
            The bytes values
        """
        return self.read(offset, size)
