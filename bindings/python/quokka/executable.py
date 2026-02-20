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

import logging
import pathlib
import struct
from typing import TYPE_CHECKING

from quokka.types import Endianness
from quokka.data_type import BaseType, EnumType, StructureType, TypeT, TypeValue


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

    def __init__(self, path: pathlib.Path|str, endianness: Endianness):
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
        The preferred method are read_bytes / read_string .

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

    def read_string(self, offset: int, size: int|None = None) -> str:
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
                raise ValueError(
                    "String is not null-terminated and size was not given"
                ) from exc

            string = self.content[offset:null_byte].decode("utf-8")

        # FIX: When returning a single character string, it does not end with a '\0'
        if len(string) > 1 and string.endswith("\x00"):
            return string[:-1]

        return string

    def read_int(self, offset: int, size: int, signed: bool = False) -> int:
        """Read an integer from the binary.

        Arguments:
            offset: Integer file offset
            size: Integer size in bytes"""
        en = {Endianness.BIG_ENDIAN: "big", Endianness.LITTLE_ENDIAN: "little"}[self.endianness]
        return int.from_bytes(self.read(offset, size), en, signed=signed) # type: ignore

    def read_type_value(self, offset: int, type: TypeT) -> TypeValue:
        """Read the data value based on its type.

        Arguments:
            offset: Data file offset
            data_type: Data type

        Returns:
            The data value
        """
        en = {Endianness.BIG_ENDIAN: ">", Endianness.LITTLE_ENDIAN: "<"}[self.endianness]

        if isinstance(type, BaseType):
            match type:
                case BaseType.FLOAT:
                    return struct.unpack(f"{en}f", self.read_bytes(offset, 4))[0]
                case BaseType.DOUBLE:
                    return struct.unpack(f"{en}d", self.read_bytes(offset, 8))[0]
                case _:
                    return self.read_int(offset, type.size)
        elif isinstance(type, StructureType):
            return self.read_struct(offset, type)
        elif isinstance(type, EnumType):
            return self.read_enum(offset, type)
        else:
            assert False, f"Unsupported type {type}"

    def read_struct(self, offset: int, struct: StructureType) -> bytes:
        """Read a struct from the binary.

        Arguments:
            offset: Struct file offset
            type: Struct type"""
        if struct.is_variable_size():
            logging.warning("Cannot read a variable size struct")
            return b""
        # FEATURE: Read a really structure instance
        return self.read_bytes(offset, struct.size)

    def read_enum(self, offset: int, enum: EnumType) -> EnumType:
        # read the underyling enum type
        value = self.read_type_value(offset, enum.base_type)  # type: ignore
        return enum(value) # type: ignore
    
    def read_bytes(self, offset: int, size: int) -> bytes:
        """Read one (or more) byte(s) in the file at `offset`.

        This is mostly used to read instructions.

        Arguments:
            offset: File offset to read
            size: Number of bytes to read

        Returns:
            The bytes values
        """
        return self.read(offset, size)
