"""Addresser : handle addresses management"""

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
from quokka.types import AddressT


class Addresser:
    """Class for managing addresses.

    Arguments:
        program: A backref to the program
        base_address: Program's base address

    Attributes:
        logger: A logger instance
        program: Program reference
        base_address: Program base address

    """

    def __init__(self, program: quokka.Program, base_address: AddressT):
        """Constructor"""
        self.logger = logging.getLogger(__name__)
        self.program: quokka.Program = program
        self.base_address: AddressT = base_address

    def absolute(self, offset: int) -> AddressT:
        """Converts an offset in the file to an absolute address

        Arguments:
            offset: Offset in the file

        Returns:
            An absolute address
        """
        return self.base_address + offset

    def file(self, offset: int) -> int:
        """Converts a program offset to a file offset.

        Arguments:
            offset: A virtual address

        Returns:
            A file offset
        """
        try:
            segment = self.program.get_segment(offset)
        except KeyError:
            raise quokka.NotInFileError("Unable to find the segment")

        if segment.file_offset != -1:
            return offset + segment.file_offset

        raise quokka.NotInFileError("Unable to find the offset in the file")
