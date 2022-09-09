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

import quokka

from quokka.types import (
    AddressT,
    SegmentType,
)


class Segment:
    """Segment

    This class represents IDA segments.

    Arguments:
        segment: Segment protobuf information
        program: Program back reference

    Attributes:
        name: Segment name
        start: Segment starting address
        permissions: Segment permissions
        size: Segment size
        type: Segment type
        program: Program reference
        file_offset: Segment offset in the file (if appropriate)

    """
    def __init__(
        self,
        segment: "quokka.pb.Quokka.Segment",
        program: quokka.Program,
    ):
        """Constructor"""
        self.name: str = segment.name
        self.start: AddressT = segment.start_addr
        self.permissions: int = segment.permissions
        self.size: int = segment.size
        self.type: "SegmentType" = SegmentType.from_proto(segment.type)

        self.program: quokka.Program = program

        self.file_offset: int = -1
        if segment.no_offset is False:
            self.file_offset = segment.file_offset - self.start

    @property
    def end(self) -> AddressT:
        """End address of the segment"""
        return self.start + self.size

    def writable(self) -> bool:
        """Is the segment writable?"""
        return self.permissions & 0x2 > 0

    def executable(self) -> bool:
        """Is the segment executable?"""
        return self.permissions & 0x1 > 0

    def readable(self) -> bool:
        """Is the segment readable?"""
        return self.permissions & 0x4 > 0

    def in_segment(self, addr: int) -> bool:
        """Does `addr` belong to this segment ?"""
        return self.start <= addr < self.start + self.size
