"""Types used in Quokka"""
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

import enum

import quokka
import quokka.pb.Quokka as QuokkaPb
from typing import (
    Any,
    DefaultDict,
    Dict,
    Generator,
    Iterable,
    Iterator,
    List,
    Literal,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
)

AddressT = int
Index = int
T = TypeVar("T")

LocationValueType = Union[
    Tuple[int, int], Tuple[int, int, int], int  # Structure  # Inst instance
]

RegType = enum.IntEnum

class RegAccessMode(enum.Enum):
    """Register access mode"""

    READ = enum.auto()
    WRITE = enum.auto()
    ANY = enum.auto()

ReferenceTarget = Union[
    "quokka.structure.Structure",
    "quokka.structure.StructureMember",
    "quokka.data.Data",
    "quokka.Instruction",
    "quokka.Chunk",
    Tuple["quokka.Chunk", "quokka.Block", Index],
]


class AddressSize(enum.Enum):
    """Address size"""

    ADDRESS_64 = enum.auto()
    ADDRESS_32 = enum.auto()
    ADDRESS_16 = enum.auto()
    ADDRESS_UNK = enum.auto()

    @staticmethod
    def from_proto(
        address_size: "QuokkaPb.AddressSizeValue",
    ) -> "AddressSize":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            QuokkaPb.ADDR_32: AddressSize.ADDRESS_32,
            QuokkaPb.ADDR_64: AddressSize.ADDRESS_64,
        }

        return mapping.get(address_size, AddressSize.ADDRESS_UNK)


class Endianness(enum.Enum):
    """Endianness of the program

    LE: Little endian (least significant bit first)
    BE: Big endian (most significant bit first)

    TODO:
        See how we can support mixed endianness
    """

    LITTLE_ENDIAN = enum.auto()
    BIG_ENDIAN = enum.auto()
    UNKNOWN = enum.auto()

    @staticmethod
    def from_proto(
        endianness: "QuokkaPb.Meta.EndianessValue",
    ) -> Endianness:
        """Convert the protobuf value into this enumeration"""
        mapping = {
            QuokkaPb.Meta.END_BE: Endianness.BIG_ENDIAN,
            QuokkaPb.Meta.END_LE: Endianness.LITTLE_ENDIAN,
        }

        return mapping.get(endianness, Endianness.UNKNOWN)


class EdgeType(enum.Enum):
    """Edge Type"""

    UNCONDITIONAL = enum.auto()
    TRUE = enum.auto()
    FALSE = enum.auto()
    SWITCH = enum.auto()

    @staticmethod
    def from_proto(
        edge_type: "QuokkaPb.Edge.EdgeTypeValue",
    ) -> "EdgeType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            QuokkaPb.Edge.TYPE_UNCONDITIONAL: EdgeType.UNCONDITIONAL,
            QuokkaPb.Edge.TYPE_TRUE: EdgeType.TRUE,
            QuokkaPb.Edge.TYPE_FALSE: EdgeType.FALSE,
            QuokkaPb.Edge.TYPE_SWITCH: EdgeType.SWITCH,
        }

        edge = mapping.get(edge_type)
        if edge is not None:
            return edge

        raise ValueError("Unable to decode Edge Type")


class FunctionType(enum.Enum):
    """Function Type"""

    NORMAL = enum.auto()
    IMPORTED = enum.auto()
    LIBRARY = enum.auto()
    THUNK = enum.auto()
    EXTERN = enum.auto()
    INVALID = enum.auto()

    @staticmethod
    def from_proto(
        function_type: "QuokkaPb.Function.FunctionTypeValue",
    ) -> "FunctionType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            QuokkaPb.Function.TYPE_NORMAL: FunctionType.NORMAL,
            QuokkaPb.Function.TYPE_IMPORTED: FunctionType.IMPORTED,
            QuokkaPb.Function.TYPE_LIBRARY: FunctionType.LIBRARY,
            QuokkaPb.Function.TYPE_THUNK: FunctionType.THUNK,
        }

        return mapping.get(function_type, FunctionType.INVALID)


class BlockType(enum.Enum):
    """Block Type"""

    NORMAL = enum.auto()
    INDJUMP = enum.auto()
    RET = enum.auto()
    NORET = enum.auto()
    CNDRET = enum.auto()
    ENORET = enum.auto()
    EXTERN = enum.auto()
    ERROR = enum.auto()
    FAKE = enum.auto()

    @staticmethod
    def from_proto(
        block_type: "QuokkaPb.FunctionChunk.Block.BlockTypeValue",
    ) -> BlockType:
        """Convert the protobuf value into this enumeration"""
        mapping = {
            QuokkaPb.FunctionChunk.Block.BLOCK_TYPE_NORMAL: BlockType.NORMAL,
            QuokkaPb.FunctionChunk.Block.BLOCK_TYPE_INDJUMP: BlockType.INDJUMP,
            QuokkaPb.FunctionChunk.Block.BLOCK_TYPE_RET: BlockType.RET,
            QuokkaPb.FunctionChunk.Block.BLOCK_TYPE_NORET: BlockType.NORET,
            QuokkaPb.FunctionChunk.Block.BLOCK_TYPE_CNDRET: BlockType.CNDRET,
            QuokkaPb.FunctionChunk.Block.BLOCK_TYPE_ENORET: BlockType.ENORET,
            QuokkaPb.FunctionChunk.Block.BLOCK_TYPE_EXTERN: BlockType.EXTERN,
            QuokkaPb.FunctionChunk.Block.BLOCK_TYPE_ERROR: BlockType.ERROR,
            QuokkaPb.FunctionChunk.Block.BLOCK_TYPE_FAKE: BlockType.FAKE,
        }

        return mapping.get(block_type, BlockType.FAKE)


class ReferenceType(enum.Enum):
    """Reference Type"""

    CALL = enum.auto()
    DATA = enum.auto()
    ENUM = enum.auto()
    STRUC = enum.auto()
    UNKNOWN = enum.auto()

    @staticmethod
    def from_proto(
        reference_type: "QuokkaPb.Reference.ReferenceTypeValue",
    ) -> "ReferenceType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            QuokkaPb.Reference.REF_CALL: ReferenceType.CALL,
            QuokkaPb.Reference.REF_DATA: ReferenceType.DATA,
            QuokkaPb.Reference.REF_ENUM: ReferenceType.ENUM,
            QuokkaPb.Reference.REF_STRUC: ReferenceType.STRUC,
        }

        return mapping.get(reference_type, ReferenceType.UNKNOWN)


class DataType(enum.Enum):
    """Data Type"""

    UNKNOWN = enum.auto()
    BYTE = enum.auto()
    WORD = enum.auto()
    DOUBLE_WORD = enum.auto()
    QUAD_WORD = enum.auto()
    OCTO_WORD = enum.auto()
    FLOAT = enum.auto()
    DOUBLE = enum.auto()
    ASCII = enum.auto()
    STRUCT = enum.auto()
    ALIGN = enum.auto()
    POINTER = enum.auto()

    @staticmethod
    def from_proto(data_type: "QuokkaPb.DataTypeValue") -> "DataType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            QuokkaPb.TYPE_B: DataType.BYTE,
            QuokkaPb.TYPE_W: DataType.WORD,
            QuokkaPb.TYPE_DW: DataType.DOUBLE_WORD,
            QuokkaPb.TYPE_QW: DataType.QUAD_WORD,
            QuokkaPb.TYPE_OW: DataType.OCTO_WORD,
            QuokkaPb.TYPE_FLOAT: DataType.FLOAT,
            QuokkaPb.TYPE_DOUBLE: DataType.DOUBLE,
            QuokkaPb.TYPE_ASCII: DataType.ASCII,
            QuokkaPb.TYPE_STRUCT: DataType.STRUCT,
            QuokkaPb.TYPE_ALIGN: DataType.ALIGN,
            QuokkaPb.TYPE_POINTER: DataType.POINTER,
        }

        return mapping.get(data_type, DataType.UNKNOWN)


class SegmentType(enum.Enum):
    """Segment Type"""

    UNKNOWN = enum.auto()
    CODE = enum.auto()
    DATA = enum.auto()
    BSS = enum.auto()
    NULL = enum.auto()
    EXTERN = enum.auto()
    NORMAL = enum.auto()
    ABSOLUTE_SYMBOLS = enum.auto()

    @staticmethod
    def from_proto(
        segment_type: "QuokkaPb.Segment.TypeValue",
    ) -> "SegmentType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            QuokkaPb.Segment.SEGMENT_CODE: SegmentType.CODE,
            QuokkaPb.Segment.SEGMENT_DATA: SegmentType.DATA,
            QuokkaPb.Segment.SEGMENT_BSS: SegmentType.BSS,
            QuokkaPb.Segment.SEGMENT_NULL: SegmentType.NULL,
            QuokkaPb.Segment.SEGMENT_NORMAL: SegmentType.NORMAL,
            QuokkaPb.Segment.SEGMENT_EXTERN: SegmentType.EXTERN,
            QuokkaPb.Segment.SEGMENT_ABSOLUTE_SYMBOLS: SegmentType.ABSOLUTE_SYMBOLS,
        }

        return mapping.get(segment_type, SegmentType.UNKNOWN)


class StructureType(enum.Enum):
    """Structure Type"""

    STRUCT = enum.auto()
    ENUM = enum.auto()
    UNION = enum.auto()
    UNKNOWN = enum.auto()

    @staticmethod
    def from_proto(
        structure_type: "QuokkaPb.Structure.StructureTypeValue",
    ) -> "StructureType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            QuokkaPb.Structure.TYPE_STRUCT: StructureType.STRUCT,
            QuokkaPb.Structure.TYPE_ENUM: StructureType.ENUM,
            QuokkaPb.Structure.TYPE_UNION: StructureType.UNION,
        }

        return mapping.get(structure_type, StructureType.UNKNOWN)


class ExporterMode(enum.IntEnum):
    """Mode type

    The exporter mode controls the type of exported data.
    """

    LIGHT = enum.auto()
    FULL = enum.auto()

    @staticmethod
    def from_proto(mode: "QuokkaPb.ExporterMeta.ModeValue") -> "ExporterMode":
        mapping = {
            QuokkaPb.ExporterMeta.MODE_LIGHT: ExporterMode.LIGHT,
            QuokkaPb.ExporterMeta.MODE_SELF_CONTAINED: ExporterMode.FULL,
        }

        return mapping[mode]

class CallingConvention(enum.Enum):
    """Calling convention"""

    UNKNOWN = enum.auto()
    CDECL = enum.auto()
    ELLIPSIS = enum.auto()
    STDCALL = enum.auto()
    PASCAL = enum.auto()
    FASTCALL = enum.auto()
    THISCALL = enum.auto()
    SWIFT = enum.auto()
    GOLANG = enum.auto()
    GOSTK = enum.auto()

    @staticmethod
    def from_proto(proto_cc: "QuokkaPb.CallingConvention") -> "CallingConvention":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            QuokkaPb.CC_CDECL: CallingConvention.CDECL,
            QuokkaPb.CC_ELLIPSIS: CallingConvention.ELLIPSIS,
            QuokkaPb.CC_STDCALL: CallingConvention.STDCALL,
            QuokkaPb.CC_PASCAL: CallingConvention.PASCAL,
            QuokkaPb.CC_FASTCALL: CallingConvention.FASTCALL,
            QuokkaPb.CC_THISCALL: CallingConvention.THISCALL,
            QuokkaPb.CC_SWIFT: CallingConvention.SWIFT,
            QuokkaPb.CC_GOLANG: CallingConvention.GOLANG,
            QuokkaPb.CC_GOSTK: CallingConvention.GOSTK,
        }[proto_cc]

class Disassembler(enum.Enum):
    """Disassembler"""

    UNKNOWN = enum.auto()
    IDA = enum.auto()
    GHIDRA = enum.auto()
    BINARY_NINJA = enum.auto()

    @staticmethod
    def from_proto(
        proto_disass: "QuokkaPb.Meta.Backend.Disassembler",
    ) -> "Disassembler":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            QuokkaPb.Meta.Backend.Disassembler.DISASS_IDA: Disassembler.IDA,
            QuokkaPb.Meta.Backend.Disassembler.DISASS_GHIDRA: Disassembler.GHIDRA,
            QuokkaPb.Meta.Backend.Disassembler.DISASS_BINARY_NINJA: Disassembler.BINARY_NINJA,
        }

        return mapping.get(proto_disass, Disassembler.UNKNOWN)
