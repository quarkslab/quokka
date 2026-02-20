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

Type = Any
ReferenceType = AddressT | Any

class AccessMode(enum.IntFlag):
    """Register access mode"""

    READ = enum.auto()
    WRITE = enum.auto()

ReferenceTarget = Union[
    "quokka.structure.Structure",
    "quokka.structure.StructureMember",
    "quokka.data.Data",
    "quokka.Instruction",
    "quokka.Function",
    Tuple["quokka.Function", "quokka.Block", Index],
]


class AddressSize(enum.Enum):
    """Address size"""

    ADDRESS_64 = enum.auto()
    ADDRESS_32 = enum.auto()
    ADDRESS_16 = enum.auto()
    ADDRESS_UNK = enum.auto()

    @staticmethod
    def from_proto(
        address_size: "quokka.pb.Quokka.AddressSizeValue",
    ) -> "AddressSize":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            quokka.pb.Quokka.ADDR_32: AddressSize.ADDRESS_32,
            quokka.pb.Quokka.ADDR_64: AddressSize.ADDRESS_64,
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
        endianness: "quokka.pb.Quokka.Meta.EndianessValue",
    ) -> Endianness:
        """Convert the protobuf value into this enumeration"""
        mapping = {
            quokka.pb.Quokka.Meta.END_BE: Endianness.BIG_ENDIAN,
            quokka.pb.Quokka.Meta.END_LE: Endianness.LITTLE_ENDIAN,
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
        edge_type: "quokka.pb.Quokka.Edge.EdgeTypeValue",
    ) -> "EdgeType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            quokka.pb.Quokka.Edge.TYPE_UNCONDITIONAL: EdgeType.UNCONDITIONAL,
            quokka.pb.Quokka.Edge.TYPE_TRUE: EdgeType.TRUE,
            quokka.pb.Quokka.Edge.TYPE_FALSE: EdgeType.FALSE,
            quokka.pb.Quokka.Edge.TYPE_SWITCH: EdgeType.SWITCH,
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
        function_type: "quokka.pb.Quokka.Function.FunctionTypeValue",
    ) -> "FunctionType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            quokka.pb.Quokka.Function.TYPE_NORMAL: FunctionType.NORMAL,
            quokka.pb.Quokka.Function.TYPE_IMPORTED: FunctionType.IMPORTED,
            quokka.pb.Quokka.Function.TYPE_LIBRARY: FunctionType.LIBRARY,
            quokka.pb.Quokka.Function.TYPE_THUNK: FunctionType.THUNK,
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
        block_type: "quokka.pb.Quokka.Block.BlockTypeValue",
    ) -> BlockType:
        """Convert the protobuf value into this enumeration"""
        mapping = {
            quokka.pb.Quokka.Block.BLOCK_TYPE_NORMAL: BlockType.NORMAL,
            quokka.pb.Quokka.Block.BLOCK_TYPE_INDJUMP: BlockType.INDJUMP,
            quokka.pb.Quokka.Block.BLOCK_TYPE_RET: BlockType.RET,
            quokka.pb.Quokka.Block.BLOCK_TYPE_NORET: BlockType.NORET,
            quokka.pb.Quokka.Block.BLOCK_TYPE_CNDRET: BlockType.CNDRET,
            quokka.pb.Quokka.Block.BLOCK_TYPE_ENORET: BlockType.ENORET,
            quokka.pb.Quokka.Block.BLOCK_TYPE_EXTERN: BlockType.EXTERN,
            quokka.pb.Quokka.Block.BLOCK_TYPE_ERROR: BlockType.ERROR,
            quokka.pb.Quokka.Block.BLOCK_TYPE_FAKE: BlockType.FAKE,
        }

        return mapping.get(block_type, BlockType.FAKE)

class OperandType(enum.Enum):
    """Operand Type"""

    REGISTER = enum.auto()
    IMMEDIATE = enum.auto()
    MEMORY = enum.auto()
    OTHER = enum.auto()

    @staticmethod
    def from_proto(
        operand_type: "quokka.pb.Quokka.Operand.OperandType",
    ) -> "OperandType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            quokka.pb.Quokka.Operand.OPERAND_REGISTER: OperandType.REGISTER,
            quokka.pb.Quokka.Operand.OPERAND_IMMEDIATE: OperandType.IMMEDIATE,
            quokka.pb.Quokka.Operand.OPERAND_MEMORY: OperandType.MEMORY,
            quokka.pb.Quokka.Operand.OPERAND_OTHER: OperandType.OTHER,
        }

        return mapping.get(operand_type, OperandType.OTHER)

class ReferenceType(enum.Enum):
    """Reference Type"""

    CODE = enum.auto()
    DATA = enum.auto()
    SYMBOL = enum.auto()
    UNKNOWN = enum.auto()

    @staticmethod
    def from_proto(
        reference_type: "quokka.pb.Quokka.Reference.ReferenceType",
    ) -> "ReferenceType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            quokka.pb.Quokka.Reference.REF_CODE: ReferenceType.CODE,
            quokka.pb.Quokka.Reference.REF_DATA: ReferenceType.DATA,
            quokka.pb.Quokka.Reference.REF_SYMBOL: ReferenceType.SYMBOL,
        }

        return mapping.get(reference_type, ReferenceType.UNKNOWN)


class BaseType(enum.Enum):
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
    def from_proto(data_type: "quokka.pb.Quokka.DataType") -> "BaseType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            quokka.pb.Quokka.TYPE_B: BaseType.BYTE,
            quokka.pb.Quokka.TYPE_W: BaseType.WORD,
            quokka.pb.Quokka.TYPE_DW: BaseType.DOUBLE_WORD,
            quokka.pb.Quokka.TYPE_QW: BaseType.QUAD_WORD,
            quokka.pb.Quokka.TYPE_OW: BaseType.OCTO_WORD,
            quokka.pb.Quokka.TYPE_FLOAT: BaseType.FLOAT,
            quokka.pb.Quokka.TYPE_DOUBLE: BaseType.DOUBLE,
            quokka.pb.Quokka.TYPE_ASCII: BaseType.ASCII,
            quokka.pb.Quokka.TYPE_STRUCT: BaseType.STRUCT,
            quokka.pb.Quokka.TYPE_ALIGN: BaseType.ALIGN,
            quokka.pb.Quokka.TYPE_POINTER: BaseType.POINTER,
        }

        return mapping.get(data_type, BaseType.UNKNOWN)

    @property
    def size(self) -> int:
        """Size of the data type in bytes"""
        mapping = {
            BaseType.BYTE: 1,
            BaseType.WORD: 2,
            BaseType.DOUBLE_WORD: 4,
            BaseType.QUAD_WORD: 8,
            BaseType.OCTO_WORD: 16,
            BaseType.FLOAT: 4,
            BaseType.DOUBLE: 8,
        }

        return mapping.get(self, 0)


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
        segment_type: "quokka.pb.Quokka.Segment.TypeValue",
    ) -> "SegmentType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            quokka.pb.Quokka.Segment.SEGMENT_CODE: SegmentType.CODE,
            quokka.pb.Quokka.Segment.SEGMENT_DATA: SegmentType.DATA,
            quokka.pb.Quokka.Segment.SEGMENT_BSS: SegmentType.BSS,
            quokka.pb.Quokka.Segment.SEGMENT_NULL: SegmentType.NULL,
            quokka.pb.Quokka.Segment.SEGMENT_NORMAL: SegmentType.NORMAL,
            quokka.pb.Quokka.Segment.SEGMENT_EXTERN: SegmentType.EXTERN,
            quokka.pb.Quokka.Segment.SEGMENT_ABSOLUTE_SYMBOLS: SegmentType.ABSOLUTE_SYMBOLS,
        }

        return mapping.get(segment_type, SegmentType.UNKNOWN)


# class StructureType(enum.Enum):
#     """Structure Type"""

#     STRUCT = enum.auto()
#     ENUM = enum.auto()
#     UNION = enum.auto()
#     UNKNOWN = enum.auto()

#     @staticmethod
#     def from_proto(
#         structure_type: "quokka.pb.Quokka.Structure.StructureTypeValue",
#     ) -> "StructureType":
#         """Convert the protobuf value into this enumeration"""
#         mapping = {
#             quokka.pb.Quokka.Structure.TYPE_STRUCT: StructureType.STRUCT,
#             quokka.pb.Quokka.Structure.TYPE_ENUM: StructureType.ENUM,
#             quokka.pb.Quokka.Structure.TYPE_UNION: StructureType.UNION,
#         }

#         return mapping.get(structure_type, StructureType.UNKNOWN)


class ExporterMode(enum.IntEnum):
    """Mode type

    The exporter mode controls the type of exported data.
    """

    LIGHT = enum.auto()
    FULL = enum.auto()

    @staticmethod
    def from_proto(mode: "quokka.pb.Quokka.ExporterMeta.ModeValue") -> "ExporterMode":
        mapping = {
            quokka.pb.Quokka.ExporterMeta.MODE_LIGHT: ExporterMode.LIGHT,
            quokka.pb.Quokka.ExporterMeta.MODE_SELF_CONTAINED: ExporterMode.FULL,
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
    def from_proto(proto_cc: "quokka.pb.Quokka.CallingConvention") -> "CallingConvention":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            quokka.pb.Quokka.CC_CDECL: CallingConvention.CDECL,
            quokka.pb.Quokka.CC_ELLIPSIS: CallingConvention.ELLIPSIS,
            quokka.pb.Quokka.CC_STDCALL: CallingConvention.STDCALL,
            quokka.pb.Quokka.CC_PASCAL: CallingConvention.PASCAL,
            quokka.pb.Quokka.CC_FASTCALL: CallingConvention.FASTCALL,
            quokka.pb.Quokka.CC_THISCALL: CallingConvention.THISCALL,
            quokka.pb.Quokka.CC_SWIFT: CallingConvention.SWIFT,
            quokka.pb.Quokka.CC_GOLANG: CallingConvention.GOLANG,
            quokka.pb.Quokka.CC_GOSTK: CallingConvention.GOSTK,
        }[proto_cc]

class Disassembler(enum.Enum):
    """Disassembler"""

    UNKNOWN = enum.auto()
    IDA = enum.auto()
    GHIDRA = enum.auto()
    BINARY_NINJA = enum.auto()

    @staticmethod
    def from_proto(
        proto_disass: "quokka.pb.Quokka.Meta.Backend.Disassembler",
    ) -> "Disassembler":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            quokka.pb.Quokka.Meta.Backend.Disassembler.DISASS_IDA: Disassembler.IDA,
            quokka.pb.Quokka.Meta.Backend.Disassembler.DISASS_GHIDRA: Disassembler.GHIDRA,
            quokka.pb.Quokka.Meta.Backend.Disassembler.DISASS_BINARY_NINJA: Disassembler.BINARY_NINJA,
        }

        return mapping.get(proto_disass, Disassembler.UNKNOWN)
