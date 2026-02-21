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
from quokka.quokka_pb2 import Quokka as Pb # pyright: ignore[reportMissingImports]
from typing import Any, Tuple, TypeVar, Union

AddressT = int
Index = int
T = TypeVar("T")

LocationValueType = Union[
    Tuple[int, int], Tuple[int, int, int], int  # Structure  # Inst instance
]

RegType = enum.IntEnum


class AccessMode(enum.IntFlag):
    """Register access mode"""

    READ = enum.auto()
    WRITE = enum.auto()


class AddressSize(enum.Enum):
    """Address size"""

    ADDRESS_64 = enum.auto()
    ADDRESS_32 = enum.auto()
    ADDRESS_16 = enum.auto()
    ADDRESS_UNK = enum.auto()

    @staticmethod
    def from_proto(
        address_size: "Pb.AddressSizeValue",
    ) -> "AddressSize":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            Pb.ADDR_32: AddressSize.ADDRESS_32,
            Pb.ADDR_64: AddressSize.ADDRESS_64,
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
        endianness: "Pb.Meta.EndianessValue",
    ) -> Endianness:
        """Convert the protobuf value into this enumeration"""
        mapping = {
            Pb.Meta.END_BE: Endianness.BIG_ENDIAN,
            Pb.Meta.END_LE: Endianness.LITTLE_ENDIAN,
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
        edge_type: "Pb.Edge.EdgeTypeValue",
    ) -> "EdgeType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            Pb.Edge.TYPE_UNCONDITIONAL: EdgeType.UNCONDITIONAL,
            Pb.Edge.TYPE_TRUE: EdgeType.TRUE,
            Pb.Edge.TYPE_FALSE: EdgeType.FALSE,
            Pb.Edge.TYPE_SWITCH: EdgeType.SWITCH,
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
        function_type: "Pb.Function.FunctionTypeValue",
    ) -> "FunctionType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            Pb.Function.TYPE_NORMAL: FunctionType.NORMAL,
            Pb.Function.TYPE_IMPORTED: FunctionType.IMPORTED,
            Pb.Function.TYPE_LIBRARY: FunctionType.LIBRARY,
            Pb.Function.TYPE_THUNK: FunctionType.THUNK,
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

    @staticmethod
    def from_proto(
        block_type: "Pb.Block.BlockTypeValue",
    ) -> BlockType:
        """Convert the protobuf value into this enumeration"""
        mapping = {
            Pb.Block.BLOCK_TYPE_NORMAL: BlockType.NORMAL,
            Pb.Block.BLOCK_TYPE_INDJUMP: BlockType.INDJUMP,
            Pb.Block.BLOCK_TYPE_RET: BlockType.RET,
            Pb.Block.BLOCK_TYPE_NORET: BlockType.NORET,
            Pb.Block.BLOCK_TYPE_CNDRET: BlockType.CNDRET,
            Pb.Block.BLOCK_TYPE_ENORET: BlockType.ENORET,
            Pb.Block.BLOCK_TYPE_EXTERN: BlockType.EXTERN,
            Pb.Block.BLOCK_TYPE_ERROR: BlockType.ERROR,
        }

        return mapping.get(block_type, BlockType.NORMAL)

class OperandType(enum.Enum):
    """Operand Type"""

    REGISTER = enum.auto()
    IMMEDIATE = enum.auto()
    MEMORY = enum.auto()
    OTHER = enum.auto()

    @staticmethod
    def from_proto(
        operand_type: "Pb.Operand.OperandType",
    ) -> "OperandType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            Pb.Operand.OPERAND_REGISTER: OperandType.REGISTER,
            Pb.Operand.OPERAND_IMMEDIATE: OperandType.IMMEDIATE,
            Pb.Operand.OPERAND_MEMORY: OperandType.MEMORY,
            Pb.Operand.OPERAND_OTHER: OperandType.OTHER,
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
        reference_type: "Pb.Reference.ReferenceType",
    ) -> "ReferenceType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            Pb.Reference.REF_CODE: ReferenceType.CODE,
            Pb.Reference.REF_DATA: ReferenceType.DATA,
            Pb.Reference.REF_SYMBOL: ReferenceType.SYMBOL,
        }

        return mapping.get(reference_type, ReferenceType.UNKNOWN)

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
        segment_type: "Pb.Segment.TypeValue",
    ) -> "SegmentType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            Pb.Segment.SEGMENT_CODE: SegmentType.CODE,
            Pb.Segment.SEGMENT_DATA: SegmentType.DATA,
            Pb.Segment.SEGMENT_BSS: SegmentType.BSS,
            Pb.Segment.SEGMENT_NULL: SegmentType.NULL,
            Pb.Segment.SEGMENT_NORMAL: SegmentType.NORMAL,
            Pb.Segment.SEGMENT_EXTERN: SegmentType.EXTERN,
            Pb.Segment.SEGMENT_ABSOLUTE_SYMBOLS: SegmentType.ABSOLUTE_SYMBOLS,
        }

        return mapping.get(segment_type, SegmentType.UNKNOWN)



class ExporterMode(enum.IntEnum):
    """Mode type

    The exporter mode controls the type of exported data.
    """

    LIGHT = enum.auto()
    FULL = enum.auto()

    @staticmethod
    def from_proto(mode: "Pb.ExporterMeta.ModeValue") -> "ExporterMode":
        mapping = {
            Pb.ExporterMeta.MODE_LIGHT: ExporterMode.LIGHT,
            Pb.ExporterMeta.MODE_SELF_CONTAINED: ExporterMode.FULL,
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
    def from_proto(proto_cc: "Pb.CallingConvention") -> "CallingConvention":
        """Convert the protobuf value into this enumeration"""
        return {
            Pb.CC_CDECL: CallingConvention.CDECL,
            Pb.CC_ELLIPSIS: CallingConvention.ELLIPSIS,
            Pb.CC_STDCALL: CallingConvention.STDCALL,
            Pb.CC_PASCAL: CallingConvention.PASCAL,
            Pb.CC_FASTCALL: CallingConvention.FASTCALL,
            Pb.CC_THISCALL: CallingConvention.THISCALL,
            Pb.CC_SWIFT: CallingConvention.SWIFT,
            Pb.CC_GOLANG: CallingConvention.GOLANG,
            Pb.CC_GOSTK: CallingConvention.GOSTK,
        }[proto_cc]
        

class Disassembler(enum.Enum):
    """Disassembler"""

    UNKNOWN = enum.auto()
    IDA = enum.auto()
    GHIDRA = enum.auto()
    BINARY_NINJA = enum.auto()

    @staticmethod
    def from_proto(
        proto_disass: "Pb.Meta.Backend.Disassembler",
    ) -> "Disassembler":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            Pb.Meta.Backend.Disassembler.DISASS_IDA: Disassembler.IDA,
            Pb.Meta.Backend.Disassembler.DISASS_GHIDRA: Disassembler.GHIDRA,
            Pb.Meta.Backend.Disassembler.DISASS_BINARY_NINJA: Disassembler.BINARY_NINJA,
        }

        return mapping.get(proto_disass, Disassembler.UNKNOWN)
