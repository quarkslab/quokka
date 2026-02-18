"""Methods to deal with instructions and operands within a binary"""

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
from abc import ABC, abstractmethod

from collections import defaultdict
from functools import cached_property
import capstone
from typing import TYPE_CHECKING

import quokka
from quokka.types import (
    AddressT,
    Any,
    DataType,
    Dict,
    ExporterMode,
    Index,
    List,
    Optional,
    ReferenceTarget,
    ReferenceType,
    Sequence,
    Union,
    OperandType,
    ExporterMode
)

if TYPE_CHECKING:
    import pypcode

logger: logging.Logger = logging.getLogger(__name__)


class Operand(ABC):
    """Abstract operand base class

    An operand is an "argument" for an instruction.
    This abstract class defines the interface for operand implementations.

    Arguments:
        program: Program reference

    Attributes:
        program: Program reference
        type: Operand type
        register: Register str (if applicable)
    """

    def __init__(self, program: quokka.Program):
        """Constructor"""
        self.program: quokka.Program = program

    @property
    @abstractmethod
    def value(self) -> Any:
        """Returns the operand value

        Returns:
            The operand value
        """
        pass

    @property
    @abstractmethod
    def type(self) -> Any:
        """Returns the operand type

        Returns:
            The operand type
        """
        pass

    @property
    @abstractmethod
    def register(self) -> Any:
        """Returns the operand type

        Returns:
            The operand type
        """
        pass



class OperandFull(Operand):
    """Operand implementation for full mode

    Uses the full protobuf data to provide operand values.
    """

    def __init__(self, program: quokka.Program, proto: "quokka.pb.Quokka.Operand"):
        """Constructor

        Arguments:
            proto_operand: Protobuf operand
            kwargs: Additional arguments for the operand (e.g. Capstone details)
        """
        super().__init__(program)
        self.proto = proto

    @property
    def type(self) -> OperandType:
        return OperandType.from_proto(self.proto.type)

    @property
    def value(self) -> Any:
        match self.type:
            case OperandType.IMMEDIATE:
                return self.proto.value
            case OperandType.REGISTER:
                # Go get register string in the register table of the program
                return self.program.proto.register_table[self.proto.register_index]
            case OperandType.MEMORY:
                return self.proto.address
            case OperandType.OTHER:
                return self.proto.other

    @property
    def register(self) -> str:
        if self.type == OperandType.REGISTER:
            return self.program.proto.register_table[self.proto.register_index]
        return ""

    def __str__(self) -> str:
        # FIXME: There is no way to retrieve it at the moment
        return f"TODO"

class OperandLight(Operand):
    """Operand implementation for light mode using Capstone

    Uses Capstone disassembly data to provide operand values.
    """

    def __init__(self, program: quokka.Program, cs_operand, cs_inst):
        """Constructor

        Arguments:
            program: Program reference
            capstone_obj: Capstone operand object
        """
        super().__init__(program)
        self.cs_op = cs_operand
        self._cs_inst = cs_inst

    @property
    def type(self) -> OperandType:
        if self.cs_op.type == capstone.CS_OP_IMM:
            return OperandType.IMMEDIATE
        elif self.cs_op.type == capstone.CS_OP_REG:
            return OperandType.REGISTER
        elif self.cs_op.type == capstone.CS_OP_MEM:
            return OperandType.MEMORY
        else:
            return OperandType.OTHER

    @property
    def value(self) -> Any:
        """Returns the operand value using Capstone data

        Returns:
            The operand value
        """
        match self.type:
            case OperandType.IMMEDIATE:
                return self.cs_op.imm
            case OperandType.REGISTER:
                return self.program.arch.regs(self.cs_op.reg)
            case OperandType.MEMORY:
                return self.cs_op.mem  #  atm: capstone.x86.X86OpMem, ...
            case OperandType.OTHER:
                return None

    @property
    def register(self) -> str:
        """Returns the operand register using Capstone data

        Returns:
            The operand register (empty string if not a register)
        """
        if self.type == OperandType.REGISTER:
            return self.program.arch.regs(self.cs_op.reg).name
        return ""

    def __str__(self) -> str:
        try:
            index = self._cs_inst.operands.index(self.cs_op)
            return ",".split(self._cs_inst.op_str)[index]
        except ValueError:
            return f"<UNK>"


class Instruction:
    """Instruction class

    An instruction is the binary bread-and-butter.
    This class abstract some elements and offer various backends integration if needed.

    Arguments:
        proto_index: Protobuf index of the instruction
        inst_index: Instruction index in the block
        address: Instruction address
        block: Parent block reference

    Attributes:
        program: Reference to the program
        parent: Parent block
        proto_index: Protobuf index of the instruction
        inst_tuple: A tuple composed of the (function_index, block_index, inst_index). This
            uniquely identify an instruction within the program.
        thumb: is the instruction thumb?
        index: Instruction index in the parent block
    """

    def __init__(
        self,
        proto_index: Index,  # index in protobuf file
        inst_index: int,
        address: AddressT,
        block: quokka.Block,
    ):
        self.parent: quokka.Block = block

        if self.program.mode == ExporterMode.FULL:
            self._proto = self.program.proto.instructions[proto_index]
        elif self.program.mode == ExporterMode.LIGHT:
            self._proto = None

        self.inst_tuple = (block.parent.proto_index, block.proto_index, inst_index)

        #: Instruction index in the parent block
        self.index: int = inst_index

        # TODO(dm) Sometimes, IDA merge two instruction in one
        #  (e.g. 0x1ab16 of d53a), deal with that
        self.address: AddressT = address

    @property
    def proto(self) -> "quokka.pb.Quokka.Instruction":
        """Return the instruction protobuf if in full mode"""
        assert self._proto is not None
        return self._proto

    @property
    def program(self) -> quokka.Program:
        """Return the parent function of the instruction"""
        return self.parent.program

    @property
    def size(self) -> int:
        """Return the instruction size"""
        if self.program.mode == ExporterMode.FULL:
            return self.proto.size
        elif self.program.mode == ExporterMode.LIGHT:
            return self.cs_inst.size

    @property
    def is_thumb(self) -> bool:
        """Return whether the instruction is a thumb instruction"""
        if self.program.mode == ExporterMode.FULL:
            return self.proto.is_thumb
        elif self.program.mode == ExporterMode.LIGHT:
            return self.parent.is_thumb

    @cached_property
    def mnemonic(self) -> str:
        """Return the mnemonic for the instruction.

        First, try to use capstone because it's prettier
        Otherwise, fallback to the IDA mnemonic which is better than nothing.

        Returns:
            A string representation of the mnemonic
        """
        if self.program.mode == ExporterMode.LIGHT:
            return self.cs_inst.mnemonic  # return capstone mnemonic
        elif self.program.mode == ExporterMode.FULL:
            return self.program.proto.mnemonics[self.proto.mnemonic_index]
        else:
            assert False

    @cached_property
    def cs_inst(self) -> capstone.CsInsn:
        """Load an instruction from Capstone backend

        If the decoding fails, the result won't be cached, and it will be attempted
        again.

        Returns:
            A Capstone instruction

        """
        ins = quokka.backends.capstone_decode_instruction(self)
        assert ins is not None, f"Capstone failed to decode instruction at 0x{self.address:x}"
        return ins

    @cached_property
    def pcode_insts(self) -> Sequence[pypcode.PcodeOp]:
        """Retrieve the PcodeOps associated to the instruction

        Returns:
            A sequence of PCode instructions
        """
        from quokka.backends.pypcode import pypcode_decode_instruction

        return pypcode_decode_instruction(self)

    @cached_property
    def string(self) -> Optional[str]:
        """String used by the instruction (if any)"""
        for data in self.data_references:
            if isinstance(data, quokka.data.Data) and data.type == DataType.ASCII:
                return data.value

        return None

    @property
    def references(self) -> Dict[ReferenceType, List[ReferenceTarget]]:
        """Returns all the references towards the instruction"""

        ref = defaultdict(list)
        for reference in self.program.references.resolve_inst_instance(
            self.inst_tuple, towards=True
        ):
            ref[reference.type].append(reference.source)
        return ref

    @property
    def data_references(self) -> List[ReferenceTarget]:
        """Returns all data reference to this instruction"""
        return self.references[ReferenceType.DATA]

    @property
    def struct_references(self) -> List[ReferenceTarget]:
        """Returns all struct reference to this instruction"""
        return self.references[ReferenceType.STRUC]

    @property
    def enum_references(self) -> List[ReferenceTarget]:
        """Returns all enum reference to this instruction"""
        return self.references[ReferenceType.ENUM]

    @property
    def call_references(self) -> List[ReferenceTarget]:
        """Returns all call reference to this instruction"""
        return self.references[ReferenceType.CALL]

    @property
    def operands(self) -> list[Operand]:
        """Retrieve the instruction operands and initialize them with Capstone"""
        operands: list[Operand] = []

        if self.program.mode == ExporterMode.LIGHT:
            # Retrieve operands from Capstone
            for op in self.cs_inst.operands:
                operands.append(OperandLight(self.program, op, self.cs_inst))

        elif self.program.mode == ExporterMode.FULL:
            for op_idx in self.proto.operand_index:
                op = self.program.proto.operands[op_idx]
        else:
            assert False

        return operands

    @cached_property
    def call_target(self) -> quokka.Function:
        """Find the call target of an instruction if any exists"""
        call_target = False

        candidates = set()
        for reference in self.program.references.resolve_inst_instance(
            self.inst_tuple, ReferenceType.CALL, towards=False
        ):
            # FIX: in Quokka a bug existed where the call target could be data
            if isinstance(reference.destination, tuple):
                candidates.add(reference.destination[0])  # A function
            elif isinstance(reference.destination, quokka.Function):
                candidates.add(reference.destination)

        try:
            call_target = candidates.pop()
        except KeyError:
            pass

        if candidates:
            logger.warning(
                f"We found multiple candidate targets for 0x{self.address:x}"
            )

        return call_target

    @property
    def has_call(self) -> bool:
        """Check if the instruction has a call target"""
        return self.call_target is not False

    @cached_property
    def constants(self) -> List[int]:
        """Fast accessor for instructions constant not using Capstone."""
        return [x.value for x in self.operands if x.type == OperandType.IMMEDIATE]

    def __str__(self) -> str:
        """String representation of the instruction

        First, try by capstone because it's prettier
        Otherwise, fallback to the mnemonic which is better than nothing.

        Returns:
            A string representation of the mnemonic
        """

        if self.program.mode == ExporterMode.LIGHT:
            return f"{self.cs_inst.mnemonic} {self.cs_inst.op_str}"
        elif self.program.mode == ExporterMode.FULL:
            operands = ", ".join(
                self.program.proto.operand_table[x] for x in self.proto.operand_strings  # FIXME: operand_strings do not exists anymore
            )
            return f"{self.mnemonic} {operands}"
        else:
            assert False

    def __repr__(self) -> str:
        return f"<Ins 0x{self.address:x} {str(self)}>"

    @cached_property
    def bytes(self) -> bytes:
        """Read the program binary to find the bytes associated to the instruction.

        This is not cached as it is already in memory.

        Returns:
            Bytes associated to the instruction
        """
        try:
            file_offset = self.program.addresser.file(self.address)
        except quokka.NotInFileError:
            return b""

        return self.program.executable.read_bytes(
            offset=file_offset,
            size=self.size,
        )
