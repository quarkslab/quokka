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
    AccessMode,
    Sequence,
    Union,
    OperandType
)
from quokka.reference import TypeReference

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
        self.xrefs: Any = {}

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

    @property
    @abstractmethod
    def access(self) -> AccessMode:
        """Returns the operand access mode

        Returns:
            The operand access mode
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

    @property
    def access(self) -> AccessMode:
        match self.proto.access:
            case 1:
                return AccessMode.READ
            case 2:
                return AccessMode.WRITE
            case 3:
                return AccessMode.READ | AccessMode.WRITE
        assert False, f"Unknown access mode {self.proto.access}"

    def __str__(self) -> str:
        return self.program.proto.operand_strings[self.proto.operand_string_index]


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
    def access(self) -> AccessMode:
        match self.cs_op.access:
            case 1:
                return AccessMode.READ
            case 2:
                return AccessMode.WRITE
            case 3:
                return AccessMode.READ | AccessMode.WRITE
        assert False, f"Unknown access mode {self.cs_op.access}"

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
        backend_inst: Optional[capstone.CsInsn] = None,
    ):
        self.parent: quokka.Block = block

        if self.program.mode == ExporterMode.FULL:
            self._proto = self.program.proto.instructions[proto_index]
        elif self.program.mode == ExporterMode.LIGHT:
            self._proto = None
            self._cs_inst = backend_inst

        # self.inst_tuple = (block.parent.proto_index, block.proto_index, inst_index)

        # Retrieve xrefs (for the instruction)
        self._xrefs_from = [self.program.proto.references[x.xref_index] for x in block.proto.instructions_xref_from if x.instr_bb_idx == inst_index]
        self._xrefs_to = [self.program.proto.references[x.xref_index] for x in block.proto.instructions_xref_to if x.instr_bb_idx == inst_index]


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
    def data_refs_to(self) -> List[AddressT]:
        """Returns all data reference to this instruction"""
        # If querying refs_to get the source address
        return [xref.source.address for xref in self._xrefs_to if xref.reference_type == quokka.pb.Quokka.Reference.REF_DATA]

    @property
    def data_refs_from(self) -> List[AddressT]:
        """Returns all data reference from this instruction"""
        # If querying refs_from get the destination address
        return [xref.destination.address for xref in self._xrefs_from if xref.reference_type == quokka.pb.Quokka.Reference.REF_DATA]

    @property
    def code_refs_from(self) -> List[AddressT]:
        """Returns all code reference from this instruction"""
        # If querying refs_from get the destination address
        return [xref.destination.address for xref in self._xrefs_from if xref.reference_type == quokka.pb.Quokka.Reference.REF_CODE]

    @property
    def code_refs_to(self) -> List[AddressT]:
        """Returns all code reference to this instruction"""
        # If querying refs_to get the source address
        return [xref.source.address for xref in self._xrefs_to if xref.reference_type == quokka.pb.Quokka.Reference.REF_CODE]

    @property
    def type_refs_from(self) -> List[TypeReference]:
        """Returns all type reference from this instruction"""
        # Get protobuf type ids
        type_ids = [xref.destination.data_type_identifier for xref in self._xrefs_from if xref.reference_type == quokka.pb.Quokka.Reference.REF_SYMBOL]
        # Resolve type ids to actual types
        return [self.program.get_type(type_id) for type_id in type_ids]
    
    @property
    def call_references(self) -> List[AddressT]:
        """Returns all call reference to this instruction"""
        # Check if the reference address points to a function head
        return [addr for addr in self.code_refs_from if addr in self.program]

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
                operands.append(OperandFull(self.program, op))
        else:
            assert False

        self._resolve_xrefs_on_operands(operands)

        return operands

    def _resolve_xrefs_on_operands(self, operands: list[Operand]) -> None:
        """Resolve xrefs on the instruction operands and update them accordingly

        Arguments:
            operands: List of operands to update with xref information
        """
        mem_ops = [x for x in operands if x.type == OperandType.MEMORY]
        imm_ops = [x for x in operands if x.type == OperandType.IMMEDIATE]

        for dxref in (x for x in self._xrefs_from if x.reference_type == quokka.pb.Quokka.Reference.REF_DATA):
            # If there is only one memory operand assign data ref to it
            if len(operands) == 1:  # Only one operand, assign the data ref to it
                operands[0].xrefs[ReferenceType.DATA] = dxref
            elif len(mem_ops) == 1:  # Only one memory operand, assign the data ref to it
                mem_ops[0].xrefs[ReferenceType.DATA] = dxref
            elif len(imm_ops) == 1:  # Only one immediate operand, assign the data ref to it
                imm_ops[0].xrefs[ReferenceType.DATA] = dxref
            else:
                logger.warning(f"{self.address:#x} inst {str(self)} can't assign data refs")
        
        for cxref in (x for x in self._xrefs_from if x.reference_type == quokka.pb.Quokka.Reference.REF_CODE):
            # If there is only one memory operand assign code ref to it
            if len(operands) == 1:  # Only one operand, assign the code ref to it
                operands[0].xrefs[ReferenceType.CODE] = cxref
            elif len(mem_ops) == 1:  # Only one memory operand, assign the code ref to it
                mem_ops[0].xrefs[ReferenceType.CODE] = cxref
            elif len(imm_ops) == 1:  # Only one immediate operand, assign the code ref to it
                imm_ops[0].xrefs[ReferenceType.CODE] = cxref
            else:
                logger.warning(f"{self.address:#x} inst {str(self)} can't assign code refs")


    @cached_property
    def call_target(self) -> quokka.Function:
        """Find the call target of an instruction if any exists.
        Does not resolve thunk functions.
        
        Raises FunctionMissingError if the call target is not
        found.
        """
        call_targets = self.call_references

        if not call_targets:
            raise quokka.FunctionMissingError(f"No call reference found for instruction at 0x{self.address:x}")
        elif len(call_targets) > 1:
            logger.warning(f"Multiple call references found for instruction at 0x{self.address:x}, taking the first one")
            raise quokka.FunctionMissingError(f"Multiple call references found for instruction at 0x{self.address:x}")
        else:  # Only on call reference, take it
            return self.program[call_targets[0]]

    @property
    def has_call(self) -> bool:
        """Check if the instruction has a call target (namely
        code refs on a function entrypoint)"""
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
