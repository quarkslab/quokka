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

from collections import defaultdict
from functools import cached_property
import capstone
import pypcode

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
)

logger: logging.Logger = logging.getLogger(__name__)


class Operand:
    """Operand object

    An operand is an "argument" for an instruction.
    This class represent them but is rather lackluster at the moment.

    Arguments:
        proto_operand: Protobuf data
        capstone_operand: Capstone data (if any)
        program: Program reference

    Attributes:
        program: Program reference
        type: Operand type
        flags: Operand flags
        address: Operand address
        value_type: IDA value type
        reg_id: IDA register ID (if applicable)
        details: Capstone details
    """

    # Operand rewrite to integrate capstone information as well

    def __init__(
        self,
        proto_operand: "quokka.pb.Quokka.Operand",
        capstone_operand=None,
        program: Union[None, quokka.Program] = None,
    ):
        """Constructor"""
        self.program: quokka.Program = program

        self.type: int = proto_operand.type
        self.flags: int = proto_operand.flags  # TODO(dm)

        self.address: Optional[int] = (
            proto_operand.address if proto_operand.address != 0 else None
        )

        self.value_type = proto_operand.value_type
        self.reg_id = proto_operand.register_id

        self._value = proto_operand.value

        self.details = capstone_operand

    @property
    def value(self) -> Any:
        """Returns the operand value
        Warning: this is only implemented for constant operand (in IDA).

        Returns:
            The operand value

        """
        if self.type == 5:  # Type: IDA constant
            return self._value

        raise NotImplementedError

    def is_constant(self) -> bool:
        """Check if the operand is a constant"""
        return self.type == 5


class Instruction:
    """Instruction class

    An instruction is the binary bread-and-butter.
    This class abstract some elements and offer various backends integration if needed.

    Arguments:
        proto_index: Protobuf index of the instruction
        inst_index: Instruction index in the parent block
        address: Instruction address
        block: Parent block reference

    Attributes:
        program: Reference to the program
        parent: Parent block
        proto_index: Protobuf index of the instruction
        inst_tuple: A tuple composed of the (chunk_index, block_index, inst_index). This
            uniquely identify an instruction within the program.
        thumb: is the instruction thumb?
        index: Instruction index in the parent block
    """

    def __init__(
        self,
        proto_index: Index,
        inst_index: int,
        address: AddressT,
        block: quokka.Block,
    ):
        self.program: quokka.Program = block.program
        self.parent: quokka.Block = block
        self.proto_index: Index = proto_index

        self.inst_tuple = (block.parent.proto_index, block.proto_index, inst_index)

        instruction = self.program.proto.instructions[proto_index]

        self.size = instruction.size
        self.thumb = instruction.is_thumb

        self.index: int = inst_index

        # TODO(dm) Sometimes, IDA merge two instruction in one
        #  (e.g. 0x1ab16 of d53a), deal with that
        self.address: AddressT = address

    @cached_property
    def mnemonic(self) -> str:
        """Return the mnemonic for the instruction.

        First, try to use capstone because it's prettier
        Otherwise, fallback to the IDA mnemonic which is better than nothing.

        Returns:
            A string representation of the mnemonic
        """
        if self.cs_inst is not None:
            return self.cs_inst.mnemonic

        instruction = self.program.proto.instructions[self.proto_index]
        return self.program.proto.mnemonics[instruction.mnemonic_index]

    @cached_property
    def cs_inst(self) -> Optional[capstone.CsInsn]:
        """Load an instruction from Capstone backend

        If the decoding fails, the result won't be cached, and it will be attempted
        again.

        Returns:
            A Capstone instruction

        """
        return quokka.backends.capstone_decode_instruction(self)

    @cached_property
    def pcode_insts(self) -> Sequence[pypcode.PcodeOp]:
        """Retrieve the PcodeOps associated to the instruction

        Returns:
            A sequence of PCode instructions
        """
        return quokka.backends.pypcode_decode_instruction(self)

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
    def operands(self) -> List[Operand]:
        """Retrieve the instruction operands and initialize them with Capstone"""
        operands: List[Operand] = []

        inst = self.program.proto.instructions[self.proto_index]

        try:
            capstone_operands = len(self.cs_inst.operands)
        except AttributeError:
            capstone_operands = 0

        operand_count = max(capstone_operands, len(inst.operand_index))

        for idx in range(operand_count):
            try:
                operand_index = inst.operand_index[idx]
            except IndexError:
                # logger.debug('Less IDA operands than capstone')
                continue

            details = None
            try:
                details = self.cs_inst.operands[idx]
            except (IndexError, quokka.exc.InstructionError):
                # logger.debug('Missing an IDA operand for capstone')
                pass

            # TODO(dm): Allow partial operands with only half of the data
            if operand_index != -1:
                operands.append(
                    Operand(
                        self.program.proto.operands[operand_index],
                        capstone_operand=details,
                        program=self.program,
                    )
                )

        return operands

    @cached_property
    def call_target(self) -> quokka.Chunk:
        """Find the call target of an instruction if any exists"""
        call_target = False

        candidates = set()
        for reference in self.program.references.resolve_inst_instance(
            self.inst_tuple, ReferenceType.CALL, towards=False
        ):
            # FIX: in Quokka a bug existed where the call target could be data
            if isinstance(reference.destination, tuple):
                candidates.add(reference.destination[0])  # A chunk
            elif isinstance(reference.destination, quokka.Chunk):
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
        constants = []
        for op_index in self.program.proto.instructions[self.proto_index].operand_index:
            operand: quokka.pb.Quokka.Operand = self.program.proto.operands[op_index]
            if operand.type == 5:

                # FIX: This bug is due to IDA mislabelling operands for some
                #   operations like ADRP on ARM where the operand points to a
                #   memory area (2) but the type is CONSTANT (5).
                #   The behavior is inconsistent with LEA on Intel arch where
                #   the operand is properly labelled (either 2 or 5).
                if not self.data_references:
                    constants.append(operand.value)

        return constants

    def __str__(self) -> str:
        """String representation of the instruction

        First, try by capstone because it's prettier
        Otherwise, fallback to the mnemonic which is better than nothing.

        Returns:
            A string representation of the mnemonic
        """

        # First, try with the operand strings (case MODE FULL)
        inst = self.program.proto.instructions[self.proto_index]
        if self.program.mode == ExporterMode.FULL:
            operands = ", ".join(
                self.program.proto.operand_table[x] for x in inst.operand_strings
            )
            return f"<Inst {self.mnemonic} {operands}>"

        # Second tentative, use capstone
        if self.cs_inst is not None:
            return f"<{self.cs_inst.mnemonic} {self.cs_inst.op_str}>"

        # Finally, just use the mnemonic
        return f"<Inst {self.mnemonic}>"

    @cached_property
    def bytes(self) -> bytes:
        """Read the program binary to find the bytes associated to the instruction.

        This is not cached as it is already in memory.

        Returns:
            Bytes associated to the instruction
        """
        try:
            file_offset = self.program.addresser.file(self.address)
        except quokka.exc.NotInFileError:
            return b""

        return self.program.executable.read_byte(
            offset=file_offset,
            size=self.size,
        )
