"""PyPCode integration"""
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

import itertools
import logging

import pypcode

import quokka
import quokka.analysis
from quokka.types import Any, Dict, Endianness, List, Sequence, Type, Optional

logger: logging.Logger = logging.getLogger(__name__)


def get_arch_from_string(target_id: str) -> pypcode.ArchLanguage:
    """Find the architecture for an arch based on the target identification

    Arguments:
        target_id: Identifier of the architecture

    Raises:
        PypcodeError: if the architecture is not found

    Returns:
        The appropriate ArchLang
    """
    pcode_arch: pypcode.Arch
    for pcode_arch in pypcode.Arch.enumerate():
        for lang in pcode_arch.languages:
            if lang.id == target_id:
                return lang

    raise quokka.PypcodeError("Unable to find the appropriate arch: missing lang")


def get_pypcode_context(
        arch: Type[quokka.analysis.QuokkaArch],
        endian: Type[Endianness] = Endianness.LITTLE_ENDIAN
) -> pypcode.Context:
    """Convert an arch from Quokka to Pypcode

    For the moment, only the arch described in quokka.analysis are supported.
    This method is a bit slow because enum are generated by pypcode on the fly but should
    be executed only once.

    Arguments:
        arch: Quokka program architecture
        endian: Architecture endianness

    Raises:
        PypcodeError: if the conversion for arch is not found

    Returns:
        A pypcode.Context instance
    """
    names: Dict[Type[quokka.analysis.arch.QuokkaArch], str] = {
        quokka.analysis.ArchX64: "x86:LE:64:default",
        quokka.analysis.ArchX86: "x86:LE:32:default",
        quokka.analysis.ArchARM: "ARM:LE:32:v8",
        quokka.analysis.ArchARM64: "AARCH64:LE:64:v8A",
        quokka.analysis.ArchARMThumb: "ARM:LE:32:v8T",
        quokka.analysis.ArchMIPS: "MIPS:LE:32:default",
        quokka.analysis.ArchMIPS64: "MIPS:LE:64:default",
        quokka.analysis.ArchPPC: "PowerPC:LE:32:default",
        quokka.analysis.ArchPPC64: "PowerPC:LE:64:default",
    }

    try:
        target_id = names[arch]
    except KeyError as exc:
        raise quokka.PypcodeError(
            "Unable to find the appropriate arch: missing id"
        ) from exc

    if endian == Endianness.BIG_ENDIAN:
        target_id = target_id.replace(":LE:", ":BE:")

    pcode_arch = get_arch_from_string(target_id)
    return pypcode.Context(pcode_arch)


def update_pypcode_context(program: quokka.Program, is_thumb: bool) -> pypcode.Context:
    """Return an appropriate pypcode context for the decoding

    For ARM architecture, if the block starts with a Thumb instruction, we must use
    a different pypcode Context.

    We use the boolean `is_thumb` directly to allow caching of the call here because it
    is costly to generate the context.

    Arguments:
        program: Program to consider
        is_thumb: Is the instruction a thumb one?

    Returns:
        The correct pypcode context
    """

    if (
        program.arch
        in (
            quokka.analysis.ArchARM,
            quokka.analysis.ArchARM64,
            quokka.analysis.ArchARMThumb,
        )
        and is_thumb
    ):
        return get_pypcode_context(quokka.analysis.ArchARMThumb)

    return program.pypcode


def pypcode_decode_block(block: quokka.Block) -> List[pypcode.PcodeOp]:
    """Decode a block at once.

    This method decode a block of instructions using Pypcode context all at once.
    This is faster than multiple calls to the decode at the instruction level.

    Arguments:
        block: Block to decode

    Returns:
        A list of pcode operations
    """

    # Fast guard, empty blocks do not have any Pcode operations
    first_instruction: Optional[quokka.Instruction] = next(block.instructions, None)
    if first_instruction is None:
        return []

    # Retrieve the context from the instruction
    context: pypcode.Context = update_pypcode_context(
        block.program, first_instruction.thumb
    )

    try:
        # Translate
        translation = context.translate(
            block.bytes,  # buf
            block.start,  # base_address
            0,  # max_bytes
            0,  # max_instructions
        )
        return translation.ops

    except pypcode.BadDataError as e:
        logger.error(e)
        raise quokka.PypcodeError(f"Decoding error for block at 0x{block.start:x} (BadDataError)")
    except pypcode.UnimplError as e:
        logger.error(e)
        raise quokka.PypcodeError(f"Decoding error for block at 0x{block.start:x} (UnimplError)")


def pypcode_decode_instruction(
    inst: quokka.Instruction,
) -> Sequence[pypcode.PcodeOp]:
    """Decode an instruction using Pypcode

    This will return the list of Pcode operations done for the instruction.
    Note that a (binary) instruction is expected to have several pcode instructions
    associated. When decoding a single instruction IMARK instructions are excluded!

    Arguments:
        inst: Instruction to translate

    Raises:
        PypcodeError: if the decoding fails

    Returns:
        A sequence of PcodeOp
    """

    context: pypcode.Context = update_pypcode_context(inst.program, inst.thumb)
    try:
        translation = context.translate(
            inst.bytes,  # buf
            inst.address,  # base_address
            0,  # max_bytes
            1,  # max_instructions
        )

        return [x for x in translation.ops if x.opcode != pypcode.OpCode.IMARK]

    except pypcode.BadDataError as e:
        logger.error(e)
        raise quokka.PypcodeError(f"Unable to decode instruction (BadDataError)")
    except pypcode.UnimplError as e:
        logger.error(e)
        raise quokka.PypcodeError(f"Unable to decode instruction (UnimplError)")
