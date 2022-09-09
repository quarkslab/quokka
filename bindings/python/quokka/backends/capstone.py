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
import capstone

import quokka
import quokka.analysis

from quokka.types import AddressT, Type, Optional


def get_capstone_context(arch: Type[quokka.analysis.QuokkaArch]) -> capstone.Cs:
    """Compute the capstone context for the program

    The Capstone context is used to decode instructions afterwards. Since we are
    interested in most of the details, we already set the details to True.

    Arguments:
        arch: Quokka program architecture

    Returns:
        A capstone Cs instance
    """
    mapping = {
        quokka.analysis.ArchARM: (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
        quokka.analysis.ArchARM64: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        quokka.analysis.ArchX86: (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        quokka.analysis.ArchX64: (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        quokka.analysis.ArchARMThumb: (
            capstone.CS_ARCH_ARM,
            capstone.CS_MODE_THUMB,
        ),
    }

    try:
        capstone_arch, capstone_mode = mapping.get(arch)
    except TypeError:
        raise quokka.CapstoneError("Unable to find the Architecture")

    context = capstone.Cs(capstone_arch, capstone_mode)
    context.detail = True

    return context


def _decode(
    context: capstone.Cs, opcode: bytes, address: AddressT, count: int = 1
) -> Optional[capstone.CsInsn]:
    """Inner method to decode with capstone

    Arguments:
        context: A capstone context (see `get_capstone_context`)
        opcode: Bytes to decode
        address: Address of the instruction
        count: Number of instructions to decode

    Returns:
        A capstone instruction if any are found
    """
    capstone_insts = context.disasm(opcode, address, count)
    return next(capstone_insts, None)


def update_capstone_context(program: quokka.Program, is_thumb: bool) -> capstone.Cs:
    """Returns an appropriate context for Capstone instructions

    For ARM architecture, if the instruction is Thumb, we must use a different context.

    Arguments:
        program: Program to consider
        is_thumb: Is the instruction a thumb one?

    Returns:
        The correct capstone context
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
        return get_capstone_context(quokka.analysis.ArchARMThumb)

    return program.capstone


def capstone_decode_instruction(
    inst: quokka.Instruction,
) -> Optional[capstone.CsInsn]:
    """Decode an instruction with capstone

    Decode an instruction and retry for ARM to check if the Thumb mode was activated
    The decoding logic is done by the inner method `_decode`.

    Arguments:
        inst: Instruction to translate

    Returns:
        A capstone instruction if it has been decoded
    """

    context: capstone.Cs = update_capstone_context(inst.program, inst.thumb)
    capstone_inst = _decode(context, inst.bytes, inst.address, count=1)

    if capstone_inst is None and context.arch == capstone.CS_ARCH_ARM:
        if context.mode == capstone.CS_MODE_THUMB:
            new_context = get_capstone_context(quokka.analysis.ArchARM)
        else:
            new_context = get_capstone_context(quokka.analysis.ArchARMThumb)

        capstone_inst = _decode(new_context, inst.bytes, inst.address, count=1)

    return capstone_inst
