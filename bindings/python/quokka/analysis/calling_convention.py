"""Calling conventions"""
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

from quokka.analysis import ArchX86, ArchX64, ArchARM, ArchARM64
from quokka.types import List, RegType


# Inspired from https://github.com/angr/angr/blob/master/angr/calling_conventions.py


class CallingConvention:
    """Base class for a calling convention"""

    name: str
    argument_registers: List[RegType]
    floating_point_registers: List[RegType]
    caller_saved_registers: List[RegType]
    callee_saved: bool = False

    return_value: RegType
    overflow_return: RegType


class CCdecl(CallingConvention):
    """Cdecl calling convention"""

    name = "cdecl"
    argument_registers: List[RegType] = []  # All arguments are on the stack
    floating_point_registers: List[RegType] = []  # Same
    caller_saved_registers = [
        ArchX86.regs.EAX,
        ArchX86.regs.ECX,
        ArchX86.regs.EDX,
    ]

    return_value = ArchX86.regs.EAX
    overflow_return = ArchX86.regs.EDX


class Stdcall(CCdecl):
    """Stdcall calling convention"""

    name = "stdcall"
    callee_saved = True


class Fastcall(CallingConvention):
    """Fastcall calling convention"""

    name = "fastcall"
    argument_registers = [ArchX86.regs.ECX, ArchX86.regs.EDX]
    floating_point_registers = [ArchX86.regs.ST0, ArchX86.regs.ST1]  # TODO(dm) check
    caller_saved_registers = [
        ArchX86.regs.EBX,
        ArchX86.regs.EBX,
        ArchX86.regs.ESI,
        ArchX86.regs.EDI,
    ]

    return_value = ArchX86.regs.EAX
    overflow_return = ArchX86.regs.EDX


class MicrosoftAMD64(CallingConvention):
    """Microsoft 64 calling convention"""

    name = "ms"
    argument_registers = [
        ArchX64.regs.RCX,
        ArchX64.regs.RDX,
        ArchX64.regs.R8,
        ArchX64.regs.R9,
    ]

    floating_point_registers = [
        ArchX64.regs.XMM0,
        ArchX64.regs.XMM1,
        ArchX64.regs.XMM2,
        ArchX64.regs.XMM3,
    ]

    return_value = ArchX64.regs.RAX
    overflow_return = ArchX64.regs.RDX


class SystemVAMD(CallingConvention):
    """SysV calling convention"""

    name = "sysv"
    argument_registers = [
        ArchX64.regs.RDI,
        ArchX64.regs.RSI,
        ArchX64.regs.RDX,
        ArchX64.regs.RCX,
        ArchX64.regs.R8,
        ArchX64.regs.R9,
    ]

    floating_point_registers = [
        ArchX64.regs.XMM0,
        ArchX64.regs.XMM1,
        ArchX64.regs.XMM2,
        ArchX64.regs.XMM3,
        ArchX64.regs.XMM4,
        ArchX64.regs.XMM5,
        ArchX64.regs.XMM6,
        ArchX64.regs.XMM7,
    ]

    caller_saved_registers = argument_registers + [
        ArchX64.regs.R10,
        ArchX64.regs.R11,
        ArchX64.regs.RAX,
    ]

    return_value = ArchX64.regs.RAX
    overflow_return = ArchX64.regs.RDX


class ARMCC(CallingConvention):
    """AAPCS calling convention for ARM"""

    name = "aapcs"
    argument_registers = [
        ArchARM.regs.R0,
        ArchARM.regs.R1,
        ArchARM.regs.R2,
        ArchARM.regs.R3,
    ]
    floating_point_registers: List[RegType] = []  # TODO
    caller_saved_registers: List[RegType] = []
    return_value = ArchARM.regs.R0


class ARM64CC(CallingConvention):
    """AAPCS calling convention for Aarch64"""

    name = "aapcs"
    argument_registers = [
        ArchARM64.regs.X0,
        ArchARM64.regs.X1,
        ArchARM64.regs.X2,
        ArchARM64.regs.X3,
        ArchARM64.regs.X4,
        ArchARM64.regs.X5,
        ArchARM64.regs.X6,
        ArchARM64.regs.X7,
    ]

    floating_point_registers: List[RegType] = []  # TODO
    caller_saved_registers: List[RegType] = []
    return_value = ArchARM64.regs.X0
