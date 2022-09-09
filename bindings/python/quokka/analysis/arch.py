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

import capstone
import collections
from enum import IntEnum, IntFlag
from quokka.types import List, RegType


def make_enums(
    capstone_module, items: List[str], blacklist: List[str], flags_enums: List[str]
) -> List:
    """Make enums from capstone module

    Dynamically generate enums from capstone constants
    0
    Arguments:
        capstone_module: Capstone module
        items: Name of enums
        blacklist: Fields to not consider
        flags_enums: List of flag enums

    Returns:
        A list of IntEnum/IntFlag
    """
    data = collections.defaultdict(dict)
    for k, v in getattr(capstone_module, "__dict__").items():
        _, cat, name = k.split("_", maxsplit=2)
        if name not in blacklist:
            name = "_" + name if "0" <= name[0] <= "9" else name
            data[cat][name] = v

    return [
        IntEnum(x, names=data[x], module=__name__)
        if x not in flags_enums
        else IntFlag(x, names=data[x], module=__name__)
        for x in items
        if x
    ]


class ArchEnum(IntEnum):
    """
    Enum identifying various architectures. The integer
    values are based on capstone enum.
    """

    UNKNOWN = capstone.CS_ARCH_ALL
    ARM = capstone.CS_ARCH_ARM
    ARM64 = capstone.CS_ARCH_ARM64
    EVM = capstone.CS_ARCH_EVM
    M680X = capstone.CS_ARCH_M680X
    M68K = capstone.CS_ARCH_M68K
    MIPS = capstone.CS_ARCH_MIPS
    PPC = capstone.CS_ARCH_PPC
    SPARC = capstone.CS_ARCH_SPARC
    SYSZ = capstone.CS_ARCH_SYSZ
    TMS320C64X = capstone.CS_ARCH_TMS320C64X
    X86 = capstone.CS_ARCH_X86
    XCORE = capstone.CS_ARCH_XCORE


class QuokkaArch:
    """Base class for a QuokkaArch"""
    address_size: int
    compared_mnemonics: List[str]
    stack_pointer: RegType
    inst_pointer: RegType


class ArchX86(QuokkaArch):  # type: ignore
    """Arch X86 definition"""

    address_size = 32

    regs, insts, groups, prefixes, optypes, _flags_state = make_enums(
        capstone_module=capstone.x86_const,
        items=["REG", "INS", "GRP", "PREFIX", "OP", "EFLAGS"],
        blacklist=["ENDING"],
        flags_enums=["EFLAGS"],
    )

    compared_mnemonics = [insts.CMP, insts.TEST]

    frame_pointer = regs.EBP
    stack_pointer = regs.ESP
    inst_pointer = regs.EIP


class ArchX64(ArchX86):  # type: ignore
    """Arch X64 definition"""
    address_size = 64

    frame_pointer = ArchX86.regs.RBP
    stack_pointer = ArchX86.regs.RSP
    inst_pointer = ArchX86.regs.RIP


class ArchARM(QuokkaArch):  # type: ignore
    """ArchARM definition"""
    (
        cc,
        cpsflag,
        cpsmode,
        grps,
        insts,
        mb,
        op,
        regs,
        setend,
        sft,
        sysreg,
        vd,
    ) = make_enums(
        capstone_module=capstone.arm_const,
        items=[
            "CC",
            "CPSFLAG",
            "CPSMODE",
            "GRP",
            "INS",
            "MB",
            "OP",
            "REG",
            "SETEND",
            "SFT",
            "SYSREG",
            "VECTORDATA",
        ],
        blacklist=["ENDING", "R13", "R14", "R15", "R9", "R10", "R11", "R12"],
        flags_enums=["SYSREG"],
    )

    address_size = 32
    compared_mnemonics = [
        insts.CBNZ,
        insts.CMP,
        insts.CBZ,
        insts.CMN,
    ]

    frame_pointer = regs.FP
    stack_pointer = regs.SP
    inst_pointer = regs.PC


class ArchARMThumb(ArchARM):  # type: ignore
    """Arch Arm Thum definition"""
    thumb: bool = True


class ArchARM64(QuokkaArch):  # type: ignore
    """Arch Arm64 definition"""
    (
        at,
        barrier,
        cc,
        dc,
        ext,
        grp,
        ic,
        insts,
        op,
        prfm,
        pstate,
        regs,
        sft,
        sysreg,
        tlbi,
        vas,
        vess,
    ) = make_enums(
        capstone_module=capstone.arm64_const,
        items=[
            "AT",
            "BARRIER",
            "CC",
            "DC",
            "EXT",
            "GRP",
            "IC",
            "INS",
            "OP",
            "PRFM",
            "PSTATE",
            "REG",
            "SFT",
            "SYSREG",
            "TLBI",
            "VAS",
            "VESS",
        ],
        blacklist=["ENDING", "X16", "X17", "X29", "X30"],
        flags_enums=[],
    )

    address_size = 64
    compared_mnemonics = [
        insts.CBZ,
        insts.CBNZ,
        insts.CMP,
        insts.CCMN,
        insts.CCMP,
        insts.CMN,
        insts.TBZ,
        insts.TBNZ,
    ]

    frame_pointer = regs.FP
    stack_pointer = regs.SP  # TODO(dm)!
    inst_pointer = regs.X28
