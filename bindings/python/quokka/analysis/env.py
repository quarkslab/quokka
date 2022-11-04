"""Environment module"""
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
import enum

from quokka.analysis import ArchX64, ArchX86, ArchARM, ArchARM64
from quokka.types import Type

import quokka
import quokka.analysis.calling_convention as cc


def get_calling_convention_for_arch_platform(
    platform: quokka.analysis.Platform,
    arch: Type[quokka.analysis.QuokkaArch],
) -> Type[cc.CallingConvention]:
    """Retrieve the calling convention used for this couple platform/arch

    Arguments:
        platform: Used platform
        arch: Used architecture

    Returns:
        A calling convention
    """
    mapping = {
        quokka.analysis.Platform.LINUX: {
            ArchX64: cc.SystemVAMD,  # Must be before x86
            ArchX86: cc.CCdecl,
            ArchARM: cc.ARMCC,
            ArchARM64: cc.ARM64CC,
        },
        quokka.analysis.Platform.WINDOWS: {
            ArchX86: cc.Stdcall,
            ArchX64: cc.MicrosoftAMD64,
        },
    }

    platform_mapping = mapping.get(platform)
    if platform_mapping is None:
        return cc.CallingConvention

    for architecture, convention in platform_mapping.items():
        if issubclass(arch, architecture):
            return convention

    return cc.CallingConvention


class Environment:
    """Environment base class

    Args:
        platform: Platform
        arch: Architecture

    Attributes:
        platform: Platform
        arch: Architecture
        calling_convention: Calling convention

    """

    def __init__(
        self,
        platform: quokka.analysis.Platform,
        arch: Type[quokka.analysis.arch.QuokkaArch],
    ):
        """Constructor"""
        self.platform: quokka.analysis.Platform = platform
        self.arch: Type[quokka.analysis.arch.QuokkaArch] = arch
        self.calling_convention: Type[
            cc.CallingConvention
        ] = get_calling_convention_for_arch_platform(platform, arch)


class Platform(enum.Enum):
    """Platform enumeration"""

    UNKNOWN = enum.auto()
    WINDOWS = enum.auto()
    LINUX = enum.auto()
    APPLE = enum.auto()
