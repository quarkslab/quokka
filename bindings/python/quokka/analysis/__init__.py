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

from quokka.analysis.arch import (
    QuokkaArch,
    ArchEnum,
    ArchX86,
    ArchX64,
    ArchARM,
    ArchARM64,
    ArchARMThumb,
)

from quokka.analysis.calling_convention import (
    CallingConvention,
    CCdecl,
    Stdcall,
    Fastcall,
    MicrosoftAMD64,
    SystemVAMD,
    ARMCC,
    ARM64CC,
)

from quokka.analysis.env import (
    get_calling_convention_for_arch_platform,
    Environment,
    Platform,
)

from quokka.analysis.replacer import Replacer

from quokka.analysis.utils import split_chunk

__all__ = [
    # From arch.py
    QuokkaArch,
    ArchEnum,
    ArchX86,
    ArchX64,
    ArchARM,
    ArchARM64,
    ArchARMThumb,
    # From calling_convention.py
    CallingConvention,
    CCdecl,
    Stdcall,
    Fastcall,
    MicrosoftAMD64,
    SystemVAMD,
    ARMCC,
    ARM64CC,
    # From env.py
    get_calling_convention_for_arch_platform,
    Environment,
    Platform,
    # From utils.py
    split_chunk,
    # From replacer.py
    Replacer,
]
