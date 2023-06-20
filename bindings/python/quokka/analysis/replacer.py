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
import quokka
from quokka.types import List, Dict, Any, RegType


class Replacer:
    """Replacer class

    Warning: This class has been used in some experiments but will/should probably be
    removed because it does not belong to the project.
    """

    ignored_registers: List[str]
    ignored_mnemonics: List[str]

    regs: RegType
    compared_mnemonics: List[str]
    calling_registers: List[RegType]

    replacement: Dict[RegType, RegType]

    @staticmethod
    def norm_mnemonic(mnemonic: str) -> str:
        """
        Norm a mnemonic (remove everything after '.').
        Examples:
            cmp.w -> CMP
            mov -> MOV

        Arguments:
            mnemonic: Mnemonic to norm

        Returns:
            Normed mnemonic
        """
        if "." in mnemonic:
            return mnemonic[: mnemonic.rfind(".")].upper()

        return mnemonic.upper()

    def get(self, item) -> RegType:
        assert self.replacement is not None
        if isinstance(item, RegType):
            return self.replacement.get(item, item)
        return item

    def is_ignored(self, item) -> bool:
        assert self.ignored_registers is not None
        return self.get(item) in self.ignored_registers

    def __call__(self, *args: Any, **kwargs: Any) -> RegType:
        return self.get(*args, **kwargs)

    def is_ignored_mnemonics(self, mnemonic: str) -> bool:
        assert self.ignored_mnemonics is not None
        return self.norm_mnemonic(mnemonic) in self.ignored_mnemonics

    def is_compared_mnemonic(self, mnemonic: str) -> bool:
        assert self.compared_mnemonics is not None
        return self.norm_mnemonic(mnemonic) in self.compared_mnemonics

    def calling_convention(self) -> List[RegType]:
        assert self.calling_registers is not None
        return self.calling_registers

    def argument_registers(self, platform: quokka.analysis.Platform) -> List:
        return []
