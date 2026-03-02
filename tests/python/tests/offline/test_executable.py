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

import quokka


def test_read_string_unknown_size(prog: quokka.Program):
    data_address: int = 0x3088
    assert prog.executable.read_string(data_address) == "F00d1e"


def test_read_string(prog: quokka.Program):
    # "F00d1e" is 6 chars + null terminator
    assert prog.executable.read_string(0x3088, 7) == "F00d1e"
