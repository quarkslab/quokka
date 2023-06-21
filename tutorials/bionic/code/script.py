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


"""BIONIC User ID extractor

This snippet uses Quokka to extract the user ID mapping from a Bionic LibC

Usage:
    python ./script <bionic_path>

Author:
    Written by dm (Alexis Challande) in 2022.
"""

import quokka
from quokka import Data
from quokka.types import AddressT, DataType


def print_usertable(bionic: quokka.Program):
    """Extract the user table with a bionic libc"""

    # Step1 : Find the function
    getpwuid = bionic.get_function("getpwuid", approximative=False)

    # Step 2: find the data ref
    user_table: Data = getpwuid.data_references[1]

    # Step 3: Read the first entry
    users = []

    first_user = bionic.executable.read_string(user_table.value)
    first_id = bionic.get_data(user_table.address + 0x4).value
    users.append((first_user, first_id))

    # Read other entries
    def read_userid(prog: quokka.Program, address: AddressT) -> int:
        return prog.executable.read_data(
            prog.addresser.file(address), DataType.DOUBLE_WORD
        )

    # Gather all components together
    start = user_table.address + 0x8
    while True:
        data: Data = bionic.get_data(start)
        if data.code_references:
            break

        user_name = bionic.executable.read_string(data.value)
        user_id = read_userid(bionic, data.address + 0x4)

        print(f"New user {user_name} with ID {user_id}")
        users.append((user_name, user_id))

        start += 0x8

    # Print the user table
    for user_name, user_id in users:
        print(f"{user_name=} : {user_id=}")


if __name__ == "__main__":
    program: quokka.Program = quokka.Program.from_binary(sys.argv[1])
    print_usertable(program)
