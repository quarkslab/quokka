"""Exceptions for quokka.

All exceptions must derive from the QuokkaError.
"""

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


class QuokkaError(Exception):
    """Base exception in Quokka"""

    pass


class NotInFileError(QuokkaError):
    """Raised when trying to read a string outside the file"""

    pass


class ChunkMissingError(QuokkaError):
    """Raised when a chunk has not been found"""

    pass


class FunctionMissingError(QuokkaError):
    """Raised when a function has not been found"""

    pass


class ThunkMissingError(QuokkaError):
    """Raised when a thunk has not been found"""

    pass


class InstructionError(QuokkaError):
    """Raised when serious errors in Instructions handling"""

    pass


class CapstoneError(QuokkaError):
    """Exceptions used for Capstone integration"""

    pass


class PypcodeError(QuokkaError):
    """Main exception for pypcode integration"""

    pass
