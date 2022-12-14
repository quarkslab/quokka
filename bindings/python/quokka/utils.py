"""Utilities functions"""

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

import functools
import hashlib
import pathlib
import logging

import quokka
from quokka.analysis import (
    QuokkaArch,
    ArchEnum,
    ArchX86,
    ArchX64,
    ArchARM,
    ArchARM64,
    ArchARMThumb,
)

from quokka.types import Type

logger = logging.getLogger()


def md5_file(file_path: pathlib.Path) -> str:
    """Compute the MD5 of a file"""
    md5 = hashlib.md5()
    with open(file_path.as_posix(), "rb") as fd:
        for byte in iter(lambda: fd.read(65535), b""):
            md5.update(byte)

    return md5.hexdigest()


def sha256_file(file_path: pathlib.Path) -> str:
    """Compute the SHA-256 of a file"""
    sha = hashlib.sha256()
    with open(file_path.as_posix(), "rb") as fd:
        for byte in iter(lambda: fd.read(65535), b""):
            sha.update(byte)

    return sha.hexdigest()


def check_hash(hash_proto: quokka.pb.Quokka.Meta.Hash, file_path: pathlib.Path) -> bool:
    """Check if the hash is valid

    This method computes the appropriate hash based on what is available in the export
    file and compare them.

    Arguments:
        hash_proto: Protobuf message containing the hash
        file_path: Path to the binary

    Returns:
        Boolean for success
    """
    hash_methods = {
        quokka.pb.Quokka.Meta.Hash.HASH_MD5: md5_file,
        quokka.pb.Quokka.Meta.Hash.HASH_SHA256: sha256_file,
    }

    hash_method = hash_methods.get(hash_proto.hash_type)
    if hash_method is None:
        logger.info("Failed to verify hash for file because no hash was provided.")
        return True

    file_hash = hash_method(file_path)
    return file_hash == hash_proto.hash_value


def get_isa(
    proto_isa: "quokka.pb.Quokka.Meta.ISAValue",
) -> ArchEnum:
    """Convert a proto isa to an architecture"""
    mapping = {
        quokka.pb.Quokka.Meta.PROC_INTEL: ArchEnum.X86,
        quokka.pb.Quokka.Meta.PROC_ARM: ArchEnum.ARM,
        quokka.pb.Quokka.Meta.PROC_PPC: ArchEnum.PPC,
        quokka.pb.Quokka.Meta.PROC_MIPS: ArchEnum.MIPS,
    }

    return mapping.get(proto_isa, ArchEnum.UNKNOWN)


def convert_address_size(
    proto_address_size: "quokka.pb.Quokka.AddressSizeValue",
) -> int:
    """Convert the proto address size to an int value

    Arguments:
        proto_address_size: Protobuf field

    Returns:
        An integer value

    Raises:
        ValueError: When the address size is not known
    """
    if proto_address_size == quokka.pb.Quokka.ADDR_32:
        return 32
    if proto_address_size == quokka.pb.Quokka.ADDR_64:
        return 64

    raise ValueError("Address size not known")


@functools.lru_cache(maxsize=2, typed=True)
def get_arch(
    isa: ArchEnum, address_size: int, is_thumb: bool = False
) -> Type["QuokkaArch"]:
    """Convert an isa to an arch.

    Arguments:
        isa: Instruction set
        address_size: Address size
        is_thumb: Is it thumb mode?

    Returns:
        A QuokkaArch
    """
    mapping = {
        ArchEnum.ARM: {
            32: ArchARM,
            64: ArchARM64,
        },
        ArchEnum.X86: {
            32: ArchX86,
            64: ArchX64,
        },
    }

    platform_arch = mapping.get(isa)
    if platform_arch is None:
        return QuokkaArch

    arch = platform_arch.get(address_size, QuokkaArch)

    if arch == ArchARM and is_thumb:
        arch = ArchARMThumb

    return arch
