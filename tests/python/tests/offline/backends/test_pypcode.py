import pypcode
import pytest

import quokka
import quokka.backends.pypcode as pypcode_backend


def test_pypcode_context():

    context = pypcode_backend.get_pypcode_context(quokka.analysis.ArchX86)
    assert context.language.id == "x86:LE:32:default"

    context = pypcode_backend.get_pypcode_context(quokka.analysis.ArchX64)
    assert context.language.id == "x86:LE:64:default"

    context = pypcode_backend.get_pypcode_context(quokka.analysis.ArchARM64)
    assert context.language.id == "AARCH64:LE:64:v8A"

    context = pypcode_backend.get_pypcode_context(quokka.analysis.ArchARM)
    assert context.language.id == "ARM:LE:32:v8"

    with pytest.raises(quokka.PypcodeError):
        pypcode_backend.get_pypcode_context(quokka.analysis.QuokkaArch)


def test_pypcode_decode_instruction(mocker):

    inst = mocker.MagicMock()
    inst.bytes = b"\x55"  # push rbp
    inst.address = 0x1000
    inst.program.pypcode = pypcode_backend.get_pypcode_context(
        quokka.analysis.ArchX64
    )

    inst_decoded = pypcode_backend.pypcode_decode_instruction(inst)
    assert len(inst_decoded) == 3
    assert isinstance(inst_decoded[0], pypcode.PcodeOp)


def test_pypcode_decode_block(mocker):

    block_bytes = [b"\x55", b"\x48\x89\xe5", b"\xc9", b"\xc3"]

    block = mocker.MagicMock()
    block.bytes = b"".join(block_bytes)
    block.start = 0x1000
    block.__len__ = lambda _: len(block_bytes)

    instructions = [
        mocker.MagicMock(size=len(inst_bytes), is_thumb=False)
        for inst_bytes in block_bytes
    ]
    # block.instructions is a property returning an iterator; mock it as such
    type(block).instructions = mocker.PropertyMock(
        return_value=iter(instructions)
    )
    block.program.arch = quokka.analysis.ArchX64
    block.program.pypcode = pypcode_backend.get_pypcode_context(
        quokka.analysis.ArchX64
    )

    decoded_block = pypcode_backend.pypcode_decode_block(block)
    assert len(decoded_block) > 0
