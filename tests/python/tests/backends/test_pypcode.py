import pypcode
import pytest

import quokka
import quokka.backends.pypcode as pypcode_backend


def test_pypcode_context():

    context = pypcode_backend.get_pypcode_context(quokka.analysis.ArchX86)
    assert context.lang.id == "x86:LE:32:default"

    context = pypcode_backend.get_pypcode_context(quokka.analysis.ArchX64)
    assert context.lang.id == "x86:LE:64:default"

    context = pypcode_backend.get_pypcode_context(quokka.analysis.ArchARM64)
    assert context.lang.id == "AARCH64:LE:64:v8A"

    context = pypcode_backend.get_pypcode_context(quokka.analysis.ArchARM)
    assert context.lang.id == "ARM:LE:32:v8"

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


@pytest.mark.skip(reason="Must rewrite this because using a generator is a pain")
def test_pypcode_decode_block(mocker):

    block_bytes = [b"\x55", b"\x48\x89\xe5", b"\xc9", b"\xc3"]

    block = mocker.MagicMock()
    block.bytes = b"".join(block_bytes)
    block.start = 0x1000
    block.__len__ = lambda _: len(block_bytes)

    instructions = [mocker.MagicMock(size=len(inst_bytes)) for inst_bytes in block_bytes]
    block.instructions = instructions
    block.program.pypcode = pypcode_backend.get_pypcode_context(
        quokka.analysis.ArchX64
    )

    decoded_block = pypcode_backend.pypcode_decode_block(block)
    assert len(decoded_block) > 0
