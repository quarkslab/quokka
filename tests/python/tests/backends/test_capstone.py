import capstone
import pytest

import quokka
import quokka.backends


def test_capstone_context():

    context = quokka.backends.get_capstone_context(quokka.analysis.ArchX86)
    assert context.detail is True
    assert (context.arch, context.mode) == (capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    context = quokka.backends.get_capstone_context(quokka.analysis.ArchX64)
    assert (context.arch, context.mode) == (capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    context = quokka.backends.get_capstone_context(quokka.analysis.ArchARM64)
    assert (context.arch, context.mode) == (
        capstone.CS_ARCH_ARM64,
        capstone.CS_MODE_ARM,
    )

    context = quokka.backends.get_capstone_context(quokka.analysis.ArchARM)
    assert (context.arch, context.mode) == (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)

    with pytest.raises(quokka.CapstoneError):
        quokka.backends.get_capstone_context(quokka.analysis.QuokkaArch)


def test_capstone_decode(mocker):

    inst = mocker.MagicMock()
    inst.bytes = b"\x90"
    inst.address = 0x1000
    inst.program.capstone = quokka.backends.get_capstone_context(quokka.analysis.ArchX64)

    inst_decoded = quokka.backends.capstone_decode_instruction(inst)
    assert isinstance(inst_decoded, capstone.CsInsn)

    assert inst_decoded.mnemonic == "nop"
