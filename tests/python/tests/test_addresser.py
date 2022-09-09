import pytest

import quokka


def test_file_offset(mocker):
    program = mocker.MagicMock()
    program.get_segment.side_effect = [
        mocker.Mock(file_offset=1),
        mocker.Mock(file_offset=-1),
        KeyError,
    ]

    addresser = quokka.addresser.Addresser(program, base_address=0x100)

    assert addresser.file(1) == 2

    with pytest.raises(quokka.exc.NotInFileError):
        addresser.file(1)

    with pytest.raises(quokka.exc.NotInFileError):
        addresser.file(1)


def test_absolute(mocker):
    addresser = quokka.addresser.Addresser(mocker.MagicMock(), base_address=0x100)

    assert addresser.absolute(0x100) == 0x200
