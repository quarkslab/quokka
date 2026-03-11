"""Tests for the -o/--output template expansion in quokka-cli."""

from pathlib import Path

import click
import pytest

from quokka.__main__ import expand_output_template


@pytest.fixture
def binary_path(tmp_path):
    p = tmp_path / "usr" / "bin" / "hello.elf"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.touch()
    return p


class TestExpandOutputTemplate:
    def test_default_template(self, binary_path):
        result = expand_output_template("%F.quokka", binary_path)
        assert result == Path("hello.elf.quokka")

    def test_stem_specifier(self, binary_path):
        result = expand_output_template("%f.quokka", binary_path)
        assert result == Path("hello.quokka")

    def test_full_path_specifier(self, binary_path):
        result = expand_output_template("%P.quokka", binary_path)
        assert result == Path(str(binary_path.resolve()) + ".quokka")

    def test_parent_specifier(self, binary_path):
        result = expand_output_template("%p/exports/%f.quokka", binary_path)
        expected = Path(str(binary_path.resolve().parent) + "/exports/hello.quokka")
        assert result == expected

    def test_extension_specifier(self, binary_path):
        result = expand_output_template("%f_%e.quokka", binary_path)
        assert result == Path("hello_elf.quokka")

    def test_extension_specifier_no_ext(self, tmp_path):
        p = tmp_path / "noext"
        p.touch()
        result = expand_output_template("%f_%e.quokka", p)
        assert result == Path("noext_.quokka")

    def test_literal_percent(self, binary_path):
        result = expand_output_template("%%output.quokka", binary_path)
        assert result == Path("%output.quokka")

    def test_unknown_specifier_raises(self, binary_path):
        with pytest.raises(click.BadParameter, match="Unknown specifier '%z'"):
            expand_output_template("%z.quokka", binary_path)

    def test_trailing_percent_raises(self, binary_path):
        with pytest.raises(click.BadParameter, match="Trailing '%'"):
            expand_output_template("output%", binary_path)

    def test_literal_path_no_specifiers(self, binary_path):
        result = expand_output_template("/tmp/out/result.quokka", binary_path)
        assert result == Path("/tmp/out/result.quokka")

    def test_combined_specifiers(self, binary_path):
        result = expand_output_template("%p/%f_export.quokka", binary_path)
        expected = Path(str(binary_path.resolve().parent) + "/hello_export.quokka")
        assert result == expected
