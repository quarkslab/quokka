"""Tests for the -o/--output template expansion in quokka-cli."""

from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from quokka.__main__ import expand_output_template, _template_has_specifiers, main as quokka_cli


@pytest.fixture
def binary_path(tmp_path):
    p = tmp_path / "usr" / "bin" / "hello.elf"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.touch()
    return p


class TestExpandOutputTemplate:
    def test_default_template(self, binary_path):
        result = expand_output_template("%F.quokka", binary_path)
        assert result == binary_path.resolve().parent / "hello.elf.quokka"

    def test_stem_specifier(self, binary_path):
        result = expand_output_template("%f.quokka", binary_path)
        assert result == binary_path.resolve().parent / "hello.quokka"

    def test_full_path_specifier(self, binary_path):
        result = expand_output_template("%P.quokka", binary_path)
        assert result == Path(str(binary_path.resolve()) + ".quokka")

    def test_parent_specifier(self, binary_path):
        result = expand_output_template("%p/exports/%f.quokka", binary_path)
        expected = Path(str(binary_path.resolve().parent) + "/exports/hello.quokka")
        assert result == expected

    def test_extension_specifier(self, binary_path):
        result = expand_output_template("%f_%e.quokka", binary_path)
        assert result == binary_path.resolve().parent / "hello_elf.quokka"

    def test_extension_specifier_no_ext(self, tmp_path):
        p = tmp_path / "noext"
        p.touch()
        result = expand_output_template("%f_%e.quokka", p)
        assert result == p.resolve().parent / "noext_.quokka"

    def test_literal_percent(self, binary_path):
        result = expand_output_template("%%output.quokka", binary_path)
        assert result == binary_path.resolve().parent / "%output.quokka"

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


class TestTemplateHasSpecifiers:
    def test_default_template(self):
        assert _template_has_specifiers("%F.quokka") is True

    def test_all_specifiers(self):
        for s in ("f", "F", "P", "p", "e"):
            assert _template_has_specifiers(f"prefix%{s}suffix") is True

    def test_no_specifiers(self):
        assert _template_has_specifiers("output.quokka") is False

    def test_literal_percent_only(self):
        assert _template_has_specifiers("%%output.quokka") is False

    def test_specifier_after_literal_percent(self):
        # "%%%f" is literal-% then %f
        assert _template_has_specifiers("%%%f.quokka") is True

    def test_empty_string(self):
        assert _template_has_specifiers("") is False


class TestDirectoryOutputCollision:
    def test_directory_with_fixed_output_errors(self, tmp_path):
        """Passing a directory with -o that has no specifiers must fail."""
        (tmp_path / "dummy").touch()
        runner = CliRunner()
        result = runner.invoke(quokka_cli, ["-o", "fixed.quokka", str(tmp_path)])
        assert result.exit_code != 0
        assert "no specifiers" in result.output

    def test_directory_with_literal_percent_output_errors(self, tmp_path):
        """A %% (literal percent) does not count as a specifier."""
        (tmp_path / "dummy").touch()
        runner = CliRunner()
        result = runner.invoke(quokka_cli, ["-o", "%%fixed.quokka", str(tmp_path)])
        assert result.exit_code != 0
        assert "no specifiers" in result.output

    def test_directory_with_template_output_passes_validation(self, tmp_path):
        """A directory with a parametrized -o should not trigger the collision error."""
        (tmp_path / "dummy").touch()
        runner = CliRunner()
        # This will pass the collision check but fail later (no backend),
        # so just verify the error is NOT about specifiers.
        result = runner.invoke(quokka_cli, ["-o", "%f.quokka", str(tmp_path)])
        assert "no specifiers" not in result.output

    def test_single_file_with_fixed_output_ok(self, tmp_path):
        """A single file with a fixed -o should not trigger the collision error."""
        f = tmp_path / "binary"
        f.touch()
        runner = CliRunner()
        result = runner.invoke(quokka_cli, ["-o", "fixed.quokka", str(f)])
        assert "no specifiers" not in result.output
