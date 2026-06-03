"""Tests for Ghidra extension discovery helpers."""

import getpass
import logging
import os
import platform
from pathlib import Path

import pytest

from quokka.program import (
    _parse_ghidra_application_properties,
    _get_ghidra_versioned_name,
    _get_ghidra_user_extensions_dir,
    _find_ghidra_extension,
)


@pytest.fixture
def fake_ghidra(tmp_path):
    """Create a minimal fake Ghidra install dir with application.properties."""
    ghidra_dir = tmp_path / "ghidra"
    props_dir = ghidra_dir / "Ghidra"
    props_dir.mkdir(parents=True)
    (props_dir / "application.properties").write_text(
        "application.name=Ghidra\n"
        "application.version=12.0.4\n"
        "application.release.name=PUBLIC\n"
    )
    return ghidra_dir


class TestParseApplicationProperties:
    def test_parses_version(self, fake_ghidra):
        props = _parse_ghidra_application_properties(fake_ghidra)
        assert props["application.version"] == "12.0.4"
        assert props["application.release.name"] == "PUBLIC"

    def test_missing_file_returns_empty(self, tmp_path):
        props = _parse_ghidra_application_properties(tmp_path)
        assert props == {}

    def test_skips_comments(self, tmp_path):
        props_dir = tmp_path / "Ghidra"
        props_dir.mkdir()
        (props_dir / "application.properties").write_text(
            "#comment\napplication.version=1.0\n"
        )
        props = _parse_ghidra_application_properties(tmp_path)
        assert props["application.version"] == "1.0"


class TestGetVersionedName:
    def test_returns_versioned_name(self, fake_ghidra):
        assert _get_ghidra_versioned_name(fake_ghidra) == "ghidra_12.0.4_PUBLIC"

    def test_returns_none_without_props(self, tmp_path):
        assert _get_ghidra_versioned_name(tmp_path) is None


class TestGetUserExtensionsDir:
    def test_linux_default(self, fake_ghidra, monkeypatch):
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        result = _get_ghidra_user_extensions_dir(fake_ghidra)
        expected = Path.home() / ".config" / "ghidra" / "ghidra_12.0.4_PUBLIC" / "Extensions"
        assert result == expected

    def test_linux_xdg_under_home(self, fake_ghidra, monkeypatch):
        """XDG_CONFIG_HOME under $HOME uses plain 'ghidra' dir name."""
        xdg = Path.home() / ".my_xdg"
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
        result = _get_ghidra_user_extensions_dir(fake_ghidra)
        assert result == xdg / "ghidra" / "ghidra_12.0.4_PUBLIC" / "Extensions"

    def test_linux_xdg_outside_home(self, fake_ghidra, monkeypatch):
        """XDG_CONFIG_HOME outside $HOME prepends '<user>-' to dir name."""
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.setenv("XDG_CONFIG_HOME", "/tmp/shared_xdg")
        result = _get_ghidra_user_extensions_dir(fake_ghidra)
        user = getpass.getuser()
        expected = Path("/tmp/shared_xdg") / f"{user}-ghidra" / "ghidra_12.0.4_PUBLIC" / "Extensions"
        assert result == expected

    def test_darwin(self, fake_ghidra, monkeypatch):
        monkeypatch.setattr(platform, "system", lambda: "Darwin")
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        result = _get_ghidra_user_extensions_dir(fake_ghidra)
        expected = Path.home() / "Library" / "ghidra" / "ghidra_12.0.4_PUBLIC" / "Extensions"
        assert result == expected

    def test_returns_none_without_props(self, tmp_path):
        assert _get_ghidra_user_extensions_dir(tmp_path) is None


class TestFindGhidraExtension:
    def test_finds_in_install_dir(self, fake_ghidra):
        ext = fake_ghidra / "Ghidra" / "Extensions" / "QuokkaExporter"
        ext.mkdir(parents=True)
        (ext / "extension.properties").write_text("name=QuokkaExporter\n")
        assert _find_ghidra_extension(fake_ghidra) == ext

    def test_finds_in_user_dir(self, fake_ghidra, monkeypatch, tmp_path):
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        xdg = tmp_path / "xdg"
        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
        user_ext_dir = _get_ghidra_user_extensions_dir(fake_ghidra)
        user_ext = user_ext_dir / "QuokkaExporter"
        user_ext.mkdir(parents=True)
        (user_ext / "extension.properties").write_text("name=QuokkaExporter\n")
        assert _find_ghidra_extension(fake_ghidra) == user_ext

    def test_skips_uninstalled_marker(self, fake_ghidra, monkeypatch, tmp_path):
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        xdg = tmp_path / "xdg"
        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
        user_ext_dir = _get_ghidra_user_extensions_dir(fake_ghidra)
        user_ext = user_ext_dir / "QuokkaExporter"
        user_ext.mkdir(parents=True)
        (user_ext / "extension.properties").write_text("name=QuokkaExporter\n")
        (user_ext / "extension.properties.uninstalled").write_text("")
        assert _find_ghidra_extension(fake_ghidra) is None

    def test_returns_none_when_missing(self, fake_ghidra):
        assert _find_ghidra_extension(fake_ghidra) is None

    def test_prefers_install_dir_over_user_dir(self, fake_ghidra, monkeypatch, tmp_path):
        """Strategy A (install dir) takes priority over Strategy B (user dir)."""
        install_ext = fake_ghidra / "Ghidra" / "Extensions" / "QuokkaExporter"
        install_ext.mkdir(parents=True)
        (install_ext / "extension.properties").write_text("name=QuokkaExporter\n")

        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
        user_ext_dir = _get_ghidra_user_extensions_dir(fake_ghidra)
        user_ext = user_ext_dir / "QuokkaExporter"
        user_ext.mkdir(parents=True)
        (user_ext / "extension.properties").write_text("name=QuokkaExporter\n")

        assert _find_ghidra_extension(fake_ghidra) == install_ext

    def test_warns_on_duplicate_install(self, fake_ghidra, monkeypatch, tmp_path, caplog):
        """Logs a warning when extension is in both locations."""
        install_ext = fake_ghidra / "Ghidra" / "Extensions" / "QuokkaExporter"
        install_ext.mkdir(parents=True)
        (install_ext / "extension.properties").write_text("name=QuokkaExporter\n")

        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
        user_ext_dir = _get_ghidra_user_extensions_dir(fake_ghidra)
        user_ext = user_ext_dir / "QuokkaExporter"
        user_ext.mkdir(parents=True)
        (user_ext / "extension.properties").write_text("name=QuokkaExporter\n")

        with caplog.at_level(logging.WARNING, logger="quokka.program"):
            result = _find_ghidra_extension(fake_ghidra)

        assert result == install_ext
        assert "BOTH" in caplog.text
        assert "class-loading conflicts" in caplog.text
