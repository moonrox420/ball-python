"""Tests for pycleaner.config module."""

from __future__ import annotations

import textwrap
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from pycleaner.config import ConfigError, PyCleanerConfig, load_config


class TestConfig:
    """Test suite for configuration loading, validation, and merging."""

    def test_default_config(self) -> None:
        cfg = load_config()
        assert isinstance(cfg, PyCleanerConfig)
        assert cfg.line_length == 88
        assert cfg.backup is True
        assert cfg.parallel is False
        assert cfg.max_cyclomatic_complexity == 10
        assert cfg.max_cognitive_complexity == 15
        assert cfg.security_severity_threshold == "LOW"
        assert cfg.custom_import_map == {}

    def test_load_from_pyproject_toml(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            textwrap.dedent("""
            [tool.pycleaner]
            line-length = 100
            backup = false
            security-severity-threshold = "HIGH"
            max-arguments = 7
            custom-import-map = { "logger" = "from myapp.log import logger" }
        """),
            encoding="utf-8",
        )

        cfg = load_config(project_root=tmp_path)
        assert cfg.line_length == 100
        assert cfg.backup is False
        assert cfg.security_severity_threshold == "HIGH"
        assert cfg.max_arguments == 7
        assert cfg.custom_import_map == {"logger": "from myapp.log import logger"}
        # Check that non-overridden settings preserve defaults
        assert cfg.max_cyclomatic_complexity == 10

    def test_load_from_dotfile(self, tmp_path: Path) -> None:
        dotfile = tmp_path / ".pycleaner.toml"
        dotfile.write_text(
            textwrap.dedent("""
            parallel = true
            max-workers = 8
            fix-py2-syntax = false
        """),
            encoding="utf-8",
        )

        cfg = load_config(project_root=tmp_path)
        assert cfg.parallel is True
        assert cfg.max_workers == 8
        assert cfg.fix_py2_syntax is False

    def test_config_merging_precedence(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            textwrap.dedent("""
            [tool.pycleaner]
            line-length = 90
            max-workers = 2
        """),
            encoding="utf-8",
        )

        # CLI overrides file config
        cli_overrides = {"line_length": 120}
        cfg = load_config(project_root=tmp_path, cli_overrides=cli_overrides)

        assert cfg.line_length == 120
        assert cfg.max_workers == 2

    def test_unknown_key_raises_config_error(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            textwrap.dedent("""
            [tool.pycleaner]
            non_existent_key = "boom"
        """),
            encoding="utf-8",
        )

        with pytest.raises(ConfigError, match="Unknown configuration key"):
            load_config(project_root=tmp_path)

    def test_invalid_type_raises_config_error(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            textwrap.dedent("""
            [tool.pycleaner]
            line-length = "not-an-integer"
        """),
            encoding="utf-8",
        )

        with pytest.raises(ConfigError, match="Invalid integer value"):
            load_config(project_root=tmp_path)

    def test_invalid_toml_syntax_raises_config_error(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("invalid [ toml syntax", encoding="utf-8")

        with pytest.raises(ConfigError, match="Failed to parse pyproject.toml"):
            load_config(project_root=tmp_path)

    def test_frozen_dataclass_immutability(self) -> None:
        cfg = load_config()
        with pytest.raises(FrozenInstanceError):
            cfg.line_length = 100  # type: ignore[misc]

    def test_explicit_config_file_flat_toml(self, tmp_path: Path) -> None:
        explicit = tmp_path / "custom.toml"
        explicit.write_text("line-length = 111\n", encoding="utf-8")
        cfg = load_config(project_root=None, explicit_config_file=explicit)
        assert cfg.line_length == 111

    def test_explicit_config_file_pyproject_form(self, tmp_path: Path) -> None:
        explicit = tmp_path / "pyproject.toml"
        explicit.write_text(
            textwrap.dedent("""\
                [tool.pycleaner]
                line-length = 121
            """),
            encoding="utf-8",
        )
        cfg = load_config(project_root=None, explicit_config_file=explicit)
        assert cfg.line_length == 121
        assert cfg.backup is True

    def test_explicit_config_file_missing_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="Config file not found"):
            load_config(explicit_config_file=tmp_path / "absent.toml")

    def test_explicit_config_overrides_project_discovery(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "pyproject.toml").write_text(
            "[tool.pycleaner]\nline-length = 90\n", encoding="utf-8"
        )
        explicit = tmp_path / "override.toml"
        explicit.write_text("line-length = 132\n", encoding="utf-8")
        cfg = load_config(project_root=project, explicit_config_file=explicit)
        assert cfg.line_length == 132
