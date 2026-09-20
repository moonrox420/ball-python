"""
Configuration system for pycleaner.

Loads settings from pyproject.toml [tool.pycleaner] or .pycleaner.toml,
merges with CLI arguments and built-in defaults.
Exposes configuration as a frozen PyCleanerConfig dataclass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[import-not-found,no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]


class ConfigError(ValueError):
    """Raised when configuration file parsing or validation fails."""


@dataclass(frozen=True)
class PyCleanerConfig:
    """Resolved immutable configuration for a pycleaner run."""

    # File targeting
    exclude: list[str] = field(
        default_factory=lambda: [
            "migrations/",
            "generated/",
            "*_pb2.py",
            "*_pb2_grpc.py",
            "editor-*.py",
        ]
    )
    include: list[str] = field(default_factory=list)

    # Syntax healing
    fix_py2_syntax: bool = True
    fix_conditional_assignments: bool = True

    # Import resolution
    custom_import_map: dict[str, str] = field(default_factory=dict)
    auto_add_future_annotations: bool = False

    # Linting & formatting
    line_length: int = 88
    select_rules: str = "F401,F841,I,UP,E,W"

    # Dead code
    ignore_decorators: list[str] = field(
        default_factory=lambda: [
            "@app.route",
            "@pytest.fixture",
            "@override",
        ]
    )
    ignore_names: list[str] = field(
        default_factory=lambda: [
            "_*",
            "test_*",
        ]
    )

    # Security
    security_severity_threshold: str = "LOW"
    ignore_security_rules: list[str] = field(default_factory=list)

    # Type Verification
    strict_types: bool = False

    # Complexity thresholds
    max_cyclomatic_complexity: int = 10
    max_cognitive_complexity: int = 15
    max_function_length: int = 50
    max_arguments: int = 5

    # Behavior
    backup: bool = True
    parallel: bool = False
    max_workers: int = 4


_KEY_MAP: dict[str, str] = {
    "exclude": "exclude",
    "include": "include",
    "fix-py2-syntax": "fix_py2_syntax",
    "fix_py2_syntax": "fix_py2_syntax",
    "fix-conditional-assignments": "fix_conditional_assignments",
    "fix_conditional_assignments": "fix_conditional_assignments",
    "custom-import-map": "custom_import_map",
    "custom_import_map": "custom_import_map",
    "auto-add-future-annotations": "auto_add_future_annotations",
    "auto_add_future_annotations": "auto_add_future_annotations",
    "line-length": "line_length",
    "line_length": "line_length",
    "select-rules": "select_rules",
    "select_rules": "select_rules",
    "ignore-decorators": "ignore_decorators",
    "ignore_decorators": "ignore_decorators",
    "ignore-names": "ignore_names",
    "ignore_names": "ignore_names",
    "security-severity-threshold": "security_severity_threshold",
    "security_severity_threshold": "security_severity_threshold",
    "ignore-security-rules": "ignore_security_rules",
    "ignore_security_rules": "ignore_security_rules",
    "strict-types": "strict_types",
    "strict_types": "strict_types",
    "max-cyclomatic-complexity": "max_cyclomatic_complexity",
    "max_cyclomatic_complexity": "max_cyclomatic_complexity",
    "max-cognitive-complexity": "max_cognitive_complexity",
    "max_cognitive_complexity": "max_cognitive_complexity",
    "max-function-length": "max_function_length",
    "max_function_length": "max_function_length",
    "max-arguments": "max_arguments",
    "max_arguments": "max_arguments",
    "backup": "backup",
    "parallel": "parallel",
    "max-workers": "max_workers",
    "max_workers": "max_workers",
}


def _resolve_file_config(
    project_root: Path | str | None,
    explicit_config_file: Path | str | None,
) -> dict[str, Any]:
    if explicit_config_file is not None:
        config_path = Path(explicit_config_file).resolve()
        if not config_path.is_file():
            raise ConfigError(f"Config file not found: {config_path}")
        if config_path.name == "pyproject.toml":
            return _load_from_pyproject(config_path.parent) or {}
        return _load_from_toml_file(config_path) or {}

    if project_root is not None:
        root = Path(project_root).resolve()
        if not root.is_dir():
            root = root.parent
        return _load_from_pyproject(root) or _load_from_dotfile(root) or {}

    return {}


def load_config(
    project_root: Path | str | None = None,
    cli_overrides: dict[str, Any] | None = None,
    explicit_config_file: Path | str | None = None,
) -> PyCleanerConfig:
    """Load and merge configuration from file and CLI overrides."""
    file_config = _resolve_file_config(project_root, explicit_config_file)
    merged: dict[str, Any] = {
        "exclude": [
            "migrations/",
            "generated/",
            "*_pb2.py",
            "*_pb2_grpc.py",
            "editor-*.py",
        ],
        "include": [],
        "fix_py2_syntax": True,
        "fix_conditional_assignments": True,
        "custom_import_map": {},
        "auto_add_future_annotations": False,
        "line_length": 88,
        "select_rules": "F401,F841,I,UP,E,W",
        "ignore_decorators": ["@app.route", "@pytest.fixture", "@override"],
        "ignore_names": ["_*", "test_*"],
        "security_severity_threshold": "LOW",
        "ignore_security_rules": [],
        "strict_types": False,
        "max_cyclomatic_complexity": 10,
        "max_cognitive_complexity": 15,
        "max_function_length": 50,
        "max_arguments": 5,
        "backup": True,
        "parallel": False,
        "max_workers": 4,
    }

    if file_config:
        _apply_dict(merged, file_config)
    if cli_overrides:
        _apply_dict(merged, cli_overrides)
    return PyCleanerConfig(**merged)


def _load_from_pyproject(root: Path) -> dict[str, Any] | None:
    """Attempt to load [tool.ballpython] or [tool.pycleaner] from pyproject.toml."""
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return None

    if tomllib is None:
        raise ConfigError("tomllib or tomli is required to parse pyproject.toml")

    try:
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
        tool_section = data.get("tool", {})
        return tool_section.get("ballpython") or tool_section.get("pycleaner")
    except Exception as err:
        raise ConfigError(f"Failed to parse pyproject.toml: {err}") from err


def _load_from_dotfile(root: Path) -> dict[str, Any] | None:
    """Attempt to load .ballpython.toml or .pycleaner.toml."""
    for name in (".ballpython.toml", ".pycleaner.toml"):
        dotfile = root / name
        if dotfile.is_file():
            return _load_from_toml_file(dotfile)
    return None


def _load_from_toml_file(path: Path) -> dict[str, Any] | None:
    """Load a flat pycleaner-format TOML file (top-level keys, no [tool.pycleaner] wrapper)."""
    if tomllib is None:
        raise ConfigError(f"tomllib or tomli is required to parse {path}")

    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception as err:
        raise ConfigError(f"Failed to parse {path}: {err}") from err


_EXPECTED_TYPES: dict[type, tuple[type, str]] = {
    bool: (bool, "boolean"),
    str: (str, "string"),
    list: (list, "list"),
    dict: (dict, "dict"),
}


def _validate_value_type(key: str, current: Any, value: Any) -> None:
    if type(current) is int:
        if type(value) is not int:
            raise ConfigError(f"Invalid integer value for '{key}': {value!r}")
        return

    expected = _EXPECTED_TYPES.get(type(current))
    if expected is not None:
        expected_cls, type_name = expected
        if not isinstance(value, expected_cls):
            raise ConfigError(f"Invalid {type_name} value for '{key}': {value!r}")


def _apply_dict(target: dict[str, Any], data: dict[str, Any]) -> None:
    """Apply a dictionary of settings into target dict, normalizing key names and validating types."""
    for key, value in data.items():
        attr = _KEY_MAP.get(key)
        if attr is None or attr not in target:
            raise ConfigError(f"Unknown configuration key: '{key}'")
        _validate_value_type(key, target[attr], value)
        target[attr] = value
