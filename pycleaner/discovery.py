"""
Centralized file discovery, traversal, and security/safety filtering engine.

Enforces strict exclusion of virtual environments, version control roots,
cache artifacts, and sensitive files (.env, secrets, keys, lockfiles) across
all pycleaner analysis, healing, and formatting phases.
"""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Sequence
from pathlib import Path

# Directories that must NEVER be traversed or inspected under any circumstance
DEFAULT_IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".svn",
        ".hg",
        ".venv",
        "venv",
        "env",
        ".env",
        "ENV",
        ".tox",
        ".nox",
        ".direnv",
        "site-packages",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".pytest_temp",
        ".release-test",
        "build",
        "dist",
        ".eggs",
        ".cache",
        ".idea",
        ".vscode",
    }
)

# Patterns for sensitive, secret, or lock files that must NEVER be cleaned or formatted
PROTECTED_FILE_PATTERNS: tuple[str, ...] = (
    ".env*",
    "*.env",
    "*secret*",
    "*credential*",
    "*.pem",
    "*.key",
    "*.cert",
    "*.crt",
    "*.pfx",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "pdm.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
)


def is_ignored_directory(name: str) -> bool:
    """Check if a directory name should be excluded from file discovery."""
    if name in DEFAULT_IGNORED_DIRS:
        return True
    if name.endswith(".egg-info"):
        return True
    if name.startswith(".") and name not in (".", ".."):
        return True
    return False


def is_protected_file(path: Path | str) -> bool:
    """Check if a file is protected and must not be touched by formatting or cleaning."""
    name = Path(path).name
    for pattern in PROTECTED_FILE_PATTERNS:
        if fnmatch.fnmatch(name, pattern):
            return True
    return False


def load_gitignore_patterns(project_root: Path) -> list[str]:
    """Parse .gitignore rules from the project root if present."""
    gitignore_file = project_root / ".gitignore"
    if not gitignore_file.is_file():
        return []

    patterns: list[str] = []
    try:
        for line in gitignore_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
    except OSError:
        return []
    return patterns


def matches_gitignore(rel_path: str, patterns: Sequence[str]) -> bool:
    """Check if a normalized relative POSIX path matches any gitignore pattern."""
    normalized = Path(rel_path).as_posix()
    for pat in patterns:
        pat_clean = pat.rstrip("/")
        if fnmatch.fnmatch(normalized, pat) or fnmatch.fnmatch(normalized, pat_clean):
            return True
        if fnmatch.fnmatch(normalized, f"*/{pat_clean}") or fnmatch.fnmatch(normalized, f"*/{pat}"):
            return True
        for part in normalized.split("/"):
            if fnmatch.fnmatch(part, pat_clean):
                return True
    return False


def collect_project_python_files(
    root: Path | str,
    exclude_patterns: Sequence[str] = (),
    respect_gitignore: bool = True,
) -> list[Path]:
    """
    Canonical file discovery engine.

    Recursively scans the target root, filtering out all virtual environments,
    caches, version-control folders, gitignored files, protected files, and
    custom exclude patterns. Returns sorted, resolved absolute paths.
    """
    target_root = Path(root).resolve()
    if target_root.is_file():
        if target_root.suffix == ".py" and not is_protected_file(target_root):
            return [target_root]
        return []

    gitignore_rules = load_gitignore_patterns(target_root) if respect_gitignore else []
    python_files: list[Path] = []

    for current_root, dirs, filenames in os.walk(target_root):
        # Prune ignored directories in-place to prevent os.walk from recursing into them
        dirs[:] = [
            d for d in dirs
            if not is_ignored_directory(d)
            and not (respect_gitignore and matches_gitignore(d, gitignore_rules))
        ]

        for fname in filenames:
            if not fname.endswith(".py"):
                continue

            file_path = Path(current_root) / fname
            if is_protected_file(file_path):
                continue

            try:
                rel_path = str(file_path.relative_to(target_root))
            except ValueError:
                rel_path = fname

            if respect_gitignore and matches_gitignore(rel_path, gitignore_rules):
                continue

            if exclude_patterns:
                rel_posix = Path(rel_path).as_posix()
                if any(fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(rel_posix, f"*/{pat}") for pat in exclude_patterns):
                    continue

            python_files.append(file_path.resolve())

    return sorted(python_files)
