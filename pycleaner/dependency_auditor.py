"""
Static dependency auditor for Python codebases.

Scans all Python files across a project, extracts third-party module imports,
maps import names to PyPI package distributions, inspects requirements.txt
and pyproject.toml, and detects missing or unused project dependencies.
"""

from __future__ import annotations

import ast
import importlib.metadata
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar


@dataclass(slots=True)
class DependencyAuditReport:
    """Detailed report of dependency usage across a codebase."""

    imported_modules: set[str] = field(default_factory=set)
    third_party_modules: set[str] = field(default_factory=set)
    required_packages: set[str] = field(default_factory=set)
    missing_packages: set[str] = field(default_factory=set)
    unused_packages: set[str] = field(default_factory=set)
    fixed_requirements: bool = False
    details: list[str] = field(default_factory=list)


class DependencyAuditor:
    """Performs static dependency auditing and synchronization."""

    # Static mapping for packages where import name differs from package name
    _KNOWN_IMPORT_TO_DIST: ClassVar[dict[str, str]] = {
        "yaml": "PyYAML",
        "PIL": "pillow",
        "cv2": "opencv-python",
        "dateutil": "python-dateutil",
        "bs4": "beautifulsoup4",
        "dotenv": "python-dotenv",
        "sklearn": "scikit-learn",
        "git": "GitPython",
        "fitz": "PyMuPDF",
        "serial": "pyserial",
        "magic": "python-magic",
        "jose": "python-jose",
        "docx": "python-docx",
        "pptx": "python-pptx",
        "jwt": "PyJWT",
        "OpenSSL": "pyOpenSSL",
        "websocket": "websocket-client",
        "Bio": "biopython",
        "OpenGL": "PyOpenGL",
        "attr": "attrs",
        "google": "protobuf",
    }

    def __init__(self, root_dir: str | Path) -> None:
        self.root_dir = Path(root_dir).resolve()
        self.stdlib_names = set(sys.stdlib_module_names)
        try:
            self.dist_map = importlib.metadata.packages_distributions()
        except AttributeError:
            self.dist_map = {}

    _KNOWN_DEV_TOOLS: ClassVar[frozenset[str]] = frozenset(
        {
            "ruff",
            "black",
            "isort",
            "pytest",
            "mypy",
            "flake8",
            "autoflake",
            "pylint",
            "build",
            "twine",
            "pip",
            "wheel",
            "setuptools",
        }
    )

    @staticmethod
    def canonicalize_name(name: str) -> str:
        """Canonicalize package name per PEP 503 (lowercase, dashes instead of underscores)."""
        return re.sub(r"[-_.]+", "-", name).lower()

    @staticmethod
    def _extract_imports_from_file(filepath: Path) -> set[str]:
        """Extract root imported module names from a single Python file."""
        modules: set[str] = set()
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(filepath))
        except SyntaxError:
            return modules

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules.add(node.module.split(".")[0])
        return modules

    def scan_codebase_imports(self) -> set[str]:
        """Traverse the project directory and extract all imported root module names."""
        ignore_dirs = {
            ".git",
            ".venv",
            "venv",
            "env",
            "__pycache__",
            "build",
            "dist",
            ".tox",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            "site-packages",
        }
        imported_modules: set[str] = set()
        for current_root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [
                d for d in dirs if d not in ignore_dirs and not d.startswith(".")
            ]
            for filename in files:
                if filename.endswith(".py"):
                    imported_modules.update(
                        self._extract_imports_from_file(Path(current_root) / filename)
                    )
        return imported_modules

    def identify_local_modules(self) -> set[str]:
        """Identify local modules and packages belonging to the current project."""
        local_mods: set[str] = set()
        search_dirs = [self.root_dir]

        src_dir = self.root_dir / "src"
        if src_dir.is_dir():
            search_dirs.append(src_dir)

        for sdir in search_dirs:
            for item in sdir.iterdir():
                if item.is_file() and item.suffix == ".py":
                    local_mods.add(item.stem)
                elif item.is_dir() and (item / "__init__.py").exists():
                    local_mods.add(item.name)

        return local_mods

    def module_to_distribution(self, module_name: str) -> str:
        """Map a Python import module name to its PyPI distribution package name."""
        if module_name in self._KNOWN_IMPORT_TO_DIST:
            return self._KNOWN_IMPORT_TO_DIST[module_name]

        dists = self.dist_map.get(module_name)
        if dists:
            return dists[0]

        return module_name

    def _read_requirements_txt(self) -> dict[str, str]:
        declared: dict[str, str] = {}
        req_file = self.root_dir / "requirements.txt"
        if not req_file.exists():
            return declared

        for line in req_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            pkg_match = re.match(r"^([a-zA-Z0-9_\-\.]+)", line)
            if pkg_match:
                pkg_name = pkg_match.group(1)
                canon = self.canonicalize_name(pkg_name)
                declared[canon] = line
        return declared

    def _read_pyproject_toml(self) -> dict[str, str]:
        declared: dict[str, str] = {}
        pyproject_file = self.root_dir / "pyproject.toml"
        if not pyproject_file.exists():
            return declared

        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore

        try:
            data = tomllib.loads(pyproject_file.read_text(encoding="utf-8"))
            project_deps = data.get("project", {}).get("dependencies", [])
            for dep in project_deps:
                pkg_match = re.match(r"^([a-zA-Z0-9_\-\.]+)", dep.strip())
                if pkg_match:
                    pkg_name = pkg_match.group(1)
                    canon = self.canonicalize_name(pkg_name)
                    declared[canon] = dep
        except tomllib.TOMLDecodeError:
            # Fall back to requirements.txt if pyproject.toml is malformed
            pass
        return declared

    def read_declared_dependencies(self) -> dict[str, str]:
        """Read declared dependencies from requirements.txt or pyproject.toml."""
        declared = self._read_requirements_txt()
        declared.update(self._read_pyproject_toml())
        return declared

    def _resolve_expected_distributions(
        self, third_party_mods: set[str]
    ) -> dict[str, str]:
        expected_dists: dict[str, str] = {}
        for mod in third_party_mods:
            dist_name = self.module_to_distribution(mod)
            canon = self.canonicalize_name(dist_name)
            expected_dists[canon] = dist_name
        return expected_dists

    def _find_missing_and_unused(
        self, expected_dists: dict[str, str], declared: dict[str, str]
    ) -> tuple[set[str], set[str]]:
        missing_packages = {
            orig_name
            for canon, orig_name in expected_dists.items()
            if canon not in declared
        }
        unused_packages = {
            orig_line
            for canon, orig_line in declared.items()
            if canon not in expected_dists and canon not in self._KNOWN_DEV_TOOLS
        }
        return missing_packages, unused_packages

    @staticmethod
    def _build_audit_details(
        missing: set[str], unused: set[str], fixed: bool
    ) -> list[str]:
        details: list[str] = []
        if missing:
            details.append(
                f"Missing dependencies (used in code but undeclared): {', '.join(sorted(missing))}"
            )
        if unused:
            details.append(
                f"Unused dependencies (declared but not imported): {', '.join(sorted(unused))}"
            )
        if fixed:
            details.append("Updated requirements.txt successfully")
        return details

    def audit(
        self, fix: bool = False, prune_unused: bool = False
    ) -> DependencyAuditReport:
        """Audit dependencies and optionally update requirements.txt."""
        all_imports = self.scan_codebase_imports()
        local_mods = self.identify_local_modules()

        third_party_mods = {
            m
            for m in all_imports
            if m not in self.stdlib_names and m not in local_mods and m != "__future__"
        }
        expected_dists = self._resolve_expected_distributions(third_party_mods)
        declared = self.read_declared_dependencies()

        missing_packages, unused_packages = self._find_missing_and_unused(
            expected_dists, declared
        )

        fixed_reqs = False
        if fix and (missing_packages or (prune_unused and unused_packages)):
            fixed_reqs = self._update_requirements(
                missing_packages, unused_packages if prune_unused else set()
            )

        details = self._build_audit_details(
            missing_packages, unused_packages, fixed_reqs
        )

        return DependencyAuditReport(
            imported_modules=all_imports,
            third_party_modules=third_party_mods,
            required_packages=set(declared.keys()),
            missing_packages=missing_packages,
            unused_packages=unused_packages,
            fixed_requirements=fixed_reqs,
            details=details,
        )

    def _update_requirements(
        self, missing: set[str], unused_to_remove: set[str]
    ) -> bool:
        """Append missing dependencies and remove unused ones in requirements.txt."""
        req_file = self.root_dir / "requirements.txt"
        existing_lines: list[str] = []
        if req_file.exists():
            existing_lines = req_file.read_text(encoding="utf-8").splitlines()

        remove_canons = {
            self.canonicalize_name(m.group(1))
            for u in unused_to_remove
            if (m := re.match(r"^([a-zA-Z0-9_\-\.]+)", u))
        }

        new_lines: list[str] = []
        for line in existing_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-")):
                new_lines.append(line)
                continue

            pkg_match = re.match(r"^([a-zA-Z0-9_\-\.]+)", stripped)
            if pkg_match:
                pkg_name = pkg_match.group(1)
                canon = self.canonicalize_name(pkg_name)
                if canon in remove_canons:
                    continue
            new_lines.append(line)

        # Append missing packages
        new_lines.extend(sorted(missing))

        req_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        return True
