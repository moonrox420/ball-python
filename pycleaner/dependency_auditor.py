"""
Static dependency auditor for Python codebases.

Scans all Python files across a project, extracts third-party module imports,
maps import names to PyPI package distributions, inspects requirements.txt
and pyproject.toml, and detects missing or unused project dependencies.
"""

from __future__ import annotations

import ast
import importlib.metadata
import re
import shutil
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from pycleaner.discovery import collect_project_python_files


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
        # High-frequency PyPI packages
        "nmap": "python-nmap",
        "dns": "dnspython",
        "telegram": "python-telegram-bot",
        "discord": "discord.py",
        "pkg_resources": "setuptools",
        "setuptools": "setuptools",
        "pydantic_core": "pydantic-core",
        "multipart": "python-multipart",
        "kafka": "kafka-python",
        "smart_open": "smart-open",
        "MySQLdb": "mysqlclient",
        "psycopg2": "psycopg2-binary",
        "redis": "redis",
        "playwright": "playwright",
    }

    def __init__(
        self, root_dir: str | Path, exclude_patterns: Sequence[str] = ()
    ) -> None:
        self.root_dir = Path(root_dir).resolve()
        self.exclude_patterns = tuple(exclude_patterns)
        self.stdlib_names = set(sys.stdlib_module_names)
        self._last_optional_packages: set[str] = set()
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
            "wheel",
            "setuptools",
            "pip",
            "pre-commit",
            "coverage",
            "pytest-cov",
            "tox",
            "nox",
        }
    )

    @staticmethod
    def canonicalize_name(name: str) -> str:
        """Normalize package name per PEP 503."""
        return re.sub(r"[-_.]+", "-", name).lower()

    def _extract_imports_from_file(self, file_path: Path) -> set[str]:
        imports: set[str] = set()
        try:
            tree = ast.parse(file_path.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            return imports

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_pkg = alias.name.split(".")[0]
                    imports.add(root_pkg)
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    root_pkg = node.module.split(".")[0]
                    imports.add(root_pkg)
        return imports

    def scan_codebase_imports(
        self, target_files: Sequence[Path] | None = None
    ) -> set[str]:
        """Scan Python files across the project or given targets for imported modules."""
        if target_files is not None:
            files_to_scan = [
                f for f in target_files if f.is_file() and f.suffix == ".py"
            ]
        else:
            files_to_scan = collect_project_python_files(
                self.root_dir, exclude_patterns=self.exclude_patterns
            )
        imported_modules: set[str] = set()
        for py_file in files_to_scan:
            imported_modules.update(self._extract_imports_from_file(py_file))
        return imported_modules

    def identify_local_modules(self) -> set[str]:
        """Identify local modules and packages belonging to the current project."""
        local_mods: set[str] = set()

        # 1. Project root folder itself is a primary local package / namespace candidate
        local_mods.add(self.root_dir.name)
        local_mods.add(self.root_dir.stem)

        # 2. Extract package name from pyproject.toml if present
        pyproject_file = self.root_dir / "pyproject.toml"
        if pyproject_file.is_file():
            try:
                import tomllib
            except ImportError:
                import tomli as tomllib  # type: ignore
            try:
                data = tomllib.loads(
                    pyproject_file.read_text(encoding="utf-8", errors="ignore")
                )
                proj_name = data.get("project", {}).get("name") or data.get(
                    "tool", {}
                ).get("poetry", {}).get("name")
                if proj_name:
                    local_mods.add(str(proj_name))
                    local_mods.add(str(proj_name).replace("-", "_"))
            except Exception:
                pass  # Ignore invalid or non-standard pyproject.toml configuration

        # 3. Discover local .py files and subpackages (including PEP 420 namespace packages)
        search_dirs = [self.root_dir]
        src_dir = self.root_dir / "src"
        if src_dir.is_dir():
            search_dirs.append(src_dir)

        for sdir in search_dirs:
            try:
                for item in sdir.iterdir():
                    if item.is_file() and item.suffix == ".py":
                        local_mods.add(item.stem)
                    elif item.is_dir() and not item.name.startswith((".", "__")):
                        # Standard package or PEP 420 namespace package with python files inside
                        if (item / "__init__.py").exists() or any(
                            sub.suffix == ".py"
                            for sub in item.iterdir()
                            if sub.is_file()
                        ):
                            local_mods.add(item.name)
            except OSError:
                continue

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

        for line in req_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            pkg_match = re.match(r"^([a-zA-Z0-9_.-]+)", line)
            if pkg_match:
                pkg_name = pkg_match.group(1)
                canon = self.canonicalize_name(pkg_name)
                declared[canon] = line
        return declared

    def _read_pyproject_toml(self) -> tuple[dict[str, str], set[str]]:
        declared: dict[str, str] = {}
        optional_pkgs: set[str] = set()
        pyproject_file = self.root_dir / "pyproject.toml"
        if not pyproject_file.exists():
            return declared, optional_pkgs

        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore

        try:
            data = tomllib.loads(
                pyproject_file.read_text(encoding="utf-8", errors="ignore")
            )
            project_data = data.get("project", {})
            for dep in project_data.get("dependencies", []):
                if isinstance(dep, str):
                    pkg_match = re.match(r"^([a-zA-Z0-9_.-]+)", dep.strip())
                    if pkg_match:
                        canon = self.canonicalize_name(pkg_match.group(1))
                        declared[canon] = dep

            for opt_list in project_data.get("optional-dependencies", {}).values():
                if isinstance(opt_list, list):
                    for dep in opt_list:
                        if isinstance(dep, str):
                            pkg_match = re.match(r"^([a-zA-Z0-9_.-]+)", dep.strip())
                            if pkg_match:
                                canon = self.canonicalize_name(pkg_match.group(1))
                                declared[canon] = dep
                                optional_pkgs.add(canon)

            for grp_list in data.get("dependency-groups", {}).values():
                if isinstance(grp_list, list):
                    for dep in grp_list:
                        if isinstance(dep, str):
                            pkg_match = re.match(r"^([a-zA-Z0-9_.-]+)", dep.strip())
                            if pkg_match:
                                canon = self.canonicalize_name(pkg_match.group(1))
                                declared[canon] = dep
                                optional_pkgs.add(canon)
        except Exception:
            pass  # Best-effort reading; continue if pyproject.toml is unparseable
        return declared, optional_pkgs

    def read_declared_dependencies(self) -> dict[str, str]:
        """Read declared dependencies from requirements.txt or pyproject.toml."""
        declared = self._read_requirements_txt()
        pyproj_declared, self._last_optional_packages = self._read_pyproject_toml()
        declared.update(pyproj_declared)
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
        self,
        expected_dists: dict[str, str],
        declared: dict[str, str],
        optional_packages: set[str] | None = None,
    ) -> tuple[set[str], set[str]]:
        missing_packages = {
            orig_name
            for canon, orig_name in expected_dists.items()
            if canon not in declared
        }
        optional_set = optional_packages or set()
        unused_packages = {
            orig_line
            for canon, orig_line in declared.items()
            if canon not in expected_dists
            and canon not in self._KNOWN_DEV_TOOLS
            and canon not in optional_set
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
            details.append(
                "Updated requirements.txt successfully (backup saved as requirements.txt.bak)"
            )
        return details

    def audit(
        self,
        fix: bool = False,
        prune_unused: bool = False,
        target_files: Sequence[Path] | None = None,
    ) -> DependencyAuditReport:
        """Audit dependencies and optionally update requirements.txt."""
        all_imports = self.scan_codebase_imports(target_files=target_files)
        local_mods = self.identify_local_modules()

        third_party_mods = {
            m
            for m in all_imports
            if m not in self.stdlib_names and m not in local_mods and m != "__future__"
        }
        expected_dists = self._resolve_expected_distributions(third_party_mods)
        declared = self.read_declared_dependencies()

        missing_packages, unused_packages = self._find_missing_and_unused(
            expected_dists, declared, optional_packages=self._last_optional_packages
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
        """Append missing dependencies and remove unused ones in requirements.txt with safety checks."""
        req_file = self.root_dir / "requirements.txt"
        existing_lines: list[str] = []
        if req_file.exists():
            # Create a backup before making any changes
            backup_file = req_file.with_suffix(".txt.bak")
            try:
                shutil.copy2(req_file, backup_file)
            except OSError:
                pass  # Continue if backup creation fails
            existing_lines = req_file.read_text(
                encoding="utf-8", errors="ignore"
            ).splitlines()

        remove_canons = {
            self.canonicalize_name(m.group(1))
            for u in unused_to_remove
            if (m := re.match(r"^([a-zA-Z0-9_.-]+)", u))
        }

        # Filter out any local module from being appended to requirements.txt
        local_canons = {
            self.canonicalize_name(m) for m in self.identify_local_modules()
        }
        safe_missing = {
            pkg for pkg in missing if self.canonicalize_name(pkg) not in local_canons
        }

        new_lines: list[str] = []
        for line in existing_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-")):
                new_lines.append(line)
                continue

            pkg_match = re.match(r"^([a-zA-Z0-9_.-]+)", stripped)
            if pkg_match:
                pkg_name = pkg_match.group(1)
                canon = self.canonicalize_name(pkg_name)
                if canon in remove_canons:
                    continue
            new_lines.append(line)

        # Append missing packages
        new_lines.extend(sorted(safe_missing))

        req_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        return True
