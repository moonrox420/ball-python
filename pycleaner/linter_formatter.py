"""
Static linter and code formatter engine.

Integrates ultra-fast Ruff engine for auto-fixing lint errors, sorting imports,
pruning unused imports and variables, and formatting code. Provides graceful
fallbacks via autoflake, isort, black, and built-in pure-Python AST pruning.
"""

from __future__ import annotations

import ast
import logging
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field


@dataclass(slots=True)
class LintFormatResult:
    """Result of running linting fixes and code formatting."""

    code: str
    lint_changed: bool
    format_changed: bool
    diagnostics: list[str] = field(default_factory=list)


class _UsageCollector(ast.NodeVisitor):
    """Collects loaded identifier names and import nodes across an AST."""

    def __init__(self) -> None:
        self.used_names: set[str] = set()
        self.import_nodes: list[ast.Import | ast.ImportFrom] = []

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Load, ast.Del)):
            self.used_names.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self.visit(node.value)

    def visit_Import(self, node: ast.Import) -> None:
        self.import_nodes.append(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.import_nodes.append(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            val = node.value.strip()
            # Only treat single valid Python identifiers as used names (e.g. forward references like 'Card' or __all__ = ['Card'])
            if re.fullmatch(r"[a-zA-Z_]\w*", val):
                self.used_names.add(val)
        self.generic_visit(node)


class LinterFormatter:
    """Orchestrates static lint autofixes and canonical formatting."""

    # Default rule selection for safe automated fixes:
    # F401: unused imports
    # F841: unused variables
    # I: isort (import ordering & consolidation)
    # UP: pyupgrade (modern Python syntax)
    # E, W: pycodestyle whitespace/syntax
    # B: flake8-bugbear
    # SIM: flake8-simplify
    # RUF: ruff-specific safe cleanups
    DEFAULT_SELECT_RULES = "F401,F841,I,UP,E,W,B,SIM,RUF"

    def __init__(self, ruff_path: str | None = None) -> None:
        self.ruff_cmd: str | None = ruff_path or shutil.which("ruff")
        self.autoflake_cmd: str | None = shutil.which("autoflake")
        self.black_cmd: str | None = shutil.which("black")
        self.isort_cmd: str | None = shutil.which("isort")

    def fix_and_format(
        self,
        source: str,
        filename: str = "<stdin>",
        select_rules: str = DEFAULT_SELECT_RULES,
        do_lint_fix: bool = True,
        do_format: bool = True,
    ) -> LintFormatResult:
        """Run lint fixing and code formatting sequentially on source code."""
        current_code = source
        lint_changed = False
        format_changed = False
        diagnostics: list[str] = []

        if do_lint_fix:
            fixed_code, changed, diag = self.fix_lint(
                current_code, filename=filename, select_rules=select_rules
            )
            if changed:
                lint_changed = True
                current_code = fixed_code
            if diag:
                diagnostics.extend(diag)

        if do_format:
            formatted_code, changed, diag = self.format_code(
                current_code, filename=filename
            )
            if changed:
                format_changed = True
                current_code = formatted_code
            if diag:
                diagnostics.extend(diag)

        return LintFormatResult(
            code=current_code,
            lint_changed=lint_changed,
            format_changed=format_changed,
            diagnostics=diagnostics,
        )

    def _fix_lint_ruff(
        self, source: str, filename: str, select_rules: str, diagnostics: list[str]
    ) -> tuple[str, bool, list[str]] | None:
        if not self.ruff_cmd:
            return None
        cmd = [
            self.ruff_cmd,
            "check",
            "--fix",
            f"--select={select_rules}",
            "--stdin-filename",
            filename,
            "-",
        ]
        try:
            proc = subprocess.run(
                cmd, input=source.encode("utf-8"), capture_output=True, check=False
            )
            output = proc.stdout.decode("utf-8", errors="replace")
            stderr = proc.stderr.decode("utf-8", errors="replace").strip()
            diag = [stderr] if stderr else []
            if proc.returncode in (0, 1) and output:
                return output, output != source, diag
        except OSError as err:
            diagnostics.append(
                f"Ruff unavailable ({err}); falling through to fallbacks."
            )
        return None

    def _fix_lint_autoflake(
        self, source: str, filename: str, diagnostics: list[str]
    ) -> tuple[str, bool]:
        if not self.autoflake_cmd:
            return source, False
        cmd = [
            self.autoflake_cmd,
            "--remove-all-unused-imports",
            "--stdin-display-name",
            filename,
            "-",
        ]
        try:
            proc = subprocess.run(
                cmd, input=source.encode("utf-8"), capture_output=True, check=False
            )
            if proc.returncode == 0 and proc.stdout:
                output = proc.stdout.decode("utf-8", errors="replace")
                if output != source:
                    diagnostics.append("Pruned unused imports using autoflake fallback")
                    return output, True
        except OSError:
            # Fall back to pure-Python import pruning if autoflake CLI fails
            logging.getLogger(__name__).debug("Suppressed exception", exc_info=True)
        return source, False

    def _isort_cli_sort(self, code: str) -> str | None:
        if not self.isort_cmd:
            return None
        try:
            proc = subprocess.run(
                [self.isort_cmd, "-"],
                input=code.encode("utf-8"),
                capture_output=True,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                res = proc.stdout.decode("utf-8", errors="replace")
                return res if res != code else None
        except OSError:
            # Fall back to isort Python module or pure-Python import sorter
            logging.getLogger(__name__).debug("Suppressed exception", exc_info=True)
        return None

    def _isort_module_sort(self, code: str) -> str | None:
        try:
            import isort  # type: ignore

            res = isort.code(code)
            return res if res != code else None
        except ImportError:
            return None

    def _fix_lint_isort(
        self, current_code: str, diagnostics: list[str]
    ) -> tuple[str, bool]:
        cli_sorted = self._isort_cli_sort(current_code)
        if cli_sorted is not None:
            diagnostics.append("Sorted imports using isort CLI fallback")
            return cli_sorted, True

        mod_sorted = self._isort_module_sort(current_code)
        if mod_sorted is not None:
            diagnostics.append("Sorted imports using isort module fallback")
            return mod_sorted, True

        return current_code, False

    def fix_lint(
        self,
        source: str,
        filename: str = "<stdin>",
        select_rules: str = DEFAULT_SELECT_RULES,
    ) -> tuple[str, bool, list[str]]:
        """Fix linting errors and prune unused imports."""
        current_code = source
        changed = False
        diagnostics: list[str] = []

        ruff_result = self._fix_lint_ruff(source, filename, select_rules, diagnostics)
        if ruff_result is not None:
            return ruff_result

        current_code, af_changed = self._fix_lint_autoflake(
            current_code, filename, diagnostics
        )
        changed = changed or af_changed

        if current_code == source:
            pruned_code, pruned_changed, prune_diags = (
                self._pure_python_prune_unused_imports(current_code)
            )
            if pruned_changed:
                current_code = pruned_code
                changed = True
                diagnostics.extend(prune_diags)

        current_code, isort_changed = self._fix_lint_isort(current_code, diagnostics)
        changed = changed or isort_changed

        sorted_code, sort_changed, sort_diags = self._pure_python_sort_imports(
            current_code
        )
        if sort_changed:
            current_code = sorted_code
            changed = True
            diagnostics.extend(sort_diags)

        return current_code, changed, diagnostics

    def _format_with_ruff(self, source: str, filename: str) -> tuple[str, bool] | None:
        if not self.ruff_cmd:
            return None
        cmd = [self.ruff_cmd, "format", "--stdin-filename", filename, "-"]
        try:
            proc = subprocess.run(
                cmd, input=source.encode("utf-8"), capture_output=True, check=False
            )
            if proc.returncode == 0:
                res = proc.stdout.decode("utf-8", errors="replace")
                return res, res != source
        except OSError:
            # Fall back to Black or pure-Python formatter if ruff CLI execution fails
            logging.getLogger(__name__).debug("Suppressed exception", exc_info=True)
        return None

    def _format_with_black(self, source: str) -> tuple[str, bool, list[str]] | None:
        if self.black_cmd:
            try:
                proc = subprocess.run(
                    [self.black_cmd, "-"],
                    input=source.encode("utf-8"),
                    capture_output=True,
                    check=False,
                )
                if proc.returncode == 0 and proc.stdout:
                    res = proc.stdout.decode("utf-8", errors="replace")
                    return res, res != source, ["Formatted with black CLI fallback"]
            except OSError:
                # Fall back to black module or pure-Python formatter
                logging.getLogger(__name__).debug("Suppressed exception", exc_info=True)
        try:
            import black  # type: ignore

            formatted = black.format_str(source, mode=black.Mode())
            return formatted, formatted != source, ["Formatted with black fallback"]
        except ImportError:
            return None

    def format_code(
        self,
        source: str,
        filename: str = "<stdin>",
    ) -> tuple[str, bool, list[str]]:
        """Format source code deterministically."""
        ruff_res = self._format_with_ruff(source, filename)
        if ruff_res is not None:
            return ruff_res[0], ruff_res[1], []

        black_res = self._format_with_black(source)
        if black_res is not None:
            return black_res

        formatted = self._pure_python_format(source)
        if formatted != source:
            return formatted, True, ["Applied pure-Python whitespace canonicalization"]
        return source, False, []

    def _pure_python_format(self, source: str, line_length: int = 88) -> str:
        """Strip trailing whitespace, collapse excessive blank lines, wrap long imports, and ensure a trailing newline."""
        lines = [line.rstrip() for line in source.splitlines()]
        cleaned = "\n".join(lines).strip() + "\n" if lines else ""
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
        cleaned = self._wrap_long_imports(cleaned, line_length=line_length)
        return cleaned

    @staticmethod
    def _wrap_single_line(line: str, line_length: int) -> str | None:
        stripped = line.strip()
        if (
            len(line.rstrip("\r\n")) <= line_length
            or not stripped.startswith("from ")
            or " import " not in stripped
            or "(" in stripped
        ):
            return None
        parts = stripped.split(" import ", 1)
        prefix = parts[0]
        names = [n.strip() for n in parts[1].split(",") if n.strip()]
        if len(names) <= 1:
            return None
        indent_match = re.match(r"^([ \t]*)", line)
        indent = indent_match.group(1) if indent_match else ""
        wrapped = f"{indent}{prefix} import (\n"
        for name in names:
            wrapped += f"{indent}    {name},\n"
        wrapped += f"{indent})\n"
        return wrapped

    def _wrap_long_imports(self, source: str, line_length: int = 88) -> str:
        """Wrap import statements exceeding line_length onto multiple lines."""
        lines = source.splitlines(keepends=True)
        changed = False

        for i, line in enumerate(lines):
            wrapped = self._wrap_single_line(line, line_length)
            if wrapped is not None:
                lines[i] = wrapped
                changed = True

        if changed:
            candidate = "".join(lines)
            try:
                ast.parse(candidate)
                return candidate
            except SyntaxError:
                return source
        return source

    @staticmethod
    def _categorize_import(
        node: ast.Import | ast.ImportFrom,
        stmt_str: str,
        stdlib_names: frozenset[str] | set[str],
    ) -> tuple[str, str]:
        """Return (group_name, stmt_str) where group_name is future/local/stdlib/third_party."""
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            return "future", stmt_str
        if isinstance(node, ast.ImportFrom) and (node.level and node.level > 0):
            return "local", stmt_str
        root_mod = (
            (node.module or "").split(".")[0]
            if isinstance(node, ast.ImportFrom)
            else node.names[0].name.split(".")[0]
        )
        if root_mod in stdlib_names:
            return "stdlib", stmt_str
        return "third_party", stmt_str

    @staticmethod
    def _assemble_sorted_import_block(groups_dict: dict[str, list[str]]) -> str:
        groups: list[str] = []
        combined_stdlib = sorted(groups_dict["future"]) + sorted(groups_dict["stdlib"])
        if combined_stdlib:
            groups.append("\n".join(combined_stdlib))
        if groups_dict["third_party"]:
            groups.append("\n".join(sorted(groups_dict["third_party"])))
        if groups_dict["local"]:
            groups.append("\n".join(sorted(groups_dict["local"])))
        return "\n\n".join(groups) + "\n"

    @staticmethod
    def _has_interspersed_non_imports(
        lines: list[str], import_line_set: set[int], min_line: int, max_line: int
    ) -> bool:
        for lno in range(min_line, max_line + 1):
            if lno not in import_line_set:
                txt = lines[lno - 1].strip()
                if txt and not txt.startswith("#"):
                    return True
        return False

    @staticmethod
    def _group_import_nodes(
        import_nodes: list[ast.Import | ast.ImportFrom],
        lines: list[str],
        stdlib_names: frozenset[str] | set[str],
    ) -> dict[str, list[str]]:
        groups_dict: dict[str, list[str]] = {
            "future": [],
            "stdlib": [],
            "third_party": [],
            "local": [],
        }
        for node in import_nodes:
            stmt_lines = lines[
                node.lineno - 1 : getattr(node, "end_lineno", node.lineno)
            ]
            stmt_str = "".join(stmt_lines).rstrip("\r\n")
            grp, text = LinterFormatter._categorize_import(node, stmt_str, stdlib_names)
            groups_dict[grp].append(text)
        return groups_dict

    @staticmethod
    def _validate_sorted_candidate(
        candidate: str, source: str
    ) -> tuple[str, bool, list[str]]:
        try:
            ast.parse(candidate)
            if candidate != source:
                return (
                    candidate,
                    True,
                    ["Sorted imports into stdlib, third-party, and local groups"],
                )
        except SyntaxError:
            # Return unmodified source if candidate code has syntax issues
            logging.getLogger(__name__).debug("Suppressed exception", exc_info=True)
        return source, False, []

    def _pure_python_sort_imports(self, source: str) -> tuple[str, bool, list[str]]:
        """Sort imports into 3 groups (stdlib -> third-party -> local) when ruff/isort unavailable."""
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, False, []

        import_nodes = [
            n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))
        ]
        if len(import_nodes) < 2:
            return source, False, []

        min_line = min(node.lineno for node in import_nodes)
        max_line = max(
            getattr(node, "end_lineno", node.lineno) for node in import_nodes
        )
        lines = source.splitlines(keepends=True)

        import_line_set = {
            lno
            for node in import_nodes
            for lno in range(node.lineno, getattr(node, "end_lineno", node.lineno) + 1)
        }
        if self._has_interspersed_non_imports(
            lines, import_line_set, min_line, max_line
        ):
            return source, False, []

        stdlib_names: frozenset[str] | set[str] = getattr(
            sys, "stdlib_module_names", set()
        )
        groups_dict = self._group_import_nodes(import_nodes, lines, stdlib_names)
        new_block = self._assemble_sorted_import_block(groups_dict)
        candidate = "".join(lines[: min_line - 1] + [new_block] + lines[max_line:])
        return self._validate_sorted_candidate(candidate, source)

    @staticmethod
    def _is_suppressed_import(stmt_lines: list[str]) -> bool:
        joined = "".join(stmt_lines)
        return "# noqa" in joined or "# type: ignore" in joined

    @staticmethod
    def _format_pruned_stmt(node: ast.AST, kept_aliases: list[ast.alias]) -> str:
        indent = " " * getattr(node, "col_offset", 0)
        alias_strs = [
            f"{a.name} as {a.asname}" if a.asname else a.name for a in kept_aliases
        ]
        if isinstance(node, ast.ImportFrom):
            dots = "." * (node.level or 0)
            mod = node.module or ""
            return f"{indent}from {dots}{mod} import {', '.join(alias_strs)}\n"
        return f"{indent}import {', '.join(alias_strs)}\n"

    @staticmethod
    def _partition_aliases(
        node: ast.AST, used_names: set[str]
    ) -> tuple[list[ast.alias], list[str]]:
        kept_aliases: list[ast.alias] = []
        unused_aliases: list[str] = []
        for alias in getattr(node, "names", []):
            bound = alias.asname or (
                alias.name.split(".")[0] if isinstance(node, ast.Import) else alias.name
            )
            if bound in used_names:
                kept_aliases.append(alias)
            else:
                unused_aliases.append(bound)
        return kept_aliases, unused_aliases

    def _prune_single_import(
        self,
        node: ast.AST,
        lines: list[str],
        used_names: set[str],
        diagnostics: list[str],
    ) -> bool:
        start_line = getattr(node, "lineno", None)
        end_line = getattr(node, "end_lineno", start_line)
        if start_line is None or end_line is None:
            return False

        if self._is_suppressed_import(lines[start_line - 1 : end_line]):
            return False

        if isinstance(node, ast.ImportFrom) and any(
            alias.name == "*" for alias in node.names
        ):
            return False

        kept_aliases, unused_aliases = self._partition_aliases(node, used_names)
        if not unused_aliases:
            return False

        if not kept_aliases:
            del lines[start_line - 1 : end_line]
        else:
            lines[start_line - 1 : end_line] = [
                self._format_pruned_stmt(node, kept_aliases)
            ]

        for unused_name in unused_aliases:
            diagnostics.append(
                f"Pruned unused import '{unused_name}' (pure-Python fallback)"
            )
        return True

    def _pure_python_prune_unused_imports(
        self, source: str
    ) -> tuple[str, bool, list[str]]:
        """Statically detect and prune unused imports using AST analysis."""
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, False, []

        collector = _UsageCollector()
        collector.visit(tree)
        lines = source.splitlines(keepends=True)
        diagnostics: list[str] = []
        changed = False

        sorted_imports = sorted(
            collector.import_nodes,
            key=lambda node: getattr(node, "lineno", 0),
            reverse=True,
        )

        for node in sorted_imports:
            if self._prune_single_import(
                node, lines, collector.used_names, diagnostics
            ):
                changed = True

        if not changed:
            return source, False, []

        candidate = re.sub(r"\n{3,}", "\n\n", "".join(lines))
        try:
            ast.parse(candidate)
            return candidate, True, diagnostics
        except SyntaxError:
            return source, False, []
