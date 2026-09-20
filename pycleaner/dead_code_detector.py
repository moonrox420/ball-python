"""
Dead code detector for Python codebases.

AST-based analysis that identifies unused functions, classes, variables,
unreachable code after return/raise/break/continue, and empty pass branches.
"""

from __future__ import annotations

import ast
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from pycleaner.discovery import collect_project_python_files
from pycleaner.frameworks import FrameworkRegistry, get_default_registry


@dataclass(slots=True)
class DeadCodeItem:
    """A single piece of detected dead code."""

    filepath: str
    lineno: int
    end_lineno: int | None
    name: str
    kind: str  # 'function', 'class', 'variable', 'unreachable', 'empty-branch', 'unused-import'
    reason: str
    confidence: str = "high"  # 'high', 'medium', 'low'


@dataclass(slots=True)
class DeadCodeReport:
    """Full dead code analysis report for a project."""

    items: list[DeadCodeItem] = field(default_factory=list)
    files_scanned: int = 0
    total_definitions: int = 0

    @property
    def count(self) -> int:
        return len(self.items)

    def by_kind(self, kind: str) -> list[DeadCodeItem]:
        return [item for item in self.items if item.kind == kind]


class _DefinitionCollector(ast.NodeVisitor):
    """Collects all function and class definitions with their line numbers."""

    def __init__(
        self,
        filepath: str,
        tree: ast.AST | None = None,
        registry: FrameworkRegistry | None = None,
    ) -> None:
        self.filepath = filepath
        self.tree = tree
        self.registry = registry or get_default_registry()
        self.definitions: list[tuple[str, str, int, int | None, str]] = []
        # (name, kind, lineno, end_lineno, scope_context)
        self._scope_stack: list[str] = []
        self._class_stack: list[ast.ClassDef] = []

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        context = ".".join(self._scope_stack) if self._scope_stack else "<module>"
        if self.tree is not None and self.registry.is_protected(
            node.name, "function", node, context, self.tree, self.filepath
        ):
            self._scope_stack.append(node.name)
            self.generic_visit(node)
            self._scope_stack.pop()
            return

        self.definitions.append(
            (node.name, "function", node.lineno, node.end_lineno, context)
        )
        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        context = ".".join(self._scope_stack) if self._scope_stack else "<module>"
        if self.tree is not None and self.registry.is_protected(
            node.name, "class", node, context, self.tree, self.filepath
        ):
            self._scope_stack.append(node.name)
            self._class_stack.append(node)
            self.generic_visit(node)
            self._class_stack.pop()
            self._scope_stack.pop()
            return

        self.definitions.append(
            (node.name, "class", node.lineno, node.end_lineno, context)
        )
        self._scope_stack.append(node.name)
        self._class_stack.append(node)
        self.generic_visit(node)
        self._class_stack.pop()
        self._scope_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._class_stack and self.tree is not None:
            if self.registry.is_field_protected(
                node, self._class_stack[-1], self.tree, self.filepath
            ):
                self.generic_visit(node)
                return

        # Module-level constants or class attributes (not local function variables)
        if not self._scope_stack or len(self._scope_stack) == 1:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name = target.id
                    if not name.startswith("__"):
                        context = (
                            ".".join(self._scope_stack)
                            if self._scope_stack
                            else "<module>"
                        )
                        if self.tree is not None and self.registry.is_protected(
                            name, "variable", node, context, self.tree, self.filepath
                        ):
                            continue
                        self.definitions.append(
                            (name, "variable", node.lineno, node.end_lineno, context)
                        )
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if self._class_stack and self.tree is not None:
            if self.registry.is_field_protected(
                node, self._class_stack[-1], self.tree, self.filepath
            ):
                self.generic_visit(node)
                return

        if (not self._scope_stack or len(self._scope_stack) == 1) and isinstance(
            node.target, ast.Name
        ):
            name = node.target.id
            if not name.startswith("__"):
                context = (
                    ".".join(self._scope_stack) if self._scope_stack else "<module>"
                )
                if self.tree is not None and self.registry.is_protected(
                    name, "variable", node, context, self.tree, self.filepath
                ):
                    self.generic_visit(node)
                    return
                self.definitions.append(
                    (name, "variable", node.lineno, node.end_lineno, context)
                )
        self.generic_visit(node)


class _ReferenceCollector(ast.NodeVisitor):
    """Collects all name references (loads) across source code."""

    def __init__(self) -> None:
        self.referenced_names: set[str] = set()
        self.all_exports: set[str] = set()
        self.decorated_names: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            self.referenced_names.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self.referenced_names.add(node.attr)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if node.decorator_list:
            self.decorated_names.add(node.name)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if node.decorator_list:
            self.decorated_names.add(node.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        # Detect __all__ = ['name1', 'name2']
        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id == "__all__"
                and isinstance(node.value, (ast.List, ast.Tuple, ast.Set))
            ):
                for elt in node.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        self.all_exports.add(elt.value)
        self.generic_visit(node)


class _UnreachableCodeDetector(ast.NodeVisitor):
    """Detects code after unconditional return/raise/break/continue and empty branches."""

    def __init__(self, filepath: str, source_lines: list[str] | None = None) -> None:
        self.filepath = filepath
        self.source_lines = source_lines
        self.items: list[DeadCodeItem] = []

    def visit_Module(self, node: ast.Module) -> None:
        self._check_body(node.body)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._check_body(node.body)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._check_body(node.body)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        self._check_body(node.body)
        self._check_empty_branch(node.body, "if", node.lineno)
        if node.orelse:
            self._check_body(node.orelse)
            first_orelse = node.orelse[0]
            label = "elif" if isinstance(first_orelse, ast.If) else "else"
            lineno = (
                first_orelse.lineno
                if isinstance(first_orelse, ast.If)
                else node.orelse[0].lineno
            )
            self._check_empty_branch(node.orelse, label, lineno)
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        self._check_body(node.body)
        self._check_body(node.finalbody)
        self._check_body(node.orelse)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self._check_body(node.body)
        self._check_empty_branch(node.body, "except", node.lineno)
        self.generic_visit(node)

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        self._check_body(node.body)
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_While(self, node: ast.While) -> None:
        self._check_body(node.body)
        self.generic_visit(node)

    def _check_body(self, body: list[ast.stmt]) -> None:
        """Check for unreachable code after return/raise/break/continue."""
        for i, stmt in enumerate(body):
            if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                remaining = body[i + 1 :]
                for unreachable in remaining:
                    # Skip if the unreachable statement is a function/class def (declarations)
                    if isinstance(
                        unreachable,
                        (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                    ):
                        continue
                    self.items.append(
                        DeadCodeItem(
                            filepath=self.filepath,
                            lineno=unreachable.lineno,
                            end_lineno=getattr(unreachable, "end_lineno", None),
                            name="<unreachable>",
                            kind="unreachable",
                            reason=f"Code after unconditional {type(stmt).__name__.lower()} on line {stmt.lineno}",
                            confidence="high",
                        )
                    )
                break

    def _check_empty_branch(
        self, body: list[ast.stmt], branch_kind: str, lineno: int
    ) -> None:
        """Check for empty branches containing only pass with no comment."""
        if len(body) == 1 and isinstance(body[0], ast.Pass):
            pass_node = body[0]
            if self.source_lines:
                idx = pass_node.lineno - 1
                if 0 <= idx < len(self.source_lines) and "#" in self.source_lines[idx]:
                    return
                # Check if preceding line is an explanatory comment
                if (
                    idx > 0
                    and 0 <= idx - 1 < len(self.source_lines)
                    and self.source_lines[idx - 1].strip().startswith("#")
                ):
                    return
            self.items.append(
                DeadCodeItem(
                    filepath=self.filepath,
                    lineno=lineno,
                    end_lineno=pass_node.lineno,
                    name=f"empty {branch_kind}",
                    kind="empty-branch",
                    reason=f"'{branch_kind}' block contains only 'pass' with no implementation",
                    confidence="low",
                )
            )


@dataclass(slots=True)
class _ProjectScanState:
    definitions: list[tuple[str, str, str, int, int | None, str]] = field(
        default_factory=list
    )
    references: set[str] = field(default_factory=set)
    exports: set[str] = field(default_factory=set)
    decorated: set[str] = field(default_factory=set)
    unreachable: list[DeadCodeItem] = field(default_factory=list)
    framework_registry: FrameworkRegistry = field(default_factory=get_default_registry)

    def process_file(self, py_file: Path) -> None:
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(py_file))
        except SyntaxError:
            return

        filepath_str = str(py_file)
        def_collector = _DefinitionCollector(
            filepath_str, tree=tree, registry=self.framework_registry
        )
        def_collector.visit(tree)
        for name, kind, lineno, end_lineno, ctx in def_collector.definitions:
            self.definitions.append((filepath_str, name, kind, lineno, end_lineno, ctx))

        ref_collector = _ReferenceCollector()
        ref_collector.visit(tree)
        self.references.update(ref_collector.referenced_names)
        self.exports.update(ref_collector.all_exports)
        self.decorated.update(ref_collector.decorated_names)

        unreachable = _UnreachableCodeDetector(filepath_str, content.splitlines())
        unreachable.visit(tree)
        self.unreachable.extend(unreachable.items)


class DeadCodeDetector:
    """Detects dead code across a Python project."""

    # Names that should never be flagged as dead code
    PROTECTED_NAMES = frozenset(
        {
            "__init__",
            "__new__",
            "__del__",
            "__repr__",
            "__str__",
            "__bytes__",
            "__format__",
            "__hash__",
            "__bool__",
            "__len__",
            "__getitem__",
            "__setitem__",
            "__delitem__",
            "__iter__",
            "__next__",
            "__contains__",
            "__enter__",
            "__exit__",
            "__aenter__",
            "__aexit__",
            "__await__",
            "__aiter__",
            "__anext__",
            "__call__",
            "__eq__",
            "__ne__",
            "__lt__",
            "__le__",
            "__gt__",
            "__ge__",
            "__add__",
            "__radd__",
            "__sub__",
            "__mul__",
            "__truediv__",
            "__floordiv__",
            "__mod__",
            "__pow__",
            "__and__",
            "__or__",
            "__xor__",
            "__neg__",
            "__pos__",
            "__abs__",
            "__invert__",
            "__getattr__",
            "__setattr__",
            "__delattr__",
            "__get__",
            "__set__",
            "__delete__",
            "__init_subclass__",
            "__class_getitem__",
            "__post_init__",
            "__set_name__",
            "setUp",
            "tearDown",
            "setUpClass",
            "tearDownClass",
            "main",
            "setup",
            "teardown",
        }
    )

    FRAMEWORK_DECORATORS: ClassVar[frozenset[str]] = frozenset(
        {
            "app.route",
            "router.get",
            "router.post",
            "router.put",
            "router.delete",
            "router.patch",
            "pytest.fixture",
            "abstractmethod",
            "staticmethod",
            "classmethod",
            "property",
            "override",
            "register",
            "receiver",
            "celery.task",
            "click.command",
            "click.group",
            "app.get",
            "app.post",
            "app.put",
            "app.delete",
            "app.patch",
            "app.task",
            "app.on_event",
            "on_event",
        }
    )

    def __init__(
        self,
        ignore_decorators: set[str] | None = None,
        ignore_names: set[str] | None = None,
        framework_registry: FrameworkRegistry | None = None,
    ) -> None:
        self.framework_registry = framework_registry or get_default_registry()
        extra_decorators: set[str] = set()
        for p in self.framework_registry.plugins:
            extra_decorators.update(p.get_protected_decorators())
        self.ignore_decorators = (
            (ignore_decorators or set())
            | set(self.FRAMEWORK_DECORATORS)
            | extra_decorators
        )
        self.ignore_names = ignore_names or set()

    def scan_project(
        self, root_dir: Path | str, exclude_patterns: Sequence[str] = ()
    ) -> DeadCodeReport:
        """Scan an entire project directory for dead code."""
        root = Path(root_dir).resolve()
        py_files = self._discover_files(root, exclude_patterns=exclude_patterns)

        state = _ProjectScanState(framework_registry=self.framework_registry)
        for py_file in py_files:
            state.process_file(py_file)

        items: list[DeadCodeItem] = list(state.unreachable)
        for filepath, name, kind, lineno, end_lineno, _ in state.definitions:
            if self._should_skip(
                name, state.references, state.exports, state.decorated
            ):
                continue
            items.append(
                DeadCodeItem(
                    filepath=filepath,
                    lineno=lineno,
                    end_lineno=end_lineno,
                    name=name,
                    kind=kind,
                    reason=f"{kind.capitalize()} '{name}' is defined but never referenced in the project",
                    confidence="medium",
                )
            )

        items.sort(key=lambda x: (x.filepath, x.lineno))
        return DeadCodeReport(
            items=items,
            files_scanned=len(py_files),
            total_definitions=len(state.definitions),
        )

    def scan_source(self, source: str, filename: str = "<unknown>") -> DeadCodeReport:
        """Scan a single source string for dead code patterns (unreachable/empty only)."""
        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError:
            return DeadCodeReport()

        unreachable = _UnreachableCodeDetector(filename, source.splitlines())
        unreachable.visit(tree)

        return DeadCodeReport(
            items=unreachable.items,
            files_scanned=1,
            total_definitions=0,
        )

    def _matches_ignore_pattern(self, name: str) -> bool:
        for pattern in self.ignore_names:
            if pattern.endswith("*") and name.startswith(pattern[:-1]):
                return True
            if name == pattern:
                return True
        return False

    def _is_name_exempt(self, name: str) -> bool:
        if name in self.PROTECTED_NAMES:
            return True
        exempt_prefixes = ("_", "test_", "Test", "visit_")
        return name.startswith(exempt_prefixes) or name == "generic_visit"

    def _should_skip(
        self,
        name: str,
        references: set[str],
        exports: set[str],
        decorated: set[str],
    ) -> bool:
        """Determine if a definition should be skipped (not flagged as dead)."""
        if name in references or name in exports or name in decorated:
            return True
        if self._is_name_exempt(name):
            return True
        return self._matches_ignore_pattern(name)

    def _discover_files(
        self, root: Path, exclude_patterns: Sequence[str] = ()
    ) -> list[Path]:
        """Walk the project tree and collect .py files, respecting ignore dirs and gitignore."""
        return collect_project_python_files(root, exclude_patterns=exclude_patterns)

    def fix_source(self, source: str, filename: str = "<stdin>") -> DeadCodeFixResult:
        """Surgically fix dead code in in-memory source."""
        fixer = DeadCodeFixer()
        return fixer.fix(source, filename=filename)

    def fix_file(
        self, filepath: Path | str, apply_changes: bool = True
    ) -> DeadCodeFixResult:
        """Surgically fix dead code in a file."""
        path = Path(filepath).resolve()
        content = path.read_text(encoding="utf-8", errors="replace")
        res = self.fix_source(content, filename=str(path))
        if apply_changes and res.changed:
            path.write_text(res.code, encoding="utf-8")
        return res

    def fix_project(
        self, root_dir: Path | str, exclude_patterns: Sequence[str] = ()
    ) -> dict[Path, DeadCodeFixResult]:
        """Surgically fix dead code across all project Python files."""
        root = Path(root_dir).resolve()
        py_files = self._discover_files(root, exclude_patterns=exclude_patterns)
        results: dict[Path, DeadCodeFixResult] = {}
        for pf in py_files:
            res = self.fix_file(pf, apply_changes=True)
            if res.changed:
                results[pf] = res
        return results


@dataclass(slots=True)
class DeadCodeFixResult:
    """Outcome of attempting to fix dead code in source code."""

    code: str
    changed: bool
    pruned_items: list[str] = field(default_factory=list)


class _DeadCodePrunerCollector(ast.NodeVisitor):
    """Collects line spans of unreachable code, redundant pass, and dead branches."""

    def __init__(self) -> None:
        self.deletions: list[tuple[int, int, str]] = []

    def _is_terminal_jump(self, stmt: ast.AST) -> bool:
        if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
            return True
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            func = stmt.value.func
            if isinstance(func, ast.Name) and func.id in ("exit", "quit"):
                return True
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "sys"
                and func.attr == "exit"
            ):
                return True
        return False

    def _inspect_stmts(self, stmts: list[ast.stmt]) -> None:
        terminal_seen = False
        unreachable: list[ast.stmt] = []
        non_doc = [
            s
            for s in stmts
            if not (
                isinstance(s, ast.Expr)
                and isinstance(s.value, ast.Constant)
                and isinstance(s.value.value, str)
            )
        ]

        for stmt in stmts:
            if terminal_seen:
                unreachable.append(stmt)
            elif self._is_terminal_jump(stmt):
                terminal_seen = True
            elif isinstance(stmt, ast.Pass) and len(non_doc) > 1:
                self.deletions.append(
                    (
                        stmt.lineno,
                        getattr(stmt, "end_lineno", stmt.lineno),
                        f"Pruned redundant 'pass' at line {stmt.lineno}",
                    )
                )
            elif (
                isinstance(stmt, ast.If)
                and isinstance(stmt.test, ast.Constant)
                and stmt.test.value in (False, 0)
                and not stmt.orelse
            ):
                self.deletions.append(
                    (
                        stmt.lineno,
                        getattr(stmt, "end_lineno", stmt.lineno),
                        f"Pruned dead 'if False' branch at line {stmt.lineno}",
                    )
                )
            self.visit(stmt)

        if unreachable:
            start_line = unreachable[0].lineno
            end_line = getattr(unreachable[-1], "end_lineno", unreachable[-1].lineno)
            self.deletions.append(
                (
                    start_line,
                    end_line,
                    f"Pruned {len(unreachable)} unreachable statement(s) at lines {start_line}-{end_line}",
                )
            )

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._inspect_stmts(node.body)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._inspect_stmts(node.body)

    def visit_If(self, node: ast.If) -> None:
        self._inspect_stmts(node.body)
        if node.orelse:
            self._inspect_stmts(node.orelse)

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        self._inspect_stmts(node.body)
        if node.orelse:
            self._inspect_stmts(node.orelse)

    visit_AsyncFor = visit_For

    def visit_While(self, node: ast.While) -> None:
        self._inspect_stmts(node.body)
        if node.orelse:
            self._inspect_stmts(node.orelse)

    def visit_Try(self, node: ast.Try) -> None:
        self._inspect_stmts(node.body)
        for h in node.handlers:
            self._inspect_stmts(h.body)
        if node.orelse:
            self._inspect_stmts(node.orelse)
        if node.finalbody:
            self._inspect_stmts(node.finalbody)

    def visit_With(self, node: ast.With | ast.AsyncWith) -> None:
        self._inspect_stmts(node.body)

    visit_AsyncWith = visit_With

    def visit_Match(self, node: ast.AST) -> None:
        for case in getattr(node, "cases", []):
            self._inspect_stmts(case.body)


class DeadCodeFixer:
    """Surgically eliminates unreachable statements, dead branches, and redundant pass statements."""

    def fix(self, source: str, filename: str = "<stdin>") -> DeadCodeFixResult:
        current_code = source
        all_pruned: list[str] = []

        for _ in range(2):
            try:
                tree = ast.parse(current_code, filename=filename)
            except SyntaxError:
                break

            collector = _DeadCodePrunerCollector()
            collector.visit(tree)
            if not collector.deletions:
                break

            lines = current_code.splitlines(keepends=True)
            sorted_deletions = sorted(
                collector.deletions, key=lambda x: x[0], reverse=True
            )
            for start_line, end_line, desc in sorted_deletions:
                del lines[start_line - 1 : end_line]
                all_pruned.append(desc)

            candidate = "".join(lines)
            try:
                ast.parse(candidate, filename=filename)
                current_code = candidate
            except SyntaxError:
                break

        return DeadCodeFixResult(
            code=current_code,
            changed=current_code != source,
            pruned_items=all_pruned,
        )
