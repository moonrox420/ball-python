"""
Dead code detector for Python codebases.

AST-based analysis that identifies unused functions, classes, variables,
unreachable code after return/raise/break/continue, and empty pass branches.
"""

from __future__ import annotations

import ast
import logging
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


def _is_pure_expression(node: ast.AST | None) -> bool:
    """Determine if an AST expression is pure (guaranteed free of side effects)."""
    if node is None:
        return True
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_is_pure_expression(elt) for elt in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (k is None or _is_pure_expression(k)) and _is_pure_expression(v)
            for k, v in zip(node.keys, node.values)
        )
    if isinstance(node, ast.UnaryOp):
        return _is_pure_expression(node.operand)
    if isinstance(node, ast.BinOp):
        return _is_pure_expression(node.left) and _is_pure_expression(node.right)
    if isinstance(node, ast.BoolOp):
        return all(_is_pure_expression(v) for v in node.values)
    if isinstance(node, ast.Compare):
        return _is_pure_expression(node.left) and all(
            _is_pure_expression(c) for c in node.comparators
        )
    if isinstance(node, ast.JoinedStr):
        for val in node.values:
            if isinstance(val, ast.FormattedValue) and not _is_pure_expression(
                val.value
            ):
                return False
        return True
    if isinstance(node, ast.Lambda):
        return True
    return False


def _walk_stmts_in_scope(body: list[ast.stmt]) -> list[tuple[ast.stmt, list[ast.stmt]]]:
    """Yield (stmt, parent_body) for statements within this scope without descending into nested functions/classes."""
    result: list[tuple[ast.stmt, list[ast.stmt]]] = []
    for s in body:
        result.append((s, body))
        if isinstance(s, (ast.If, ast.While, ast.For, ast.AsyncFor)):
            result.extend(_walk_stmts_in_scope(s.body))
            if s.orelse:
                result.extend(_walk_stmts_in_scope(s.orelse))
        elif isinstance(s, ast.Try):
            result.extend(_walk_stmts_in_scope(s.body))
            for h in s.handlers:
                result.extend(_walk_stmts_in_scope(h.body))
            if s.orelse:
                result.extend(_walk_stmts_in_scope(s.orelse))
            if s.finalbody:
                result.extend(_walk_stmts_in_scope(s.finalbody))
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            result.extend(_walk_stmts_in_scope(s.body))
        elif hasattr(ast, "Match") and isinstance(s, ast.Match):
            for case in s.cases:
                result.extend(_walk_stmts_in_scope(case.body))
    return result


def _has_logging_import(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "logging":
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and (
                node.module == "logging" or node.module.startswith("logging.")
            ):
                return True
    return False


def _detect_unused_locals_in_function(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    filepath: str,
) -> list[DeadCodeItem]:
    items: list[DeadCodeItem] = []
    args_set: set[str] = set()
    for a in func_node.args.posonlyargs:
        args_set.add(a.arg)
    for a in func_node.args.args:
        args_set.add(a.arg)
    for a in func_node.args.kwonlyargs:
        args_set.add(a.arg)
    if func_node.args.vararg:
        args_set.add(func_node.args.vararg.arg)
    if func_node.args.kwarg:
        args_set.add(func_node.args.kwarg.arg)

    explicit_globals: set[str] = set()
    has_dynamic = False
    loaded_names: set[str] = set()

    for sub in ast.walk(func_node):
        if isinstance(sub, (ast.Global, ast.Nonlocal)):
            explicit_globals.update(sub.names)
        elif isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
            loaded_names.add(sub.id)
        elif isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Name) and func.id in (
                "locals",
                "vars",
                "eval",
                "exec",
            ):
                has_dynamic = True

    if has_dynamic:
        return items

    stmts_in_scope = _walk_stmts_in_scope(func_node.body)
    seen_unused: set[str] = set()
    for stmt, _ in stmts_in_scope:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    name = target.id
                    if (
                        not name.startswith("_")
                        and name not in args_set
                        and name not in explicit_globals
                        and name not in loaded_names
                        and name not in seen_unused
                    ):
                        seen_unused.add(name)
                        items.append(
                            DeadCodeItem(
                                filepath=filepath,
                                lineno=target.lineno,
                                end_lineno=getattr(target, "end_lineno", target.lineno),
                                name=name,
                                kind="variable",
                                reason=f"Local variable '{name}' is assigned in '{func_node.name}' but never used",
                                confidence="high",
                            )
                        )
                elif isinstance(target, (ast.Tuple, ast.List)):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            name = elt.id
                            if (
                                not name.startswith("_")
                                and name not in args_set
                                and name not in explicit_globals
                                and name not in loaded_names
                                and name not in seen_unused
                            ):
                                seen_unused.add(name)
                                items.append(
                                    DeadCodeItem(
                                        filepath=filepath,
                                        lineno=elt.lineno,
                                        end_lineno=getattr(
                                            elt, "end_lineno", elt.lineno
                                        ),
                                        name=name,
                                        kind="variable",
                                        reason=f"Local variable '{name}' is assigned in '{func_node.name}' but never used",
                                        confidence="high",
                                    )
                                )
        elif isinstance(stmt, ast.AnnAssign):
            if isinstance(stmt.target, ast.Name):
                name = stmt.target.id
                if (
                    not name.startswith("_")
                    and name not in args_set
                    and name not in explicit_globals
                    and name not in loaded_names
                    and name not in seen_unused
                ):
                    seen_unused.add(name)
                    items.append(
                        DeadCodeItem(
                            filepath=filepath,
                            lineno=stmt.target.lineno,
                            end_lineno=getattr(
                                stmt.target, "end_lineno", stmt.target.lineno
                            ),
                            name=name,
                            kind="variable",
                            reason=f"Local variable '{name}' is assigned in '{func_node.name}' but never used",
                            confidence="high",
                        )
                    )
    return items


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
        self.items.extend(_detect_unused_locals_in_function(node, self.filepath))
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

        # In __init__.py files, all module-level non-private definitions represent public package exports
        if py_file.name == "__init__.py":
            for name, kind, lineno, end_lineno, ctx in def_collector.definitions:
                if ctx == "<module>" and not name.startswith("_"):
                    self.exports.add(name)

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
        if name == "_" or (name.startswith("__") and name.endswith("__")):
            return True
        exempt_prefixes = ("test_", "Test", "visit_")
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
    """Surgically eliminates unreachable statements, dead branches, heals empty except blocks, and fixes unused variables."""

    def fix(self, source: str, filename: str = "<stdin>") -> DeadCodeFixResult:
        current_code = source
        all_pruned: list[str] = []

        for _ in range(3):
            changed_this_pass = False

            # --- Pass 1: Empty Except Healer ---
            try:
                tree = ast.parse(current_code, filename=filename)
            except SyntaxError:
                break

            except_handlers_to_heal: list[tuple[int, int]] = []
            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler):
                    if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                        pass_node = node.body[0]
                        except_handlers_to_heal.append((node.lineno, pass_node.lineno))

            if except_handlers_to_heal:
                lines = current_code.splitlines(keepends=True)
                needs_logging_import = not _has_logging_import(tree)

                # Sort by line number descending so replacements do not shift earlier lines
                for handler_line, pass_line in sorted(
                    except_handlers_to_heal, key=lambda x: x[1], reverse=True
                ):
                    idx = pass_line - 1
                    if 0 <= idx < len(lines):
                        orig_line = lines[idx]
                        indent = orig_line[: len(orig_line) - len(orig_line.lstrip())]
                        lines[idx] = (
                            f"{indent}logging.getLogger(__name__).debug("
                            f"'Suppressed exception', exc_info=True)\n"
                        )
                        all_pruned.append(
                            f"Healed empty except block at line {handler_line} with debug logging"
                        )
                        changed_this_pass = True

                if needs_logging_import and changed_this_pass:
                    insert_idx = 0
                    while insert_idx < len(lines) and (
                        lines[insert_idx].startswith("#!")
                        or "coding:" in lines[insert_idx]
                        or "coding=" in lines[insert_idx]
                    ):
                        insert_idx += 1

                    doc_node = (
                        tree.body[0]
                        if tree.body
                        and isinstance(tree.body[0], ast.Expr)
                        and isinstance(tree.body[0].value, ast.Constant)
                        and isinstance(tree.body[0].value.value, str)
                        else None
                    )
                    if (
                        doc_node
                        and hasattr(doc_node, "end_lineno")
                        and doc_node.end_lineno is not None
                    ):
                        insert_idx = max(insert_idx, doc_node.end_lineno)

                    for stmt in tree.body:
                        if (
                            isinstance(stmt, ast.ImportFrom)
                            and stmt.module == "__future__"
                            and hasattr(stmt, "end_lineno")
                            and stmt.end_lineno is not None
                        ):
                            insert_idx = max(insert_idx, stmt.end_lineno)

                    lines.insert(insert_idx, "import logging\n")
                    all_pruned.append("Added 'import logging' for healed except block")

                candidate = "".join(lines)
                try:
                    ast.parse(candidate, filename=filename)
                    current_code = candidate
                except SyntaxError:
                    logging.getLogger(__name__).debug(
                        "Suppressed exception", exc_info=True
                    )

            # --- Pass 2: Dead Variable Fixer ---
            try:
                tree = ast.parse(current_code, filename=filename)
            except SyntaxError:
                break

            renames: list[tuple[int, int, int, str, str]] = []
            deletions: list[tuple[int, int, list[ast.stmt], str]] = []

            # 2a. Function-level local variables
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    args_set: set[str] = set()
                    for a in node.args.posonlyargs:
                        args_set.add(a.arg)
                    for a in node.args.args:
                        args_set.add(a.arg)
                    for a in node.args.kwonlyargs:
                        args_set.add(a.arg)
                    if node.args.vararg:
                        args_set.add(node.args.vararg.arg)
                    if node.args.kwarg:
                        args_set.add(node.args.kwarg.arg)

                    explicit_globals: set[str] = set()
                    has_dynamic = False
                    loaded_names: set[str] = set()

                    for sub in ast.walk(node):
                        if isinstance(sub, (ast.Global, ast.Nonlocal)):
                            explicit_globals.update(sub.names)
                        elif isinstance(sub, ast.Name) and isinstance(
                            sub.ctx, ast.Load
                        ):
                            loaded_names.add(sub.id)
                        elif isinstance(sub, ast.Call):
                            func = sub.func
                            if isinstance(func, ast.Name) and func.id in (
                                "locals",
                                "vars",
                                "eval",
                                "exec",
                            ):
                                has_dynamic = True

                    if has_dynamic:
                        continue

                    stmts_in_scope = _walk_stmts_in_scope(node.body)
                    for stmt, parent_body in stmts_in_scope:
                        if isinstance(stmt, ast.Assign):
                            if len(stmt.targets) == 1 and isinstance(
                                stmt.targets[0], ast.Name
                            ):
                                target = stmt.targets[0]
                                name = target.id
                                if (
                                    not name.startswith("_")
                                    and name not in args_set
                                    and name not in explicit_globals
                                    and name not in loaded_names
                                ):
                                    if _is_pure_expression(stmt.value):
                                        deletions.append(
                                            (
                                                stmt.lineno,
                                                getattr(
                                                    stmt, "end_lineno", stmt.lineno
                                                ),
                                                parent_body,
                                                name,
                                            )
                                        )
                                    else:
                                        if hasattr(target, "col_offset") and hasattr(
                                            target, "end_col_offset"
                                        ):
                                            renames.append(
                                                (
                                                    target.lineno,
                                                    target.col_offset,
                                                    target.end_col_offset,
                                                    f"_{name}",
                                                    name,
                                                )
                                            )
                            elif len(stmt.targets) == 1 and isinstance(
                                stmt.targets[0], (ast.Tuple, ast.List)
                            ):
                                for elt in stmt.targets[0].elts:
                                    if isinstance(elt, ast.Name):
                                        name = elt.id
                                        if (
                                            not name.startswith("_")
                                            and name not in args_set
                                            and name not in explicit_globals
                                            and name not in loaded_names
                                            and hasattr(elt, "col_offset")
                                            and hasattr(elt, "end_col_offset")
                                        ):
                                            renames.append(
                                                (
                                                    elt.lineno,
                                                    elt.col_offset,
                                                    elt.end_col_offset,
                                                    f"_{name}",
                                                    name,
                                                )
                                            )
                        elif isinstance(stmt, ast.AnnAssign):
                            if isinstance(stmt.target, ast.Name):
                                name = stmt.target.id
                                if (
                                    not name.startswith("_")
                                    and name not in args_set
                                    and name not in explicit_globals
                                    and name not in loaded_names
                                ):
                                    if stmt.value is not None and _is_pure_expression(
                                        stmt.value
                                    ):
                                        deletions.append(
                                            (
                                                stmt.lineno,
                                                getattr(
                                                    stmt, "end_lineno", stmt.lineno
                                                ),
                                                parent_body,
                                                name,
                                            )
                                        )
                                    else:
                                        target = stmt.target
                                        if hasattr(target, "col_offset") and hasattr(
                                            target, "end_col_offset"
                                        ):
                                            renames.append(
                                                (
                                                    target.lineno,
                                                    target.col_offset,
                                                    target.end_col_offset,
                                                    f"_{name}",
                                                    name,
                                                )
                                            )

            # 2b. Module-level script variables (when not an __init__.py package export)
            if not filename.endswith("__init__.py"):
                module_loads: set[str] = set()
                module_exports: set[str] = set()
                for sub in ast.walk(tree):
                    if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                        module_loads.add(sub.id)
                    elif (
                        isinstance(sub, ast.Assign)
                        and any(
                            isinstance(t, ast.Name) and t.id == "__all__"
                            for t in sub.targets
                        )
                        and isinstance(sub.value, (ast.List, ast.Tuple, ast.Set))
                    ):
                        for elt in sub.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(
                                elt.value, str
                            ):
                                module_exports.add(elt.value)

                for stmt in tree.body:
                    if (
                        isinstance(stmt, ast.Assign)
                        and len(stmt.targets) == 1
                        and isinstance(stmt.targets[0], ast.Name)
                    ):
                        target = stmt.targets[0]
                        name = target.id
                        if (
                            not name.startswith("_")
                            and name != "__all__"
                            and name not in module_loads
                            and name not in module_exports
                        ):
                            if _is_pure_expression(stmt.value):
                                deletions.append(
                                    (
                                        stmt.lineno,
                                        getattr(stmt, "end_lineno", stmt.lineno),
                                        tree.body,
                                        name,
                                    )
                                )
                            else:
                                if hasattr(target, "col_offset") and hasattr(
                                    target, "end_col_offset"
                                ):
                                    renames.append(
                                        (
                                            target.lineno,
                                            target.col_offset,
                                            target.end_col_offset,
                                            f"_{name}",
                                            name,
                                        )
                                    )

            if renames or deletions:
                lines = current_code.splitlines(keepends=True)

                # 1. Apply renames line-by-line, ordered by column descending
                renames_by_line: dict[int, list[tuple[int, int, str, str]]] = {}
                for lineno, col, end_col, new_text, name in renames:
                    renames_by_line.setdefault(lineno, []).append(
                        (col, end_col, new_text, name)
                    )

                for lineno, line_renames in renames_by_line.items():
                    idx = lineno - 1
                    if 0 <= idx < len(lines):
                        line_str = lines[idx]
                        for col, end_col, new_text, name in sorted(
                            line_renames, key=lambda x: x[0], reverse=True
                        ):
                            line_str = line_str[:col] + new_text + line_str[end_col:]
                            all_pruned.append(
                                f"Prefixed unused variable '{name}' with '_' at line {lineno} to preserve side effects"
                            )
                            changed_this_pass = True
                        lines[idx] = line_str

                # 2. Apply deletions ordered by start line descending
                for start_line, end_line, parent_body, name in sorted(
                    deletions, key=lambda x: x[0], reverse=True
                ):
                    start_idx = start_line - 1
                    if 0 <= start_idx < len(lines):
                        if len(parent_body) == 1:
                            orig_line = lines[start_idx]
                            indent = orig_line[
                                : len(orig_line) - len(orig_line.lstrip())
                            ]
                            lines[start_idx:end_line] = [f"{indent}pass\n"]
                        else:
                            del lines[start_idx:end_line]
                        all_pruned.append(
                            f"Pruned unused local variable '{name}' assignment at line {start_line}"
                        )
                        changed_this_pass = True

                candidate = "".join(lines)
                try:
                    ast.parse(candidate, filename=filename)
                    current_code = candidate
                except SyntaxError:
                    logging.getLogger(__name__).debug(
                        "Suppressed exception", exc_info=True
                    )

            # --- Pass 3: Unreachable Code & Redundant Pass ---
            try:
                tree = ast.parse(current_code, filename=filename)
            except SyntaxError:
                break

            collector = _DeadCodePrunerCollector()
            collector.visit(tree)
            if collector.deletions:
                lines = current_code.splitlines(keepends=True)
                sorted_deletions = sorted(
                    collector.deletions, key=lambda x: x[0], reverse=True
                )
                for start_line, end_line, desc in sorted_deletions:
                    del lines[start_line - 1 : end_line]
                    all_pruned.append(desc)
                    changed_this_pass = True

                candidate = "".join(lines)
                try:
                    ast.parse(candidate, filename=filename)
                    current_code = candidate
                except SyntaxError:
                    logging.getLogger(__name__).debug(
                        "Suppressed exception", exc_info=True
                    )

            if not changed_this_pass:
                break

        return DeadCodeFixResult(
            code=current_code,
            changed=current_code != source,
            pruned_items=all_pruned,
        )
