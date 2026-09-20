"""
Cyclomatic and cognitive complexity analyzer for Python source code.

Computes per-function metrics including McCabe cyclomatic complexity,
Sonar-style cognitive complexity, line count, argument count, return count,
and maximum nesting depth.
"""

from __future__ import annotations

import ast
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from pycleaner.discovery import collect_project_python_files


@dataclass(slots=True)
class ComplexityMetrics:
    """Complexity measurements for a single function or method."""

    filepath: str
    lineno: int
    end_lineno: int | None
    name: str
    qualified_name: str
    cyclomatic: int
    cognitive: int
    lines: int
    args: int
    returns: int
    max_nesting: int

    @property
    def is_complex(self) -> bool:
        """Quick check for any threshold violation using generous defaults."""
        return (
            self.cyclomatic > 10
            or self.cognitive > 15
            or self.lines > 50
            or self.args > 5
        )


@dataclass(slots=True)
class ComplexityReport:
    """Full complexity analysis report."""

    functions: list[ComplexityMetrics] = field(default_factory=list)
    files_scanned: int = 0

    @property
    def count(self) -> int:
        return len(self.functions)

    def above_threshold(
        self,
        max_cyclomatic: int = 10,
        max_cognitive: int = 15,
        max_lines: int = 50,
        max_args: int = 5,
    ) -> list[ComplexityMetrics]:
        """Return functions exceeding any configured threshold."""
        return [
            f
            for f in self.functions
            if f.cyclomatic > max_cyclomatic
            or f.cognitive > max_cognitive
            or f.lines > max_lines
            or f.args > max_args
        ]

    @property
    def average_cyclomatic(self) -> float:
        if not self.functions:
            return 0.0
        return sum(f.cyclomatic for f in self.functions) / len(self.functions)

    @property
    def average_cognitive(self) -> float:
        if not self.functions:
            return 0.0
        return sum(f.cognitive for f in self.functions) / len(self.functions)


class _CyclomaticCounter(ast.NodeVisitor):
    """Counts McCabe cyclomatic complexity decision points in a function body."""

    def __init__(self) -> None:
        self.complexity = 1  # Base complexity
        # Tracks def/async-def nesting so the counter can visit the entry
        # function's own body (depth reaches 1) while refusing to descend
        # into any function defined *inside* it (depth would reach 2+).
        # Without this, a nested helper's branches get double-counted: once
        # against itself, and again against every function that encloses it.
        self._function_depth = 0

    def visit_If(self, node: ast.If) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        self.complexity += 1
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_While(self, node: ast.While) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_With(self, node: ast.With | ast.AsyncWith) -> None:
        self.complexity += 1
        self.generic_visit(node)

    visit_AsyncWith = visit_With

    def visit_Assert(self, node: ast.Assert) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        # Each 'and' or 'or' adds a decision branch
        self.complexity += len(node.values) - 1
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        # Ternary expression: x if cond else y
        self.complexity += 1
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        self.complexity += 1
        # Each filter condition is an additional branch
        self.complexity += len(node.ifs)
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        # Each case is a branch
        self.complexity += len(node.cases)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._function_depth += 1
        if self._function_depth == 1:
            # This is the entry function being scored; walk its body.
            self.generic_visit(node)
        # A nested def is scored as its own independent entry elsewhere;
        # do not descend into it from here.
        self._function_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef


class _CognitiveCounter(ast.NodeVisitor):
    """Computes Sonar-style cognitive complexity score."""

    def __init__(self) -> None:
        self.score = 0
        self._nesting = 0

    def _increment(self, nesting_penalty: bool = True) -> None:
        self.score += 1
        if nesting_penalty:
            self.score += self._nesting

    def _handle_elif(self, orelse_node: ast.If) -> None:
        self.score += 1
        self._nesting += 1
        for child in orelse_node.body:
            self.visit(child)
        self._nesting -= 1
        for sub in orelse_node.orelse:
            if isinstance(sub, ast.If):
                self.visit_If(sub)
            else:
                self.visit(sub)

    def _handle_else(self, orelse_node: ast.AST) -> None:
        self.score += 1
        self._nesting += 1
        self.visit(orelse_node)
        self._nesting -= 1

    def visit_If(self, node: ast.If) -> None:
        self._increment(nesting_penalty=True)
        self._nesting += 1
        for child in node.body:
            self.visit(child)
        self._nesting -= 1

        for orelse_node in node.orelse:
            if isinstance(orelse_node, ast.If):
                self._handle_elif(orelse_node)
            else:
                self._handle_else(orelse_node)

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        self._increment(nesting_penalty=True)
        self._nesting += 1
        for child in node.body:
            self.visit(child)
        self._nesting -= 1
        for child in node.orelse:
            self.visit(child)

    visit_AsyncFor = visit_For

    def visit_While(self, node: ast.While) -> None:
        self._increment(nesting_penalty=True)
        self._nesting += 1
        for child in node.body:
            self.visit(child)
        self._nesting -= 1
        for child in node.orelse:
            self.visit(child)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self._increment(nesting_penalty=True)
        self._nesting += 1
        for child in node.body:
            self.visit(child)
        self._nesting -= 1

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        # Sequences of same operator (a and b and c) count as 1
        # Mixed operators count each change
        self.score += 1
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        # The caller only ever feeds this visitor the *children* of the
        # function being scored (see _extract_functions), never the
        # function's own node, so any FunctionDef reaching here is always a
        # nested helper. Nested functions get their own report entry and
        # must not contribute to the enclosing function's cognitive score.
        return

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self._increment(nesting_penalty=True)
        self.generic_visit(node)

    def visit_Break(self, node: ast.Break) -> None:
        self.score += 1

    def visit_Continue(self, node: ast.Continue) -> None:
        self.score += 1

    def visit_Match(self, node: ast.Match) -> None:
        self._increment(nesting_penalty=True)
        self._nesting += 1
        for case in node.cases:
            for child in case.body:
                self.visit(child)
        self._nesting -= 1

    def visit_Try(self, node: ast.Try) -> None:
        self._increment(nesting_penalty=True)
        self._nesting += 1
        for child in node.body:
            self.visit(child)
        self._nesting -= 1
        for handler in node.handlers:
            self.visit(handler)
        for child in node.finalbody:
            self.visit(child)
        for child in node.orelse:
            self.visit(child)

    # Python 3.11+ TryStar
    def visit_TryStar(self, node: ast.TryStar) -> None:  # type: ignore[attr-defined]
        self._increment(nesting_penalty=True)
        self._nesting += 1
        for child in node.body:
            self.visit(child)
        self._nesting -= 1
        for handler in node.handlers:
            self.visit(handler)
        for child in node.finalbody:
            self.visit(child)


class _NestingDepthCounter(ast.NodeVisitor):
    """Tracks maximum nesting depth within a function body."""

    NESTING_NODES = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.With,
        ast.AsyncWith,
        ast.Try,
        ast.ExceptHandler,
    )

    def __init__(self) -> None:
        self.max_depth = 0
        self._current_depth = 0
        self._function_depth = 0

    def generic_visit(self, node: ast.AST) -> None:
        if isinstance(node, self.NESTING_NODES):
            self._current_depth += 1
            self.max_depth = max(self.max_depth, self._current_depth)
            super().generic_visit(node)
            self._current_depth -= 1
        else:
            super().generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._function_depth += 1
        if self._function_depth == 1:
            # Entry function being scored — walk its body normally.
            self.generic_visit(node)
        # A nested def starts counting from its own zero depth in its own
        # report entry; it must not extend the enclosing function's depth.
        self._function_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef


class ComplexityAnalyzer:
    """Analyzes per-function complexity metrics across Python source files."""

    def analyze_source(
        self, source: str, filename: str = "<unknown>"
    ) -> ComplexityReport:
        """Analyze complexity metrics for all functions in a source string."""
        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError:
            return ComplexityReport(files_scanned=1)

        functions = self._extract_functions(tree, filename, source)
        return ComplexityReport(functions=functions, files_scanned=1)

    def _collect_file_metrics(
        self, current_root: str, fname: str
    ) -> list[ComplexityMetrics] | None:
        if not fname.endswith(".py"):
            return None
        fpath = Path(current_root) / fname
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
            return self.analyze_source(content, filename=str(fpath)).functions
        except OSError:
            return None

    def analyze_project(
        self, root_dir: Path | str, exclude_patterns: Sequence[str] = ()
    ) -> ComplexityReport:
        """Analyze complexity across all Python files in a project."""
        root = Path(root_dir).resolve()
        all_functions: list[ComplexityMetrics] = []
        files_scanned = 0

        for fpath in collect_project_python_files(
            root, exclude_patterns=exclude_patterns
        ):
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
                metrics = self.analyze_source(content, filename=str(fpath)).functions
                all_functions.extend(metrics)
                files_scanned += 1
            except OSError:
                continue

        all_functions.sort(key=lambda f: f.cyclomatic, reverse=True)
        return ComplexityReport(functions=all_functions, files_scanned=files_scanned)

    @staticmethod
    def _count_function_args(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
        all_args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        count = len(all_args)
        if node.args.vararg:
            count += 1
        if node.args.kwarg:
            count += 1
        if all_args and all_args[0].arg in ("self", "cls"):
            count -= 1
        return count

    def _build_function_metrics(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        tree: ast.Module,
        filename: str,
    ) -> ComplexityMetrics:
        start = node.lineno
        end = node.end_lineno or start
        return_count = sum(
            1 for c in ast.walk(node) if isinstance(c, ast.Return) and c is not node
        )

        cyclo = _CyclomaticCounter()
        cyclo.visit(node)

        cog = _CognitiveCounter()
        for child in node.body:
            cog.visit(child)

        nesting = _NestingDepthCounter()
        nesting.visit(node)

        return ComplexityMetrics(
            filepath=filename,
            lineno=start,
            end_lineno=end,
            name=node.name,
            qualified_name=self._get_qualified_name(node, tree),
            cyclomatic=cyclo.complexity,
            cognitive=cog.score,
            lines=end - start + 1,
            args=self._count_function_args(node),
            returns=return_count,
            max_nesting=nesting.max_depth,
        )

    def _extract_functions(
        self,
        tree: ast.Module,
        filename: str,
        source: str,
    ) -> list[ComplexityMetrics]:
        """Extract and analyze all function/method definitions from an AST."""
        results: list[ComplexityMetrics] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                results.append(self._build_function_metrics(node, tree, filename))
        return results

    @staticmethod
    def _get_qualified_name(
        target: ast.FunctionDef | ast.AsyncFunctionDef,
        tree: ast.Module,
    ) -> str:
        """Resolve a function's qualified name including class scope."""
        parents: dict[int, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[id(child)] = parent

        names: list[str] = [target.name]
        current: ast.AST = target
        while id(current) in parents:
            parent = parents[id(current)]
            if isinstance(
                parent, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                names.insert(0, parent.name)
            current = parent

        return ".".join(names)
