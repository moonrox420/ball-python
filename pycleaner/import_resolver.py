"""
Static undefined symbol detector and missing import resolver.

Analyzes AST scopes to find undefined loaded symbols and matches them
against Python standard library modules, common typing/dataclass constructs,
well-known third-party packages, and aliases.
"""

from __future__ import annotations

import ast
import builtins
import sys
from dataclasses import dataclass, field
from typing import ClassVar


@dataclass(slots=True)
class MissingImportDiagnostic:
    """Diagnostic detail for a missing import."""

    symbol: str
    import_statement: str
    value: str = "missing-import"
    module: str = ""
    status: str = "resolved"

    def to_dict(self) -> dict[str, str]:
        return {
            "value": self.value,
            "symbol": self.symbol,
            "import_statement": self.import_statement,
            "module": self.module,
            "status": self.status,
        }


@dataclass(slots=True)
class ImportResolutionResult:
    """Outcome of attempting to resolve missing imports in source code."""

    code: str
    resolved_imports: list[str] = field(default_factory=list)
    unresolved_symbols: list[str] = field(default_factory=list)
    diagnostics: list[MissingImportDiagnostic] = field(default_factory=list)


@dataclass(slots=True)
class _ClassificationContext:
    type_checking_symbols: set[str]
    existing_lines: set[str]
    regular_imports: list[str]
    tc_imports: list[str]
    unresolved: list[str]
    diagnostics: list[MissingImportDiagnostic]


class UndefinedSymbolFinder(ast.NodeVisitor):
    """AST visitor that detects loaded names that are not defined in any accessible scope."""

    def __init__(self) -> None:
        self.builtin_names: set[str] = set(dir(builtins))
        self.scopes: list[set[str]] = [set()]
        # Parallel to `scopes`: what kind of scope each entry is. Needed to
        # resolve two things correctly per real Python 3 semantics:
        #   1. List/set/dict comprehensions and generator expressions get
        #      their own scope -- their loop variables do NOT leak into the
        #      enclosing function/module scope (unlike Python 2).
        #   2. Assignment expressions (walrus `:=`) inside a comprehension
        #      bind to the nearest enclosing scope that is a function or
        #      module scope, skipping over both comprehension scopes and
        #      class scopes (PEP 572).
        self.scope_kinds: list[str] = ["module"]
        self.undefined_names: set[str] = set()
        self.annotation_undefined_names: set[str] = set()
        self.runtime_undefined_names: set[str] = set()
        self._in_annotation: bool = False

    def _current_scope(self) -> set[str]:
        return self.scopes[-1]

    def _is_defined(self, name: str) -> bool:
        if name in self.builtin_names:
            return True
        for scope in reversed(self.scopes):
            if name in scope:
                return True
        return False

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self._current_scope().add(name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            name = alias.asname or alias.name
            self._current_scope().add(name)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        is_type_checking = (
            isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING"
        ) or (
            isinstance(node.test, ast.Attribute) and node.test.attr == "TYPE_CHECKING"
        )
        if is_type_checking:
            self._register_type_checking_imports(node.body)
        self.generic_visit(node)

    def _register_type_checking_imports(self, body: list[ast.stmt]) -> None:
        for stmt in body:
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    self._current_scope().add(alias.asname or alias.name.split(".")[0])
            elif isinstance(stmt, ast.ImportFrom):
                for alias in stmt.names:
                    self._current_scope().add(alias.asname or alias.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._current_scope().add(node.name)
        # Class decorator and base expressions are evaluated in outer scope
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword)

        # Enter class body scope
        self.scopes.append(set())
        self.scope_kinds.append("class")
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()
        self.scope_kinds.pop()

    def _visit_arg_annotation(self, arg: ast.arg | None) -> None:
        if arg and arg.annotation:
            self._in_annotation = True
            try:
                self.visit(arg.annotation)
            finally:
                self._in_annotation = False

    def _register_function_args(self, args: ast.arguments) -> None:
        all_args = args.posonlyargs + args.args + args.kwonlyargs
        for arg in all_args:
            self._current_scope().add(arg.arg)
            self._visit_arg_annotation(arg)
        if args.vararg:
            self._current_scope().add(args.vararg.arg)
            self._visit_arg_annotation(args.vararg)
        if args.kwarg:
            self._current_scope().add(args.kwarg.arg)
            self._visit_arg_annotation(args.kwarg)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._current_scope().add(node.name)
        for decorator in node.decorator_list:
            self.visit(decorator)
        if node.returns:
            self._in_annotation = True
            try:
                self.visit(node.returns)
            finally:
                self._in_annotation = False

        self.scopes.append(set())
        self.scope_kinds.append("function")

        self._register_function_args(node.args)

        for statement in node.body:
            self.visit(statement)

        self.scopes.pop()
        self.scope_kinds.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            self.visit(node.value)
        if isinstance(node.target, ast.Name):
            self._current_scope().add(node.target.id)
        else:
            self.visit(node.target)
        self._in_annotation = True
        try:
            self.visit(node.annotation)
        finally:
            self._in_annotation = False

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.scopes.append(set())
        self.scope_kinds.append("function")
        all_args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        for arg in all_args:
            self._current_scope().add(arg.arg)
        if node.args.vararg:
            self._current_scope().add(node.args.vararg.arg)
        if node.args.kwarg:
            self._current_scope().add(node.args.kwarg.arg)

        self.visit(node.body)
        self.scopes.pop()
        self.scope_kinds.pop()

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        # PEP 572: an assignment expression's target binds in the nearest
        # enclosing scope that is a function or module scope, explicitly
        # skipping over comprehension scopes (so `[y := x for x in data]`
        # binds `y` in the scope containing the comprehension, not inside
        # it) and class scopes (a walrus inside a class body targets the
        # nearest enclosing function/module scope, not the class namespace).
        if isinstance(node.target, ast.Name):
            target_scope = self.scopes[0]  # module scope is always a safe fallback
            for scope, kind in zip(reversed(self.scopes), reversed(self.scope_kinds)):
                if kind not in ("comprehension", "class"):
                    target_scope = scope
                    break
            target_scope.add(node.target.id)
        self.visit(node.value)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._current_scope().add(node.id)
        elif isinstance(node.ctx, ast.Load) and not self._is_defined(node.id):
            self.undefined_names.add(node.id)
            if self._in_annotation:
                self.annotation_undefined_names.add(node.id)
            else:
                self.runtime_undefined_names.add(node.id)

    def visit_Global(self, node: ast.Global) -> None:
        for name in node.names:
            self.scopes[0].add(name)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        # Nonlocal is assumed defined in some outer scope
        for name in node.names:
            self._current_scope().add(name)

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        # Loop target is stored in current scope
        self._extract_store_names(node.target, self._current_scope())
        self.visit(node.iter)
        for item in node.body:
            self.visit(item)
        for item in node.orelse:
            self.visit(item)

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars:
                self._extract_store_names(item.optional_vars, self._current_scope())
        for statement in node.body:
            self.visit(statement)

    visit_AsyncWith = visit_With

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type:
            self.visit(node.type)
        if node.name:
            self._current_scope().add(node.name)
        for statement in node.body:
            self.visit(statement)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node.generators, [node.key, node.value])

    def _visit_comprehension(
        self,
        generators: list[ast.comprehension],
        value_exprs: list[ast.AST],
    ) -> None:
        """Model real Python 3 comprehension scoping.

        A comprehension is a genuine nested scope: its loop variables do not
        leak into the enclosing function/module scope (this was a Python 2
        behavior removed in Python 3). The single exception is the iterable
        of the *first* `for` clause, which is evaluated in the enclosing
        scope before the comprehension's own scope is entered -- this is
        why `[x for x in undefined_name]` reports `undefined_name` as
        undefined at the call site, not inside the comprehension.
        """
        if not generators:
            return

        # First iterable: evaluated in the *current* (enclosing) scope.
        self.visit(generators[0].iter)

        self.scopes.append(set())
        self.scope_kinds.append("comprehension")
        try:
            self._extract_store_names(generators[0].target, self._current_scope())
            for if_clause in generators[0].ifs:
                self.visit(if_clause)

            for gen in generators[1:]:
                # Subsequent iterables execute inside the comprehension's
                # own scope (they can reference earlier loop variables).
                self.visit(gen.iter)
                self._extract_store_names(gen.target, self._current_scope())
                for if_clause in gen.ifs:
                    self.visit(if_clause)

            for expr in value_exprs:
                self.visit(expr)
        finally:
            self.scopes.pop()
            self.scope_kinds.pop()

    def _extract_store_names(self, node: ast.AST, scope: set[str]) -> None:
        if isinstance(node, ast.Name):
            scope.add(node.id)
        elif isinstance(node, (ast.Tuple, ast.List)):
            for elt in node.elts:
                self._extract_store_names(elt, scope)
        elif isinstance(node, ast.Starred):
            self._extract_store_names(node.value, scope)


class ImportResolver:
    """Resolves missing imports by inspecting AST and static module databases."""

    # Static mapping for standard library members and typing constructs
    _STATIC_SYMBOLS: ClassVar[dict[str, str]] = {
        # pathlib
        "Path": "from pathlib import Path",
        "PurePath": "from pathlib import PurePath",
        "PurePosixPath": "from pathlib import PurePosixPath",
        "PureWindowsPath": "from pathlib import PureWindowsPath",
        # collections
        "defaultdict": "from collections import defaultdict",
        "deque": "from collections import deque",
        "Counter": "from collections import Counter",
        "OrderedDict": "from collections import OrderedDict",
        "namedtuple": "from collections import namedtuple",
        # datetime
        "datetime": "from datetime import datetime",
        "timedelta": "from datetime import timedelta",
        "timezone": "from datetime import timezone",
        "date": "from datetime import date",
        # typing
        "Any": "from typing import Any",
        "Callable": "from typing import Callable",
        "ClassVar": "from typing import ClassVar",
        "Dict": "from typing import Dict",
        "Final": "from typing import Final",
        "Generator": "from typing import Generator",
        "Generic": "from typing import Generic",
        "Iterable": "from typing import Iterable",
        "Iterator": "from typing import Iterator",
        "List": "from typing import List",
        "Literal": "from typing import Literal",
        "Mapping": "from typing import Mapping",
        "Optional": "from typing import Optional",
        "Protocol": "from typing import Protocol",
        "Sequence": "from typing import Sequence",
        "Set": "from typing import Set",
        "Tuple": "from typing import Tuple",
        "Type": "from typing import Type",
        "TypeVar": "from typing import TypeVar",
        "TypedDict": "from typing import TypedDict",
        "Union": "from typing import Union",
        "cast": "from typing import cast",
        "overload": "from typing import overload",
        "TYPE_CHECKING": "from typing import TYPE_CHECKING",
        "Annotated": "from typing import Annotated",
        "ParamSpec": "from typing import ParamSpec",
        "Concatenate": "from typing import Concatenate",
        # typing_extensions / 3.11+
        "Self": "from typing import Self",
        "assert_never": "from typing import assert_never",
        # dataclasses
        "dataclass": "from dataclasses import dataclass",
        "field": "from dataclasses import field",
        "asdict": "from dataclasses import asdict",
        "astuple": "from dataclasses import astuple",
        # enum
        "Enum": "from enum import Enum",
        "IntEnum": "from enum import IntEnum",
        "StrEnum": "from enum import StrEnum",
        "Flag": "from enum import Flag",
        "IntFlag": "from enum import IntFlag",
        "auto": "from enum import auto",
        # functools
        "lru_cache": "from functools import lru_cache",
        "cache": "from functools import cache",
        "partial": "from functools import partial",
        "reduce": "from functools import reduce",
        "wraps": "from functools import wraps",
        "total_ordering": "from functools import total_ordering",
        # itertools
        "chain": "from itertools import chain",
        "cycle": "from itertools import cycle",
        "islice": "from itertools import islice",
        "repeat": "from itertools import repeat",
        "accumulate": "from itertools import accumulate",
        "groupby": "from itertools import groupby",
        "product": "from itertools import product",
        "permutations": "from itertools import permutations",
        "combinations": "from itertools import combinations",
        "combinations_with_replacement": "from itertools import combinations_with_replacement",
        # contextlib
        "contextmanager": "from contextlib import contextmanager",
        "asynccontextmanager": "from contextlib import asynccontextmanager",
        "suppress": "from contextlib import suppress",
        "nullcontext": "from contextlib import nullcontext",
        "closing": "from contextlib import closing",
        # abc
        "ABC": "from abc import ABC",
        "abstractmethod": "from abc import abstractmethod",
        "abstractproperty": "from abc import abstractproperty",
        # operator
        "itemgetter": "from operator import itemgetter",
        "attrgetter": "from operator import attrgetter",
        # copy
        "deepcopy": "from copy import deepcopy",
        # pprint
        "pprint": "from pprint import pprint",
        "pformat": "from pprint import pformat",
        # urllib.parse
        "urlparse": "from urllib.parse import urlparse",
        "urlunparse": "from urllib.parse import urlunparse",
        "quote": "from urllib.parse import quote",
        "unquote": "from urllib.parse import unquote",
        # pydantic
        "BaseModel": "from pydantic import BaseModel",
        "Field": "from pydantic import Field",
        "validator": "from pydantic import validator",
        "field_validator": "from pydantic import field_validator",
        # fastapi
        "FastAPI": "from fastapi import FastAPI",
        "APIRouter": "from fastapi import APIRouter",
        "Depends": "from fastapi import Depends",
        "HTTPException": "from fastapi import HTTPException",
        # Popular aliases & data science
        "np": "import numpy as np",
        "pd": "import pandas as pd",
        "DataFrame": "from pandas import DataFrame",
        "Series": "from pandas import Series",
        "plt": "import matplotlib.pyplot as plt",
        "sns": "import seaborn as sns",
        "tf": "import tensorflow as tf",
        "nn": "from torch import nn",
        # concurrent.futures
        "ThreadPoolExecutor": "from concurrent.futures import ThreadPoolExecutor",
        "ProcessPoolExecutor": "from concurrent.futures import ProcessPoolExecutor",
        "as_completed": "from concurrent.futures import as_completed",
        "Future": "from concurrent.futures import Future",
        # threading
        "Thread": "from threading import Thread",
        "Lock": "from threading import Lock",
        "RLock": "from threading import RLock",
        "Event": "from threading import Event",
        "Semaphore": "from threading import Semaphore",
        "BoundedSemaphore": "from threading import BoundedSemaphore",
        "Condition": "from threading import Condition",
        "Barrier": "from threading import Barrier",
        "local": "from threading import local",
        # queue
        "Queue": "from queue import Queue",
        "LifoQueue": "from queue import LifoQueue",
        "PriorityQueue": "from queue import PriorityQueue",
        "Empty": "from queue import Empty",
        "Full": "from queue import Full",
        # re
        "Pattern": "from re import Pattern",
        "Match": "from re import Match",
        # http.server
        "HTTPServer": "from http.server import HTTPServer",
        "BaseHTTPRequestHandler": "from http.server import BaseHTTPRequestHandler",
        "SimpleHTTPRequestHandler": "from http.server import SimpleHTTPRequestHandler",
        # http
        "HTTPStatus": "from http import HTTPStatus",
    }

    _COMMON_STDLIB_EXPORTS: ClassVar[dict[str, str]] = {
        "sqrt": "from math import sqrt",
        "ceil": "from math import ceil",
        "floor": "from math import floor",
        "sin": "from math import sin",
        "cos": "from math import cos",
        "tan": "from math import tan",
        "log": "from math import log",
        "exp": "from math import exp",
        "pi": "from math import pi",
        "choice": "from random import choice",
        "randint": "from random import randint",
        "shuffle": "from random import shuffle",
        "sample": "from random import sample",
        "dumps": "from json import dumps",
        "loads": "from json import loads",
        "sleep": "from time import sleep",
        "perf_counter": "from time import perf_counter",
        "uuid4": "from uuid import uuid4",
        "sha256": "from hashlib import sha256",
        "md5": "from hashlib import md5",
        "NamedTemporaryFile": "from tempfile import NamedTemporaryFile",
        "TemporaryDirectory": "from tempfile import TemporaryDirectory",
        "copytree": "from shutil import copytree",
        "rmtree": "from shutil import rmtree",
        "format_exc": "from traceback import format_exc",
        "print_exc": "from traceback import print_exc",
        "Popen": "from subprocess import Popen",
        "PIPE": "from subprocess import PIPE",
    }

    def __init__(
        self,
        custom_import_map: dict[str, str] | None = None,
        auto_add_future_annotations: bool = False,
    ) -> None:
        """
        Args:
            custom_import_map: Extra/override symbol -> import-statement
                mappings, applied before the built-in static registry.
            auto_add_future_annotations: When True, always add
                `from __future__ import annotations` even if no
                TYPE_CHECKING-only symbols require it (PyCleanerConfig's
                auto_add_future_annotations). It is always added regardless
                of this flag when a TYPE_CHECKING-only import is injected,
                since deferred annotation evaluation is required for that
                pattern to work at all.
        """
        self.stdlib_names: set[str] = set(sys.stdlib_module_names)
        self.custom_import_map: dict[str, str] = (
            dict(custom_import_map) if custom_import_map else {}
        )
        self.auto_add_future_annotations = auto_add_future_annotations

    def find_undefined(self, source: str, filename: str = "<unknown>") -> list[str]:
        """Parse source into AST and return list of undefined symbol names."""
        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError:
            return []

        finder = UndefinedSymbolFinder()
        finder.visit(tree)
        return sorted(finder.undefined_names)

    def _classify_undefined_symbol(
        self,
        symbol: str,
        ctx: _ClassificationContext,
    ) -> None:
        import_stmt, mod_name = self._get_import_info(symbol)
        if not import_stmt:
            ctx.unresolved.append(symbol)
            ctx.diagnostics.append(
                MissingImportDiagnostic(
                    symbol=symbol,
                    import_statement="",
                    value="missing-import",
                    module="",
                    status="unresolved",
                )
            )
            return

        ctx.diagnostics.append(
            MissingImportDiagnostic(
                symbol=symbol,
                import_statement=import_stmt,
                value="missing-import",
                module=mod_name,
                status="resolved",
            )
        )
        is_tc_only = (
            symbol in ctx.type_checking_symbols
            and mod_name != "typing"
            and not import_stmt.startswith("from __future__")
        )
        target = ctx.tc_imports if is_tc_only else ctx.regular_imports
        if import_stmt not in ctx.existing_lines and import_stmt not in target:
            target.append(import_stmt)

    def _resolve_symbols(
        self,
        undefined: list[str],
        finder: UndefinedSymbolFinder,
        source: str,
    ) -> _ClassificationContext:
        ctx = _ClassificationContext(
            type_checking_symbols=finder.annotation_undefined_names
            - finder.runtime_undefined_names,
            existing_lines={line.strip() for line in source.splitlines()},
            regular_imports=[],
            tc_imports=[],
            unresolved=[],
            diagnostics=[],
        )
        for symbol in undefined:
            self._classify_undefined_symbol(symbol, ctx)

        if ctx.tc_imports:
            tc_stmt = "from typing import TYPE_CHECKING"
            if (
                "TYPE_CHECKING" not in finder.builtin_names
                and tc_stmt not in ctx.existing_lines
                and tc_stmt not in ctx.regular_imports
            ):
                ctx.regular_imports.append(tc_stmt)
        return ctx

    def resolve(
        self, source: str, filename: str = "<unknown>"
    ) -> ImportResolutionResult:
        """Find undefined symbols in source and inject corresponding imports."""
        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError:
            return ImportResolutionResult(code=source)

        finder = UndefinedSymbolFinder()
        finder.visit(tree)
        undefined = sorted(finder.undefined_names)
        if not undefined:
            return ImportResolutionResult(code=source)

        ctx = self._resolve_symbols(undefined, finder, source)
        all_new = ctx.regular_imports + ctx.tc_imports
        if not all_new:
            return ImportResolutionResult(
                code=source,
                unresolved_symbols=ctx.unresolved,
                diagnostics=ctx.diagnostics,
            )

        updated_code = self._inject_imports(
            source,
            regular_imports=ctx.regular_imports,
            type_checking_imports=ctx.tc_imports,
            add_future_annotations=self.auto_add_future_annotations
            or bool(ctx.tc_imports),
            parsed_tree=tree,
        )
        return ImportResolutionResult(
            code=updated_code,
            resolved_imports=all_new,
            unresolved_symbols=ctx.unresolved,
            diagnostics=ctx.diagnostics,
        )

    _KNOWN_THIRD_PARTY_ROOTS: ClassVar[frozenset[str]] = frozenset(
        {
            "requests",
            "httpx",
            "pytest",
            "yaml",
            "torch",
            "scipy",
            "click",
            "typer",
            "rich",
            "pydantic",
            "fastapi",
            "uvicorn",
            "jinja2",
            "PIL",
            "cv2",
            "dotenv",
            "sklearn",
        }
    )

    def _get_custom_import_info(self, symbol: str) -> tuple[str, str] | None:
        if not (self.custom_import_map and symbol in self.custom_import_map):
            return None
        stmt = self.custom_import_map[symbol]
        if stmt.startswith("from "):
            mod = stmt.split("import")[0].replace("from", "").strip()
        else:
            mod = stmt.replace("import", "").strip().split()[0]
        return stmt, mod

    def _get_import_info(self, symbol: str) -> tuple[str | None, str]:
        """Determine the import statement and origin module for a given undefined symbol."""
        custom = self._get_custom_import_info(symbol)
        if custom is not None:
            return custom

        catalog_stmt = self._STATIC_SYMBOLS.get(
            symbol
        ) or self._COMMON_STDLIB_EXPORTS.get(symbol)
        if catalog_stmt:
            mod = catalog_stmt.split("import")[0].replace("from", "").strip()
            return catalog_stmt, mod

        if symbol in self.stdlib_names or symbol in self._KNOWN_THIRD_PARTY_ROOTS:
            return f"import {symbol}", symbol

        return None, ""

    def _get_import_statement(self, symbol: str) -> str | None:
        """Determine the import statement for a given undefined symbol."""
        stmt, _ = self._get_import_info(symbol)
        return stmt

    def _skip_pragmas_and_comments(self, lines: list[str]) -> int:
        idx = 0
        n = len(lines)
        if idx < n and lines[idx].startswith("#!"):
            idx += 1
        if idx < n and ("coding:" in lines[idx] or "coding=" in lines[idx]):
            idx += 1
        while idx < n and (
            not lines[idx].strip() or lines[idx].strip().startswith("#")
        ):
            if "from __future__ import" in lines[idx]:
                break
            idx += 1
        return idx

    def _find_docstring_end_line(
        self, parsed_tree: ast.Module | None, source: str
    ) -> int | None:
        tree = parsed_tree
        if tree is None:
            try:
                tree = ast.parse(source)
            except SyntaxError:
                tree = None
        if tree and tree.body:
            first = tree.body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                return first.value.end_lineno
        return None

    def _find_header_insert_idx(
        self, lines: list[str], parsed_tree: ast.Module | None, source: str
    ) -> int:
        insert_idx = self._skip_pragmas_and_comments(lines)
        doc_end = self._find_docstring_end_line(parsed_tree, source)
        if doc_end is not None:
            insert_idx = max(insert_idx, doc_end)
        return insert_idx

    def _inject_future_and_regular(
        self,
        lines: list[str],
        insert_idx: int,
        regular_imports: list[str],
        add_future: bool,
        source: str,
    ) -> int:
        if add_future and "from __future__ import annotations" not in source:
            lines.insert(insert_idx, "from __future__ import annotations\n\n")
            insert_idx += 1

        while insert_idx < len(lines):
            stripped = lines[insert_idx].strip()
            if stripped.startswith("from __future__ import") or not stripped:
                insert_idx += 1
            else:
                break

        if regular_imports:
            import_block = "".join(f"{stmt}\n" for stmt in regular_imports)
            if insert_idx < len(lines) and lines[insert_idx].strip():
                import_block += "\n"
            lines.insert(insert_idx, import_block)
            insert_idx += 1
        return insert_idx

    def _inject_type_checking(
        self,
        lines: list[str],
        insert_idx: int,
        tc_imports: list[str],
    ) -> None:
        current_text = "".join(lines)
        if "if TYPE_CHECKING:" in current_text:
            tc_idx = next(
                (
                    i
                    for i, line in enumerate(lines)
                    if line.strip().startswith("if TYPE_CHECKING:")
                ),
                -1,
            )
            if tc_idx != -1:
                tc_block = "".join(f"    {stmt}\n" for stmt in tc_imports)
                lines.insert(tc_idx + 1, tc_block)
                return
        tc_block = (
            "if TYPE_CHECKING:\n"
            + "".join(f"    {stmt}\n" for stmt in tc_imports)
            + "\n"
        )
        lines.insert(insert_idx, tc_block)

    def _inject_imports(
        self,
        source: str,
        regular_imports: list[str],
        type_checking_imports: list[str] | None = None,
        add_future_annotations: bool = False,
        parsed_tree: ast.Module | None = None,
    ) -> str:
        """Insert import statements after shebangs, encoding pragmas, and module docstring."""
        lines = source.splitlines(keepends=True)
        insert_idx = self._find_header_insert_idx(lines, parsed_tree, source)
        insert_idx = self._inject_future_and_regular(
            lines, insert_idx, regular_imports, add_future_annotations, source
        )
        if type_checking_imports:
            self._inject_type_checking(lines, insert_idx, type_checking_imports)
        return "".join(lines)
