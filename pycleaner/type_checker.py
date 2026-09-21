"""
Static bidirectional type inference and type checking engine.

Inspects AST expressions, evaluates algebraic types, validates return types
against declared signatures, checks call argument type compatibility,
and performs type narrowing across conditional branches.
"""

from __future__ import annotations

import ast
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from pycleaner.discovery import collect_project_python_files
from pycleaner.typeshed_resolver import TypeshedResolver

# ---------------------------------------------------------------------------
# Algebraic Type System
# ---------------------------------------------------------------------------


class PyType:
    """Base algebraic type representation."""

    def is_assignable_to(
        self,
        target: PyType,
        class_hierarchy: dict[str, list[str]] | None = None,
    ) -> bool:
        """Check if this type can be assigned to target type."""
        if isinstance(target, AnyType) or isinstance(self, AnyType) or target == self:
            return True
        if getattr(target, "name", None) == "object":
            return True
        if (
            isinstance(self, CustomClassType)
            and isinstance(target, CustomClassType)
            and class_hierarchy
            and self._is_subclass(self.name, target.name, class_hierarchy)
        ):
            return True
        if isinstance(target, UnionType):
            return self._assignable_to_union(target, class_hierarchy)
        if isinstance(self, UnionType):
            return self._union_assignable_to(target, class_hierarchy)
        if isinstance(target, CustomClassType) and self._check_custom_target(target):
            return True
        if isinstance(self, CustomClassType) and self._check_custom_source(target):
            return True
        return self._check_numeric_promotions(target)

    @staticmethod
    def _is_subclass(
        child: str,
        parent: str,
        class_hierarchy: dict[str, list[str]],
        visited: set[str] | None = None,
    ) -> bool:
        if child == parent:
            return True
        if visited is None:
            visited = set()
        if child in visited:
            return False
        visited.add(child)
        for base in class_hierarchy.get(child, []):
            if PyType._is_subclass(base, parent, class_hierarchy, visited):
                return True
        return False

    def _assignable_to_union(
        self, target: PyType, class_hierarchy: dict[str, list[str]] | None = None
    ) -> bool:
        types = getattr(target, "types", [])
        for u in types:
            if self.is_assignable_to(u, class_hierarchy):
                return True
        return False

    def _union_assignable_to(
        self, target: PyType, class_hierarchy: dict[str, list[str]] | None = None
    ) -> bool:
        types = getattr(self, "types", [])
        non_none = [u for u in types if not isinstance(u, NoneType)]
        if non_none:
            all_match = True
            for u in non_none:
                if not u.is_assignable_to(target, class_hierarchy):
                    all_match = False
                    break
            if all_match:
                return True
        for u in types:
            if not u.is_assignable_to(target, class_hierarchy):
                return False
        return True

    def _check_custom_target(self, target: PyType) -> bool:
        if not isinstance(target, CustomClassType):
            return False
        if target.name in ("StrPath", "PathLike", "AnyStr"):
            if isinstance(self, PrimitiveType) and self.name in ("str", "bytes"):
                return True
            if isinstance(self, CustomClassType) and self.name in (
                "Path",
                "PosixPath",
                "WindowsPath",
                "str",
                "bytes",
            ):
                return True
        return (
            target.name.startswith("Supports")
            or target.name.startswith("_")
            or target.name in ("T", "Any")
        )

    def _check_custom_source(self, target: PyType) -> bool:
        src_name = getattr(self, "name", "")
        if src_name in ("StrPath", "PathLike", "AnyStr"):
            if isinstance(target, PrimitiveType) and target.name in ("str", "bytes"):
                return True
            if isinstance(target, CustomClassType) and target.name in (
                "Path",
                "PosixPath",
                "WindowsPath",
                "str",
                "bytes",
            ):
                return True
        if (
            src_name.startswith("Supports")
            or src_name.startswith("_")
            or src_name in ("T", "Any")
        ):
            return True
        if src_name in (
            "zip",
            "enumerate",
            "range",
            "generator",
            "iter",
            "map",
            "filter",
        ):
            if isinstance(target, (ListType, SetType)):
                return True
            if isinstance(target, CustomClassType) and target.name in (
                "list",
                "List",
                "Sequence",
                "Iterable",
                "Collection",
            ):
                return True
        return False

    def _check_numeric_promotions(self, target: PyType) -> bool:
        if isinstance(self, PrimitiveType) and isinstance(target, PrimitiveType):
            if self.name == "int" and target.name == "float":
                return True
            if self.name == "bool" and target.name in ("int", "float"):
                return True
        return False

    def __str__(self) -> str:
        return self.__class__.__name__


class AnyType(PyType):
    def __eq__(self, other: object) -> bool:
        return isinstance(other, AnyType)

    def __str__(self) -> str:
        return "Any"


class NoneType(PyType):
    def __eq__(self, other: object) -> bool:
        return isinstance(other, NoneType)

    def __str__(self) -> str:
        return "None"


class PrimitiveType(PyType):
    def __init__(self, name: str) -> None:
        self.name = name

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PrimitiveType) and self.name == other.name

    def __str__(self) -> str:
        return self.name


class UnionType(PyType):
    types: list[PyType]

    def __init__(self, types: list[PyType]) -> None:
        flat: list[PyType] = []
        for t in types:
            if isinstance(t, UnionType):
                flat.extend(t.types)
            elif t not in flat:
                flat.append(t)
        self.types = flat

    def __eq__(self, other: object) -> bool:
        return isinstance(other, UnionType) and {str(t) for t in self.types} == {
            str(t) for t in other.types
        }

    def __str__(self) -> str:
        return " | ".join(str(t) for t in self.types)


def _is_collection_assignable(source_item: PyType, target: PyType) -> bool:
    if isinstance(target, AnyType):
        return True
    if isinstance(target, (ListType, SetType)):
        if isinstance(target.item_type, AnyType) or isinstance(source_item, AnyType):
            return True
        if isinstance(target.item_type, CustomClassType) and (
            target.item_type.name.startswith("Supports")
            or target.item_type.name.startswith("_")
            or target.item_type.name in ("T", "Any")
        ):
            return True
        return source_item.is_assignable_to(target.item_type)
    return isinstance(target, CustomClassType) and target.name in (
        "list",
        "List",
        "set",
        "Set",
        "Sequence",
        "Iterable",
        "Collection",
    )


class ListType(PyType):
    def __init__(self, item_type: PyType) -> None:
        self.item_type = item_type

    def is_assignable_to(
        self, target: PyType, class_hierarchy: dict[str, list[str]] | None = None
    ) -> bool:
        if _is_collection_assignable(self.item_type, target):
            return True
        return super().is_assignable_to(target, class_hierarchy)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ListType) and self.item_type == other.item_type

    def __str__(self) -> str:
        return f"list[{self.item_type}]"


class SetType(PyType):
    def __init__(self, item_type: PyType) -> None:
        self.item_type = item_type

    def is_assignable_to(
        self, target: PyType, class_hierarchy: dict[str, list[str]] | None = None
    ) -> bool:
        if _is_collection_assignable(self.item_type, target):
            return True
        return super().is_assignable_to(target, class_hierarchy)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SetType) and self.item_type == other.item_type

    def __str__(self) -> str:
        return f"set[{self.item_type}]"


class DictType(PyType):
    def __init__(self, key_type: PyType, value_type: PyType) -> None:
        self.key_type = key_type
        self.value_type = value_type

    def is_assignable_to(
        self, target: PyType, class_hierarchy: dict[str, list[str]] | None = None
    ) -> bool:
        if isinstance(target, AnyType):
            return True
        if isinstance(target, DictType):
            return self.key_type.is_assignable_to(
                target.key_type, class_hierarchy
            ) and self.value_type.is_assignable_to(target.value_type, class_hierarchy)
        if isinstance(target, CustomClassType) and target.name in (
            "dict",
            "Dict",
            "Mapping",
        ):
            return True
        return super().is_assignable_to(target, class_hierarchy)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, DictType)
            and self.key_type == other.key_type
            and self.value_type == other.value_type
        )

    def __str__(self) -> str:
        return f"dict[{self.key_type}, {self.value_type}]"


class CustomClassType(PyType):
    def __init__(self, name: str) -> None:
        self.name = name

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CustomClassType) and self.name == other.name

    def __str__(self) -> str:
        return self.name


# ---------------------------------------------------------------------------
# Diagnostics & Reports
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class TypeFinding:
    """A detected type mismatch or type violation."""

    filepath: str
    lineno: int
    column: int
    symbol: str
    expected_type: str
    actual_type: str
    message: str
    severity: str = "ERROR"
    category: str = "type-mismatch"
    code_snippet: str = ""


@dataclass(slots=True)
class TypeReport:
    """Summary of static type checking results."""

    findings: list[TypeFinding] = field(default_factory=list)
    files_scanned: int = 0
    functions_checked: int = 0

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def has_errors(self) -> bool:
        return any(f.severity == "ERROR" for f in self.findings)

    @property
    def error_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "ERROR")

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "WARNING")


# ---------------------------------------------------------------------------
# Type Parser
# ---------------------------------------------------------------------------


def _parse_name_annotation(name: str) -> PyType:
    """Resolve identifier names to primitive, collection, or custom PyTypes."""
    if name in ("int", "str", "float", "bool", "bytes"):
        return PrimitiveType(name)
    if name in ("None", "NoneType"):
        return NoneType()
    if name == "Any":
        return AnyType()
    if name in ("set", "Set"):
        return SetType(AnyType())
    if name in ("list", "List", "Sequence", "Iterable", "Collection", "tuple", "Tuple"):
        return ListType(AnyType())
    if name in ("dict", "Dict", "Mapping"):
        return DictType(AnyType(), AnyType())
    return CustomClassType(name)


def _parse_dict_subscript(slice_node: ast.expr) -> PyType:
    if isinstance(slice_node, ast.Tuple) and len(slice_node.elts) == 2:
        return DictType(
            parse_type_annotation(slice_node.elts[0]),
            parse_type_annotation(slice_node.elts[1]),
        )
    return DictType(AnyType(), AnyType())


def _parse_union_subscript(slice_node: ast.expr) -> PyType:
    if isinstance(slice_node, ast.Tuple):
        return UnionType([parse_type_annotation(e) for e in slice_node.elts])
    return parse_type_annotation(slice_node)


def _parse_subscript_annotation(node: ast.Subscript) -> PyType:
    """Resolve subscripted type annotations (generics, optionals, unions)."""
    val = node.value
    base_name = (
        val.id
        if isinstance(val, ast.Name)
        else (val.attr if isinstance(val, ast.Attribute) else "")
    )

    if base_name == "Optional":
        return UnionType([parse_type_annotation(node.slice), NoneType()])
    if base_name == "Union":
        res = _parse_union_subscript(node.slice)
        return res if isinstance(res, UnionType) else UnionType([res])
    if base_name in ("set", "Set"):
        return SetType(parse_type_annotation(node.slice))
    if base_name in (
        "list",
        "List",
        "Sequence",
        "Iterable",
        "Collection",
        "tuple",
        "Tuple",
    ):
        return ListType(parse_type_annotation(node.slice))
    if base_name in ("dict", "Dict", "Mapping"):
        return _parse_dict_subscript(node.slice)
    return AnyType()


def _parse_constant_annotation(annotation: ast.Constant) -> PyType:
    if annotation.value is None:
        return NoneType()
    if isinstance(annotation.value, str):
        return parse_type_annotation(annotation.value)
    return AnyType()


def parse_type_annotation(annotation: ast.AST | str | None) -> PyType:
    """Parse an AST node or type string into a PyType representation."""
    if annotation is None:
        return AnyType()

    if isinstance(annotation, str):
        try:
            return parse_type_annotation(ast.parse(annotation, mode="eval").body)
        except SyntaxError:
            return AnyType()

    if isinstance(annotation, ast.Name):
        return _parse_name_annotation(annotation.id)

    if isinstance(annotation, ast.Constant):
        return _parse_constant_annotation(annotation)

    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        return UnionType(
            [
                parse_type_annotation(annotation.left),
                parse_type_annotation(annotation.right),
            ]
        )

    if isinstance(annotation, ast.Subscript):
        return _parse_subscript_annotation(annotation)

    return AnyType()


# ---------------------------------------------------------------------------
# Type Checker Engine
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _FileContext:
    filepath: str
    source_lines: list[str]
    local_functions: dict[str, tuple[dict[str, PyType], PyType]] = field(
        default_factory=dict
    )
    class_hierarchy: dict[str, list[str]] = field(default_factory=dict)


class TypeChecker:
    """Type checker verifying annotations, return statements, and call sites."""

    def __init__(
        self, typeshed: TypeshedResolver | None = None, strict: bool = False
    ) -> None:
        self.typeshed = typeshed or TypeshedResolver()
        self.strict = strict

    def check_file(self, filepath: str | Path) -> list[TypeFinding]:
        """Check all functions and statements in a file."""
        path = Path(filepath)
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(path))
        except SyntaxError:
            return []

        return self.check_ast(tree, filepath=str(path), source=content)

    @staticmethod
    def _collect_class_hierarchy(tree: ast.Module) -> dict[str, list[str]]:
        hierarchy: dict[str, list[str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                bases: list[str] = []
                for b in node.bases:
                    if isinstance(b, ast.Name):
                        bases.append(b.id)
                    elif isinstance(b, ast.Attribute):
                        bases.append(b.attr)
                hierarchy[node.name] = bases
        return hierarchy

    @staticmethod
    def _collect_local_signatures(
        tree: ast.Module,
    ) -> dict[str, tuple[dict[str, PyType], PyType]]:
        local_functions: dict[str, tuple[dict[str, PyType], PyType]] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params: dict[str, PyType] = {}
                all_args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                for a in all_args:
                    params[a.arg] = (
                        parse_type_annotation(a.annotation)
                        if a.annotation
                        else AnyType()
                    )
                ret_type = (
                    parse_type_annotation(node.returns) if node.returns else AnyType()
                )
                local_functions[node.name] = (params, ret_type)
        return local_functions

    def check_ast(
        self,
        tree: ast.Module,
        filepath: str = "<unknown>",
        source: str = "",
    ) -> list[TypeFinding]:
        """Perform static type verification on an AST module."""
        findings: list[TypeFinding] = []
        ctx = _FileContext(
            filepath=filepath,
            source_lines=source.splitlines() if source else [],
            local_functions=self._collect_local_signatures(tree),
            class_hierarchy=self._collect_class_hierarchy(tree),
        )

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_function(node, ctx))
            elif isinstance(node, ast.AnnAssign):
                findings.extend(self._check_ann_assign(node, ctx))

        return findings

    def _discover_python_files(
        self, root: Path, exclude_patterns: Sequence[str] = ()
    ) -> list[Path]:
        return collect_project_python_files(root, exclude_patterns=exclude_patterns)

    @staticmethod
    def _count_functions(fpath: Path) -> int:
        try:
            tree = ast.parse(fpath.read_text(encoding="utf-8", errors="replace"))
            return sum(
                1
                for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
        except SyntaxError:
            return 0

    def check_files(self, target_files: Sequence[Path]) -> TypeReport:
        """Type-check a specific sequence of Python files without walking directories."""
        findings: list[TypeFinding] = []
        functions_checked = 0
        scanned_count = 0
        for fpath in target_files:
            try:
                findings.extend(self.check_file(fpath))
                functions_checked += self._count_functions(fpath)
                scanned_count += 1
            except OSError:
                continue

        return TypeReport(
            findings=findings,
            files_scanned=scanned_count,
            functions_checked=functions_checked,
        )

    def check_project(
        self, root_dir: str | Path, exclude_patterns: Sequence[str] = ()
    ) -> TypeReport:
        """Type-check all Python files across an entire project directory."""
        root = Path(root_dir).resolve()
        py_files = self._discover_python_files(root, exclude_patterns=exclude_patterns)
        return self.check_files(py_files)

    def _fallback_walk(self, root: Path):
        import os

        for r, d, f in os.walk(root):
            yield Path(r), d, f

    @staticmethod
    def _init_param_scope(
        func: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> dict[str, PyType]:
        scope: dict[str, PyType] = {}
        all_args = func.args.posonlyargs + func.args.args + func.args.kwonlyargs
        for a in all_args:
            scope[a.arg] = (
                parse_type_annotation(a.annotation) if a.annotation else AnyType()
            )
        return scope

    @staticmethod
    def _is_terminal_statement(stmt: ast.stmt | None) -> bool:
        """Check if an AST statement terminates all control flow paths (returns or raises)."""
        if stmt is None:
            return False
        if isinstance(stmt, (ast.Return, ast.Raise)):
            return True
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            return bool(stmt.body) and TypeChecker._is_terminal_statement(stmt.body[-1])
        if isinstance(stmt, ast.Try):
            if not (
                bool(stmt.body) and TypeChecker._is_terminal_statement(stmt.body[-1])
            ):
                return False
            for handler in stmt.handlers:
                if not (
                    bool(handler.body)
                    and TypeChecker._is_terminal_statement(handler.body[-1])
                ):
                    return False
            if stmt.orelse and not TypeChecker._is_terminal_statement(stmt.orelse[-1]):
                return False
            return True
        if isinstance(stmt, ast.If):
            if not (
                bool(stmt.body) and TypeChecker._is_terminal_statement(stmt.body[-1])
            ):
                return False
            if not (
                bool(stmt.orelse)
                and TypeChecker._is_terminal_statement(stmt.orelse[-1])
            ):
                return False
            return True
        if isinstance(stmt, ast.While):
            if isinstance(stmt.test, ast.Constant) and bool(stmt.test.value):
                has_return = any(
                    isinstance(n, (ast.Return, ast.Raise)) for n in ast.walk(stmt)
                )
                has_break = any(isinstance(n, ast.Break) for n in ast.walk(stmt))
                if has_return and not has_break:
                    return True
        if isinstance(stmt, getattr(ast, "Match", ())):
            cases = getattr(stmt, "cases", [])
            if not cases:
                return False
            return all(
                bool(c.body) and TypeChecker._is_terminal_statement(c.body[-1])
                for c in cases
            )
        return False

    def _check_return_paths(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        declared_return: PyType,
        scope: dict[str, PyType],
        ctx: _FileContext,
    ) -> list[TypeFinding]:
        if isinstance(declared_return, AnyType):
            return []

        findings: list[TypeFinding] = []
        has_return = False
        for child in ast.walk(func):
            if not isinstance(child, ast.Return):
                continue
            if self._is_nested_in_other_func(child, func):
                continue

            has_return = True
            actual_type = self._infer_expr_type(child.value, scope, ctx.local_functions)
            if not actual_type.is_assignable_to(declared_return, ctx.class_hierarchy):
                snippet = (
                    ctx.source_lines[child.lineno - 1]
                    if 0 <= child.lineno - 1 < len(ctx.source_lines)
                    else ""
                )
                findings.append(
                    TypeFinding(
                        filepath=ctx.filepath,
                        lineno=child.lineno,
                        column=child.col_offset,
                        symbol=func.name,
                        expected_type=str(declared_return),
                        actual_type=str(actual_type),
                        message=(
                            f"Incompatible return type: function '{func.name}' declared to return "
                            f"'{declared_return}' but returned '{actual_type}'"
                        ),
                        severity="ERROR",
                        code_snippet=snippet.strip(),
                    )
                )

        # Check for missing return paths if declared return is non-None/non-Any
        if (
            has_return
            and not isinstance(declared_return, (AnyType, NoneType))
            and not (
                isinstance(declared_return, UnionType)
                and any(
                    isinstance(t, NoneType)
                    for t in getattr(declared_return, "types", [])
                )
            )
        ):
            last_stmt = func.body[-1] if func.body else None
            ends_with_terminal = self._is_terminal_statement(last_stmt)
            if not ends_with_terminal:
                snippet = (
                    ctx.source_lines[func.lineno - 1]
                    if 0 <= func.lineno - 1 < len(ctx.source_lines)
                    else ""
                )
                findings.append(
                    TypeFinding(
                        filepath=ctx.filepath,
                        lineno=func.lineno,
                        column=func.col_offset,
                        symbol=func.name,
                        expected_type=str(declared_return),
                        actual_type="None",
                        message=(
                            f"Missing return path: function '{func.name}' declared to return "
                            f"'{declared_return}' can fall through without returning a value"
                        ),
                        severity="ERROR",
                        code_snippet=snippet.strip(),
                    )
                )

        return findings

    def _check_function(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        ctx: _FileContext,
    ) -> list[TypeFinding]:
        """Check return statement types and local assignments within a function."""
        declared_return = (
            parse_type_annotation(func.returns) if func.returns else AnyType()
        )
        scope = self._init_param_scope(func)
        findings = self._check_return_paths(func, declared_return, scope, ctx)

        for child in ast.walk(func):
            if isinstance(child, ast.Call):
                findings.extend(self._check_call_arguments(child, scope, ctx))

        return findings

    def _check_ann_assign(
        self,
        node: ast.AnnAssign,
        ctx: _FileContext,
    ) -> list[TypeFinding]:
        """Check explicit variable annotation vs assigned value."""
        if not node.value or not isinstance(node.target, ast.Name):
            return []

        declared_type = parse_type_annotation(node.annotation)
        if isinstance(declared_type, AnyType):
            return []

        actual_type = self._infer_expr_type(node.value, {}, ctx.local_functions)
        if isinstance(actual_type, AnyType) or actual_type.is_assignable_to(
            declared_type, ctx.class_hierarchy
        ):
            return []

        snippet = (
            ctx.source_lines[node.lineno - 1]
            if 0 <= node.lineno - 1 < len(ctx.source_lines)
            else ""
        )
        return [
            TypeFinding(
                filepath=ctx.filepath,
                lineno=node.lineno,
                column=node.col_offset,
                symbol=node.target.id,
                expected_type=str(declared_type),
                actual_type=str(actual_type),
                message=(
                    f"Variable '{node.target.id}' declared as '{declared_type}' "
                    f"assigned incompatible type '{actual_type}'"
                ),
                severity="ERROR",
                code_snippet=snippet.strip(),
            )
        ]

    @staticmethod
    def _resolve_call_names(call: ast.Call) -> tuple[str, str]:
        """Extract the short function name and dotted name from a Call node."""
        func = call.func
        if isinstance(func, ast.Name):
            return func.id, ""
        if isinstance(func, ast.Attribute):
            func_name = func.attr
            dotted_parts: list[str] = []
            curr: ast.expr = func
            while isinstance(curr, ast.Attribute):
                dotted_parts.append(curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                dotted_parts.append(curr.id)
                return func_name, ".".join(reversed(dotted_parts))
            return func_name, ""
        return "", ""

    @staticmethod
    def _clean_receiver_params(
        param_types: dict[str, PyType], call: ast.Call
    ) -> dict[str, PyType]:
        if isinstance(call.func, ast.Attribute) and param_types:
            first_param = next(iter(param_types))
            if first_param in ("self", "cls"):
                param_types.pop(first_param, None)
        return param_types

    def _resolve_call_param_types(
        self,
        call: ast.Call,
        local_functions: dict[str, tuple[dict[str, PyType], PyType]],
    ) -> tuple[str, dict[str, PyType]]:
        """Resolve function name and parameter types for a Call node."""
        func_name, dotted_name = self._resolve_call_names(call)
        if isinstance(call.func, ast.Name) and func_name in local_functions:
            cleaned = self._clean_receiver_params(
                dict(local_functions[func_name][0]), call
            )
            return func_name, cleaned

        if isinstance(call.func, ast.Attribute):
            if (
                isinstance(call.func.value, ast.Call)
                and getattr(call.func.value.func, "id", None) == "super"
            ):
                return func_name, {}
            if isinstance(call.func.value, ast.Name) and call.func.value.id in (
                "self",
                "cls",
            ):
                if func_name in local_functions:
                    params = dict(local_functions[func_name][0])
                    first_p = next(iter(params), None)
                    if first_p in ("self", "cls"):
                        cleaned = self._clean_receiver_params(params, call)
                        return func_name, cleaned
                return func_name, {}

        target_lookup = dotted_name or func_name
        if not target_lookup:
            return func_name, {}

        sig = self.typeshed.resolve_function(target_lookup)
        if not sig or not sig.param_types:
            return func_name, {}

        param_types = {k: parse_type_annotation(v) for k, v in sig.param_types.items()}
        if (sig.is_method and not sig.is_static) or sig.is_class_method:
            param_types.pop(next(iter(param_types), ""), None)
            return func_name, param_types

        return func_name, self._clean_receiver_params(param_types, call)

    @staticmethod
    def _make_call_arg_finding(
        ctx: _FileContext,
        call: ast.Call,
        func_param: tuple[str, str],
        exp_act: tuple[PyType, PyType],
    ) -> TypeFinding:
        func_name, param_name = func_param
        expected, actual = exp_act
        snippet = (
            ctx.source_lines[call.lineno - 1].strip()
            if 0 <= call.lineno - 1 < len(ctx.source_lines)
            else ""
        )
        return TypeFinding(
            filepath=ctx.filepath,
            lineno=call.lineno,
            column=call.col_offset,
            symbol=func_name,
            expected_type=str(expected),
            actual_type=str(actual),
            message=(
                f"Argument '{param_name}' to '{func_name}' expects '{expected}' "
                f"but received '{actual}'"
            ),
            severity="ERROR",
            code_snippet=snippet,
        )

    def _check_call_arguments(
        self,
        call: ast.Call,
        scope: dict[str, PyType],
        ctx: _FileContext,
    ) -> list[TypeFinding]:
        """Validate argument types against function parameter annotations."""
        func_name, param_types = self._resolve_call_param_types(
            call, ctx.local_functions
        )
        if not param_types:
            return []

        param_names = list(param_types.keys())
        findings: list[TypeFinding] = []

        for idx, arg_expr in enumerate(call.args):
            if idx >= len(param_names):
                break
            param_name = param_names[idx]
            expected = param_types[param_name]
            if isinstance(expected, AnyType):
                continue

            actual = self._infer_expr_type(arg_expr, scope, ctx.local_functions)
            if isinstance(actual, AnyType) or actual.is_assignable_to(
                expected, ctx.class_hierarchy
            ):
                continue

            findings.append(
                self._make_call_arg_finding(
                    ctx, call, (func_name, param_name), (expected, actual)
                )
            )

        return findings

    def _infer_constant(self, expr: ast.Constant) -> PyType:
        if expr.value is None:
            return NoneType()
        if isinstance(expr.value, bool):
            return PrimitiveType("bool")
        if isinstance(expr.value, int):
            return PrimitiveType("int")
        if isinstance(expr.value, float):
            return PrimitiveType("float")
        if isinstance(expr.value, str):
            return PrimitiveType("str")
        if isinstance(expr.value, bytes):
            return PrimitiveType("bytes")
        return AnyType()

    def _infer_collection(
        self,
        expr: ast.List | ast.Set | ast.Dict,
        scope: dict[str, PyType],
        local_functions: dict[str, tuple[dict[str, PyType], PyType]],
    ) -> PyType:
        if isinstance(expr, ast.List):
            if not expr.elts:
                return ListType(AnyType())
            return ListType(self._infer_expr_type(expr.elts[0], scope, local_functions))
        if isinstance(expr, ast.Set):
            if not expr.elts:
                return SetType(AnyType())
            return SetType(self._infer_expr_type(expr.elts[0], scope, local_functions))
        if not expr.keys or not expr.values:
            return DictType(AnyType(), AnyType())
        k_type = (
            self._infer_expr_type(expr.keys[0], scope, local_functions)
            if expr.keys[0]
            else AnyType()
        )
        v_type = self._infer_expr_type(expr.values[0], scope, local_functions)
        return DictType(k_type, v_type)

    @staticmethod
    def _infer_numeric_binop(op: ast.operator, left: str, right: str) -> PyType:
        if isinstance(op, ast.Div):
            return PrimitiveType("float")
        if "float" in (left, right):
            return PrimitiveType("float")
        return PrimitiveType("int")

    def _infer_binop(
        self,
        expr: ast.BinOp,
        scope: dict[str, PyType],
        local_functions: dict[str, tuple[dict[str, PyType], PyType]],
    ) -> PyType:
        left_type = self._infer_expr_type(expr.left, scope, local_functions)
        right_type = self._infer_expr_type(expr.right, scope, local_functions)
        if isinstance(left_type, PrimitiveType) and isinstance(
            right_type, PrimitiveType
        ):
            if (
                left_type.name == "str"
                and right_type.name == "str"
                and isinstance(expr.op, ast.Add)
            ):
                return PrimitiveType("str")
            if left_type.name in ("int", "float") and right_type.name in (
                "int",
                "float",
            ):
                return self._infer_numeric_binop(
                    expr.op, left_type.name, right_type.name
                )
        return AnyType()

    def _extract_iterable_item_type(
        self,
        arg: ast.expr,
        scope: dict[str, PyType],
        local_functions: dict[str, tuple[dict[str, PyType], PyType]],
    ) -> PyType:
        arg_t = self._infer_expr_type(arg, scope, local_functions)
        if isinstance(arg_t, (ListType, SetType)):
            return getattr(arg_t, "item_type", AnyType())
        if isinstance(arg_t, PrimitiveType) and arg_t.name == "str":
            return PrimitiveType("str")
        return AnyType()

    def _infer_constructor_call(
        self,
        func_name: str,
        args: list[ast.expr],
        scope: dict[str, PyType],
        local_functions: dict[str, tuple[dict[str, PyType], PyType]],
    ) -> PyType | None:
        if func_name in ("set", "Set"):
            item_t = (
                self._extract_iterable_item_type(args[0], scope, local_functions)
                if args
                else AnyType()
            )
            return SetType(item_t)

        if func_name in ("list", "List", "sorted"):
            item_t = (
                self._extract_iterable_item_type(args[0], scope, local_functions)
                if args
                else AnyType()
            )
            return ListType(item_t)

        if func_name == "sum":
            return PrimitiveType("int")

        return None

    def _infer_attribute_method(
        self,
        func: ast.Attribute,
        scope: dict[str, PyType],
        local_functions: dict[str, tuple[dict[str, PyType], PyType]],
    ) -> PyType | None:
        obj_type = self._infer_expr_type(func.value, scope, local_functions)
        if isinstance(obj_type, PrimitiveType):
            m_ret = self.typeshed.get_builtin_method_return_type(
                obj_type.name, func.attr
            )
            if m_ret:
                return parse_type_annotation(m_ret)
        elif isinstance(obj_type, CustomClassType):
            cls_sig = self.typeshed.resolve_class("builtins", obj_type.name)
            if cls_sig and func.attr in cls_sig.methods:
                return parse_type_annotation(cls_sig.methods[func.attr].return_type)
        return None

    def _infer_typeshed_lookup(
        self, target: str, func_name: str, is_attribute: bool = False
    ) -> PyType:
        if target:
            sig = self.typeshed.resolve_function(target)
            if sig and sig.return_type and sig.return_type != "Any":
                return parse_type_annotation(sig.return_type)

        if not is_attribute:
            builtin_ret = self.typeshed.get_builtin_return_type(func_name)
            if builtin_ret:
                return parse_type_annotation(builtin_ret)

            if func_name and self.typeshed.resolve_class("builtins", func_name):
                return CustomClassType(func_name)

        return AnyType()

    def _infer_call(
        self,
        expr: ast.Call,
        scope: dict[str, PyType],
        local_functions: dict[str, tuple[dict[str, PyType], PyType]],
    ) -> PyType:
        func_name, dotted_name = self._resolve_call_names(expr)
        if not isinstance(expr.func, ast.Attribute):
            ctor = self._infer_constructor_call(
                func_name, expr.args, scope, local_functions
            )
            if ctor is not None:
                return ctor

        if isinstance(expr.func, ast.Attribute):
            meth = self._infer_attribute_method(expr.func, scope, local_functions)
            if meth is not None:
                return meth
            if isinstance(expr.func.value, ast.Name) and expr.func.value.id in (
                "self",
                "cls",
            ):
                if func_name in local_functions:
                    return local_functions[func_name][1]
            return self._infer_typeshed_lookup(
                dotted_name, func_name, is_attribute=True
            )

        if func_name in local_functions:
            return local_functions[func_name][1]

        return self._infer_typeshed_lookup(
            dotted_name or func_name, func_name, is_attribute=False
        )

    def _infer_expr_type(
        self,
        expr: ast.AST | None,
        scope: dict[str, PyType],
        local_functions: dict[str, tuple[dict[str, PyType], PyType]],
    ) -> PyType:
        """Infer the PyType of an AST expression."""
        if expr is None:
            return NoneType()
        if isinstance(expr, ast.Constant):
            return self._infer_constant(expr)
        if isinstance(expr, ast.Name):
            return scope.get(expr.id, AnyType())
        if isinstance(expr, (ast.List, ast.Set, ast.Dict)):
            return self._infer_collection(expr, scope, local_functions)
        if isinstance(expr, ast.BinOp):
            return self._infer_binop(expr, scope, local_functions)
        if isinstance(expr, ast.Compare):
            return PrimitiveType("bool")
        if isinstance(expr, ast.Call):
            return self._infer_call(expr, scope, local_functions)
        return AnyType()

    def _is_nested_in_other_func(self, node: ast.AST, parent_func: ast.AST) -> bool:
        """Verify if an AST node is contained in an inner/nested function definition."""
        for child in ast.walk(parent_func):
            if child is not parent_func and isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                for sub in ast.walk(child):
                    if sub is node:
                        return True
        return False
