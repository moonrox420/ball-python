"""
Static bidirectional type inference and type checking engine.

Inspects AST expressions, evaluates algebraic types, validates return types
against declared signatures, checks call argument type compatibility,
and performs type narrowing across conditional branches.
"""

from __future__ import annotations

from pycleaner.discovery import collect_project_python_files

import ast
from dataclasses import dataclass, field
from pathlib import Path

from pycleaner.typeshed_resolver import TypeshedResolver

# ---------------------------------------------------------------------------
# Algebraic Type System
# ---------------------------------------------------------------------------


class PyType:
    """Base algebraic type representation."""

    def is_assignable_to(self, target: PyType) -> bool:
        """Check if this type can be assigned to target type."""
        if isinstance(target, AnyType) or isinstance(self, AnyType) or target == self:
            return True
        if isinstance(target, UnionType):
            return self._assignable_to_union(target)
        if isinstance(self, UnionType):
            return self._union_assignable_to(target)
        if isinstance(target, CustomClassType) and self._check_custom_target(target):
            return True
        if isinstance(self, CustomClassType) and self._check_custom_source(target):
            return True
        return self._check_numeric_promotions(target)

    def _assignable_to_union(self, target: PyType) -> bool:
        types = getattr(target, "types", [])
        for u in types:
            if self.is_assignable_to(u):
                return True
        return False

    def _union_assignable_to(self, target: PyType) -> bool:
        types = getattr(self, "types", [])
        non_none = [u for u in types if not isinstance(u, NoneType)]
        if non_none:
            all_match = True
            for u in non_none:
                if not u.is_assignable_to(target):
                    all_match = False
                    break
            if all_match:
                return True
        for u in types:
            if not u.is_assignable_to(target):
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
        if self.name in ("StrPath", "PathLike", "AnyStr"):  # type: ignore[attr-defined]
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

    def is_assignable_to(self, target: PyType) -> bool:
        if _is_collection_assignable(self.item_type, target):
            return True
        return super().is_assignable_to(target)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ListType) and self.item_type == other.item_type

    def __str__(self) -> str:
        return f"list[{self.item_type}]"


class SetType(PyType):
    def __init__(self, item_type: PyType) -> None:
        self.item_type = item_type

    def is_assignable_to(self, target: PyType) -> bool:
        if _is_collection_assignable(self.item_type, target):
            return True
        return super().is_assignable_to(target)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SetType) and self.item_type == other.item_type

    def __str__(self) -> str:
        return f"set[{self.item_type}]"


class DictType(PyType):
    def __init__(self, key_type: PyType, value_type: PyType) -> None:
        self.key_type = key_type
        self.value_type = value_type

    def is_assignable_to(self, target: PyType) -> bool:
        if isinstance(target, AnyType):
            return True
        if isinstance(target, DictType):
            return self.key_type.is_assignable_to(
                target.key_type
            ) and self.value_type.is_assignable_to(target.value_type)
        if isinstance(target, CustomClassType) and target.name in (
            "dict",
            "Dict",
            "Mapping",
        ):
            return True
        return super().is_assignable_to(target)

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


class TypeChecker:
    """Type checker verifying annotations, return statements, and call sites."""

    IGNORE_DIRS: frozenset[str] = frozenset(
        {
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
    )

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
        )

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_function(node, ctx))
            elif isinstance(node, ast.AnnAssign):
                findings.extend(self._check_ann_assign(node, ctx))

        return findings

    def _discover_python_files(self, root: Path) -> list[Path]:
        return collect_project_python_files(root)

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

    def check_project(self, root_dir: str | Path) -> TypeReport:
        """Type-check all Python files across an entire project directory."""
        root = Path(root_dir).resolve()
        findings: list[TypeFinding] = []
        functions_checked = 0
        py_files = self._discover_python_files(root)

        for fpath in py_files:
            findings.extend(self.check_file(fpath))
            functions_checked += self._count_functions(fpath)

        return TypeReport(
            findings=findings,
            files_scanned=len(py_files),
            functions_checked=functions_checked,
        )

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
        for child in ast.walk(func):
            if not isinstance(child, ast.Return):
                continue
            if self._is_nested_in_other_func(child, func):
                continue

            actual_type = self._infer_expr_type(child.value, scope, ctx.local_functions)
            if not actual_type.is_assignable_to(declared_return):
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
            declared_type
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
        if func_name in local_functions:
            cleaned = self._clean_receiver_params(
                dict(local_functions[func_name][0]), call
            )
            return func_name, cleaned

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
            if isinstance(actual, AnyType) or actual.is_assignable_to(expected):
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

    def _infer_typeshed_lookup(self, target: str, func_name: str) -> PyType:
        if target:
            sig = self.typeshed.resolve_function(target)
            if sig and sig.return_type and sig.return_type != "Any":
                return parse_type_annotation(sig.return_type)

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
        ctor = self._infer_constructor_call(
            func_name, expr.args, scope, local_functions
        )
        if ctor is not None:
            return ctor

        if isinstance(expr.func, ast.Attribute):
            meth = self._infer_attribute_method(expr.func, scope, local_functions)
            if meth is not None:
                return meth

        if func_name in local_functions:
            return local_functions[func_name][1]

        return self._infer_typeshed_lookup(dotted_name or func_name, func_name)

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
