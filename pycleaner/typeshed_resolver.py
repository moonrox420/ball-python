"""
Typeshed stub parser and symbol signature resolver.

Parses .pyi stub files, extracts typed function and method signatures,
and provides return types, argument types, and class attributes for
built-in and standard library symbols.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar


@dataclass(slots=True)
class FunctionSignature:
    """Type signature for a function or method."""

    name: str
    param_types: dict[str, str] = field(default_factory=dict)
    return_type: str = "Any"
    is_method: bool = False
    is_static: bool = False
    is_class_method: bool = False


@dataclass(slots=True)
class ClassSignature:
    """Type signature for a class definition."""

    name: str
    methods: dict[str, FunctionSignature] = field(default_factory=dict)
    attributes: dict[str, str] = field(default_factory=dict)
    base_classes: list[str] = field(default_factory=list)


class TypeshedResolver:
    """Resolves type annotations and signatures from typeshed stubs and built-in catalogs."""

    DEFAULT_TYPESHED_CANDIDATES: ClassVar[list[str]] = [
        r"C:\Temp\pyrefly_bundled_typeshed_df16aab5f050",
    ]

    # Core built-in function return types (guaranteed baseline without file I/O)
    BUILTIN_FUNCTIONS: ClassVar[dict[str, str]] = {
        "len": "int",
        "str": "str",
        "int": "int",
        "float": "float",
        "bool": "bool",
        "list": "list",
        "dict": "dict",
        "set": "set",
        "tuple": "tuple",
        "bytes": "bytes",
        "abs": "int | float",
        "all": "bool",
        "any": "bool",
        "bin": "str",
        "hex": "str",
        "oct": "str",
        "chr": "str",
        "ord": "int",
        "hash": "int",
        "id": "int",
        "repr": "str",
        "round": "int | float",
        "sum": "int | float",
        "min": "Any",
        "max": "Any",
        "open": "typing.IO[Any]",
        "isinstance": "bool",
        "issubclass": "bool",
        "callable": "bool",
        "hasattr": "bool",
        "getattr": "Any",
        "pow": "int | float",
        "divmod": "tuple[int, int]",
    }

    # Core built-in method return types
    BUILTIN_METHODS: ClassVar[dict[str, dict[str, str]]] = {
        "str": {
            "upper": "str",
            "lower": "str",
            "strip": "str",
            "lstrip": "str",
            "rstrip": "str",
            "split": "list[str]",
            "rsplit": "list[str]",
            "splitlines": "list[str]",
            "join": "str",
            "replace": "str",
            "startswith": "bool",
            "endswith": "bool",
            "find": "int",
            "rfind": "int",
            "index": "int",
            "rindex": "int",
            "count": "int",
            "encode": "bytes",
            "format": "str",
            "isdigit": "bool",
            "isalpha": "bool",
            "isalnum": "bool",
            "isspace": "bool",
            "title": "str",
            "capitalize": "str",
        },
        "list": {
            "append": "None",
            "extend": "None",
            "insert": "None",
            "remove": "None",
            "pop": "Any",
            "clear": "None",
            "index": "int",
            "count": "int",
            "sort": "None",
            "reverse": "None",
            "copy": "list[Any]",
        },
        "dict": {
            "get": "Any",
            "keys": "typing.KeysView[Any]",
            "values": "typing.ValuesView[Any]",
            "items": "typing.ItemsView[Any, Any]",
            "pop": "Any",
            "popitem": "tuple[Any, Any]",
            "clear": "None",
            "update": "None",
            "setdefault": "Any",
            "copy": "dict[Any, Any]",
        },
        "set": {
            "add": "None",
            "remove": "None",
            "discard": "None",
            "pop": "Any",
            "clear": "None",
            "union": "set[Any]",
            "intersection": "set[Any]",
            "difference": "set[Any]",
            "symmetric_difference": "set[Any]",
            "issubset": "bool",
            "issuperset": "bool",
            "isdisjoint": "bool",
            "copy": "set[Any]",
        },
    }

    # Common standard library function signatures
    STDLIB_FUNCTIONS: ClassVar[dict[str, dict[str, str]]] = {
        "math": {
            "sqrt": "float",
            "ceil": "int",
            "floor": "int",
            "sin": "float",
            "cos": "float",
            "tan": "float",
            "log": "float",
            "exp": "float",
            "radians": "float",
            "degrees": "float",
        },
        "os": {
            "getcwd": "str",
            "listdir": "list[str]",
            "system": "int",
        },
        "os.path": {
            "join": "str",
            "abspath": "str",
            "basename": "str",
            "dirname": "str",
            "exists": "bool",
            "isfile": "bool",
            "isdir": "bool",
        },
        "json": {
            "dumps": "str",
            "loads": "Any",
        },
    }

    def __init__(self, typeshed_path: str | Path | None = None) -> None:
        self.typeshed_root: Path | None = self._locate_typeshed(typeshed_path)
        self._parsed_stubs: dict[str, ast.Module] = {}
        self._class_cache: dict[str, ClassSignature] = {}
        self._func_cache: dict[str, FunctionSignature] = {}

    def _locate_typeshed(self, custom_path: str | Path | None) -> Path | None:
        if custom_path:
            p = Path(custom_path).resolve()
            if p.is_dir():
                return p

        for candidate in self.DEFAULT_TYPESHED_CANDIDATES:
            cand_path = Path(candidate)
            if cand_path.is_dir():
                return cand_path

        # Check environment variable
        env_path = os.environ.get("TYPESHED_PATH")
        if env_path:
            p = Path(env_path).resolve()
            if p.is_dir():
                return p

        return None

    def get_builtin_return_type(self, func_name: str) -> str | None:
        """Get return type for a built-in function."""
        return self.BUILTIN_FUNCTIONS.get(func_name)

    def get_builtin_method_return_type(
        self, type_name: str, method_name: str
    ) -> str | None:
        """Get return type for a method on a built-in type."""
        methods = self.BUILTIN_METHODS.get(type_name)
        if methods:
            return methods.get(method_name)
        return None

    def load_stub_for_module(self, module_name: str) -> ast.Module | None:
        """Load and parse the .pyi stub for a module."""
        if not self.typeshed_root:
            return None

        if module_name in self._parsed_stubs:
            return self._parsed_stubs[module_name]

        # Look for module.pyi or module/__init__.pyi
        rel_parts = module_name.split(".")
        candidate_file = self.typeshed_root.joinpath(*rel_parts).with_suffix(".pyi")
        candidate_pkg = self.typeshed_root.joinpath(*rel_parts, "__init__.pyi")

        target_file: Path | None = None
        if candidate_file.is_file():
            target_file = candidate_file
        elif candidate_pkg.is_file():
            target_file = candidate_pkg
        elif len(rel_parts) == 1 and rel_parts[0] == "builtins":
            builtins_stub = self.typeshed_root / "builtins.pyi"
            if builtins_stub.is_file():
                target_file = builtins_stub

        if not target_file:
            return None

        try:
            content = target_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(target_file))
            self._parsed_stubs[module_name] = tree
            return tree
        except SyntaxError:
            return None

    @staticmethod
    def _normalize_func_target(
        module_name: str, func_name: str | None
    ) -> tuple[str, str]:
        if func_name is not None:
            return module_name, func_name
        if "." in module_name:
            mod, fn = module_name.rsplit(".", 1)
            return mod, fn
        return "builtins", module_name

    def _resolve_func_from_catalog(
        self, module_name: str, func_name: str
    ) -> FunctionSignature | None:
        if module_name in ("builtins", "") and func_name in self.BUILTIN_FUNCTIONS:
            return FunctionSignature(
                name=func_name, return_type=self.BUILTIN_FUNCTIONS[func_name]
            )
        if (
            module_name in self.STDLIB_FUNCTIONS
            and func_name in self.STDLIB_FUNCTIONS[module_name]
        ):
            return FunctionSignature(
                name=func_name,
                return_type=self.STDLIB_FUNCTIONS[module_name][func_name],
            )
        return None

    def _resolve_func_from_stub(
        self, module_name: str, func_name: str
    ) -> FunctionSignature | None:
        tree = self.load_stub_for_module(module_name)
        if not tree:
            return None
        for node in tree.body:
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == func_name
            ):
                return self._extract_function_signature(node)
        return None

    def resolve_function(
        self,
        module_name: str,
        func_name: str | None = None,
    ) -> FunctionSignature | None:
        """Resolve a function's typed signature from stubs or catalog tables."""
        mod, fn = self._normalize_func_target(module_name, func_name)
        cache_key = f"{mod}.{fn}"
        if cache_key in self._func_cache:
            return self._func_cache[cache_key]

        sig = self._resolve_func_from_catalog(mod, fn) or self._resolve_func_from_stub(
            mod, fn
        )
        if sig is not None:
            self._func_cache[cache_key] = sig
        return sig

    def resolve_class(self, module_name: str, class_name: str) -> ClassSignature | None:
        """Resolve a class's typed signature and member signatures from stubs."""
        cache_key = f"{module_name}.{class_name}"
        if cache_key in self._class_cache:
            return self._class_cache[cache_key]

        tree = self.load_stub_for_module(module_name)
        if not tree:
            return None

        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                cls_sig = self._extract_class_signature(node)
                self._class_cache[cache_key] = cls_sig
                return cls_sig

        return None

    def _extract_function_signature(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        is_method: bool = False,
    ) -> FunctionSignature:
        """Extract a FunctionSignature from an AST node."""
        param_types: dict[str, str] = {}
        all_args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        for arg in all_args:
            if arg.annotation:
                param_types[arg.arg] = ast.unparse(arg.annotation)
            else:
                param_types[arg.arg] = "Any"

        return_type = "Any"
        if node.returns:
            return_type = ast.unparse(node.returns)

        is_static = any(
            isinstance(d, ast.Name) and d.id == "staticmethod"
            for d in node.decorator_list
        )
        is_class = any(
            isinstance(d, ast.Name) and d.id == "classmethod"
            for d in node.decorator_list
        )

        return FunctionSignature(
            name=node.name,
            param_types=param_types,
            return_type=return_type,
            is_method=is_method,
            is_static=is_static,
            is_class_method=is_class,
        )

    def _extract_class_signature(self, node: ast.ClassDef) -> ClassSignature:
        """Extract a ClassSignature from an AST ClassDef node."""
        methods: dict[str, FunctionSignature] = {}
        attributes: dict[str, str] = {}
        base_classes: list[str] = [ast.unparse(b) for b in node.bases]

        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                methods[stmt.name] = self._extract_function_signature(
                    stmt, is_method=True
                )
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                attributes[stmt.target.id] = ast.unparse(stmt.annotation)

        return ClassSignature(
            name=node.name,
            methods=methods,
            attributes=attributes,
            base_classes=base_classes,
        )
