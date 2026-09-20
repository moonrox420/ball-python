"""
pycleaner.frameworks.plugins
============================

Concrete Framework Plugins for Pydantic, Pytest, FastAPI, SQLAlchemy, and Dataclasses.
"""

from __future__ import annotations

import ast
from pathlib import Path


def _get_decorator_name(node: ast.expr) -> str:
    """Extract string name from decorator node (e.g. 'pytest.fixture' or 'app.get')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        val = _get_decorator_name(node.value)
        return f"{val}.{node.attr}" if val else node.attr
    if isinstance(node, ast.Call):
        return _get_decorator_name(node.func)
    return ""


def _has_base_named(class_node: ast.ClassDef, base_names: set[str]) -> bool:
    """Check if class node inherits from any name in base_names."""
    for base in class_node.bases:
        if isinstance(base, ast.Name) and base.id in base_names:
            return True
        if isinstance(base, ast.Attribute) and base.attr in base_names:
            return True
    return False


class PydanticPlugin:
    """Understands Pydantic BaseModel, Field, model_config, and validators."""

    name = "pydantic"
    _MODEL_BASES = {"BaseModel", "BaseSettings", "RootModel", "GenericModel"}
    _VALIDATOR_DECORATORS = {
        "field_validator",
        "model_validator",
        "validator",
        "root_validator",
        "computed_field",
    }

    def is_applicable(self, tree: ast.AST, filepath: Path | str) -> bool:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == "pydantic":
                        return True
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] == "pydantic":
                    return True
        return False

    def get_protected_names(self, tree: ast.AST) -> set[str]:
        return {"model_config", "Config", "ConfigDict"}

    def get_protected_decorators(self) -> set[str]:
        return self._VALIDATOR_DECORATORS

    def is_protected_field(self, node: ast.AST, class_node: ast.ClassDef) -> bool:
        return _has_base_named(class_node, self._MODEL_BASES)

    def should_ignore_definition(
        self,
        name: str,
        kind: str,
        node: ast.AST,
        context: str,
        tree: ast.AST,
    ) -> bool:
        if name in self.get_protected_names(tree):
            return True

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for deco in node.decorator_list:
                deco_name = _get_decorator_name(deco)
                for val_dec in self._VALIDATOR_DECORATORS:
                    if val_dec in deco_name:
                        return True
        return False


class PytestPlugin:
    """Understands Pytest fixtures, hooks, parameterizations, and marks."""

    name = "pytest"

    def is_applicable(self, tree: ast.AST, filepath: Path | str) -> bool:
        f_name = Path(filepath).name
        if (
            f_name.startswith("test_")
            or f_name.endswith("_test.py")
            or f_name == "conftest.py"
        ):
            return True
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        if a.name == "pytest":
                            return True
                elif node.module and node.module.split(".")[0] == "pytest":
                    return True
        return False

    def get_protected_names(self, tree: ast.AST) -> set[str]:
        return {
            "pytestmark",
            "pytest_plugins",
            "pytest_configure",
            "pytest_unconfigure",
            "pytest_addoption",
            "pytest_collection_modifyitems",
            "pytest_sessionstart",
            "pytest_sessionfinish",
        }

    def get_protected_decorators(self) -> set[str]:
        return {"pytest.fixture", "fixture", "pytest.mark"}

    def is_protected_field(self, node: ast.AST, class_node: ast.ClassDef) -> bool:
        return False

    def should_ignore_definition(
        self,
        name: str,
        kind: str,
        node: ast.AST,
        context: str,
        tree: ast.AST,
    ) -> bool:
        if name in self.get_protected_names(tree):
            return True

        # Test functions themselves are discovered by pytest runner
        if kind == "function" and (name.startswith("test_") or name.endswith("_test")):
            return True
        if kind == "class" and name.startswith("Test"):
            return True

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for deco in node.decorator_list:
                d_name = _get_decorator_name(deco)
                if "fixture" in d_name or "mark." in d_name:
                    return True
        return False


class FastAPIPlugin:
    """Understands FastAPI route handlers, dependencies, and lifecycle hooks."""

    name = "fastapi"
    _ROUTE_METHODS = {
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "options",
        "head",
        "api_route",
    }

    def is_applicable(self, tree: ast.AST, filepath: Path | str) -> bool:
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        if a.name in ("fastapi", "starlette"):
                            return True
                elif node.module and node.module.split(".")[0] in (
                    "fastapi",
                    "starlette",
                ):
                    return True
        return False

    def get_protected_names(self, tree: ast.AST) -> set[str]:
        return set()

    def get_protected_decorators(self) -> set[str]:
        return {"app.get", "app.post", "router.get", "router.post"}

    def is_protected_field(self, node: ast.AST, class_node: ast.ClassDef) -> bool:
        return False

    def should_ignore_definition(
        self,
        name: str,
        kind: str,
        node: ast.AST,
        context: str,
        tree: ast.AST,
    ) -> bool:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for deco in node.decorator_list:
                d_name = _get_decorator_name(deco)
                parts = d_name.split(".")
                if len(parts) >= 2 and parts[-1] in self._ROUTE_METHODS:
                    return True
                if (
                    "middleware" in d_name
                    or "on_event" in d_name
                    or "exception_handler" in d_name
                ):
                    return True
        return False


class SQLAlchemyPlugin:
    """Understands SQLAlchemy DeclarativeBase, Mapped, Column, and relationships."""

    name = "sqlalchemy"
    _BASE_CLASSES = {"Base", "DeclarativeBase", "DeclarativeBaseNoMeta"}

    def is_applicable(self, tree: ast.AST, filepath: Path | str) -> bool:
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        if a.name.split(".")[0] == "sqlalchemy":
                            return True
                elif node.module and node.module.split(".")[0] == "sqlalchemy":
                    return True
        return False

    def get_protected_names(self, tree: ast.AST) -> set[str]:
        return {"__tablename__", "__table_args__", "__mapper_args__"}

    def get_protected_decorators(self) -> set[str]:
        return {"validates"}

    def is_protected_field(self, node: ast.AST, class_node: ast.ClassDef) -> bool:
        if _has_base_named(class_node, self._BASE_CLASSES):
            return True
        # Check if attribute annotation uses Mapped[...]
        if isinstance(node, ast.AnnAssign):
            ann = node.annotation
            if isinstance(ann, ast.Subscript):
                if isinstance(ann.value, ast.Name) and ann.value.id == "Mapped":
                    return True
        return False

    def should_ignore_definition(
        self,
        name: str,
        kind: str,
        node: ast.AST,
        context: str,
        tree: ast.AST,
    ) -> bool:
        return name in self.get_protected_names(tree)


class DataclassPlugin:
    """Understands standard library dataclasses and attrs."""

    name = "dataclass"

    def is_applicable(self, tree: ast.AST, filepath: Path | str) -> bool:
        return True

    def get_protected_names(self, tree: ast.AST) -> set[str]:
        return {"__post_init__"}

    def get_protected_decorators(self) -> set[str]:
        return {"dataclass"}

    def is_protected_field(self, node: ast.AST, class_node: ast.ClassDef) -> bool:
        for deco in class_node.decorator_list:
            d_name = _get_decorator_name(deco)
            if "dataclass" in d_name:
                return True
        return False

    def should_ignore_definition(
        self,
        name: str,
        kind: str,
        node: ast.AST,
        context: str,
        tree: ast.AST,
    ) -> bool:
        return name in self.get_protected_names(tree)
