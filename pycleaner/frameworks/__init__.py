"""
pycleaner.frameworks
====================

Framework Semantic Index and Extensible Plugin Protocol.

Provides AST-level awareness of framework contracts (Pydantic, Pytest, FastAPI,
SQLAlchemy, Dataclasses) to eliminate false positives in dead-code detection,
type inference, and automated transformations.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class FrameworkPlugin(Protocol):
    """Protocol that every framework awareness plugin must implement."""

    name: str

    def is_applicable(self, tree: ast.AST, filepath: Path | str) -> bool:
        """Return True if this framework is utilized within the AST or file."""
        ...

    def get_protected_names(self, tree: ast.AST) -> set[str]:
        """Return special method or attribute names dynamically called by the framework."""
        ...

    def get_protected_decorators(self) -> set[str]:
        """Return decorator prefixes that register symbols dynamically."""
        ...

    def is_protected_field(self, node: ast.AST, class_node: ast.ClassDef) -> bool:
        """Return True if node is a framework field declaration that must not be pruned."""
        ...

    def should_ignore_definition(
        self,
        name: str,
        kind: str,
        node: ast.AST,
        context: str,
        tree: ast.AST,
    ) -> bool:
        """Return True if the symbol definition is implicitly loaded by the framework."""
        ...


class FrameworkRegistry:
    """Central registry of framework awareness plugins."""

    def __init__(self) -> None:
        self._plugins: list[FrameworkPlugin] = []
        self._applicable_cache: dict[tuple[int, str], list[FrameworkPlugin]] = {}

    def register(self, plugin: FrameworkPlugin) -> None:
        self._plugins.append(plugin)
        self._applicable_cache.clear()

    @property
    def plugins(self) -> list[FrameworkPlugin]:
        return list(self._plugins)

    def get_applicable_plugins(
        self, tree: ast.AST, filepath: Path | str
    ) -> list[FrameworkPlugin]:
        cache_key = (id(tree), str(filepath))
        if cache_key in self._applicable_cache:
            return self._applicable_cache[cache_key]
        applicable = [p for p in self._plugins if p.is_applicable(tree, filepath)]
        self._applicable_cache[cache_key] = applicable
        return applicable

    def is_protected(
        self,
        name: str,
        kind: str,
        node: ast.AST,
        context: str,
        tree: ast.AST,
        filepath: Path | str,
    ) -> bool:
        """Check if any applicable plugin protects this symbol from being marked dead."""
        for plugin in self.get_applicable_plugins(tree, filepath):
            if plugin.should_ignore_definition(name, kind, node, context, tree):
                return True
        return False

    def is_field_protected(
        self,
        node: ast.AST,
        class_node: ast.ClassDef,
        tree: ast.AST,
        filepath: Path | str,
    ) -> bool:
        for plugin in self.get_applicable_plugins(tree, filepath):
            if plugin.is_protected_field(node, class_node):
                return True
        return False


def get_default_registry() -> FrameworkRegistry:
    """Construct and populate the default registry with built-in plugins."""
    from pycleaner.frameworks.plugins import (
        DataclassPlugin,
        FastAPIPlugin,
        PydanticPlugin,
        PytestPlugin,
        PyTorchPlugin,
        SQLAlchemyPlugin,
    )

    reg = FrameworkRegistry()
    reg.register(PydanticPlugin())
    reg.register(PytestPlugin())
    reg.register(FastAPIPlugin())
    reg.register(SQLAlchemyPlugin())
    reg.register(DataclassPlugin())
    reg.register(PyTorchPlugin())
    return reg
