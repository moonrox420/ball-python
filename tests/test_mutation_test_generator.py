from __future__ import annotations

from pathlib import Path

import pytest

from pycleaner.test_generator import AstMutator, TestGenerator


def test_generator_emits_no_tautologies_and_real_assertions(tmp_path: Path) -> None:
    code = """
def multiply(a: int, b: int) -> int:
    return a * b

class Calculator:
    def __init__(self, offset: int = 0):
        self.offset = offset

    def compute(self, x: int) -> int:
        return x + self.offset
"""
    f = tmp_path / "math_service.py"
    f.write_text(code, encoding="utf-8")

    generator = TestGenerator()
    suite = generator.generate_for_file(f)

    rendered = suite.rendered_code

    # Assert ZERO tautologies
    assert "assert True" not in rendered
    assert "except TypeError:" not in rendered
    assert "pass  # Requires instantiated parent" not in rendered

    # Assert real type and instance assertions
    assert "assert isinstance(result, int)" in rendered
    assert "instance = math_service.Calculator()" in rendered

    # Assert mutation receipt
    assert suite.mutation_kill_rate >= 0.70
    assert "mutation_kill_rate=" in rendered


def test_ast_mutator_generates_comparison_and_binary_mutants() -> None:
    import ast

    code = "def check(x: int, y: int) -> bool:\n    return x < y and x + y == 10\n"
    tree = ast.parse(code)
    mutator = AstMutator()
    mutator.visit(tree)

    assert mutator.mutations_applied >= 3
