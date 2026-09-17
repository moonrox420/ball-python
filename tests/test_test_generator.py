"""Tests for pycleaner.test_generator module."""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from pycleaner.test_generator import TestGenerator


class TestTestGenerator:
    """Test suite for automated pytest test suite synthesizer."""

    def test_generate_for_typed_function(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            def calculate_area(length: float, width: float) -> float:
                \"\"\"Calculate rectangle area.\"\"\"
                if length < 0 or width < 0:
                    raise ValueError("Dimensions must be non-negative")
                return length * width
        """)
        f = tmp_path / "geometry.py"
        f.write_text(code, encoding="utf-8")

        generator = TestGenerator()
        suite = generator.generate_for_file(f)

        assert suite.module_name == "geometry"
        assert suite.test_count >= 3

        test_names = [tc.test_name for tc in suite.test_cases]
        assert "test_calculate_area_happy_path" in test_names
        assert "test_calculate_area_boundary_values" in test_names
        assert "test_calculate_area_raises_valueerror" in test_names

        # Verify the generated code is valid, parseable Python
        parsed = ast.parse(suite.rendered_code)
        assert isinstance(parsed, ast.Module)

    def test_generate_for_class_methods(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            class DataBuffer:
                def __init__(self, capacity: int = 100) -> None:
                    self.capacity = capacity
                    self.items: list[str] = []

                def add_item(self, item: str) -> None:
                    self.items.append(item)
        """)
        f = tmp_path / "buffer.py"
        f.write_text(code, encoding="utf-8")

        generator = TestGenerator()
        suite = generator.generate_for_file(f)

        assert suite.test_count >= 2
        test_names = [tc.test_name for tc in suite.test_cases]
        assert "test_databuffer_instantiation" in test_names
        assert "test_databuffer_add_item_execution" in test_names

    def test_project_generation_and_saving(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        out_dir = tmp_path / "generated_tests"

        (src_dir / "calc.py").write_text(
            "def add(a: int, b: int) -> int:\n    return a + b\n",
            encoding="utf-8",
        )

        generator = TestGenerator()
        suites = generator.generate_for_project(src_dir, output_dir=out_dir)

        assert len(suites) == 1
        gen_file = out_dir / "test_calc_generated.py"
        assert gen_file.is_file()
        content = gen_file.read_text(encoding="utf-8")
        assert "def test_add_happy_path() -> None:" in content
