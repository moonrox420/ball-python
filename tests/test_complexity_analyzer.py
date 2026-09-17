"""Tests for pycleaner.complexity_analyzer module."""

from __future__ import annotations

import textwrap
from pathlib import Path

from pycleaner.complexity_analyzer import (
    ComplexityAnalyzer,
)


class TestComplexityAnalyzer:
    """Test suite for cyclomatic and cognitive complexity analysis."""

    def test_mccabe_scoring_for_known_functions(self) -> None:
        source = textwrap.dedent("""
            def simple_function(x):
                return x + 1

            def branchy_function(a, b, c):
                if a > 0:
                    if b > 0:
                        return a + b
                    elif c > 0:
                        return a + c
                elif b < 0:
                    for i in range(10):
                        if i == c:
                            break
                return 0
        """)
        analyzer = ComplexityAnalyzer()
        report = analyzer.analyze_source(source, filename="functions.py")

        metrics_map = {f.name: f for f in report.functions}

        # simple_function has 0 decision points -> base complexity 1
        assert metrics_map["simple_function"].cyclomatic == 1

        # branchy_function has:
        # if a > 0 (+1)
        #   if b > 0 (+1)
        #   elif c > 0 (+1)
        # elif b < 0 (+1)
        #   for i in range (+1)
        #     if i == c (+1)
        # base: 1 + 6 = 7
        assert metrics_map["branchy_function"].cyclomatic == 7

    def test_cognitive_complexity_scoring(self) -> None:
        source = textwrap.dedent("""
            def linear_logic(x):
                y = x * 2
                z = y + 3
                return z

            def deeply_nested_logic(data):
                total = 0
                if data:                       # +1 (nesting 0)
                    for row in data:           # +2 (nesting 1)
                        if row:                # +3 (nesting 2)
                            for val in row:    # +4 (nesting 3)
                                if val > 0:    # +5 (nesting 4)
                                    total += val
                return total
        """)
        analyzer = ComplexityAnalyzer()
        report = analyzer.analyze_source(source, filename="cognitive.py")

        metrics_map = {f.name: f for f in report.functions}
        assert metrics_map["linear_logic"].cognitive == 0
        # 1 + 2 + 3 + 4 + 5 = 15
        assert metrics_map["deeply_nested_logic"].cognitive == 15

    def test_threshold_violation_detection(self) -> None:
        source = textwrap.dedent("""
            def many_arguments(a, b, c, d, e, f, g):
                return a + b + c + d + e + f + g

            def many_returns(x):
                if x == 1:
                    return 1
                if x == 2:
                    return 2
                if x == 3:
                    return 3
                if x == 4:
                    return 4
                return 0
        """)
        analyzer = ComplexityAnalyzer()
        report = analyzer.analyze_source(source, filename="thresholds.py")

        violating_args = report.above_threshold(max_args=5)
        assert any(f.name == "many_arguments" for f in violating_args)

        metrics_returns = next(f for f in report.functions if f.name == "many_returns")
        assert metrics_returns.returns == 5

    def test_nested_function_handling_and_qualified_names(self) -> None:
        source = textwrap.dedent("""
            class Service:
                def outer_method(self, items):
                    def inner_helper(item):
                        if item > 0:
                            return item
                        return 0
                    return sum(inner_helper(x) for x in items)
        """)
        analyzer = ComplexityAnalyzer()
        report = analyzer.analyze_source(source, filename="nested.py")

        names = {f.qualified_name: f for f in report.functions}
        assert "Service.outer_method" in names
        assert "Service.outer_method.inner_helper" in names

        inner = names["Service.outer_method.inner_helper"]
        assert inner.args == 1
        assert inner.cyclomatic == 2

    def test_nesting_depth_calculation(self) -> None:
        source = textwrap.dedent("""
            def check_nesting(x):
                if x:
                    while x > 0:
                        try:
                            with open("file.txt") as f:
                                pass
                        except Exception:
                            pass
        """)
        analyzer = ComplexityAnalyzer()
        report = analyzer.analyze_source(source, filename="nesting.py")

        metrics = report.functions[0]
        # if (1) -> while (2) -> try (3) -> with (4)
        assert metrics.max_nesting == 4

    def test_analyze_project(self, tmp_path: Path) -> None:
        file1 = tmp_path / "mod1.py"
        file1.write_text(
            textwrap.dedent("""
            def func_a(x):
                return x * 2
        """),
            encoding="utf-8",
        )

        file2 = tmp_path / "mod2.py"
        file2.write_text(
            textwrap.dedent("""
            def func_b(x):
                if x:
                    return 1
                return 0
        """),
            encoding="utf-8",
        )

        analyzer = ComplexityAnalyzer()
        report = analyzer.analyze_project(tmp_path)

        assert report.files_scanned >= 2
        assert len(report.functions) == 2
        assert report.average_cyclomatic > 0.0
