"""Unit tests for LinterFormatter and pure-Python fallbacks."""

from __future__ import annotations

import unittest

from pycleaner.linter_formatter import LinterFormatter


class TestLinterFormatter(unittest.TestCase):
    def setUp(self) -> None:
        self.formatter_without_ruff = LinterFormatter(ruff_path="__non_existent_ruff__")
        self.formatter_without_ruff.autoflake_cmd = None
        self.formatter_without_ruff.black_cmd = None
        self.formatter_without_ruff.isort_cmd = None

    def test_pure_python_prune_unused_imports(self) -> None:
        code = (
            "import math\n"
            "import sys\n"
            "from pathlib import Path\n"
            "\n"
            "def get_home():\n"
            "    return Path.home()\n"
        )
        result = self.formatter_without_ruff.fix_and_format(
            code, do_lint_fix=True, do_format=False
        )
        self.assertNotIn("import math", result.code)
        self.assertNotIn("import sys", result.code)
        self.assertIn("from pathlib import Path", result.code)
        self.assertTrue(result.lint_changed)
        self.assertTrue(any("Pruned unused import" in d for d in result.diagnostics))

    def test_pure_python_prune_partial_from_import(self) -> None:
        code = (
            "from collections import defaultdict, deque\n"
            "\n"
            "def build_graph():\n"
            "    return defaultdict(list)\n"
        )
        result = self.formatter_without_ruff.fix_and_format(
            code, do_lint_fix=True, do_format=False
        )
        self.assertIn("from collections import defaultdict", result.code)
        self.assertNotIn("deque", result.code)
        self.assertTrue(result.lint_changed)

    def test_pure_python_preserve_type_ignore_and_noqa(self) -> None:
        code = (
            "import unused1  # type: ignore\n"
            "import unused2  # noqa\n"
            "\n"
            "def run():\n"
            "    return 42\n"
        )
        result = self.formatter_without_ruff.fix_and_format(
            code, do_lint_fix=True, do_format=False
        )
        self.assertIn("import unused1  # type: ignore", result.code)
        self.assertIn("import unused2  # noqa", result.code)

    def test_pure_python_preserve_all_export(self) -> None:
        code = "from math import sqrt\n\n__all__ = ['sqrt']\n"
        result = self.formatter_without_ruff.fix_and_format(
            code, do_lint_fix=True, do_format=False
        )
        self.assertIn("from math import sqrt", result.code)

    def test_pure_python_whitespace_formatting(self) -> None:
        code = "def hello():   \n    return 'world'    \n\n\n\n"
        result = self.formatter_without_ruff.fix_and_format(
            code, do_lint_fix=False, do_format=True
        )
        self.assertTrue(result.format_changed)
        self.assertNotIn("   \n", result.code)
        self.assertNotIn("\n\n\n\n", result.code)
        self.assertTrue(result.code.endswith("\n"))

    def test_pure_python_sort_imports(self) -> None:
        code = (
            "import requests\n"
            "import sys\n"
            "import os\n"
            "\n"
            "def run():\n"
            "    return os.name, sys.platform, requests.__version__\n"
        )
        sorted_code, sort_changed, _ = (
            self.formatter_without_ruff._pure_python_sort_imports(code)
        )
        self.assertTrue(sort_changed)
        lines = [
            line.strip()
            for line in sorted_code.splitlines()
            if line.strip().startswith("import")
        ]
        # Stdlib (os, sys) should come before third-party (requests)
        self.assertEqual(lines, ["import os", "import sys", "import requests"])

    def test_wrap_long_imports(self) -> None:
        long_import = "from very_long_module_name.submodule.handlers import first_handler, second_handler, third_handler, fourth_handler"
        wrapped = self.formatter_without_ruff._wrap_long_imports(
            long_import, line_length=60
        )
        self.assertIn("(", wrapped)
        self.assertIn(")", wrapped)
        for line in wrapped.splitlines():
            self.assertLessEqual(len(line), 75)


if __name__ == "__main__":
    unittest.main()
