"""Unit tests for ImportResolver."""

from __future__ import annotations

import unittest

from pycleaner.import_resolver import ImportResolver


class TestImportResolver(unittest.TestCase):
    def setUp(self) -> None:
        self.resolver = ImportResolver()

    def test_no_missing_imports(self) -> None:
        code = "import os\n\ndef get_cwd() -> str:\n    return os.getcwd()\n"
        res = self.resolver.resolve(code)
        self.assertEqual(len(res.resolved_imports), 0)
        self.assertEqual(res.code, code)

    def test_resolve_stdlib_modules(self) -> None:
        code = (
            "def run():\n"
            "    current = os.getcwd()\n"
            "    data = json.loads('{}')\n"
            "    return current, data\n"
        )
        res = self.resolver.resolve(code)
        self.assertIn("import os", res.resolved_imports)
        self.assertIn("import json", res.resolved_imports)
        self.assertIn("import os", res.code)
        self.assertIn("import json", res.code)

    def test_resolve_typing_and_pathlib(self) -> None:
        code = (
            "def load_file(path: Path) -> Optional[dict]:\n"
            "    if not path.exists():\n"
            "        return None\n"
            "    return {}\n"
        )
        res = self.resolver.resolve(code)
        self.assertIn("from pathlib import Path", res.resolved_imports)
        self.assertIn("from typing import Optional", res.resolved_imports)
        self.assertIn("from pathlib import Path", res.code)
        self.assertIn("from typing import Optional", res.code)

    def test_resolve_alias_np(self) -> None:
        code = "def zeros():\n    return np.zeros((3, 3))\n"
        res = self.resolver.resolve(code)
        self.assertIn("import numpy as np", res.resolved_imports)
        self.assertIn("import numpy as np", res.code)

    def test_insertion_after_docstring(self) -> None:
        code = (
            '"""Module description docstring."""\n\n'
            "def check():\n"
            "    return sys.platform\n"
        )
        res = self.resolver.resolve(code)
        self.assertIn("import sys", res.resolved_imports)
        lines = res.code.splitlines()
        self.assertEqual(lines[0], '"""Module description docstring."""')
        self.assertTrue(any("import sys" in line for line in lines[:5]))

    def test_missing_import_diagnostic_value(self) -> None:
        code = "def calc():\n    return sqrt(25)\n"
        res = self.resolver.resolve(code)
        self.assertEqual(len(res.diagnostics), 1)
        diag = res.diagnostics[0]
        self.assertEqual(diag.value, "missing-import")
        self.assertEqual(diag.symbol, "sqrt")
        self.assertEqual(diag.import_statement, "from math import sqrt")
        self.assertEqual(diag.status, "resolved")

    def test_resolve_expanded_symbols(self) -> None:
        code = (
            "def concurrency_setup():\n"
            "    pool = ThreadPoolExecutor(max_workers=2)\n"
            "    lock = Lock()\n"
            "    evt = Event()\n"
            "    q = Queue()\n"
            "    return pool, lock, evt, q\n"
        )
        res = self.resolver.resolve(code)
        self.assertIn(
            "from concurrent.futures import ThreadPoolExecutor", res.resolved_imports
        )
        self.assertIn("from threading import Lock", res.resolved_imports)
        self.assertIn("from threading import Event", res.resolved_imports)
        self.assertIn("from queue import Queue", res.resolved_imports)

    def test_resolve_custom_import_map(self) -> None:
        custom_map = {
            "SpecialClient": "from myorg.client import SpecialClient",
        }
        resolver = ImportResolver(custom_import_map=custom_map)
        code = "def get_client():\n    return SpecialClient()\n"
        res = resolver.resolve(code)
        self.assertIn("from myorg.client import SpecialClient", res.resolved_imports)
        self.assertIn("from myorg.client import SpecialClient", res.code)

    def test_type_checking_guard_injection(self) -> None:
        code = "def process_data(item: DataFrame) -> None:\n    print(item)\n"
        res = self.resolver.resolve(code)
        self.assertIn("from __future__ import annotations", res.code)
        self.assertIn("if TYPE_CHECKING:", res.code)
        self.assertIn("from pandas import DataFrame", res.code)

    def test_find_undefined_method(self) -> None:
        source = "def compute():\n    return sqrt(val) + unknown_var\n"
        undefined = self.resolver.find_undefined(source)
        self.assertIn("sqrt", undefined)
        self.assertIn("val", undefined)
        self.assertIn("unknown_var", undefined)


if __name__ == "__main__":
    unittest.main()
