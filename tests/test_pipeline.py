"""Integration tests for CleanPipeline."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pycleaner.config import PyCleanerConfig
from pycleaner.pipeline import CleanPipeline


class TestPipeline(unittest.TestCase):
    def test_end_to_end_cleanup_pipeline(self) -> None:
        # A realistic broken, badly formatted file:
        # 1. Unused import: 'import math'
        # 2. Missing import: 'Path' used without import
        # 3. Missing colons: 'def process(path)' and 'if len(path) = 0'
        # 4. Bad formatting: irregular spacing
        messy_code = (
            "import math\n\n"
            "def process(path)\n"
            "    if len(path) = 0\n"
            "        return Path('.')\n"
            "    return Path(path)\n"
        )

        pipeline = CleanPipeline()
        res = pipeline.process_source(messy_code, filename="example.py")

        self.assertTrue(res.is_valid_python)
        self.assertTrue(res.changed)

        # Syntax healed: missing colons and ==
        self.assertIn("def process(path):", res.cleaned_code)
        self.assertIn("if len(path) == 0:", res.cleaned_code)

        # Missing import resolved
        self.assertIn("from pathlib import Path", res.cleaned_code)

        # Unused import 'math' pruned
        self.assertNotIn("import math", res.cleaned_code)

        # Diff is available
        self.assertGreater(len(res.diff), 0)

    def test_file_processing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = Path(tmp_dir) / "broken.py"
            test_file.write_text(
                "import sys\n\ndef greet(name)\n    print 'hello ' + name\n",
                encoding="utf-8",
            )

            pipeline = CleanPipeline()
            result = pipeline.process_file(test_file, apply_changes=True)

            self.assertTrue(result.is_valid_python)
            self.assertTrue(result.changed)

            cleaned_content = test_file.read_text(encoding="utf-8")
            self.assertIn("def greet(name):", cleaned_content)
            self.assertIn('print("hello " + name)', cleaned_content)
            # sys was unused, pruned by linter
            self.assertNotIn("import sys", cleaned_content)

    def test_backup_file_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = Path(tmp_dir) / "target.py"
            original_code = "def foo()\n    return 42\n"
            test_file.write_text(original_code, encoding="utf-8")

            pipeline = CleanPipeline()
            # 1. With backup=True, .pycleaner.bak must be created containing the original code
            res = pipeline.process_file(test_file, apply_changes=True, backup=True)
            self.assertTrue(res.changed)

            bak_file = test_file.with_name(test_file.name + ".pycleaner.bak")
            self.assertTrue(bak_file.exists())
            self.assertEqual(bak_file.read_text(encoding="utf-8"), original_code)
            self.assertIn("def foo():", test_file.read_text(encoding="utf-8"))

            # 2. With backup=False, no new .bak is created if we delete the old one
            bak_file.unlink()
            test_file.write_text("def bar()\n    return 99\n", encoding="utf-8")
            pipeline.process_file(test_file, apply_changes=True, backup=False)
            self.assertFalse(bak_file.exists())

    def test_parallel_processing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            files = []
            for i in range(3):
                f = Path(tmp_dir) / f"mod_{i}.py"
                f.write_text(f"def func_{i}()\n    return {i}\n", encoding="utf-8")
                files.append(f)

            pipeline = CleanPipeline()
            results = pipeline.process_files(
                files, apply_changes=True, backup=False, max_workers=2
            )

            self.assertEqual(len(results), 3)
            for res in results:
                self.assertTrue(res.is_valid_python)
                self.assertTrue(res.changed)

            for i, f in enumerate(files):
                content = f.read_text(encoding="utf-8")
                self.assertIn(f"def func_{i}():", content)

    def test_config_driven_pipeline(self) -> None:
        cfg = PyCleanerConfig(
            custom_import_map={
                "my_custom_func": "from my_custom_pkg import my_custom_func"
            },
        )
        pipeline = CleanPipeline(config=cfg)

        source = "def run():\n    return my_custom_func()\n"
        res = pipeline.process_source(source, filename="custom_test.py")

        self.assertTrue(res.is_valid_python)
        self.assertTrue(res.changed)
        self.assertIn("from my_custom_pkg import my_custom_func", res.cleaned_code)


if __name__ == "__main__":
    unittest.main()
