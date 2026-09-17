"""Unit and integration tests for DeadCodeDetector."""

import tempfile
import unittest
from pathlib import Path

from pycleaner.dead_code_detector import DeadCodeDetector


class TestDeadCodeDetector(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = DeadCodeDetector()

    def test_unused_function_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            f1 = root / "module.py"
            f1.write_text(
                "def active_function():\n"
                "    return 42\n\n"
                "def abandoned_helper():\n"
                "    return 99\n\n"
                "x = active_function()\n",
                encoding="utf-8",
            )
            report = self.detector.scan_project(root)
            dead_names = [item.name for item in report.items if item.kind == "function"]
            self.assertIn("abandoned_helper", dead_names)
            self.assertNotIn("active_function", dead_names)

    def test_unused_class_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            f1 = root / "models.py"
            f1.write_text(
                "class UsedModel:\n"
                "    pass\n\n"
                "class OrphanModel:\n"
                "    pass\n\n"
                "model = UsedModel()\n",
                encoding="utf-8",
            )
            report = self.detector.scan_project(root)
            dead_classes = [item.name for item in report.items if item.kind == "class"]
            self.assertIn("OrphanModel", dead_classes)
            self.assertNotIn("UsedModel", dead_classes)

    def test_unreachable_code_after_return(self) -> None:
        code = (
            "def calculate(x: int) -> int:\n"
            "    return x * 2\n"
            "    print('This will never execute')\n"
            "    y = x + 1\n"
        )
        report = self.detector.scan_source(code, filename="calc.py")
        unreachable = report.by_kind("unreachable")
        self.assertGreaterEqual(len(unreachable), 1)
        self.assertTrue(any("return" in item.reason for item in unreachable))

    def test_unreachable_code_after_raise(self) -> None:
        code = (
            "def validate(val):\n"
            "    if val < 0:\n"
            "        raise ValueError('Negative value')\n"
            "        val = 0\n"
            "    return val\n"
        )
        report = self.detector.scan_source(code, filename="validator.py")
        unreachable = report.by_kind("unreachable")
        self.assertEqual(len(unreachable), 1)
        self.assertIn("raise", unreachable[0].reason)

    def test_empty_pass_branches(self) -> None:
        code = (
            "def handle(event):\n"
            "    if event == 'click':\n"
            "        process_click()\n"
            "    else:\n"
            "        pass\n"
        )
        report = self.detector.scan_source(code, filename="handler.py")
        empty_branches = report.by_kind("empty-branch")
        self.assertEqual(len(empty_branches), 1)
        self.assertIn("else", empty_branches[0].name)

    def test_all_export_exclusion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            f1 = root / "api.py"
            f1.write_text(
                "__all__ = ['public_api_function', 'PublicClass']\n\n"
                "def public_api_function():\n"
                "    return True\n\n"
                "class PublicClass:\n"
                "    pass\n",
                encoding="utf-8",
            )
            report = self.detector.scan_project(root)
            dead_names = [
                item.name for item in report.items if item.kind in ("function", "class")
            ]
            self.assertNotIn("public_api_function", dead_names)
            self.assertNotIn("PublicClass", dead_names)

    def test_decorator_exclusion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            f1 = root / "routes.py"
            f1.write_text(
                "def route(path):\n"
                "    return lambda f: f\n\n"
                "@route('/home')\n"
                "def home_endpoint():\n"
                "    return 'Home'\n",
                encoding="utf-8",
            )
            report = self.detector.scan_project(root)
            dead_names = [item.name for item in report.items if item.kind == "function"]
            self.assertNotIn("home_endpoint", dead_names)

    def test_used_across_files_not_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            f1 = root / "util.py"
            f1.write_text(
                "def shared_tool():\n    return 100\n",
                encoding="utf-8",
            )
            f2 = root / "service.py"
            f2.write_text(
                "from util import shared_tool\nresult = shared_tool()\n",
                encoding="utf-8",
            )
            report = self.detector.scan_project(root)
            dead_names = [item.name for item in report.items if item.kind == "function"]
            self.assertNotIn("shared_tool", dead_names)


if __name__ == "__main__":
    unittest.main()
