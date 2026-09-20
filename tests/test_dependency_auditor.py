"""Unit tests for DependencyAuditor."""

import tempfile
import unittest
from pathlib import Path

from pycleaner.dependency_auditor import DependencyAuditor


class TestDependencyAuditor(unittest.TestCase):
    def test_dependency_auditor_detects_missing_and_unused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            code_file = tmp_path / "app.py"
            code_file.write_text(
                "import os\n"
                "import requests\n"
                "import yaml\n"
                "\n"
                "def run():\n"
                "    return os.getcwd()\n",
                encoding="utf-8",
            )

            req_file = tmp_path / "requirements.txt"
            # Declares requests and unused package 'click', but misses PyYAML
            req_file.write_text(
                "requests>=2.28.0\nclick==8.1.0\n",
                encoding="utf-8",
            )

            auditor = DependencyAuditor(tmp_path)
            report = auditor.audit(fix=False)

            # requests is used and declared
            # PyYAML is used (via yaml) but missing from requirements.txt
            self.assertIn("PyYAML", report.missing_packages)
            # click is declared but never imported
            self.assertTrue(any("click" in u for u in report.unused_packages))

    def test_dependency_auditor_fixes_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            code_file = tmp_path / "main.py"
            code_file.write_text(
                "import httpx\n",
                encoding="utf-8",
            )

            req_file = tmp_path / "requirements.txt"
            req_file.write_text("old-unused-pkg\n", encoding="utf-8")

            auditor = DependencyAuditor(tmp_path)
            report = auditor.audit(fix=True, prune_unused=True)

            self.assertTrue(report.fixed_requirements)
            updated_reqs = req_file.read_text(encoding="utf-8")
            self.assertIn("httpx", updated_reqs)
            self.assertNotIn("old-unused-pkg", updated_reqs)

    def test_nmap_maps_to_python_nmap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            code_file = tmp_path / "scanner.py"
            code_file.write_text("import nmap\n", encoding="utf-8")

            req_file = tmp_path / "requirements.txt"
            req_file.write_text("python-nmap\n", encoding="utf-8")

            auditor = DependencyAuditor(tmp_path)
            report = auditor.audit(fix=False)

            self.assertNotIn("nmap", report.missing_packages)
            self.assertNotIn("python-nmap", report.missing_packages)
            self.assertEqual(len(report.unused_packages), 0)

    def test_local_workspace_module_never_added_to_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            # Pretend the workspace root is named "cipher_snark"
            proj_dir = tmp_path / "cipher_snark"
            proj_dir.mkdir()

            code_file = proj_dir / "main.py"
            code_file.write_text(
                "from cipher_snark.gui import App\n",
                encoding="utf-8",
            )
            gui_file = proj_dir / "gui.py"
            gui_file.write_text("class App: pass\n", encoding="utf-8")

            req_file = proj_dir / "requirements.txt"
            req_file.write_text("requests\n", encoding="utf-8")

            auditor = DependencyAuditor(proj_dir)
            report = auditor.audit(fix=True)

            self.assertNotIn("cipher_snark", report.missing_packages)
            updated_reqs = req_file.read_text(encoding="utf-8")
            self.assertNotIn("cipher_snark", updated_reqs)


if __name__ == "__main__":
    unittest.main()
