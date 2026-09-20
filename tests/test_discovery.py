"""Unit tests for pycleaner.discovery."""

import tempfile
import unittest
from pathlib import Path

from pycleaner.discovery import (
    collect_project_python_files,
    is_ignored_directory,
    is_protected_file,
)


class TestDiscovery(unittest.TestCase):
    def test_is_ignored_directory(self) -> None:
        self.assertTrue(is_ignored_directory(".venv"))
        self.assertTrue(is_ignored_directory("venv"))
        self.assertTrue(is_ignored_directory("env"))
        self.assertTrue(is_ignored_directory(".env"))
        self.assertTrue(is_ignored_directory("__pycache__"))
        self.assertTrue(is_ignored_directory(".git"))
        self.assertTrue(is_ignored_directory("site-packages"))
        self.assertTrue(is_ignored_directory("ballpython.egg-info"))
        self.assertFalse(is_ignored_directory("pycleaner"))
        self.assertFalse(is_ignored_directory("src"))
        self.assertFalse(is_ignored_directory("tests"))

    def test_is_protected_file(self) -> None:
        self.assertTrue(is_protected_file(".env"))
        self.assertTrue(is_protected_file(".env.production"))
        self.assertTrue(is_protected_file("secrets.json"))
        self.assertTrue(is_protected_file("credentials.yml"))
        self.assertTrue(is_protected_file("server.key"))
        self.assertTrue(is_protected_file("cert.pem"))
        self.assertTrue(is_protected_file("poetry.lock"))
        self.assertTrue(is_protected_file("uv.lock"))
        self.assertTrue(is_protected_file("package-lock.json"))
        self.assertFalse(is_protected_file("main.py"))
        self.assertFalse(is_protected_file("utils.py"))

    def test_collect_project_python_files_skips_venv_and_caches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            # Create legitimate python files
            (root / "app.py").write_text("x = 1\n", encoding="utf-8")
            pkg_dir = root / "mypkg"
            pkg_dir.mkdir()
            (pkg_dir / "mod.py").write_text("y = 2\n", encoding="utf-8")

            # Create files in .venv, venv, and __pycache__
            venv_dir = root / ".venv" / "Lib" / "site-packages"
            venv_dir.mkdir(parents=True)
            (venv_dir / "ignored.py").write_text("z = 3\n", encoding="utf-8")

            cache_dir = root / "__pycache__"
            cache_dir.mkdir()
            (cache_dir / "cached.py").write_text("c = 4\n", encoding="utf-8")

            # Create protected file with .py suffix
            (root / "my_secret_keys.py").write_text("k = 5\n", encoding="utf-8")

            discovered = collect_project_python_files(root)
            discovered_names = {f.name for f in discovered}

            self.assertIn("app.py", discovered_names)
            self.assertIn("mod.py", discovered_names)
            self.assertNotIn("ignored.py", discovered_names)
            self.assertNotIn("cached.py", discovered_names)
            self.assertNotIn("my_secret_keys.py", discovered_names)

    def test_collect_project_python_files_respects_gitignore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "included.py").write_text("a = 1\n", encoding="utf-8")
            (root / "scratch.py").write_text("b = 2\n", encoding="utf-8")

            generated_dir = root / "generated"
            generated_dir.mkdir()
            (generated_dir / "gen.py").write_text("c = 3\n", encoding="utf-8")

            (root / ".gitignore").write_text(
                "scratch.py\ngenerated/\n",
                encoding="utf-8",
            )

            discovered = collect_project_python_files(root, respect_gitignore=True)
            discovered_names = {f.name for f in discovered}

            self.assertIn("included.py", discovered_names)
            self.assertNotIn("scratch.py", discovered_names)
            self.assertNotIn("gen.py", discovered_names)


if __name__ == "__main__":
    unittest.main()
