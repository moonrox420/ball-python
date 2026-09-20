"""Integration tests for pycleaner CLI."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from pycleaner.cli import main


class TestCLI(unittest.TestCase):
    def test_fix_all_whole_folder_one_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)

            # 1. Broken syntax file (missing colon on def, one-liner on else)
            file1 = folder / "file1.py"
            file1.write_text(
                "def compute(a, b)\n    if a > b: return a\n    else: return b\n",
                encoding="utf-8",
            )

            # 2. Missing import + unused import
            file2 = folder / "file2.py"
            file2.write_text(
                "import math\n\ndef fetch():\n    return Path('.')\n",
                encoding="utf-8",
            )

            # 3. Third-party dependency needing requirements.txt sync
            file3 = folder / "file3.py"
            file3.write_text(
                "import yaml\n\ndef parse_data(s):\n    return yaml.safe_load(s)\n",
                encoding="utf-8",
            )

            reqs = folder / "requirements.txt"
            reqs.write_text("old-unused-package==1.0.0\n", encoding="utf-8")

            # Run pycleaner with -a / --all on the whole folder
            exit_code = main(["-a", str(folder)])
            self.assertEqual(exit_code, 0)

            # 1. Verify file1 syntax was healed without breaking the one-liner
            c1 = file1.read_text(encoding="utf-8")
            self.assertIn("def compute(a, b):", c1)
            self.assertNotIn("else: return b:", c1)
            self.assertIn("return b", c1)

            # 2. Verify file2 missing import added and unused import pruned
            c2 = file2.read_text(encoding="utf-8")
            self.assertIn("from pathlib import Path", c2)
            self.assertNotIn("import math", c2)

            # 3. Verify requirements.txt synchronized with missing dependency and pruned unused
            req_content = reqs.read_text(encoding="utf-8")
            self.assertIn("PyYAML", req_content)
            self.assertNotIn("old-unused-package", req_content)

    def test_subcommand_check_mode_exit_code_1_on_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            f = folder / "unformatted.py"
            f.write_text("def needs_colon(x)\n    return x\n", encoding="utf-8")

            # In check mode without writing, exit code must be 1 because modifications are needed
            exit_code = main(["check", str(folder)])
            self.assertEqual(exit_code, 1)

            # Verify file was NOT modified in check mode
            self.assertEqual(
                f.read_text(encoding="utf-8"), "def needs_colon(x)\n    return x\n"
            )

    def test_config_error_returns_exit_code_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            pyproject = folder / "pyproject.toml"
            pyproject.write_text("invalid [[ toml syntax", encoding="utf-8")

            exit_code = main(["fix", str(folder)])
            self.assertEqual(exit_code, 2)

    def test_subcommand_scan_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            f = folder / "clean.py"
            f.write_text(
                "def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8"
            )

            exit_code = main(["scan", str(folder)])
            self.assertEqual(exit_code, 0)

    def test_subcommand_scan_critical_finding_exit_code_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            f = folder / "unsafe.py"
            f.write_text(
                "eval('import os; os.system(\"rm -rf /\")')\n", encoding="utf-8"
            )

            exit_code = main(["scan", str(folder)])
            self.assertEqual(exit_code, 1)

    def test_subcommand_complexity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            f = folder / "simple.py"
            f.write_text("def simple_fn():\n    return 42\n", encoding="utf-8")

            exit_code = main(["complexity", str(folder)])
            self.assertEqual(exit_code, 0)

    def test_subcommand_dead_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            f = folder / "unused.py"
            f.write_text("def _unused_private():\n    pass\n", encoding="utf-8")

            exit_code = main(["dead-code", str(folder)])
            self.assertEqual(exit_code, 0)

    def test_subcommand_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            f = folder / "script.py"
            f.write_text("import sys\nprint(sys.version)\n", encoding="utf-8")

            exit_code = main(["audit", str(folder)])
            self.assertEqual(exit_code, 0)

    def test_subcommand_hook(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            exit_code = main(["hook"])
        output = stdout_buf.getvalue()

        self.assertEqual(exit_code, 0)
        self.assertIn("repos:", output)
        self.assertIn("id: pycleaner", output)

    def test_subcommand_all(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            f = folder / "good.py"
            f.write_text("def ok():\n    return 1\n", encoding="utf-8")

            exit_code = main(["all", str(folder)])
            self.assertEqual(exit_code, 0)

    def test_progress_bar_rich_multi_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            for i in range(5):
                f = folder / f"file_{i}.py"
                f.write_text(f"def func_{i}():\n    return {i}\n", encoding="utf-8")

            exit_code = main(["fix", str(folder)])
            self.assertEqual(exit_code, 0)

    def test_json_output_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            f = folder / "test_script.py"
            f.write_text("eval('1+1')\n", encoding="utf-8")

            # Scan JSON
            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf):
                exit_code = main(["scan", "--json", str(folder)])
            self.assertEqual(exit_code, 1)
            scan_data = json.loads(stdout_buf.getvalue())
            self.assertIsInstance(scan_data, list)
            self.assertTrue(
                any(item["category"] == "dangerous-eval" for item in scan_data)
            )

            # Dead-code JSON
            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf):
                main(["dead-code", "--json", str(folder)])
            dead_data = json.loads(stdout_buf.getvalue())
            self.assertIsInstance(dead_data, list)

            # Complexity JSON
            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf):
                main(["complexity", "--json", str(folder)])
            comp_data = json.loads(stdout_buf.getvalue())
            self.assertIsInstance(comp_data, list)

            # Hook JSON
            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf):
                main(["hook", "--json"])
            hook_data = json.loads(stdout_buf.getvalue())
            self.assertEqual(hook_data["status"], "ok")

    def test_check_with_diff_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            f = folder / "needs_fix.py"
            f.write_text("def missing_colon()\n    return 10\n", encoding="utf-8")

            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf):
                exit_code = main(["check", "--diff", str(folder)])
            self.assertEqual(exit_code, 1)
            output = stdout_buf.getvalue()
            self.assertIn("def missing_colon():", output)

    def test_flat_flags_backward_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            f = folder / "clean_script.py"
            f.write_text("import sys\n\nprint(sys.version)\n", encoding="utf-8")

            # Flat --deps-only
            exit_code = main(["--deps-only", str(folder)])
            self.assertEqual(exit_code, 0)

            # Flat --check --diff on clean file
            exit_code = main(["--check", "--diff", str(folder)])
            self.assertEqual(exit_code, 0)

    def test_parallel_flag_in_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            for i in range(3):
                f = folder / f"pfile_{i}.py"
                f.write_text(f"def foo_{i}()\n    return {i}\n", encoding="utf-8")

            exit_code = main(["fix", "--parallel", "--workers", "2", str(folder)])
            self.assertEqual(exit_code, 0)
            for i in range(3):
                content = (folder / f"pfile_{i}.py").read_text(encoding="utf-8")
                self.assertIn(f"def foo_{i}():", content)

    def test_cli_types_subcommand(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            f = folder / "bad_type.py"
            f.write_text(
                "def get_number() -> int:\n    return 'not_a_number'\n",
                encoding="utf-8",
            )

            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf):
                exit_code = main(["types", "--json", str(folder)])
            self.assertEqual(exit_code, 1)
            data = json.loads(stdout_buf.getvalue())
            self.assertTrue(len(data) >= 1)
            self.assertEqual(data[0]["expected"], "int")
            self.assertEqual(data[0]["actual"], "str")

    def test_cli_taint_subcommand(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            f = folder / "taint_cmd.py"
            f.write_text(
                "import os\n\ndef run():\n    cmd = input()\n    os.system(cmd)\n",
                encoding="utf-8",
            )

            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf):
                exit_code = main(["taint", "--json", str(folder)])
            self.assertEqual(exit_code, 1)
            data = json.loads(stdout_buf.getvalue())
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["sink_type"], "COMMAND_INJECTION")

    def test_cli_test_gen_subcommand(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            f = folder / "service.py"
            f.write_text(
                "def process_text(text: str) -> str:\n    return text.strip()\n",
                encoding="utf-8",
            )

            out_dir = folder / "generated"
            exit_code = main(["test-gen", "--output-dir", str(out_dir), str(folder)])
            self.assertEqual(exit_code, 0)
            self.assertTrue((out_dir / "test_service_generated.py").is_file())

    def test_cli_ultimate_subcommand(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            f = folder / "clean_module.py"
            f.write_text(
                "def double(n: int) -> int:\n    return n * 2\n", encoding="utf-8"
            )

            exit_code = main(["ultimate", str(folder)])
            self.assertEqual(exit_code, 0)

    def test_config_flag_explicit_file_is_honored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            target = folder / "custom.py"
            target.write_text("def needs_colon(x)\n    return x\n", encoding="utf-8")
            skip_me = folder / "skipme.py"
            skip_me.write_text("def needs_colon(y)\n    return y\n", encoding="utf-8")
            explicit = folder / "explicit.toml"
            explicit.write_text('exclude = ["skipme.py"]\n', encoding="utf-8")

            exit_code = main(["--config", str(explicit), "fix", str(folder)])
            self.assertEqual(exit_code, 0)
            self.assertIn("def needs_colon(x):", target.read_text(encoding="utf-8"))
            self.assertEqual(
                skip_me.read_text(encoding="utf-8"),
                "def needs_colon(y)\n    return y\n",
            )

    def test_config_flag_check_mode_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            target = folder / "unformatted.py"
            original = "def needs_colon(x)\n    return x\n"
            target.write_text(original, encoding="utf-8")
            explicit = folder / "explicit.toml"
            explicit.write_text("backup = false\n", encoding="utf-8")

            exit_code = main(["--config", str(explicit), "check", str(folder)])
            self.assertEqual(exit_code, 1)
            self.assertEqual(target.read_text(encoding="utf-8"), original)

    def test_config_flag_missing_file_exits_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            exit_code = main(
                ["--config", str(folder / "absent.toml"), "check", str(folder)]
            )
            self.assertEqual(exit_code, 2)

    def test_config_flag_unknown_key_exits_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            explicit = folder / "bad.toml"
            explicit.write_text("line-lenght = 88\n", encoding="utf-8")
            exit_code = main(["--config", str(explicit), "check", str(folder)])
            self.assertEqual(exit_code, 2)

    def test_subcommand_hook_shows_python_type_and_repo_url(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            exit_code = main(["hook"])
        output = stdout_buf.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("types: [python]", output)
        self.assertIn("https://github.com/moonrox420/ball-python", output)

    def test_default_invocation_runs_fix_not_ultimate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            target = folder / "app.py"
            target.write_text("def run(x)\n    return x\n", encoding="utf-8")

            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf):
                exit_code = main([str(folder)])
            output = stdout_buf.getvalue()

            self.assertEqual(exit_code, 0)
            self.assertIn("def run(x):", target.read_text(encoding="utf-8"))
            # Must NOT invoke 6-phase analytical ultimate runner
            self.assertNotIn("Full Spectrum Analysis & Healing", output)
            self.assertNotIn("Phase 2: Project Dependency Audit", output)


if __name__ == "__main__":
    unittest.main()
