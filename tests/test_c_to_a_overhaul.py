import os
import stat
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from pycleaner.cli import main
from pycleaner.dead_code_detector import DeadCodeDetector
from pycleaner.pipeline import CleanPipeline
from pycleaner.security_scanner import SecurityScanner, is_secret_literal
from pycleaner.syntax_healer import SyntaxHealer


class TestCToAOverhaul(unittest.TestCase):
    """
    Verification tests for the 7-point C- to A- overhaul.
    """

    def test_1_dead_code_pruning_protects_secrets_and_protected_names(self) -> None:
        """Item 1: Dead-code pruning must NEVER delete or underscore-prefix planted secrets."""
        dummy_aws = "AKIA" + "1234567890123456"
        dummy_ghp = "ghp_" + "123456789012345678901234567890"
        dummy_stripe = f"{'sk'}_{'live'}_1234567890123456789012345"
        dummy_sg = "SG." + "1234567890123456789012.1234567890123456789012"
        dummy_dsn = "postgres://user:secretpass@localhost:5432/mydb"
        dummy_stripe_test = f"{'sk'}_{'test'}_98765432109876543210"

        source = (
            f"AWS_KEY = '{dummy_aws}'\n"
            f"GITHUB_TOKEN = '{dummy_ghp}'\n"
            f"STRIPE_KEY = '{dummy_stripe}'\n"
            f"SENDGRID = '{dummy_sg}'\n"
            f"DSN = '{dummy_dsn}'\n"
            "unused_var = 42\n"
            "def worker():\n"
            f"    API_KEY = '{dummy_stripe_test}'\n"
            "    local_unused = 99\n"
            "    return 1\n"
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            f = Path(tmp_dir) / "secrets.py"
            f.write_text(source, encoding="utf-8")

            detector = DeadCodeDetector()
            detector.fix_file(f)

            fixed_content = f.read_text(encoding="utf-8")
            # Secrets must be preserved exactly
            self.assertIn(f"AWS_KEY = '{dummy_aws}'", fixed_content)
            self.assertIn(
                f"GITHUB_TOKEN = '{dummy_ghp}'", fixed_content
            )
            self.assertIn(
                f"STRIPE_KEY = '{dummy_stripe}'", fixed_content
            )
            self.assertIn(
                f"SENDGRID = '{dummy_sg}'",
                fixed_content,
            )
            self.assertIn(
                f"DSN = '{dummy_dsn}'", fixed_content
            )
            self.assertIn(f"API_KEY = '{dummy_stripe_test}'", fixed_content)

            # Never rename them to _AWS_KEY or prune them
            self.assertNotIn("_AWS_KEY", fixed_content)
            self.assertNotIn("_STRIPE_KEY", fixed_content)

            # Normal unused vars should be pruned or underscore-prefixed
            self.assertNotIn("unused_var = 42", fixed_content)

    def test_2_secret_patterns_gap_closing(self) -> None:
        """Item 2: Stripe, SendGrid, credentialed DSN, and relaxed GitHub tokens are detected."""
        stripe_live = f"{'sk'}_{'live'}_51Abcdefghijklmnopqrstuvwx"
        sendgrid_key = "SG." + "abcdefghijklmnopqrstuv.1234567890abcdefghij12"
        postgres_dsn = "postgres://admin:supersecret@db.production.internal:5432/prod"
        github_token = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123"

        self.assertTrue(is_secret_literal(stripe_live))
        self.assertTrue(is_secret_literal(sendgrid_key))
        self.assertTrue(is_secret_literal(postgres_dsn))
        self.assertTrue(is_secret_literal(github_token))

        code = (
            f"stripe = '{stripe_live}'\n"
            f"sg = '{sendgrid_key}'\n"
            f"db = '{postgres_dsn}'\n"
            f"gh = '{github_token}'\n"
        )
        scanner = SecurityScanner(severity_threshold="HIGH")
        report = scanner.scan_source(code, filename="test_secrets.py")

        messages = {f.message for f in report.findings}
        self.assertTrue(any("Stripe Secret Key" in m for m in messages))
        self.assertTrue(any("SendGrid API Key" in m for m in messages))
        self.assertTrue(any("Credentialed Database URL" in m for m in messages))
        self.assertTrue(any("GitHub Token" in m for m in messages))

    def test_3_dangerous_calls_first_class_during_fix(self) -> None:
        """Item 3: Dangerous calls survive fix intact and cause fix command to report findings and exit 1."""
        code = (
            "import os\n"
            "import pickle\n"
            "def handle(data):\n"
            "    os.system(data)\n"
            "    obj = pickle.loads(data)\n"
            "    eval(data)\n"
            "    return obj\n"
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            f = Path(tmp_dir) / "dangerous.py"
            f.write_text(code, encoding="utf-8")

            buf = StringIO()
            with patch("sys.stdout", buf):
                exit_code = main(["fix", str(f)])

            # Must exit with 1 because critical/high security issues remain unresolved
            self.assertEqual(exit_code, 1)

            # File must still have the dangerous calls intact (no silent deletion)
            content = f.read_text(encoding="utf-8")
            self.assertIn("os.system(data)", content)
            self.assertIn("pickle.loads(data)", content)
            self.assertIn("eval(data)", content)

            output = buf.getvalue()
            self.assertIn("Unresolved Security Findings", output)
            self.assertIn("os.system()", output)
            self.assertIn("eval()", output)
            self.assertIn("pickle.loads()", output)

    def test_4_partial_syntax_repair_unbalanced_brackets_and_colons(self) -> None:
        """Item 4: Partial repair instead of total abort on unbalanced brackets."""
        # Unbalanced bracket: extra closing parenthesis that cannot compile
        code = (
            "def calculate(x)\n"
            "    unbalanced = 1 + 2)\n"
            "    return x\n"
            "\n"
            "def format_data(val)\n"
            "    return val * 2\n"
        )
        healer = SyntaxHealer()
        result = healer.heal(code, filename="partial.py")

        # Result is invalid Python because of unbalanced ')', but colons must be repaired
        self.assertFalse(result.is_valid)
        self.assertTrue(len(result.repairs) >= 1)
        self.assertIn(
            "Appended missing ':' to 2 compound statement header(s)", result.repairs
        )
        self.assertIn("def calculate(x):", result.code)
        self.assertIn("def format_data(val):", result.code)

        # In pipeline, partial repairs must be saved to disk
        with tempfile.TemporaryDirectory() as tmp_dir:
            f = Path(tmp_dir) / "broken.py"
            f.write_text(code, encoding="utf-8")

            pipeline = CleanPipeline()
            res = pipeline.process_file(f, apply_changes=True)

            self.assertTrue(res.changed)
            saved = f.read_text(encoding="utf-8")
            self.assertIn("def calculate(x):", saved)
            self.assertIn("def format_data(val):", saved)

    def test_5_graceful_handling_of_read_only_files(self) -> None:
        """Item 5: Graceful handling of read-only files without unhandled PermissionError crash."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            normal_file = folder / "normal.py"
            normal_file.write_text(
                "def needs_colon(x)\n    return x\n", encoding="utf-8"
            )

            readonly_file = folder / "readonly.py"
            readonly_file.write_text(
                "def broken_ro(y)\n    return y\n", encoding="utf-8"
            )
            # Make readonly_file read-only
            os.chmod(readonly_file, stat.S_IREAD)

            try:
                buf = StringIO()
                with patch("sys.stdout", buf):
                    main(["fix", str(folder)])

                # The process must not crash; normal file should be fixed
                self.assertIn(
                    "def needs_colon(x):", normal_file.read_text(encoding="utf-8")
                )
                output = buf.getvalue()
                # Should mention permission or error for readonly_file
                self.assertTrue(
                    "Permission denied" in output or "ERROR in readonly.py" in output
                )
            finally:
                # Restore write permissions so temporary directory can be cleaned up
                os.chmod(readonly_file, stat.S_IWRITE | stat.S_IREAD)

    def test_6_check_mode_never_claims_updated_when_zero_bytes_changed(self) -> None:
        """Item 6: 'check' must never claim 'updated' and must state '0 written'."""
        code = "def needs_colon(x)\n    return x\n"
        with tempfile.TemporaryDirectory() as tmp_dir:
            f = Path(tmp_dir) / "check_test.py"
            f.write_text(code, encoding="utf-8")

            buf = StringIO()
            with patch("sys.stdout", buf):
                exit_code = main(["check", str(f)])

            self.assertEqual(exit_code, 1)
            output = buf.getvalue()

            # Must state would change, 0 written, and never use 'updated'
            self.assertIn("1 would change", output)
            self.assertIn("0 written", output)
            self.assertNotIn("updated", output)

            # Verify zero bytes changed
            self.assertEqual(f.read_text(encoding="utf-8"), code)

    def test_7_scope_hygiene_only_scans_asked_file(self) -> None:
        """Item 7: Scope hygiene - explicit file argument does not scan sibling files."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            clean_target = folder / "clean_target.py"
            clean_target.write_text(
                "def greet(name: str) -> str:\n    return f'Hello {name}'\n",
                encoding="utf-8",
            )

            sibling_poison = folder / "sibling_poison.py"
            sibling_poison.write_text(
                "eval('os.system(\"rm -rf /\")')\n", encoding="utf-8"
            )

            # Scan ONLY clean_target.py
            buf = StringIO()
            with patch("sys.stdout", buf):
                exit_code = main(["scan", str(clean_target)])

            # clean_target has zero security issues, so exit code MUST be 0!
            self.assertEqual(exit_code, 0)
            output = buf.getvalue()
            self.assertNotIn("sibling_poison.py", output)
            self.assertIn("No security issues detected", output)

    def test_8_colon_healer_idempotent_and_no_double_colon_regression(self) -> None:
        """Item 8: Colon healer must be idempotent and never introduce double colons (::)."""
        healer = SyntaxHealer()

        # 1. Code already containing colons must remain unchanged across multiple passes
        code = (
            "def bad_function(x):\n"
            "    if x == 0:\n"
            "        return 1\n"
            "class BrokenClass:\n"
            "    def method(self):\n"
            "        pass\n"
        )
        for _ in range(5):
            res = healer.heal(code)
            self.assertTrue(res.is_valid)
            self.assertNotIn("::", res.code)
            self.assertEqual(res.code, code)

        # 2. Existing double colons must be healed to single colons
        doubled_code = (
            "def bad_function(x)::\n"
            "    if x == 0::\n"
            "        return 1\n"
            "class BrokenClass::\n"
            "    def method(self)::\n"
            "        pass\n"
        )
        res_healed = healer.heal(doubled_code)
        self.assertTrue(res_healed.is_valid)
        self.assertNotIn("::", res_healed.code)
        self.assertIn("def bad_function(x):", res_healed.code)
        self.assertIn("if x == 0:", res_healed.code)
        self.assertIn("class BrokenClass:", res_healed.code)

        # 3. Headers with trailing spaces/comments must not get duplicate colons
        spaced_headers = (
            "def bad_function(x):  \n    if x == 0: # check zero\n        pass\n"
        )
        res_spaced = healer.heal(spaced_headers)
        self.assertNotIn("::", res_spaced.code)

    def test_9_dangerous_calls_surfaced_as_critical_on_valid_and_broken_files(
        self,
    ) -> None:
        """Item 9: eval, os.system, pickle.loads, and yaml.load/unsafe_load must be CRITICAL."""
        scanner = SecurityScanner()

        # Valid file
        valid_source = (
            "import os, pickle, yaml\n"
            "def run(payload):\n"
            "    eval(payload)\n"
            "    os.system(payload)\n"
            "    pickle.loads(payload)\n"
            "    yaml.unsafe_load(payload)\n"
            "    yaml.load(payload)\n"
        )
        rep1 = scanner.scan_source(valid_source, filename="valid_dangerous.py")
        crit_messages1 = {f.message: f.severity for f in rep1.findings}
        self.assertEqual(
            crit_messages1.get("eval() executes arbitrary Python code"), "CRITICAL"
        )
        self.assertEqual(
            crit_messages1.get(
                "os.system() passes commands through the shell and is vulnerable to injection"
            ),
            "CRITICAL",
        )
        self.assertEqual(
            crit_messages1.get(
                "pickle.loads() deserializes arbitrary objects and can execute arbitrary code"
            ),
            "CRITICAL",
        )
        self.assertEqual(
            crit_messages1.get(
                "yaml.unsafe_load() can execute arbitrary Python objects"
            ),
            "CRITICAL",
        )
        self.assertEqual(
            crit_messages1.get(
                "yaml.load() without SafeLoader can execute arbitrary Python objects"
            ),
            "CRITICAL",
        )

        # Syntax-broken file (AST cannot parse)
        broken_source = (
            "def broken_syntax(\n"
            "    eval(payload)\n"
            "    os.system(payload)\n"
            "    pickle.loads(payload)\n"
            "    yaml.unsafe_load(payload)\n"
            "    yaml.load(payload)\n"
        )
        rep2 = scanner.scan_source(broken_source, filename="broken_dangerous.py")
        crit_messages2 = {f.message: f.severity for f in rep2.findings}
        self.assertEqual(
            crit_messages2.get("eval() executes arbitrary Python code"), "CRITICAL"
        )
        self.assertEqual(
            crit_messages2.get(
                "os.system() passes commands through the shell and is vulnerable to injection"
            ),
            "CRITICAL",
        )
        self.assertEqual(
            crit_messages2.get(
                "pickle.loads() deserializes arbitrary objects and can execute arbitrary code"
            ),
            "CRITICAL",
        )
        self.assertEqual(
            crit_messages2.get(
                "yaml.unsafe_load() can execute arbitrary Python objects"
            ),
            "CRITICAL",
        )
        self.assertEqual(
            crit_messages2.get(
                "yaml.load() without SafeLoader can execute arbitrary Python objects"
            ),
            "CRITICAL",
        )

    def test_10_partial_success_reported_accurately_in_cli_summary(self) -> None:
        """Item 10: Accurate partial success reporting: 'Summary: 1 inspected, 1 partially updated, 1 remaining error'."""
        code = (
            "def partially_repaired():\n"
            '    print "legacy print repaired"\n'
            "    def def class 12345\n"
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            f = Path(tmp_dir) / "partial_test.py"
            f.write_text(code, encoding="utf-8")

            buf = StringIO()
            with patch("sys.stdout", buf):
                exit_code = main(["fix", str(f)])

            # Non-zero exit code due to remaining error
            self.assertEqual(exit_code, 1)

            output = buf.getvalue()
            # Must explicitly report partial success in summary
            self.assertIn("1 inspected", output)
            self.assertIn("1 partially updated", output)
            self.assertIn("1 remaining error", output)
            self.assertNotIn("0 updated", output)

            # And the legitimate repair (print -> print()) was written to disk
            saved_content = f.read_text(encoding="utf-8")
            self.assertIn('print("legacy print repaired")', saved_content)


if __name__ == "__main__":
    unittest.main()
