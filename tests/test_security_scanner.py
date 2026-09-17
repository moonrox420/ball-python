"""Tests for pycleaner.security_scanner module."""

from __future__ import annotations

import textwrap
from pathlib import Path

from pycleaner.security_scanner import SecurityReport, SecurityScanner


class TestSecurityScanner:
    """Test suite for static security vulnerability detection."""

    def test_eval_exec_detection(self) -> None:
        source = textwrap.dedent("""
            def run_user_input(code_str):
                eval(code_str)
                exec(code_str)
                compile(code_str, "<string>", "exec")
        """)
        scanner = SecurityScanner()
        report = scanner.scan_source(source, filename="unsafe_run.py")

        categories = [f.category for f in report.findings]
        assert "dangerous-eval" in categories
        assert "dangerous-exec" in categories
        assert "dangerous-compile" in categories

        eval_finding = next(
            f for f in report.findings if f.category == "dangerous-eval"
        )
        assert eval_finding.severity == "CRITICAL"
        assert eval_finding.lineno == 3

    def test_hardcoded_secrets_detection(self) -> None:
        source = textwrap.dedent("""
            AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
            API_KEY = "sk-live-12345678901234567890"
            password = "supersecretpassword123"
        """)
        scanner = SecurityScanner()
        report = scanner.scan_source(source, filename="production_config.py")

        categories = [f.category for f in report.findings]
        assert categories.count("hardcoded-secret") >= 2
        messages = [f.message for f in report.findings]
        assert any("AWS Access Key" in m for m in messages)
        assert any("Generic Password" in m or "Generic API Key" in m for m in messages)

    def test_sql_injection_detection(self) -> None:
        source = textwrap.dedent("""
            def get_user_fstring(cursor, user_id):
                cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

            def get_user_concat(cursor, user_id):
                cursor.execute("SELECT * FROM users WHERE id = " + user_id)

            def get_user_format(cursor, user_id):
                cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))

            def get_user_percent(cursor, user_id):
                cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
        """)
        scanner = SecurityScanner()
        report = scanner.scan_source(source, filename="database_ops.py")

        sql_findings = [f for f in report.findings if f.category == "sql-injection"]
        assert len(sql_findings) == 4
        assert all(f.severity == "CRITICAL" for f in sql_findings)

    def test_shell_true_detection(self) -> None:
        source = textwrap.dedent("""
            import subprocess

            def execute_cmd(cmd):
                subprocess.run(cmd, shell=True)
                subprocess.call(cmd, shell=True)
                subprocess.Popen(cmd, shell=True)
        """)
        scanner = SecurityScanner()
        report = scanner.scan_source(source, filename="commands.py")

        shell_findings = [f for f in report.findings if f.category == "shell-injection"]
        assert len(shell_findings) == 3
        assert all(f.severity == "HIGH" for f in shell_findings)

    def test_verify_false_detection(self) -> None:
        source = textwrap.dedent("""
            import requests
            import httpx

            def fetch_insecure():
                requests.get("https://internal.service", verify=False)
                httpx.post("https://internal.service/api", verify=False)
        """)
        scanner = SecurityScanner()
        report = scanner.scan_source(source, filename="client.py")

        tls_findings = [f for f in report.findings if f.category == "insecure-tls"]
        assert len(tls_findings) == 2
        assert all(f.severity == "HIGH" for f in tls_findings)

    def test_insecure_deserialization_detection(self) -> None:
        source = textwrap.dedent("""
            import pickle
            import yaml

            def load_untrusted(data):
                obj1 = pickle.loads(data)
                obj2 = yaml.load(data)
        """)
        scanner = SecurityScanner()
        report = scanner.scan_source(source, filename="loader.py")

        deserial_findings = [
            f for f in report.findings if f.category == "insecure-deserialization"
        ]
        assert len(deserial_findings) == 2
        assert all(f.severity == "CRITICAL" for f in deserial_findings)

    def test_assert_in_production_detection(self) -> None:
        source = textwrap.dedent("""
            def transfer_funds(amount):
                assert amount > 0, "Amount must be positive"
                return amount
        """)
        scanner = SecurityScanner()
        report = scanner.scan_source(source, filename="billing.py")

        assert_findings = [
            f for f in report.findings if f.category == "assert-in-production"
        ]
        assert len(assert_findings) == 1
        assert assert_findings[0].severity == "LOW"

    def test_false_positive_resistance(self) -> None:
        source = textwrap.dedent("""
            import subprocess
            import requests
            import yaml

            def safe_database_query(cursor, user_id):
                cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
                cursor.executemany("INSERT INTO audit VALUES (?)", [(1,), (2,)])

            def safe_subprocess(cmd_args):
                subprocess.run(["python", "-m", "pytest"])

            def safe_requests():
                requests.get("https://example.com")

            def safe_yaml(data):
                yaml.safe_load(data)
                yaml.load(data, Loader=yaml.SafeLoader)
        """)
        scanner = SecurityScanner(severity_threshold="LOW", ignore_rules=set())
        report = scanner.scan_source(source, filename="safe_patterns.py")

        dangerous_categories = {
            "sql-injection",
            "shell-injection",
            "insecure-tls",
            "insecure-deserialization",
        }
        flagged = [f for f in report.findings if f.category in dangerous_categories]
        assert len(flagged) == 0

    def test_severity_threshold_filter(self) -> None:
        source = textwrap.dedent("""
            def test_fn():
                eval("1+1")  # CRITICAL
                assert 1 == 1  # LOW
        """)
        scanner_high = SecurityScanner(severity_threshold="HIGH")
        report_high = scanner_high.scan_source(source, filename="test_filter.py")
        severities = {f.severity for f in report_high.findings}
        assert severities.issubset({"CRITICAL", "HIGH"})
        categories = {f.category for f in report_high.findings}
        assert "dangerous-eval" in categories
        assert "assert-in-production" not in categories

    def test_ignored_rules(self) -> None:
        source = textwrap.dedent("""
            def test_fn():
                eval("1+1")  # CRITICAL
                assert 1 == 1  # LOW
        """)
        scanner_ignore = SecurityScanner(
            severity_threshold="LOW", ignore_rules={"dangerous-eval"}
        )
        report_ignore = scanner_ignore.scan_source(source, filename="test_filter.py")
        categories = {f.category for f in report_ignore.findings}
        assert "dangerous-eval" not in categories
        assert "assert-in-production" in categories

    def test_scan_project(self, tmp_path: Path) -> None:
        file1 = tmp_path / "unsafe.py"
        file1.write_text("import pickle\npickle.loads(b'data')\n", encoding="utf-8")

        file2 = tmp_path / "safe.py"
        file2.write_text("print('clean')\n", encoding="utf-8")

        scanner = SecurityScanner()
        report = scanner.scan_project(tmp_path)

        assert report.files_scanned >= 2
        assert report.critical_count == 1
        assert report.findings[0].category == "insecure-deserialization"

    def test_security_report_by_category(self) -> None:
        report = SecurityReport(findings=[])
        assert len(report.by_category("dangerous-eval")) == 0
