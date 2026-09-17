"""Tests for pycleaner.taint_engine module."""

from __future__ import annotations

import textwrap
from pathlib import Path

from pycleaner.taint_engine import TaintEngine


class TestTaintEngine:
    """Test suite for interprocedural SAST dataflow taint analysis."""

    def test_direct_command_injection(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            import os

            def run_cmd():
                user_cmd = input("Enter command: ")
                os.system(user_cmd)
        """)
        f = tmp_path / "vuln_cmd.py"
        f.write_text(code, encoding="utf-8")

        engine = TaintEngine()
        report = engine.scan_path(f)

        assert report.count == 1
        finding = report.findings[0]
        assert finding.sink_type == "COMMAND_INJECTION"
        assert finding.sink_call == "os.system"
        assert finding.severity == "CRITICAL"
        assert "input" in finding.source_desc

    def test_fstring_propagation(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            import os

            def execute_ping():
                target_host = input()
                ping_cmd = f"ping -c 1 {target_host}"
                os.system(ping_cmd)
        """)
        f = tmp_path / "vuln_fstring.py"
        f.write_text(code, encoding="utf-8")

        engine = TaintEngine()
        report = engine.scan_path(f)

        assert report.count == 1
        finding = report.findings[0]
        assert finding.sink_type == "COMMAND_INJECTION"
        assert any("ping_cmd =" in step for step in finding.propagation_path)

    def test_sanitizer_neutralizes_taint(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            import os

            def run_safe():
                user_val = input()
                safe_int = int(user_val)
                os.system(f"process_id {safe_int}")
        """)
        f = tmp_path / "safe_cmd.py"
        f.write_text(code, encoding="utf-8")

        engine = TaintEngine()
        report = engine.scan_path(f)

        assert report.count == 0

    def test_sql_injection_concatenation(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            import sqlite3

            def fetch_user(cursor):
                user_id = input()
                query = "SELECT * FROM users WHERE id = " + user_id
                cursor.execute(query)
        """)
        f = tmp_path / "vuln_sql.py"
        f.write_text(code, encoding="utf-8")

        engine = TaintEngine()
        report = engine.scan_path(f)

        assert report.count == 1
        finding = report.findings[0]
        assert finding.sink_type == "SQL_INJECTION"
        assert finding.sink_call == "cursor.execute"
        assert finding.severity == "CRITICAL"

    def test_path_traversal(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            def read_user_file():
                filename = input()
                with open(filename) as f:
                    return f.read()
        """)
        f = tmp_path / "vuln_path.py"
        f.write_text(code, encoding="utf-8")

        engine = TaintEngine()
        report = engine.scan_path(f)

        assert report.count == 1
        finding = report.findings[0]
        assert finding.sink_type == "PATH_TRAVERSAL"
        assert finding.sink_call == "open"

    def test_interprocedural_return_taint(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            import os

            def get_untrusted_input():
                return input()

            def run_task():
                cmd = get_untrusted_input()
                os.system(cmd)
        """)
        f = tmp_path / "interproc.py"
        f.write_text(code, encoding="utf-8")

        engine = TaintEngine()
        report = engine.scan_path(f)

        assert report.count == 1
        finding = report.findings[0]
        assert finding.sink_type == "COMMAND_INJECTION"
        assert "get_untrusted_input()" in finding.source_desc
