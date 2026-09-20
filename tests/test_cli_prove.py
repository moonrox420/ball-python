from __future__ import annotations

import json
from pathlib import Path
import pytest

from pycleaner.cli import main


def test_cli_prove_subcommand_clean_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    test_file = tmp_path / "app.py"
    test_file.write_text("def mul(a: int, b: int) -> int:\n    return a * b\n", encoding="utf-8")
    report_file = tmp_path / "report.json"

    rc = main(["prove", str(test_file), "--output-json", str(report_file), "--proof-iterations", "5"])
    assert rc == 0
    assert report_file.exists()
    data = json.loads(report_file.read_text(encoding="utf-8"))
    assert data["total_inspected"] == 1
    assert data["refused_tier_c_callables"] == 0


def test_cli_prove_subcommand_with_sound_transformation(tmp_path: Path) -> None:
    # Code with an unreachable statement that gets pruned and verified
    test_file = tmp_path / "sound.py"
    test_file.write_text(
        "def compute(x: int) -> int:\n    return x + 1\n    dead_call()\n",
        encoding="utf-8",
    )
    report_file = tmp_path / "report.json"

    rc = main([
        "prove",
        str(test_file),
        "--output-json",
        str(report_file),
        "--proof-iterations",
        "5",
        "--diff",
    ])
    assert rc == 0
    assert report_file.exists()
    data = json.loads(report_file.read_text(encoding="utf-8"))
    assert data["proven_tier_a_callables"] >= 1
    assert data["refused_tier_c_callables"] == 0


def test_cli_check_with_prove_flag(tmp_path: Path) -> None:
    test_file = tmp_path / "check_mod.py"
    test_file.write_text("def sub(a: int, b: int) -> int:\n    return a - b\n", encoding="utf-8")
    report_file = tmp_path / "check_report.json"

    rc = main(["check", str(test_file), "--prove", "--output-json", str(report_file), "--proof-iterations", "5"])
    assert rc == 0
    assert report_file.exists()
