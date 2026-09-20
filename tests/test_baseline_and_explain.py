from __future__ import annotations

import json
from pathlib import Path
import pytest

from pycleaner.baseline import BaselineFingerprint, BaselineManager
from pycleaner.cli import main
from pycleaner.explanations import get_explanation, list_rules


def test_baseline_save_and_load(tmp_path: Path) -> None:
    baseline_file = tmp_path / "baseline.json"
    mgr = BaselineManager(baseline_file)

    fps = [
        BaselineFingerprint(rule="DC001", file="app.py", line=10, symbol="unused_x"),
        BaselineFingerprint(rule="SEC001", file="db.py", line=45, symbol="raw_query"),
    ]

    mgr.save_baseline(fps, tmp_path)
    assert baseline_file.exists()

    loaded_hashes = mgr.load_fingerprints()
    assert len(loaded_hashes) == 2
    for fp in fps:
        assert fp.to_hash() in loaded_hashes


def test_baseline_filter_new_debt(tmp_path: Path) -> None:
    baseline_file = tmp_path / "baseline.json"
    mgr = BaselineManager(baseline_file)

    old_issue = BaselineFingerprint(rule="DC001", file="app.py", line=10, symbol="unused_x")
    mgr.save_baseline([old_issue], tmp_path)

    new_issue = BaselineFingerprint(rule="SEC002", file="shell.py", line=5, symbol="popen")

    tolerated, new_debt = mgr.filter_new_issues([old_issue, new_issue])
    assert len(tolerated) == 1
    assert tolerated[0].rule == "DC001"
    assert len(new_debt) == 1
    assert new_debt[0].rule == "SEC002"


def test_explanations_catalog() -> None:
    rules = list_rules()
    assert len(rules) >= 10

    sec = get_explanation("SEC001")
    assert sec is not None
    assert sec.severity == "Critical"
    assert "SQL Injection" in sec.title

    prove = get_explanation("PROVE003")
    assert prove is not None
    assert prove.severity == "Critical"
    assert "Tier C" in prove.title

    assert get_explanation("NONEXISTENT_RULE_XYZ") is None


def test_cli_explain_command(capsys: pytest.CaptureFixture[str]) -> None:
    rc_list = main(["explain"])
    assert rc_list == 0

    rc_single = main(["explain", "PROVE001"])
    assert rc_single == 0

    rc_invalid = main(["explain", "DOES_NOT_EXIST"])
    assert rc_invalid == 1


def test_cli_baseline_command(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.py"
    test_file.write_text("def unused_fn():\n    pass\n", encoding="utf-8")
    baseline_out = tmp_path / "my_baseline.json"

    rc = main(["baseline", str(test_file), "--output", str(baseline_out)])
    assert rc == 0
    assert baseline_out.exists()

    data = json.loads(baseline_out.read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert "issue_count" in data
