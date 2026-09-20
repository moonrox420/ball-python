"""
pycleaner.baseline
==================

Technical Debt Ratchet and Baseline Management Engine.

Enables incremental adoption of PyCleaner on legacy codebases by snapshotting
existing diagnostic violations into `.pycleaner/baseline.json`. Future CI/CD
checks ensure that existing technical debt can only decrease, never increase.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class BaselineFingerprint:
    rule: str
    file: str
    line: int
    symbol: str

    def to_hash(self) -> str:
        raw = f"{self.rule}:{self.file}:{self.line}:{self.symbol}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "file": self.file,
            "line": self.line,
            "symbol": self.symbol,
            "hash": self.to_hash(),
        }


class BaselineManager:
    """Manages baseline generation, loading, and ratchet comparison."""

    def __init__(self, baseline_path: Path | str = ".pycleaner/baseline.json") -> None:
        self.baseline_path = Path(baseline_path)

    def load_fingerprints(self) -> set[str]:
        """Loads baseline issue hashes from disk."""
        if not self.baseline_path.exists():
            return set()
        try:
            data = json.loads(self.baseline_path.read_text(encoding="utf-8"))
            fingerprints = data.get("fingerprints", [])
            return {
                str(fp["hash"])
                for fp in fingerprints
                if isinstance(fp, dict) and fp.get("hash")
            }
        except json.JSONDecodeError:
            return set()

    def save_baseline(
        self,
        fingerprints: list[BaselineFingerprint],
        root_dir: Path,
    ) -> Path:
        """Serializes fingerprints to the baseline JSON file."""
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "root_dir": str(root_dir.resolve()),
            "issue_count": len(fingerprints),
            "fingerprints": [fp.to_dict() for fp in fingerprints],
        }
        self.baseline_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return self.baseline_path

    @staticmethod
    def create_fingerprint(
        rule: str,
        file_path: Path | str,
        line: int,
        symbol: str,
        root_dir: Path | None = None,
    ) -> BaselineFingerprint:
        """Constructs a deterministic fingerprint with normalized relative path."""
        p = Path(file_path)
        if root_dir is not None:
            try:
                rel = str(p.resolve().relative_to(root_dir.resolve())).replace(
                    "\\", "/"
                )
            except ValueError:
                rel = p.name
        else:
            rel = p.name

        return BaselineFingerprint(
            rule=rule,
            file=rel,
            line=line,
            symbol=symbol,
        )

    def filter_new_issues(
        self,
        issues: list[BaselineFingerprint],
    ) -> tuple[list[BaselineFingerprint], list[BaselineFingerprint]]:
        """
        Separates issues into (tolerated_baseline_issues, new_debt_issues).
        Returns:
            (tolerated, new_debt)
        """
        known_hashes = self.load_fingerprints()
        tolerated: list[BaselineFingerprint] = []
        new_debt: list[BaselineFingerprint] = []

        for issue in issues:
            if issue.to_hash() in known_hashes:
                tolerated.append(issue)
            else:
                new_debt.append(issue)

        return tolerated, new_debt
