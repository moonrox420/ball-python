from __future__ import annotations

from pathlib import Path

from pycleaner.cache import (
    ContentAddressableCache,
    extract_file_dependencies,
)
from pycleaner.pipeline import CleanPipeline, PipelineOptions


def test_content_addressable_cache_basics(tmp_path: Path) -> None:
    db_file = tmp_path / "test_cache.db"
    cache = ContentAddressableCache(db_path=db_file)
    assert db_file.exists()

    source = "def foo():\n    return 42\n"
    target = tmp_path / "foo.py"
    target.write_text(source, encoding="utf-8")

    # Initial get should be miss
    assert cache.get(target, source) is None

    pipeline = CleanPipeline(
        options=PipelineOptions(enable_cache=True, cache_db_path=str(db_file))
    )
    res1 = pipeline.process_file(target, apply_changes=False)

    # Cache should now have the entry
    cached_res = cache.get(target, source)
    assert cached_res is not None
    assert cached_res.cleaned_code == res1.cleaned_code
    assert cached_res.is_valid_python == res1.is_valid_python

    # Second pipeline run should hit cache
    res2 = pipeline.process_file(target, apply_changes=False)
    assert res2.cleaned_code == res1.cleaned_code

    # Changing file content should miss cache
    modified_source = "def foo():\n    return 99\n"
    assert cache.get(target, modified_source) is None

    # Invalidation
    cache.invalidate(target)
    assert cache.get(target, source) is None


def test_provenance_ledger(tmp_path: Path) -> None:
    db_file = tmp_path / "provenance.db"
    cache = ContentAddressableCache(db_path=db_file)

    cache.record_provenance(
        file_path=tmp_path / "calc.py",
        transformation_type="modernize",
        verification_tier="TIER_A_PROVEN",
        seed=1337,
        diff="--- a/calc.py\n+++ b/calc.py\n@@ -1 +1 @@\n-x = 1\n+x: int = 1",
    )

    records = cache.get_provenance(limit=10)
    assert len(records) == 1
    assert records[0]["transformation_type"] == "modernize"
    assert records[0]["verification_tier"] == "TIER_A_PROVEN"
    assert records[0]["seed"] == 1337
    assert "calc.py" in records[0]["file_path"]


def test_dependency_extraction() -> None:
    source = """
import os
import sys as system
from pathlib import Path
from math import sqrt, ceil
"""
    deps = extract_file_dependencies(source)
    assert deps == ["math", "os", "pathlib", "sys"]
