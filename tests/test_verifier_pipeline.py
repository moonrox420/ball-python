from __future__ import annotations

from pathlib import Path

from pycleaner.pipeline import CleanPipeline, PipelineOptions
from pycleaner.verifier import VerificationTier


def test_pipeline_with_prove_on_sound_code(tmp_path: Path) -> None:
    source = "def add_nums(a: int, b: int) -> int:\n    return a + b\n    dead_call()\n"
    test_file = tmp_path / "sound.py"
    test_file.write_text(source, encoding="utf-8")

    pipeline = CleanPipeline(
        options=PipelineOptions(
            verify_proofs=True,
            proof_iterations=10,
            proof_seed=42,
            enable_dead_code_pruning=True,
        )
    )
    result = pipeline.process_file(test_file, apply_changes=True)

    assert result.is_valid_python
    assert result.verification_tier == VerificationTier.TIER_A_PROVEN
    assert len(result.proof_receipts) > 0
    assert len(result.refused_changes) == 0
    assert result.changed is True
    # The file should have been updated on disk
    updated_disk = test_file.read_text(encoding="utf-8")
    assert "dead_call()" not in updated_disk
    assert "return a + b" in updated_disk


def test_pipeline_refusal_and_rollback_on_unsound_divergence(tmp_path: Path) -> None:
    source = """def is_nonnegative(n: int) -> bool:
    if n >= 0:
        return True
    return False
"""
    test_file = tmp_path / "divergent.py"
    test_file.write_text(source, encoding="utf-8")

    pipeline = CleanPipeline(
        options=PipelineOptions(
            verify_proofs=True,
            proof_iterations=20,
            proof_seed=42,
        )
    )

    flawed_code = """def is_nonnegative(n: int) -> bool:
    if n > 0:
        return True
    return False
"""
    receipt = pipeline.verifier.verify_transformation(
        str(test_file), source, flawed_code, "is_nonnegative"
    )
    assert receipt.tier == VerificationTier.TIER_C_REFUSED
    assert receipt.counterexample is not None
    assert 0 in receipt.counterexample.arguments


def test_pipeline_no_changes_tier_is_none(tmp_path: Path) -> None:
    clean_code = "def square(x: int) -> int:\n    return x * x\n"
    test_file = tmp_path / "already_clean.py"
    test_file.write_text(clean_code, encoding="utf-8")

    pipeline = CleanPipeline(
        options=PipelineOptions(
            verify_proofs=True,
            proof_iterations=5,
            enable_formatting=False,
            enable_lint_fixing=False,
            enable_modernizer=False,
            enable_dead_code_pruning=False,
            enable_syntax_healing=False,
            enable_import_resolution=False,
        )
    )
    result = pipeline.process_file(test_file, apply_changes=True)

    assert result.changed is False
    assert result.verification_tier is None
    assert test_file.read_text(encoding="utf-8") == clean_code
