import pytest
from pycleaner.verifier import (
    IsolatedDifferentialVerifier,
    VerificationTier,
)


def test_verifier_tier_a_on_behavior_preserving_transformation() -> None:
    original = """
def compute(x: int, y: int) -> int:
    unused_var = 100
    if x > 0:
        return x + y
    return y
"""
    transformed = """
def compute(x: int, y: int) -> int:
    if x > 0:
        return x + y
    return y
"""
    verifier = IsolatedDifferentialVerifier(iterations=15, timeout_seconds=1.0, base_seed=42)
    receipt = verifier.verify_transformation("math_mod.py", original, transformed, "compute")

    assert receipt.tier == VerificationTier.TIER_A_PROVEN
    assert receipt.iterations_run == 15
    assert receipt.counterexample is None


def test_verifier_tier_c_refused_on_semantic_divergence() -> None:
    original = """
def is_positive(x: int) -> bool:
    if x >= 0:
        return True
    return False
"""
    # Flawed transformation: altered condition from >= 0 to > 0 (breaks x == 0)
    flawed = """
def is_positive(x: int) -> bool:
    if x > 0:
        return True
    return False
"""
    verifier = IsolatedDifferentialVerifier(iterations=30, timeout_seconds=1.0, base_seed=42)
    receipt = verifier.verify_transformation("logic.py", original, flawed, "is_positive")

    assert receipt.tier == VerificationTier.TIER_C_REFUSED
    assert receipt.counterexample is not None
    assert receipt.counterexample.callable_name == "is_positive"
    # The counterexample must demonstrate the exact divergent case: x == 0
    assert 0 in receipt.counterexample.arguments
    assert receipt.counterexample.original_result == "True"
    assert receipt.counterexample.transformed_result == "False"


def test_verifier_tier_b_on_unresolvable_callable() -> None:
    original = "x = 10\ny = 20"
    transformed = "x = 10\ny = 25"
    verifier = IsolatedDifferentialVerifier(iterations=5, timeout_seconds=0.5)
    receipt = verifier.verify_transformation("script.py", original, transformed, "non_existent")

    assert receipt.tier == VerificationTier.TIER_B_SUGGESTED
    assert "could not be isolated" in receipt.reason
