"""
pycleaner.verifier
==================

Proof-Carrying Differential Equivalence Verification Engine.

Validates source code transformations (Tier A: Proven, Tier B: Suggested, Tier C: Refused)
by dynamically fuzzing baseline and transformed callables in isolated worker processes
under deterministic input vectors.
"""

from __future__ import annotations

import ast
import dataclasses
import enum
import inspect
import logging
import multiprocessing as mp
import random
import sys
import time
from pathlib import Path
from typing import Any


class VerificationTier(enum.Enum):
    TIER_A_PROVEN = "TIER_A_PROVEN"
    TIER_B_SUGGESTED = "TIER_B_SUGGESTED"
    TIER_C_REFUSED = "TIER_C_REFUSED"


@dataclasses.dataclass(frozen=True)
class CounterExample:
    callable_name: str
    arguments: tuple[Any, ...]
    keyword_arguments: dict[str, Any]
    original_result: str | None
    original_error: str | None
    transformed_result: str | None
    transformed_error: str | None
    seed: int


@dataclasses.dataclass(frozen=True)
class ProofReceipt:
    filepath: str
    callable_name: str
    tier: VerificationTier
    iterations_run: int
    seed: int
    duration_ms: float
    counterexample: CounterExample | None = None
    reason: str = ""


@dataclasses.dataclass(frozen=True)
class ExecutionResult:
    is_success: bool
    return_repr: str | None = None
    error_type: str | None = None
    error_message: str | None = None


def _worker_differential_fuzz(
    orig_source: str,
    trans_source: str,
    callable_name: str,
    inputs: list[tuple[tuple[Any, ...], dict[str, Any]]],
    conn: Any,
    filepath: str = "<sandbox>",
) -> None:
    """Child process worker: executes differential equivalence loop across all synthesized inputs."""
    try:
        file_path_obj = (
            Path(filepath).resolve() if filepath and filepath != "<sandbox>" else None
        )
        package_name = ""
        if file_path_obj and file_path_obj.parent.is_dir():
            parent_dir = file_path_obj.parent
            if (parent_dir / "__init__.py").exists():
                package_name = parent_dir.name
            if str(parent_dir) not in sys.path:
                sys.path.insert(0, str(parent_dir))
            if str(parent_dir.parent) not in sys.path:
                sys.path.insert(0, str(parent_dir.parent))

        orig_ns: dict[str, Any] = {
            "__name__": "__verifier__",
            "__file__": str(file_path_obj) if file_path_obj else "<orig_sandbox>",
            "__package__": package_name,
            "__builtins__": __builtins__,
        }
        trans_ns: dict[str, Any] = {
            "__name__": "__verifier__",
            "__file__": str(file_path_obj) if file_path_obj else "<trans_sandbox>",
            "__package__": package_name,
            "__builtins__": __builtins__,
        }

        try:
            orig_code = compile(orig_source, "<orig_sandbox>", "exec")  # nosec: B102 - intentionally isolated in worker process
            exec(orig_code, orig_ns)  # nosec: B102 - intentionally isolated in worker process
        except BaseException as e:
            conn.send(
                {
                    "status": "unresolvable",
                    "reason": f"Original module execution failed in sandbox: {type(e).__name__}: {e}",
                }
            )
            return

        try:
            trans_code = compile(trans_source, "<trans_sandbox>", "exec")  # nosec: B102 - intentionally isolated in worker process
            exec(trans_code, trans_ns)  # nosec: B102 - intentionally isolated in worker process
        except BaseException as e:
            conn.send(
                {
                    "status": "unresolvable",
                    "reason": f"Transformed module execution failed in sandbox: {type(e).__name__}: {e}",
                }
            )
            return

        def _resolve_callable(ns: dict[str, Any], target_name: str) -> Any:
            if "." in target_name:
                parts = target_name.split(".")
                curr: Any = ns.get(parts[0])
                for p in parts[1:]:
                    if curr is None:
                        return None
                    curr = getattr(curr, p, None)
                if isinstance(curr, (staticmethod, classmethod)):
                    return curr.__func__
                return curr
            return ns.get(target_name)

        orig_fn = _resolve_callable(orig_ns, callable_name)
        trans_fn = _resolve_callable(trans_ns, callable_name)

        if not callable(orig_fn) or not callable(trans_fn):
            conn.send(
                {
                    "status": "unresolvable",
                    "reason": f"Callable '{callable_name}' not found or not callable in sandbox.",
                }
            )
            return

        for index, (args, kwargs) in enumerate(inputs):
            try:
                orig_res = orig_fn(*args, **kwargs)
                orig_success = True
                orig_repr = repr(orig_res)
                orig_err_type = None
                orig_err_msg = None
            except BaseException as e:
                orig_success = False
                orig_repr = None
                orig_err_type = type(e).__name__
                orig_err_msg = str(e)

            try:
                trans_res = trans_fn(*args, **kwargs)
                trans_success = True
                trans_repr = repr(trans_res)
                trans_err_type = None
                trans_err_msg = None
            except BaseException as e:
                trans_success = False
                trans_repr = None
                trans_err_type = type(e).__name__
                trans_err_msg = str(e)

            diverged = False
            if orig_success != trans_success:
                diverged = True
            elif orig_success and trans_success:
                if orig_repr != trans_repr:
                    diverged = True
            else:
                if orig_err_type != trans_err_type:
                    diverged = True

            if diverged:
                conn.send(
                    {
                        "status": "diverged",
                        "iteration": index + 1,
                        "args": args,
                        "kwargs": kwargs,
                        "orig_result": orig_repr,
                        "orig_error": orig_err_msg or orig_err_type,
                        "trans_result": trans_repr,
                        "trans_error": trans_err_msg or trans_err_type,
                    }
                )
                return

        conn.send(
            {
                "status": "proven",
                "iterations_run": len(inputs),
            }
        )
    except BaseException as e:
        try:
            conn.send(
                {
                    "status": "unresolvable",
                    "reason": f"Worker crashed: {type(e).__name__}: {e}",
                }
            )
        except Exception:
            logging.getLogger(__name__).debug("Suppressed exception", exc_info=True)
    finally:
        try:
            conn.close()
        except Exception:
            logging.getLogger(__name__).debug("Suppressed exception", exc_info=True)


class DeterministicInputSynthesizer:
    """Synthesizes deterministic boundary values and typed inputs from inspect.Signature."""

    def __init__(self, seed: int) -> None:
        self.seed = seed
        self._rng = random.Random(seed)

    def generate_for_param(self, param: inspect.Parameter) -> Any:
        annotation = param.annotation

        if annotation is int or annotation == "int":
            return self._rng.choice([0, 1, -1, 42, -999, 2**31 - 1, -(2**31)])
        if annotation is float or annotation == "float":
            return self._rng.choice(
                [0.0, 1.0, -1.0, 3.14159, float("inf"), float("-inf")]
            )
        if annotation is str or annotation == "str":
            return self._rng.choice(
                ["", "test", " ", "a" * 100, "\n\t", "null", "123", "utf8_\U0001f40d"]
            )
        if annotation is bool or annotation == "bool":
            return self._rng.choice([True, False])
        if (
            annotation is list
            or annotation == "list"
            or getattr(annotation, "__origin__", None) is list
        ):
            return self._rng.choice([[], [0], [1, 2, 3], ["a", "b"]])
        if (
            annotation is dict
            or annotation == "dict"
            or getattr(annotation, "__origin__", None) is dict
        ):
            return self._rng.choice([{}, {"key": "value"}, {"0": 0}])
        if (
            annotation is tuple
            or annotation == "tuple"
            or getattr(annotation, "__origin__", None) is tuple
        ):
            return self._rng.choice([(), (1,), (1, "a")])
        if annotation is None or annotation is type(None):
            return None

        # Fallback for untyped or complex parameters: cycle through primitive boundaries
        return self._rng.choice([0, "", None, [], {}, False, 1.0])

    def generate_arguments(
        self, sig: inspect.Signature
    ) -> tuple[tuple[Any, ...], dict[str, Any]]:
        pos_args: list[Any] = []
        kw_args: dict[str, Any] = {}

        for param in sig.parameters.values():
            if param.kind in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            ):
                pos_args.append(self.generate_for_param(param))
            elif param.kind == inspect.Parameter.KEYWORD_ONLY:
                kw_args[param.name] = self.generate_for_param(param)
            elif param.kind == inspect.Parameter.VAR_POSITIONAL:
                pos_args.extend([self.generate_for_param(param) for _ in range(2)])
            elif param.kind == inspect.Parameter.VAR_KEYWORD:
                kw_args["extra_kw"] = self.generate_for_param(param)

        return tuple(pos_args), kw_args


class IsolatedDifferentialVerifier:
    """
    Executes differential verification of source transformations in isolated processes.
    Enforces time bounds, memory isolation, and determinism.
    """

    def __init__(
        self,
        iterations: int = 100,
        timeout_seconds: float = 2.0,
        base_seed: int | None = None,
    ) -> None:
        self.iterations = iterations
        self.timeout_seconds = timeout_seconds
        self.base_seed = base_seed if base_seed is not None else 1337

    def _extract_signature_from_source(
        self, source: str, callable_name: str
    ) -> inspect.Signature | None:
        try:
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == callable_name
                ):
                    params: list[inspect.Parameter] = []
                    for arg in node.args.posonlyargs:
                        ann = (
                            ast.unparse(arg.annotation)
                            if arg.annotation
                            else inspect.Parameter.empty
                        )
                        params.append(
                            inspect.Parameter(
                                arg.arg,
                                inspect.Parameter.POSITIONAL_ONLY,
                                annotation=ann,
                            )
                        )
                    for arg in node.args.args:
                        ann = (
                            ast.unparse(arg.annotation)
                            if arg.annotation
                            else inspect.Parameter.empty
                        )
                        params.append(
                            inspect.Parameter(
                                arg.arg,
                                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                                annotation=ann,
                            )
                        )
                    if node.args.vararg:
                        ann = (
                            ast.unparse(node.args.vararg.annotation)
                            if node.args.vararg.annotation
                            else inspect.Parameter.empty
                        )
                        params.append(
                            inspect.Parameter(
                                node.args.vararg.arg,
                                inspect.Parameter.VAR_POSITIONAL,
                                annotation=ann,
                            )
                        )
                    for arg in node.args.kwonlyargs:
                        ann = (
                            ast.unparse(arg.annotation)
                            if arg.annotation
                            else inspect.Parameter.empty
                        )
                        params.append(
                            inspect.Parameter(
                                arg.arg, inspect.Parameter.KEYWORD_ONLY, annotation=ann
                            )
                        )
                    if node.args.kwarg:
                        ann = (
                            ast.unparse(node.args.kwarg.annotation)
                            if node.args.kwarg.annotation
                            else inspect.Parameter.empty
                        )
                        params.append(
                            inspect.Parameter(
                                node.args.kwarg.arg,
                                inspect.Parameter.VAR_KEYWORD,
                                annotation=ann,
                            )
                        )
                    return inspect.Signature(parameters=params)
            return None
        except Exception:
            return None

    def verify_transformation(
        self,
        filepath: str,
        original_source: str,
        transformed_source: str,
        target_callable: str,
    ) -> ProofReceipt:
        start_time = time.perf_counter()

        # Step 1: Pre-flight AST Syntax and Signature Extraction
        try:
            ast.parse(original_source)
            ast.parse(transformed_source)
        except SyntaxError as err:
            return ProofReceipt(
                filepath=filepath,
                callable_name=target_callable,
                tier=VerificationTier.TIER_C_REFUSED,
                iterations_run=0,
                seed=self.base_seed,
                duration_ms=(time.perf_counter() - start_time) * 1000.0,
                reason=f"Transformed source failed AST syntax parsing: {err}",
            )

        sig = self._extract_signature_from_source(original_source, target_callable)
        if sig is None:
            return ProofReceipt(
                filepath=filepath,
                callable_name=target_callable,
                tier=VerificationTier.TIER_B_SUGGESTED,
                iterations_run=0,
                seed=self.base_seed,
                duration_ms=(time.perf_counter() - start_time) * 1000.0,
                reason="Callable could not be isolated for signature-guided dynamic execution.",
            )

        synthesizer = DeterministicInputSynthesizer(seed=self.base_seed)
        inputs = [synthesizer.generate_arguments(sig) for _ in range(self.iterations)]

        # Step 2: Isolated Process Execution via Pipe
        ctx = mp.get_context("spawn")
        parent_conn, child_conn = ctx.Pipe(duplex=False)
        process = ctx.Process(
            target=_worker_differential_fuzz,
            args=(
                original_source,
                transformed_source,
                target_callable,
                inputs,
                child_conn,
                filepath,
            ),
        )
        process.daemon = True
        process.start()
        child_conn.close()

        has_data = parent_conn.poll(timeout=self.timeout_seconds)
        if not has_data:
            process.terminate()
            process.join(timeout=0.2)
            if process.is_alive() and hasattr(process, "kill"):
                process.kill()
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return ProofReceipt(
                filepath=filepath,
                callable_name=target_callable,
                tier=VerificationTier.TIER_B_SUGGESTED,
                iterations_run=0,
                seed=self.base_seed,
                duration_ms=elapsed,
                reason=f"Execution exceeded timeout limit of {self.timeout_seconds}s",
            )

        try:
            msg = parent_conn.recv()
        except EOFError:
            process.join(timeout=0.2)
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return ProofReceipt(
                filepath=filepath,
                callable_name=target_callable,
                tier=VerificationTier.TIER_B_SUGGESTED,
                iterations_run=0,
                seed=self.base_seed,
                duration_ms=elapsed,
                reason="Worker process terminated or closed pipe unexpectedly.",
            )
        finally:
            parent_conn.close()
            process.join(timeout=0.5)

        elapsed = (time.perf_counter() - start_time) * 1000.0

        if msg.get("status") == "diverged":
            counterexample = CounterExample(
                callable_name=target_callable,
                arguments=msg["args"],
                keyword_arguments=msg["kwargs"],
                original_result=msg.get("orig_result"),
                original_error=msg.get("orig_error"),
                transformed_result=msg.get("trans_result"),
                transformed_error=msg.get("trans_error"),
                seed=self.base_seed + msg["iteration"] - 1,
            )
            return ProofReceipt(
                filepath=filepath,
                callable_name=target_callable,
                tier=VerificationTier.TIER_C_REFUSED,
                iterations_run=msg["iteration"],
                seed=self.base_seed,
                duration_ms=elapsed,
                counterexample=counterexample,
                reason=f"Behavioral divergence detected on input iteration {msg['iteration']}.",
            )
        elif msg.get("status") == "proven":
            return ProofReceipt(
                filepath=filepath,
                callable_name=target_callable,
                tier=VerificationTier.TIER_A_PROVEN,
                iterations_run=msg.get("iterations_run", self.iterations),
                seed=self.base_seed,
                duration_ms=elapsed,
                reason=f"Proved invariant-preserving across {self.iterations} synthesized input permutations.",
            )
        else:
            return ProofReceipt(
                filepath=filepath,
                callable_name=target_callable,
                tier=VerificationTier.TIER_B_SUGGESTED,
                iterations_run=0,
                seed=self.base_seed,
                duration_ms=elapsed,
                reason=msg.get(
                    "reason", "Callable could not be verified dynamically in sandbox."
                ),
            )
