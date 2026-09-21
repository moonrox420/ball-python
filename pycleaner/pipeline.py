"""
Cleanup pipeline coordinating syntax healing, code modernization, dead-code pruning,
import resolution, linting, and formatting.
"""

from __future__ import annotations

import ast
import difflib
import shutil
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pycleaner.cache import ContentAddressableCache
from pycleaner.dead_code_detector import DeadCodeFixer
from pycleaner.import_resolver import ImportResolver
from pycleaner.linter_formatter import LinterFormatter
from pycleaner.modernizer import Modernizer
from pycleaner.security_scanner import SecurityFinding, SecurityScanner
from pycleaner.syntax_healer import SyntaxHealer
from pycleaner.verifier import (
    CounterExample,
    IsolatedDifferentialVerifier,
    ProofReceipt,
    VerificationTier,
)

if TYPE_CHECKING:
    from pycleaner.config import PyCleanerConfig


@dataclass(slots=True)
class CleanResult:
    """Detailed result of cleaning a single Python file."""

    path: Path
    original_code: str
    cleaned_code: str
    changed: bool
    is_valid_python: bool
    syntax_repairs: list[str] = field(default_factory=list)
    modernize_transforms: list[str] = field(default_factory=list)
    dead_code_pruned: list[str] = field(default_factory=list)
    resolved_imports: list[str] = field(default_factory=list)
    unresolved_symbols: list[str] = field(default_factory=list)
    lint_changed: bool = False
    format_changed: bool = False
    error: str | None = None
    diagnostics: list[dict[str, str]] = field(default_factory=list)
    security_findings: list[SecurityFinding] = field(default_factory=list)
    proof_receipts: list[ProofReceipt] = field(default_factory=list)
    refused_changes: list[CounterExample] = field(default_factory=list)
    verification_tier: VerificationTier | None = None

    @property
    def diff(self) -> str:
        """Produce unified diff string comparing original and cleaned code."""
        if not self.changed:
            return ""
        orig_lines = self.original_code.splitlines(keepends=True)
        clean_lines = self.cleaned_code.splitlines(keepends=True)
        filename = str(self.path)
        diff_lines = difflib.unified_diff(
            orig_lines,
            clean_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )
        return "".join(diff_lines)


@dataclass(slots=True)
class PipelineOptions:
    """Configurable feature flags and mappings for CleanPipeline."""

    enable_syntax_healing: bool = True
    enable_modernizer: bool = True
    enable_dead_code_pruning: bool = True
    enable_import_resolution: bool = True
    enable_lint_fixing: bool = True
    enable_formatting: bool = True
    custom_import_map: dict[str, str] | None = None
    verify_proofs: bool = False
    proof_iterations: int = 50
    proof_seed: int | None = None
    enable_cache: bool = False
    cache_db_path: str = ".pycleaner/cache.db"


class CleanPipeline:
    """Orchestrates all static cleanup passes for Python source files."""

    def __init__(
        self,
        options: PipelineOptions | None = None,
        config: PyCleanerConfig | Any | None = None,
        **kwargs: Any,
    ) -> None:
        opts = options or PipelineOptions(
            enable_syntax_healing=kwargs.get("enable_syntax_healing", True),
            enable_modernizer=kwargs.get("enable_modernizer", True),
            enable_dead_code_pruning=kwargs.get("enable_dead_code_pruning", True),
            enable_import_resolution=kwargs.get("enable_import_resolution", True),
            enable_lint_fixing=kwargs.get("enable_lint_fixing", True),
            enable_formatting=kwargs.get("enable_formatting", True),
            custom_import_map=kwargs.get("custom_import_map"),
            verify_proofs=kwargs.get("verify_proofs", False),
            proof_iterations=kwargs.get("proof_iterations", 50),
            proof_seed=kwargs.get("proof_seed"),
            enable_cache=kwargs.get("enable_cache", False),
            cache_db_path=kwargs.get("cache_db_path", ".pycleaner/cache.db"),
        )
        self.enable_syntax_healing = opts.enable_syntax_healing
        self.enable_modernizer = opts.enable_modernizer
        self.enable_dead_code_pruning = opts.enable_dead_code_pruning
        self.enable_import_resolution = opts.enable_import_resolution
        self.enable_lint_fixing = opts.enable_lint_fixing
        self.enable_formatting = opts.enable_formatting
        self.verify_proofs = opts.verify_proofs
        self.proof_iterations = opts.proof_iterations
        self.proof_seed = opts.proof_seed
        self.enable_cache = opts.enable_cache
        self.cache = (
            ContentAddressableCache(opts.cache_db_path) if opts.enable_cache else None
        )
        self.config = config
        self.verifier = IsolatedDifferentialVerifier(
            iterations=self.proof_iterations,
            base_seed=self.proof_seed,
        )

        import_map = dict(opts.custom_import_map or {})
        custom_map = getattr(config, "custom_import_map", None)
        if custom_map:
            import_map.update(custom_map)

        self.syntax_healer = SyntaxHealer()
        self.modernizer = Modernizer()
        self.dead_code_fixer = DeadCodeFixer()
        self.import_resolver = ImportResolver(custom_import_map=import_map)
        self.linter_formatter = LinterFormatter()
        self.security_scanner = SecurityScanner(severity_threshold="HIGH")

    def _stage_heal(
        self, current_code: str, filename: str, syntax_repairs: list[str]
    ) -> tuple[str, str | None]:
        """Execute Stage 1: Syntax Healing."""
        if not self.enable_syntax_healing:
            return current_code, None

        heal_res = self.syntax_healer.heal(current_code, filename=filename)
        if heal_res.repairs:
            syntax_repairs.extend(heal_res.repairs)
            current_code = heal_res.code

        if not heal_res.is_valid:
            col_info = (
                f":{heal_res.error_offset}" if heal_res.error_offset is not None else ""
            )
            return (
                current_code,
                f"SyntaxError at line {heal_res.error_lineno}{col_info}: {heal_res.error_message}",
            )
        return current_code, None

    def _stage_modernize(
        self, current_code: str, filename: str, modernize_transforms: list[str]
    ) -> str:
        """Execute Stage 2: Code Modernization."""
        if not self.enable_modernizer:
            return current_code

        mod_res = self.modernizer.modernize(current_code, filename=filename)
        if mod_res.changed:
            modernize_transforms.extend(mod_res.transformations)
            return mod_res.code
        return current_code

    def _stage_dead_code(
        self, current_code: str, filename: str, dead_code_pruned: list[str]
    ) -> str:
        """Execute Stage 3: Dead Code Pruning."""
        if not self.enable_dead_code_pruning:
            return current_code

        dc_res = self.dead_code_fixer.fix(current_code, filename=filename)
        if dc_res.changed:
            dead_code_pruned.extend(dc_res.pruned_items)
            return dc_res.code
        return current_code

    def _stage_resolve_imports(
        self,
        current_code: str,
        filename: str,
        resolved_imports: list[str],
        unresolved_symbols: list[str],
        diagnostics: list[dict[str, str]],
    ) -> str:
        """Execute Stage 4: Missing Import Resolution."""
        if self.enable_import_resolution:
            import_res = self.import_resolver.resolve(current_code, filename=filename)
            if import_res.resolved_imports:
                resolved_imports.extend(import_res.resolved_imports)
                current_code = import_res.code
            if import_res.unresolved_symbols:
                unresolved_symbols.extend(import_res.unresolved_symbols)
            for d in import_res.diagnostics:
                diag_dict = d.to_dict()
                diag_dict["file"] = filename
                diagnostics.append(diag_dict)
        else:
            missing_syms = self.import_resolver.find_undefined(
                current_code, filename=filename
            )
            if missing_syms:
                unresolved_symbols.extend(missing_syms)
        return current_code

    def _stage_lint_format(
        self, current_code: str, filename: str
    ) -> tuple[str, bool, bool]:
        """Execute Stage 5: Lint Auto-fixing and Formatting."""
        if not (self.enable_lint_fixing or self.enable_formatting):
            return current_code, False, False

        lf_res = self.linter_formatter.fix_and_format(
            current_code,
            filename=filename,
            do_lint_fix=self.enable_lint_fixing,
            do_format=self.enable_formatting,
        )
        return lf_res.code, lf_res.lint_changed, lf_res.format_changed

    @staticmethod
    def _validate_syntax(
        current_code: str, filename: str, error_msg: str | None
    ) -> tuple[bool, str | None]:
        try:
            ast.parse(current_code, filename=filename)
            return True, error_msg
        except SyntaxError as err:
            msg = error_msg or f"SyntaxError at line {err.lineno}: {err.msg}"
            return False, msg

    def process_source(self, source: str, filename: str = "<stdin>") -> CleanResult:
        """Process in-memory Python source code through the pipeline."""
        current_code = source
        syntax_repairs: list[str] = []
        modernize_transforms: list[str] = []
        dead_code_pruned: list[str] = []
        resolved_imports: list[str] = []
        unresolved_symbols: list[str] = []
        lint_changed = False
        format_changed = False
        error_msg: str | None = None
        diagnostics: list[dict[str, str]] = []

        for _ in range(2):
            prev_code = current_code
            current_code, error_msg = self._stage_heal(
                current_code, filename, syntax_repairs
            )
            if error_msg is not None:
                break

            current_code = self._stage_modernize(
                current_code, filename, modernize_transforms
            )
            current_code = self._stage_dead_code(
                current_code, filename, dead_code_pruned
            )
            current_code = self._stage_resolve_imports(
                current_code,
                filename,
                resolved_imports,
                unresolved_symbols,
                diagnostics,
            )
            current_code, l_chg, f_chg = self._stage_lint_format(current_code, filename)
            lint_changed = lint_changed or l_chg
            format_changed = format_changed or f_chg
            if current_code == prev_code:
                break

        is_valid, final_error = self._validate_syntax(current_code, filename, error_msg)

        proof_receipts: list[ProofReceipt] = []
        refused_changes: list[CounterExample] = []
        verification_tier: VerificationTier | None = None

        if self.verify_proofs and current_code != source and is_valid:
            target_callables = self._find_modified_callables(source, current_code)
            if not target_callables:
                verification_tier = VerificationTier.TIER_B_SUGGESTED
            else:
                all_proven = True
                for func_name in target_callables:
                    receipt = self.verifier.verify_transformation(
                        filepath=filename,
                        original_source=source,
                        transformed_source=current_code,
                        target_callable=func_name,
                    )
                    proof_receipts.append(receipt)
                    if receipt.tier == VerificationTier.TIER_C_REFUSED:
                        all_proven = False
                        if receipt.counterexample:
                            refused_changes.append(receipt.counterexample)
                    elif receipt.tier != VerificationTier.TIER_A_PROVEN:
                        all_proven = False

                if refused_changes:
                    verification_tier = VerificationTier.TIER_C_REFUSED
                    # Absolute rollback guarantee on Tier C refusal
                    current_code = source
                elif all_proven and proof_receipts:
                    verification_tier = VerificationTier.TIER_A_PROVEN
                else:
                    verification_tier = VerificationTier.TIER_B_SUGGESTED

        # Scan for dangerous calls and security findings
        sec_report = self.security_scanner.scan_source(current_code, filename=filename)
        security_findings = list(sec_report.findings)
        for sf in security_findings:
            diagnostics.append(
                {
                    "file": filename,
                    "line": str(sf.lineno),
                    "severity": sf.severity,
                    "category": sf.category,
                    "message": sf.message,
                    "suggestion": sf.suggestion,
                }
            )

        return CleanResult(
            path=Path(filename),
            original_code=source,
            cleaned_code=current_code,
            changed=(current_code != source)
            and (verification_tier != VerificationTier.TIER_C_REFUSED),
            is_valid_python=is_valid,
            syntax_repairs=syntax_repairs,
            modernize_transforms=modernize_transforms,
            dead_code_pruned=dead_code_pruned,
            resolved_imports=resolved_imports,
            unresolved_symbols=unresolved_symbols,
            lint_changed=lint_changed,
            format_changed=format_changed,
            error=final_error,
            diagnostics=diagnostics,
            security_findings=security_findings,
            proof_receipts=proof_receipts,
            refused_changes=refused_changes,
            verification_tier=verification_tier,
        )

    @staticmethod
    def _find_modified_callables(orig_code: str, clean_code: str) -> list[str]:
        """Identify functions/methods whose AST has changed."""
        try:
            orig_tree = ast.parse(orig_code)
            clean_tree = ast.parse(clean_code)
        except SyntaxError:
            return []

        orig_funcs: dict[str, str] = {}
        for node in ast.walk(orig_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                orig_funcs[node.name] = ast.dump(node)

        modified: list[str] = []
        clean_funcs: list[str] = []
        for node in ast.walk(clean_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                clean_funcs.append(node.name)
                clean_dump = ast.dump(node)
                if node.name not in orig_funcs or orig_funcs[node.name] != clean_dump:
                    if node.name not in modified:
                        modified.append(node.name)

        if not modified and clean_funcs:
            return clean_funcs[:3]

        return modified

    def process_file(
        self,
        filepath: Path | str,
        apply_changes: bool = True,
        backup: bool = False,
    ) -> CleanResult:
        """Process a single file on disk and optionally write back updates."""
        path = Path(filepath).resolve()
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as err:
            return CleanResult(
                path=path,
                original_code="",
                cleaned_code="",
                changed=False,
                is_valid_python=False,
                error=f"Permission denied (read-only?): {err}",
            )

        if self.cache is not None:
            cached_result = self.cache.get(path, content)
            if cached_result is not None:
                can_apply_cached = (
                    apply_changes
                    and cached_result.changed
                    and (
                        cached_result.is_valid_python
                        or bool(cached_result.syntax_repairs)
                    )
                    and (
                        cached_result.verification_tier
                        != VerificationTier.TIER_C_REFUSED
                    )
                )
                if can_apply_cached:
                    if backup:
                        bak_path = path.with_name(path.name + ".pycleaner.bak")
                        try:
                            shutil.copy2(path, bak_path)
                        except OSError as err:
                            return CleanResult(
                                path=path,
                                original_code=content,
                                cleaned_code=content,
                                changed=False,
                                is_valid_python=cached_result.is_valid_python,
                                error=f"Permission denied creating backup (read-only?): {err}",
                            )
                    try:
                        path.write_text(cached_result.cleaned_code, encoding="utf-8")
                    except OSError as err:
                        return CleanResult(
                            path=path,
                            original_code=content,
                            cleaned_code=content,
                            changed=False,
                            is_valid_python=cached_result.is_valid_python,
                            error=f"Permission denied (read-only?): {err}",
                        )
                return cached_result

        result = self.process_source(content, filename=str(path))

        if self.cache is not None:
            self.cache.set(path, content, result)
            if result.changed and apply_changes:
                tier_label = (
                    result.verification_tier.value
                    if result.verification_tier
                    else "UNVERIFIED"
                )
                self.cache.record_provenance(
                    file_path=path,
                    transformation_type="clean",
                    verification_tier=tier_label,
                    seed=self.proof_seed,
                    diff=result.diff,
                )

        can_apply = (
            apply_changes
            and result.changed
            and (result.is_valid_python or bool(result.syntax_repairs))
            and (result.verification_tier != VerificationTier.TIER_C_REFUSED)
        )
        if can_apply:
            if backup:
                bak_path = path.with_name(path.name + ".pycleaner.bak")
                try:
                    shutil.copy2(path, bak_path)
                except OSError as err:
                    return CleanResult(
                        path=path,
                        original_code=content,
                        cleaned_code=content,
                        changed=False,
                        is_valid_python=result.is_valid_python,
                        error=f"Permission denied creating backup (read-only?): {err}",
                        syntax_repairs=result.syntax_repairs,
                        modernize_transforms=result.modernize_transforms,
                        dead_code_pruned=result.dead_code_pruned,
                        resolved_imports=result.resolved_imports,
                        unresolved_symbols=result.unresolved_symbols,
                        diagnostics=result.diagnostics,
                        security_findings=result.security_findings,
                    )
            try:
                path.write_text(result.cleaned_code, encoding="utf-8")
            except OSError as err:
                return CleanResult(
                    path=path,
                    original_code=content,
                    cleaned_code=content,
                    changed=False,
                    is_valid_python=result.is_valid_python,
                    error=f"Permission denied (read-only?): {err}",
                    syntax_repairs=result.syntax_repairs,
                    modernize_transforms=result.modernize_transforms,
                    dead_code_pruned=result.dead_code_pruned,
                    resolved_imports=result.resolved_imports,
                    unresolved_symbols=result.unresolved_symbols,
                    diagnostics=result.diagnostics,
                    security_findings=result.security_findings,
                )

        return result

    def process_files(
        self,
        filepaths: list[Path],
        apply_changes: bool = True,
        backup: bool = False,
        max_workers: int | None = None,
    ) -> list[CleanResult]:
        """Process multiple files, optionally in parallel."""
        if max_workers is not None and max_workers > 1 and len(filepaths) > 1:
            return self._process_parallel(filepaths, apply_changes, backup, max_workers)
        return [
            self.process_file(fp, apply_changes=apply_changes, backup=backup)
            for fp in filepaths
        ]

    @staticmethod
    def _collect_future_result(future: Any, fpath: Path) -> CleanResult:
        if future.cancelled():
            return CleanResult(
                path=fpath,
                original_code="",
                cleaned_code="",
                changed=False,
                is_valid_python=False,
                error="Processing error: Task was cancelled",
            )
        exc = future.exception()
        if exc is not None:
            return CleanResult(
                path=fpath,
                original_code="",
                cleaned_code="",
                changed=False,
                is_valid_python=False,
                error=f"Processing error: {exc}",
            )
        return future.result()

    def _process_parallel(
        self,
        filepaths: list[Path],
        apply_changes: bool,
        backup: bool,
        max_workers: int,
    ) -> list[CleanResult]:
        """Process files in parallel using ProcessPoolExecutor."""
        results: dict[Path, CleanResult] = {}
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            future_to_path = {
                executor.submit(
                    _process_file_standalone,
                    _StandaloneWorkerTask(
                        filepath=fp,
                        apply_changes=apply_changes,
                        backup=backup,
                        enable_syntax=self.enable_syntax_healing,
                        enable_modernize=self.enable_modernizer,
                        enable_dead_code=self.enable_dead_code_pruning,
                        enable_imports=self.enable_import_resolution,
                        enable_lint=self.enable_lint_fixing,
                        enable_format=self.enable_formatting,
                        custom_import_map=self.import_resolver.custom_import_map,
                    ),
                ): fp
                for fp in filepaths
            }
            for future in as_completed(future_to_path):
                fpath = future_to_path[future]
                results[fpath] = self._collect_future_result(future, fpath)
        return [results[fp] for fp in filepaths]


@dataclass(slots=True)
class _StandaloneWorkerTask:
    """Encapsulates arguments for parallel worker tasks."""

    filepath: Path
    apply_changes: bool
    backup: bool
    enable_syntax: bool
    enable_modernize: bool
    enable_dead_code: bool
    enable_imports: bool
    enable_lint: bool
    enable_format: bool
    custom_import_map: dict[str, str] | None = None
    verify_proofs: bool = False
    proof_iterations: int = 50
    proof_seed: int | None = None


def _process_file_standalone(task: _StandaloneWorkerTask) -> CleanResult:
    """Standalone function for ProcessPoolExecutor (must be module-level and picklable)."""
    pipeline = CleanPipeline(
        enable_syntax_healing=task.enable_syntax,
        enable_modernizer=task.enable_modernize,
        enable_dead_code_pruning=task.enable_dead_code,
        enable_import_resolution=task.enable_imports,
        enable_lint_fixing=task.enable_lint,
        enable_formatting=task.enable_format,
        custom_import_map=task.custom_import_map,
        verify_proofs=task.verify_proofs,
        proof_iterations=task.proof_iterations,
        proof_seed=task.proof_seed,
    )
    return pipeline.process_file(
        task.filepath, apply_changes=task.apply_changes, backup=task.backup
    )
