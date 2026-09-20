"""
Command line interface for pycleaner.

Provides subcommands (fix, check, audit, scan, complexity, dead-code, all, watch)
and backward-compatible flat argument style. Features Rich progress bars, JSON output,
and granular pass control.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pycleaner.baseline import BaselineFingerprint, BaselineManager
from pycleaner.cache import ContentAddressableCache
from pycleaner.complexity_analyzer import ComplexityAnalyzer
from pycleaner.config import ConfigError, PyCleanerConfig, load_config
from pycleaner.dead_code_detector import DeadCodeDetector
from pycleaner.dependency_auditor import DependencyAuditor, DependencyAuditReport
from pycleaner.discovery import (
    DEFAULT_IGNORED_DIRS,
    collect_project_python_files,
    find_project_root,
    is_protected_file,
)
from pycleaner.explanations import get_explanation, list_rules
from pycleaner.pipeline import CleanPipeline, CleanResult
from pycleaner.security_scanner import SecurityScanner
from pycleaner.taint_engine import TaintEngine
from pycleaner.test_generator import TestGenerator
from pycleaner.type_checker import TypeChecker
from pycleaner.verifier import CounterExample, ProofReceipt, VerificationTier

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
    )
    from rich.syntax import Syntax
    from rich.table import Table

    has_rich = True
except ImportError:
    has_rich = False


SUBCOMMANDS = {
    "fix",
    "check",
    "prove",
    "audit",
    "scan",
    "complexity",
    "dead-code",
    "all",
    "watch",
    "hook",
    "types",
    "taint",
    "test-gen",
    "ultimate",
    "baseline",
    "explain",
    "cache",
    "help",
}

_OPTIONS_WITH_VALUE = {
    "--config",
    "--workers",
    "--severity",
    "--max-cyclomatic",
    "--max-cognitive",
    "--max-lines",
    "--max-args",
    "--interval",
    "--output-dir",
    "--output-json",
    "--proof-iterations",
    "--proof-seed",
    "--baseline",
    "--cache-db",
    "--output",
}


def _has_subcommand(argv: Sequence[str]) -> bool:
    skip_next = False
    for token in argv:
        if skip_next:
            skip_next = False
            continue
        if token in _OPTIONS_WITH_VALUE:
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        return token in SUBCOMMANDS
    return False


def _register_fix_subparsers(subparsers: Any) -> None:
    fix_p = subparsers.add_parser(
        "fix", help="Heal syntax, resolve imports, lint, and format"
    )
    _add_common_args(fix_p)
    _add_fix_args(fix_p)
    fix_p.add_argument("--diff", action="store_true", help="Show unified diffs")

    check_p = subparsers.add_parser(
        "check", help="Dry-run: report issues without modifying files"
    )
    _add_common_args(check_p)
    _add_fix_args(check_p)
    check_p.add_argument("--diff", action="store_true", help="Show unified diffs")

    all_p = subparsers.add_parser(
        "all", help="Run everything: fix + audit + scan + complexity + dead-code"
    )
    _add_common_args(all_p)
    _add_fix_args(all_p)
    all_p.add_argument("--diff", action="store_true", help="Show unified diffs")

    ult_p = subparsers.add_parser(
        "ultimate",
        help="The Ultimate Python Tool: Run healing + imports + lint + types + taint + security + complexity + dead-code",
    )
    _add_common_args(ult_p)
    _add_fix_args(ult_p)
    ult_p.add_argument("--diff", action="store_true", help="Show unified diffs")

    prove_p = subparsers.add_parser(
        "prove",
        help="Verify transformations using differential execution fuzzing (Tier A/B/C)",
    )
    _add_common_args(prove_p)
    _add_fix_args(prove_p)
    prove_p.add_argument("--diff", action="store_true", help="Show unified diffs")
    prove_p.add_argument(
        "--apply",
        action="store_true",
        help="Apply proven (Tier A) changes to disk",
    )


def _register_analysis_subparsers(subparsers: Any) -> None:
    audit_p = subparsers.add_parser("audit", help="Audit project dependencies")
    _add_common_args(audit_p)
    audit_p.add_argument(
        "--fix-deps", action="store_true", help="Auto-fix requirements.txt"
    )
    audit_p.add_argument(
        "--prune-deps", action="store_true", help="Remove unused dependencies"
    )

    scan_p = subparsers.add_parser("scan", help="Security vulnerability scanner")
    _add_common_args(scan_p)
    scan_p.add_argument(
        "--severity",
        default="LOW",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Minimum severity to report",
    )

    cx_p = subparsers.add_parser("complexity", help="Complexity analysis per function")
    _add_common_args(cx_p)
    cx_p.add_argument(
        "--max-cyclomatic", type=int, default=10, help="Max cyclomatic complexity"
    )
    cx_p.add_argument(
        "--max-cognitive", type=int, default=15, help="Max cognitive complexity"
    )
    cx_p.add_argument("--max-lines", type=int, default=50, help="Max function length")
    cx_p.add_argument("--max-args", type=int, default=5, help="Max argument count")

    dc_p = subparsers.add_parser(
        "dead-code", help="Detect unused functions, classes, and unreachable code"
    )
    _add_common_args(dc_p)
    dc_p.add_argument(
        "--fix",
        action="store_true",
        help="Auto-prune unreachable code, redundant pass statements, and dead branches",
    )

    types_p = subparsers.add_parser(
        "types",
        help="Bidirectional type checking and inference with Typeshed stubs",
    )
    _add_common_args(types_p)

    taint_p = subparsers.add_parser(
        "taint", help="Interprocedural SAST dataflow and taint analysis"
    )
    _add_common_args(taint_p)


def _register_tool_subparsers(subparsers: Any) -> None:
    watch_p = subparsers.add_parser(
        "watch", help="Watch files for changes and auto-fix on save"
    )
    _add_common_args(watch_p)
    watch_p.add_argument(
        "--interval", type=float, default=1.0, help="Polling interval in seconds"
    )

    hook_p = subparsers.add_parser(
        "hook", help="Output pre-commit hook configuration and instructions"
    )
    hook_p.add_argument("--json", action="store_true", help="Output JSON diagnostics")

    tg_p = subparsers.add_parser(
        "test-gen", help="Automated behavioral contract test generator"
    )
    _add_common_args(tg_p)
    tg_p.add_argument(
        "--output-dir",
        default=None,
        help="Directory to save generated test suites",
    )
    tg_p.add_argument(
        "--preview",
        action="store_true",
        help="Print generated tests to stdout without saving",
    )

    baseline_p = subparsers.add_parser(
        "baseline",
        help="Generate or update technical debt baseline for ratchet enforcement",
    )
    _add_common_args(baseline_p)
    baseline_p.add_argument(
        "--output",
        default=".pycleaner/baseline.json",
        help="Path to save baseline JSON (default: .pycleaner/baseline.json)",
    )

    explain_p = subparsers.add_parser(
        "explain",
        help="Explain diagnostic codes, security rules, and verification tiers",
    )
    explain_p.add_argument(
        "code",
        nargs="?",
        default=None,
        help="Diagnostic rule code or topic to explain (e.g. DC001, SEC001, PROVE001, or omit to list all)",
    )

    help_p = subparsers.add_parser(
        "help",
        help="Show help for ballpython or a specific command",
    )
    help_p.add_argument(
        "command_name",
        nargs="?",
        default=None,
        metavar="COMMAND",
        help="Subcommand to show help for (e.g. fix, prove, check)",
    )

    cache_p = subparsers.add_parser(
        "cache",
        help="Inspect, query statistics, or invalidate content-addressable cache",
    )
    cache_p.add_argument(
        "--stats",
        action="store_true",
        help="Display cache utilization and database storage statistics",
    )
    cache_p.add_argument(
        "--clear",
        action="store_true",
        help="Wipe all entries from the local cache database",
    )
    cache_p.add_argument(
        "--db",
        default=None,
        help="Custom path to cache SQLite database file (default: .pycleaner/cache.db)",
    )
    cache_p.add_argument(
        "--json",
        action="store_true",
        help="Output statistics in JSON format",
    )


def build_parser(prog: str = "ballpython") -> argparse.ArgumentParser:
    """Construct command-line argument parser with subcommands."""
    from pycleaner import __version__

    parser = argparse.ArgumentParser(
        prog=prog,
        description="The Ultimate Static Python Intelligence, Healing, and Verification Suite.",
    )
    parser.add_argument(
        "--version", action="version", version=f"ballpython {__version__}"
    )
    parser.add_argument(
        "--config",
        default=None,
        metavar="PATH",
        help="Path to an explicit pycleaner config file (pyproject.toml or a .toml file), "
        "overriding auto-discovery from the target path",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    _register_fix_subparsers(subparsers)
    _register_analysis_subparsers(subparsers)
    _register_tool_subparsers(subparsers)

    return parser


def build_flat_parser(prog: str = "ballpython") -> argparse.ArgumentParser:
    """Construct backward-compatible flat argument parser (no subcommands)."""
    from pycleaner import __version__

    parser = argparse.ArgumentParser(
        prog=prog,
        description="The Ultimate Static Python Intelligence, Healing, and Verification Suite.",
    )
    parser.add_argument(
        "--version", action="version", version=f"ballpython {__version__}"
    )
    parser.add_argument(
        "--config",
        default=None,
        metavar="PATH",
        help="Path to an explicit pycleaner config file (pyproject.toml or a .toml file), "
        "overriding auto-discovery from the target path",
    )
    _add_common_args(parser)
    _add_fix_args(parser)
    parser.add_argument("--check", action="store_true", help="Dry-run mode")
    parser.add_argument("--diff", action="store_true", help="Show unified diffs")
    parser.add_argument(
        "--fix-deps", action="store_true", help="Auto-fix requirements.txt"
    )
    parser.add_argument(
        "--prune-deps", action="store_true", help="Remove unused dependencies"
    )
    parser.add_argument(
        "--deps-only", action="store_true", help="Only run dependency audit"
    )
    parser.add_argument(
        "--missing-imports-only",
        action="store_true",
        help="Only resolve missing imports",
    )
    parser.add_argument(
        "-a",
        "--all",
        "--fix-all",
        dest="fix_all",
        action="store_true",
        help="Fix everything in one command",
    )
    return parser


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments shared by all subcommands."""
    parser.add_argument(
        "paths", nargs="*", default=["."], help="Files or directories to process"
    )
    parser.add_argument("--json", action="store_true", help="Output JSON diagnostics")
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip .bak file creation before writing",
    )
    parser.add_argument(
        "--parallel", action="store_true", help="Process files in parallel"
    )
    parser.add_argument(
        "--workers", type=int, default=4, help="Number of parallel workers"
    )


def _add_fix_args(parser: argparse.ArgumentParser) -> None:
    """Add fix-specific arguments."""
    parser.add_argument(
        "--no-syntax-fix", action="store_true", help="Disable syntax healing"
    )
    parser.add_argument(
        "--no-modernize",
        action="store_true",
        help="Disable PEP 585/604 code modernization",
    )
    parser.add_argument(
        "--no-dead-code", action="store_true", help="Disable dead code pruning"
    )
    parser.add_argument(
        "--no-missing-imports", action="store_true", help="Disable import resolution"
    )
    parser.add_argument(
        "--no-lint-fix", action="store_true", help="Disable lint auto-fixing"
    )
    parser.add_argument(
        "--no-format", action="store_true", help="Disable code formatting"
    )
    parser.add_argument(
        "--prove",
        action="store_true",
        help="Prove transformations preserve behavior using differential execution fuzzing",
    )
    parser.add_argument(
        "--proof-iterations",
        type=int,
        default=50,
        help="Number of differential fuzzing test cases per callable (default: 50)",
    )
    parser.add_argument(
        "--proof-seed",
        type=int,
        default=None,
        help="Deterministic random seed for differential proof engine",
    )
    parser.add_argument(
        "--output-json",
        default=".pycleaner/verification-report.json",
        help="Path to save verification receipt JSON",
    )
    parser.add_argument(
        "--cache",
        action="store_true",
        help="Enable content-addressable incremental caching (.pycleaner/cache.db)",
    )
    parser.add_argument(
        "--cache-db",
        default=".pycleaner/cache.db",
        help="Path to SQLite cache database (default: .pycleaner/cache.db)",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        metavar="PATH",
        help="Path to baseline JSON for ratchet enforcement (e.g. .pycleaner/baseline.json)",
    )


_DEFAULT_IGNORE_DIRS = DEFAULT_IGNORED_DIRS


def _collect_dir_python_files(
    dir_path: Path, ignore_dirs: frozenset[str]
) -> list[Path]:
    result: list[Path] = []
    for current_root, dirs, filenames in os.walk(dir_path):
        dirs[:] = [d for d in dirs if d not in ignore_dirs and not d.startswith(".")]
        for fname in filenames:
            if fname.endswith(".py"):
                result.append(Path(current_root) / fname)
    return result


def _collect_target_files(
    targets: Sequence[str], ignore_dirs: frozenset[str] = _DEFAULT_IGNORE_DIRS
) -> list[Path]:
    files: list[Path] = []
    for target in targets:
        path = Path(target).resolve()
        if path.is_file():
            if path.suffix == ".py" and not is_protected_file(path):
                files.append(path)
        elif path.is_dir():
            files.extend(collect_project_python_files(path))
    return files


def _is_file_excluded(f: Path, root: Path, exclude_patterns: Sequence[str]) -> bool:
    import fnmatch

    try:
        rel = f.relative_to(root)
    except ValueError:
        rel = f
    rel_parts = rel.parts
    rel_str = str(rel)

    for pat in exclude_patterns:
        clean_pat = pat.rstrip("/\\")
        if clean_pat in rel_parts:
            return True
        if fnmatch.fnmatch(f.name, pat) or fnmatch.fnmatch(rel_str, pat):
            return True
    return False


def _resolve_project_root(effective_targets: Sequence[str]) -> Path:
    first_target = (
        Path(effective_targets[0]).resolve() if effective_targets else Path.cwd()
    )
    return first_target if first_target.is_dir() else first_target.parent


def discover_python_files(
    targets: list[str],
    config: PyCleanerConfig | None = None,
    root: Path | None = None,
) -> list[Path]:
    """Find all relevant Python files from given targets."""
    effective_targets = list(targets)
    if (not targets or targets == ["."]) and config and config.include:
        effective_targets = config.include

    resolved_root = (
        root if root is not None else _resolve_project_root(effective_targets)
    )

    explicit_files: list[Path] = []
    dir_targets: list[str] = []
    for target in effective_targets:
        p = Path(target).resolve()
        if p.is_file():
            if p.suffix == ".py" and not is_protected_file(p):
                explicit_files.append(p)
        elif p.is_dir():
            dir_targets.append(str(p))

    files = list(explicit_files)
    if dir_targets:
        dir_files = _collect_target_files(dir_targets)
        if config and config.exclude:
            dir_files = [
                f
                for f in dir_files
                if not _is_file_excluded(f, resolved_root, config.exclude)
            ]
        files.extend(dir_files)

    return sorted(set(files))


def _create_printer(console: Any) -> Any:
    def print_msg(msg: str, style: str = "") -> None:
        if console:
            console.print(msg, style=style)
        else:
            import re

            cleaned = re.sub(r"\[/?[a-z ]*\]", "", msg)
            print(cleaned)

    return print_msg


def _resolve_cli_command(args: argparse.Namespace) -> str:
    command = getattr(args, "command", None)
    if command is not None:
        return command
    if getattr(args, "deps_only", False):
        return "audit"
    if getattr(args, "fix_all", False):
        return "all"
    if getattr(args, "check", False):
        return "check"
    return "ultimate"


def _run_all_command(
    args: argparse.Namespace, config: PyCleanerConfig, print_msg: Any, console: Any
) -> int:
    backup = config.backup and not getattr(args, "no_backup", False)
    rc = _cmd_fix(
        args,
        config,
        print_msg,
        console,
        _FixOptions(
            apply_changes=True,
            show_diff=getattr(args, "diff", False),
            backup=backup,
        ),
    )
    audit_rc = _cmd_audit(args, config, print_msg)
    scan_rc = _cmd_scan(args, config, print_msg, console)
    _cmd_complexity(args, config, print_msg, console)
    _cmd_dead_code(args, config, print_msg, console)
    return max(rc, audit_rc, scan_rc)


def _route_command(
    command: str,
    args: argparse.Namespace,
    config: PyCleanerConfig,
    print_msg: Any,
    console: Any,
) -> int:
    backup = config.backup and not getattr(args, "no_backup", False)
    diff = getattr(args, "diff", False)

    dispatch_simple = {
        "help": lambda: _cmd_help(args, print_msg),
        "hook": lambda: _cmd_hook(args, print_msg),
        "audit": lambda: _cmd_audit(args, config, print_msg),
        "scan": lambda: _cmd_scan(args, config, print_msg, console),
        "complexity": lambda: _cmd_complexity(args, config, print_msg, console),
        "dead-code": lambda: _cmd_dead_code(args, config, print_msg, console),
        "types": lambda: _cmd_types(args, config, print_msg, console),
        "taint": lambda: _cmd_taint(args, config, print_msg, console),
        "test-gen": lambda: _cmd_test_gen(args, config, print_msg),
        "watch": lambda: _cmd_watch(args, config, print_msg),
        "ultimate": lambda: _cmd_ultimate(args, config, print_msg, console),
        "all": lambda: _run_all_command(args, config, print_msg, console),
        "prove": lambda: _cmd_prove(args, config, print_msg, console),
        "baseline": lambda: _cmd_baseline(args, config, print_msg, console),
        "explain": lambda: _cmd_explain(args, print_msg, console),
        "cache": lambda: _cmd_cache(args, config, print_msg, console),
        "check": lambda: _cmd_fix(
            args,
            config,
            print_msg,
            console,
            _FixOptions(apply_changes=False, show_diff=diff, backup=False),
        ),
    }
    handler = dispatch_simple.get(command)
    if handler:
        return handler()

    return _cmd_fix(
        args,
        config,
        print_msg,
        console,
        _FixOptions(apply_changes=True, show_diff=diff, backup=backup),
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Main CLI entry point."""
    raw_args = list(sys.argv[1:] if argv is None else argv)

    # If --help / -h is passed without a subcommand, use the subcommand parser to show full help
    if ("-h" in raw_args or "--help" in raw_args) and not _has_subcommand(raw_args):
        parser = build_parser()
        parser.parse_args(raw_args)
        return 0

    parser = build_parser() if _has_subcommand(raw_args) else build_flat_parser()
    args = parser.parse_args(raw_args)
    console = Console() if has_rich else None
    print_msg = _create_printer(console)

    targets = getattr(args, "paths", ["."])
    target_path = Path(targets[0]).resolve() if targets else Path.cwd()
    root_dir = find_project_root(target_path)

    try:
        config = load_config(
            project_root=root_dir,
            explicit_config_file=getattr(args, "config", None),
        )
    except ConfigError as err:
        print_msg(f"[red]Configuration Error:[/red] {err}")
        return 2

    command = _resolve_cli_command(args)
    return _route_command(command, args, config, print_msg, console)


# ---------------------------------------------------------------------------
# Command Implementations
# ---------------------------------------------------------------------------


@dataclass
class _FixBatchState:
    changed_count: int = 0
    error_count: int = 0
    diagnostics: list[dict[str, str]] = field(default_factory=list)
    proven_count: int = 0
    suggested_count: int = 0
    refused_count: int = 0
    proof_receipts: list[ProofReceipt] = field(default_factory=list)
    counterexamples: list[CounterExample] = field(default_factory=list)


@dataclass(slots=True)
class _FixOptions:
    apply_changes: bool = True
    show_diff: bool = False
    backup: bool = False
    in_progress: bool = False


_DEFAULT_FIX_OPTS = _FixOptions()


def _render_fix_diff(diff: str, console: Any) -> None:
    if console and has_rich:
        syntax = Syntax(diff, "diff", theme="monokai", line_numbers=True)
        console.print(syntax)
    else:
        print(diff)


def _report_file_modifications(
    result: CleanResult, py_file: Path, apply_changes: bool, print_msg: Any
) -> None:
    action = "Cleaned" if apply_changes else "Would modify"
    print_msg(f"[green]{action}:[/green] {py_file.name}")
    for repair in result.syntax_repairs:
        print_msg(f"  • Syntax: {repair}", style="cyan")
    for mod in result.modernize_transforms:
        print_msg(f"  • Modernize: {mod}", style="green")
    for dc in result.dead_code_pruned:
        print_msg(f"  • Dead-code: {dc}", style="yellow")
    for imp in result.resolved_imports:
        print_msg(f"  • Import: {imp}", style="magenta")
    if result.lint_changed:
        print_msg("  • Lint: fixed errors and pruned unused imports", style="blue")
    if result.format_changed:
        print_msg("  • Format: applied PEP 8 formatting", style="blue")


def _accumulate_result(
    result: CleanResult,
    py_file: Path,
    state: _FixBatchState,
    opts: _FixOptions,
    io_ctx: tuple[Any, Any, bool],
) -> None:
    print_msg, console, is_json = io_ctx
    if result.diagnostics:
        state.diagnostics.extend(result.diagnostics)

    if result.proof_receipts:
        state.proof_receipts.extend(result.proof_receipts)
    if result.refused_changes:
        state.counterexamples.extend(result.refused_changes)
        state.refused_count += len(result.refused_changes)
    if result.verification_tier == VerificationTier.TIER_A_PROVEN:
        state.proven_count += 1
    elif result.verification_tier == VerificationTier.TIER_B_SUGGESTED:
        state.suggested_count += 1
    elif result.verification_tier == VerificationTier.TIER_C_REFUSED:
        if not is_json:
            print_msg(
                f"[bold red]Refused (Tier C):[/bold red] {py_file.name} — transformation falsified by differential fuzzing; rolled back!"
            )
            for ce in result.refused_changes:
                print_msg(
                    f"  • {ce.callable_name} diverged on args={ce.arguments} kwargs={ce.keyword_arguments}"
                )
                print_msg(
                    f"    original={ce.original_result or ce.original_error} vs transformed={ce.transformed_result or ce.transformed_error} (seed {ce.seed})"
                )

    if result.error:
        state.error_count += 1
        if not is_json:
            print_msg(f"[red]ERROR in {py_file.name}:[/red] {result.error}")
        return

    if result.changed:
        state.changed_count += 1
        if not is_json and not opts.in_progress:
            _report_file_modifications(result, py_file, opts.apply_changes, print_msg)
            if opts.show_diff and result.diff:
                _render_fix_diff(result.diff, console)


def _build_fix_pipeline(
    args: argparse.Namespace, config: PyCleanerConfig
) -> CleanPipeline:
    verify_proofs = (
        getattr(args, "prove", False) or getattr(args, "command", None) == "prove"
    )
    proof_iterations = getattr(args, "proof_iterations", 50)
    proof_seed = getattr(args, "proof_seed", None)
    enable_cache = getattr(args, "cache", False)
    cache_db_path = getattr(args, "cache_db", ".pycleaner/cache.db")
    if getattr(args, "missing_imports_only", False):
        return CleanPipeline(
            enable_syntax_healing=False,
            enable_modernizer=False,
            enable_dead_code_pruning=False,
            enable_import_resolution=True,
            enable_lint_fixing=False,
            enable_formatting=False,
            config=config,
            verify_proofs=verify_proofs,
            proof_iterations=proof_iterations,
            proof_seed=proof_seed,
            enable_cache=enable_cache,
            cache_db_path=cache_db_path,
        )
    return CleanPipeline(
        enable_syntax_healing=not getattr(args, "no_syntax_fix", False),
        enable_modernizer=not getattr(args, "no_modernize", False),
        enable_dead_code_pruning=not getattr(args, "no_dead_code", False),
        enable_import_resolution=not getattr(args, "no_missing_imports", False),
        enable_lint_fixing=not getattr(args, "no_lint_fix", False),
        enable_formatting=not getattr(args, "no_format", False),
        config=config,
        verify_proofs=verify_proofs,
        proof_iterations=proof_iterations,
        proof_seed=proof_seed,
        enable_cache=enable_cache,
        cache_db_path=cache_db_path,
    )


def _run_progress_fix(
    pipeline: CleanPipeline,
    py_files: list[Path],
    opts: _FixOptions,
    state: _FixBatchState,
    io_ctx: tuple[Any, Any, bool],
) -> None:
    prog_opts = _FixOptions(
        apply_changes=opts.apply_changes,
        show_diff=opts.show_diff,
        backup=opts.backup,
        in_progress=True,
    )
    _print_msg, console, _is_json = io_ctx
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Processing...", total=len(py_files))
        for i, py_file in enumerate(py_files, 1):
            progress.update(task, description=f"[{i}/{len(py_files)}] {py_file.name}")
            result = pipeline.process_file(
                py_file, apply_changes=opts.apply_changes, backup=opts.backup
            )
            _accumulate_result(result, py_file, state, prog_opts, io_ctx)
            progress.advance(task)


def _execute_fix_batch(
    pipeline: CleanPipeline,
    py_files: list[Path],
    opts: _FixOptions,
    io_ctx: tuple[Any, Any, bool],
    parallel_settings: tuple[bool, int],
) -> _FixBatchState:
    state = _FixBatchState()
    use_parallel, workers = parallel_settings
    print_msg, console, is_json = io_ctx

    if use_parallel:
        if not is_json:
            print_msg(f"[dim]Processing with {workers} parallel worker(s)...[/dim]")
        results = pipeline.process_files(
            py_files,
            apply_changes=opts.apply_changes,
            backup=opts.backup,
            max_workers=workers,
        )
        for py_file, result in zip(py_files, results):
            _accumulate_result(result, py_file, state, opts, io_ctx)
    elif has_rich and console and not is_json and len(py_files) > 3:
        _run_progress_fix(pipeline, py_files, opts, state, io_ctx)
    else:
        for py_file in py_files:
            res = pipeline.process_file(
                py_file, apply_changes=opts.apply_changes, backup=opts.backup
            )
            _accumulate_result(res, py_file, state, opts, io_ctx)

    return state


def _render_audit_terminal_output(
    audit_report: DependencyAuditReport,
    print_msg: Any,
    should_fix: bool,
) -> None:
    if not (
        audit_report.missing_packages
        or audit_report.unused_packages
        or audit_report.fixed_requirements
    ):
        return

    print_msg("\n[bold cyan]Project Dependency Audit:[/bold cyan]")
    if audit_report.missing_packages:
        print_msg(
            f"  [red]Missing:[/red] {', '.join(sorted(audit_report.missing_packages))}"
        )
        if not should_fix:
            print_msg(
                "  [dim]Tip: Run with -a/--all or --fix-deps to append them[/dim]"
            )
    if audit_report.unused_packages:
        print_msg(
            f"  [yellow]Unused:[/yellow] {', '.join(sorted(audit_report.unused_packages))}"
        )
    if audit_report.fixed_requirements:
        print_msg("  [green]requirements.txt synchronized.[/green]")


def _run_fix_audit(
    root_dir: Path,
    apply_changes: bool,
    args: argparse.Namespace,
    print_msg: Any,
    config: PyCleanerConfig | None = None,
    target_files: Sequence[Path] | None = None,
) -> DependencyAuditReport:
    exclude_patterns = config.exclude if config else ()
    auditor = DependencyAuditor(root_dir, exclude_patterns=exclude_patterns)
    fix_any = getattr(args, "fix_deps", False) or getattr(args, "fix_all", False)
    prune_any = getattr(args, "prune_deps", False) or getattr(args, "fix_all", False)
    should_fix = apply_changes and fix_any
    should_prune = apply_changes and prune_any
    audit_report = auditor.audit(
        fix=should_fix, prune_unused=should_prune, target_files=target_files
    )
    _render_audit_terminal_output(audit_report, print_msg, should_fix)
    return audit_report


def _compute_fix_exit_code(
    state: _FixBatchState,
    audit_report: DependencyAuditReport,
    apply_changes: bool,
    is_prove_cmd: bool = False,
) -> int:
    if state.refused_count > 0:
        return 1
    if is_prove_cmd:
        return 0 if state.error_count == 0 else 1
    if not apply_changes and (
        state.changed_count > 0
        or state.error_count > 0
        or bool(audit_report.missing_packages)
    ):
        return 1
    return 0 if state.error_count == 0 else 1


def _is_parallel_enabled(
    args: argparse.Namespace, config: PyCleanerConfig, file_count: int
) -> tuple[bool, int]:
    workers_cfg = getattr(args, "workers", None) or config.max_workers
    use_parallel = (
        (getattr(args, "parallel", False) or config.parallel)
        and workers_cfg > 1
        and file_count > 1
    )
    return use_parallel, workers_cfg


def _resolve_root_dir(paths: Sequence[str] | None) -> Path:
    target = Path(paths[0]).resolve() if paths else Path.cwd()
    return find_project_root(target)


def _report_fix_start(count: int, apply_changes: bool, print_msg: Any) -> None:
    action_label = "Cleaning" if apply_changes else "Checking"
    print_msg(f"[bold blue]{action_label} {count} file(s)...[/bold blue]")


def _cmd_fix(
    args: argparse.Namespace,
    config: PyCleanerConfig,
    print_msg: Any,
    console: Any,
    opts: _FixOptions = _DEFAULT_FIX_OPTS,
) -> int:
    """Core fix command: heal + resolve + lint + format."""
    pipeline = _build_fix_pipeline(args, config)
    root_dir = _resolve_root_dir(args.paths)
    py_files = discover_python_files(args.paths, config=config, root=root_dir)
    is_json = bool(getattr(args, "json", False))

    if not py_files:
        if is_json:
            print(json.dumps([]))
        else:
            print_msg("No Python files found matching target paths.", style="yellow")
        return 0

    if not is_json:
        _report_fix_start(len(py_files), opts.apply_changes, print_msg)

    parallel_info = _is_parallel_enabled(args, config, len(py_files))
    io_ctx = (print_msg, console, is_json)
    state = _execute_fix_batch(pipeline, py_files, opts, io_ctx, parallel_info)

    if is_json:
        print(json.dumps(state.diagnostics, indent=2))
        return 0 if state.error_count == 0 else 1

    audit_report = _run_fix_audit(
        root_dir,
        opts.apply_changes,
        args,
        print_msg,
        config=config,
        target_files=py_files,
    )
    print_msg(
        f"\n[bold]Summary: {len(py_files)} inspected, {state.changed_count} updated, {state.error_count} errors.[/bold]"
    )

    if pipeline.verify_proofs:
        total_proven_callables = sum(
            1 for r in state.proof_receipts if r.tier == VerificationTier.TIER_A_PROVEN
        )
        total_refused_callables = len(state.counterexamples)
        if not is_json:
            print_msg("\n[bold cyan]Verification Receipts (Trust Ladder):[/bold cyan]")
            print_msg(
                f"  [bold green]• Proven (Tier A):[/bold green] {total_proven_callables} callable(s) invariant-preserving across {pipeline.proof_iterations} input(s)"
            )
            if state.suggested_count > 0:
                print_msg(
                    f"  [yellow]• Suggested (Tier B):[/yellow] {state.suggested_count} module(s) (not isolated for dynamic fuzzing)"
                )
            if total_refused_callables > 0:
                print_msg(
                    f"  [bold red]• Refused (Tier C):[/bold red] {total_refused_callables} transformation(s) diverged; rolled back"
                )

        output_report_path = getattr(
            args, "output_json", ".pycleaner/verification-report.json"
        )
        try:
            out_p = Path(output_report_path)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            report_data = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "total_inspected": len(py_files),
                "proven_tier_a_callables": total_proven_callables,
                "suggested_tier_b_files": state.suggested_count,
                "refused_tier_c_callables": total_refused_callables,
                "proof_receipts": [
                    {
                        "file": r.filepath,
                        "callable": r.callable_name,
                        "tier": r.tier.value,
                        "iterations": r.iterations_run,
                        "seed": r.seed,
                        "duration_ms": r.duration_ms,
                        "reason": r.reason,
                    }
                    for r in state.proof_receipts
                ],
                "counterexamples": [
                    {
                        "callable": ce.callable_name,
                        "arguments": [repr(a) for a in ce.arguments],
                        "kwargs": {k: repr(v) for k, v in ce.keyword_arguments.items()},
                        "original_result": ce.original_result,
                        "original_error": ce.original_error,
                        "transformed_result": ce.transformed_result,
                        "transformed_error": ce.transformed_error,
                        "seed": ce.seed,
                    }
                    for ce in state.counterexamples
                ],
            }
            out_p.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
            if not is_json:
                print_msg(f"  [dim]Report saved to {output_report_path}[/dim]")
        except OSError as e:
            if not is_json:
                print_msg(f"  [red]Failed to write verification report:[/red] {e}")

    if getattr(args, "baseline", None):
        baseline_mgr = BaselineManager(args.baseline)
        current_issues: list[BaselineFingerprint] = []
        for diag in state.diagnostics:
            current_issues.append(
                BaselineManager.create_fingerprint(
                    rule=diag.get("rule", "LINT001"),
                    file_path=diag.get("file", "<unknown>"),
                    line=int(diag.get("line", 1)),
                    symbol=diag.get("message", "diagnostic violation"),
                    root_dir=root_dir,
                )
            )
        tolerated, new_debt = baseline_mgr.filter_new_issues(current_issues)
        if not is_json:
            print_msg(
                f"\n[bold cyan]Baseline Ratchet Enforcement ({args.baseline}):[/bold cyan]"
            )
            if tolerated:
                print_msg(
                    f"  • Baseline tolerated: [yellow]{len(tolerated)}[/yellow] existing issue(s)"
                )
            if new_debt:
                print_msg(
                    f"  • [bold red]Ratchet Violation:[/bold red] {len(new_debt)} new technical debt issue(s) detected!"
                )
                for nd in new_debt:
                    print_msg(
                        f"    [red]• [X] {nd.rule} at {nd.file}:{nd.line} ({nd.symbol})[/red]"
                    )
                return 1
            else:
                print_msg(
                    "  • [bold green]Ratchet Passed:[/bold green] 0 new technical debt issues introduced."
                )
        elif new_debt:
            return 1

    is_prove = getattr(args, "command", None) == "prove"
    return _compute_fix_exit_code(
        state, audit_report, opts.apply_changes, is_prove_cmd=is_prove
    )


def _cmd_prove(
    args: argparse.Namespace,
    config: PyCleanerConfig,
    print_msg: Any,
    console: Any,
) -> int:
    """The Proof-Carrying Differential Equivalence Runner."""
    args.prove = True
    diff = getattr(args, "diff", False)
    apply_changes = getattr(args, "apply", False)

    print_msg(
        "[bold cyan]=== PyCleaner Prove: Differential Equivalence Verification ===[/bold cyan]\n"
    )

    return _cmd_fix(
        args,
        config,
        print_msg,
        console,
        _FixOptions(
            apply_changes=apply_changes,
            show_diff=diff,
            backup=config.backup and not getattr(args, "no_backup", False),
        ),
    )


def _cmd_baseline(
    args: argparse.Namespace,
    config: PyCleanerConfig,
    print_msg: Any,
    console: Any,
) -> int:
    """Generate or update technical debt baseline for ratchet enforcement."""
    output_path = Path(getattr(args, "output", ".pycleaner/baseline.json"))
    root_dir = _resolve_root_dir(getattr(args, "paths", None))
    py_files = discover_python_files(args.paths, config=config, root=root_dir)

    print_msg(
        "[bold cyan]=== Generating PyCleaner Technical Debt Baseline ===[/bold cyan]"
    )
    print_msg(f"Inspecting {len(py_files)} file(s) across {root_dir.name}...")

    fingerprints: list[BaselineFingerprint] = []

    detector = DeadCodeDetector()
    dead_code_report = detector.scan_project(root_dir)
    for item in dead_code_report.items:
        if item.kind == "unused-import":
            rule = "DC002"
        elif item.kind in ("function", "class"):
            rule = "DC003"
        else:
            rule = "DC001"
        fingerprints.append(
            BaselineManager.create_fingerprint(
                rule=rule,
                file_path=item.filepath,
                line=item.lineno,
                symbol=item.name,
                root_dir=root_dir,
            )
        )

    scanner = SecurityScanner()
    sec_report = scanner.scan_project(root_dir)
    for finding in sec_report.findings:
        fingerprints.append(
            BaselineManager.create_fingerprint(
                rule=finding.category,
                file_path=finding.filepath,
                line=finding.lineno,
                symbol=finding.message,
                root_dir=root_dir,
            )
        )

    analyzer = ComplexityAnalyzer()
    comp_report = analyzer.analyze_project(root_dir)
    thresholds = (
        getattr(args, "max_cyclomatic", config.max_cyclomatic_complexity),
        getattr(args, "max_cognitive", config.max_cognitive_complexity),
        getattr(args, "max_lines", config.max_function_length),
        getattr(args, "max_args", config.max_arguments),
    )
    violations = comp_report.above_threshold(*thresholds)
    for v in violations:
        fingerprints.append(
            BaselineManager.create_fingerprint(
                rule="CMP001",
                file_path=v.filepath,
                line=v.lineno,
                symbol=f"{v.qualified_name} (CC={v.cyclomatic})",
                root_dir=root_dir,
            )
        )

    manager = BaselineManager(output_path)
    saved_file = manager.save_baseline(fingerprints, root_dir)

    print_msg(f"\n[bold green]Baseline successfully recorded![/bold green]")
    print_msg(f"  • Issues snapshotted: [bold yellow]{len(fingerprints)}[/bold yellow]")
    print_msg(f"  • Output file: [bold]{saved_file}[/bold]")
    print_msg(
        "\n[dim]Ratchet Guarantee: Technical debt in this repository is now locked. Run CI with:[/dim]"
    )
    print_msg(f"  [cyan]pycleaner check --baseline {output_path}[/cyan]\n")

    return 0


def _cmd_explain(
    args: argparse.Namespace,
    print_msg: Any,
    console: Any,
) -> int:
    """Explain diagnostic codes, security rules, and verification tiers."""
    code = getattr(args, "code", None)

    if not code:
        rules = list_rules()
        print_msg(
            "[bold cyan]PyCleaner Diagnostic & Verification Rules Catalog[/bold cyan]\n"
        )
        if console and has_rich:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Code", style="cyan", width=10)
            table.add_column("Category", style="yellow", width=25)
            table.add_column("Severity", width=12)
            table.add_column("Title", style="white")
            for r in rules:
                sev_color = (
                    "red"
                    if r.severity in ("Critical", "High")
                    else ("yellow" if r.severity == "Medium" else "green")
                )
                table.add_row(
                    r.code,
                    r.category,
                    f"[{sev_color}]{r.severity}[/{sev_color}]",
                    r.title,
                )
            console.print(table)
        else:
            for r in rules:
                print(f"{r.code:8} [{r.severity:8}] {r.title} ({r.category})")
        print_msg(
            "\n[dim]Run 'pycleaner explain <CODE>' for full details and remediation examples.[/dim]"
        )
        return 0

    rule = get_explanation(code)
    if rule is None:
        print_msg(f"[bold red]Unknown rule code or topic:[/bold red] '{code}'")
        print_msg(
            "[dim]Run 'pycleaner explain' without arguments to list all available rules.[/dim]"
        )
        return 1

    sev_color = (
        "red"
        if rule.severity in ("Critical", "High")
        else ("yellow" if rule.severity == "Medium" else "green")
    )
    print_msg(
        f"\n[bold cyan]PyCleaner Rule Guide: {rule.code} - {rule.title}[/bold cyan]"
    )
    print_msg(
        f"  [bold]Category:[/bold] {rule.category} | [bold]Severity:[/bold] [{sev_color}]{rule.severity}[/{sev_color}]\n"
    )
    print_msg(f"[bold]Description:[/bold]\n{rule.description}\n")

    if rule.vulnerable_example:
        print_msg("[bold red][X] Flawed / Baseline Example:[/bold red]")
        if console and has_rich:
            console.print(
                Syntax(
                    rule.vulnerable_example,
                    "python",
                    theme="monokai",
                    line_numbers=False,
                )
            )
        else:
            print(rule.vulnerable_example)

    if rule.remediated_example:
        print_msg("\n[bold green][+] Verified / Remediated Example:[/bold green]")
        if console and has_rich:
            console.print(
                Syntax(
                    rule.remediated_example,
                    "python",
                    theme="monokai",
                    line_numbers=False,
                )
            )
        else:
            print(rule.remediated_example)

    print_msg(
        f"\n[bold]Remediation Details & Proof Invariants:[/bold]\n{rule.remediation_details}\n"
    )
    return 0


def _cmd_help(args: argparse.Namespace, print_msg: Any) -> int:
    cmd_name = getattr(args, "command_name", None)
    parser = build_parser()
    if not cmd_name:
        parser.print_help()
        return 0

    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            if cmd_name in action.choices:
                action.choices[cmd_name].print_help()
                return 0
    print_msg(
        f"Unknown command: '{cmd_name}'. Run 'ballpython --help' to view available commands.",
        style="yellow",
    )
    return 1


def _cmd_cache(
    args: argparse.Namespace,
    config: PyCleanerConfig,
    print_msg: Any,
    console: Any,
) -> int:
    """Manage and inspect the content-addressable verification and AST cache."""
    db_path = getattr(args, "db", None) or getattr(
        config, "cache_db_path", ".pycleaner/cache.db"
    )
    cache = ContentAddressableCache(db_path=db_path)

    if getattr(args, "clear", False):
        cache.clear()
        print_msg("[green]Content-addressable cache cleared successfully.[/green]")
        return 0

    stats = cache.get_stats()
    if getattr(args, "json", False):
        print(json.dumps(stats, indent=2))
        return 0

    print_msg("[bold cyan]=== Content-Addressable Cache Statistics ===[/bold cyan]")
    print_msg(f"  Database Path:       {cache.db_path}")
    print_msg(f"  Cached File Entries: {stats['file_cache_entries']}")
    print_msg(f"  Provenance Records:  {stats['provenance_entries']}")
    print_msg(f"  Database File Size:  {stats['db_size_bytes']:,} bytes")
    return 0


def _render_audit_json(audit_report: DependencyAuditReport) -> int:
    print(
        json.dumps(
            {
                "imported_modules": sorted(audit_report.imported_modules),
                "third_party_modules": sorted(audit_report.third_party_modules),
                "required_packages": sorted(audit_report.required_packages),
                "missing": sorted(audit_report.missing_packages),
                "unused": sorted(audit_report.unused_packages),
                "fixed": audit_report.fixed_requirements,
            },
            indent=2,
        )
    )
    return (
        1
        if audit_report.missing_packages and not audit_report.fixed_requirements
        else 0
    )


def _render_audit_cli_output(
    audit_report: DependencyAuditReport, print_msg: Any
) -> int:
    print_msg("[bold cyan]Dependency Audit:[/bold cyan]")
    if audit_report.missing_packages:
        print_msg(
            f"  [red]Missing:[/red] {', '.join(sorted(audit_report.missing_packages))}"
        )
    if audit_report.unused_packages:
        print_msg(
            f"  [yellow]Unused:[/yellow] {', '.join(sorted(audit_report.unused_packages))}"
        )
    if not audit_report.missing_packages and not audit_report.unused_packages:
        print_msg("  [green]All dependencies clean.[/green]")
    if audit_report.fixed_requirements:
        print_msg("  [green]requirements.txt synchronized.[/green]")

    return (
        1
        if audit_report.missing_packages and not audit_report.fixed_requirements
        else 0
    )


def _cmd_audit(args: argparse.Namespace, config: PyCleanerConfig, print_msg) -> int:
    """Dependency audit command."""
    root_dir = find_project_root(args.paths[0] if args.paths else None)

    is_check = getattr(args, "check", False)
    auditor = DependencyAuditor(root_dir, exclude_patterns=config.exclude)
    audit_report = auditor.audit(
        fix=getattr(args, "fix_deps", False) and not is_check,
        prune_unused=getattr(args, "prune_deps", False) and not is_check,
    )

    if getattr(args, "json", False):
        return _render_audit_json(audit_report)
    return _render_audit_cli_output(audit_report, print_msg)


def _render_scan_json(report: Any) -> int:
    findings = [
        {
            "file": f.filepath,
            "line": f.lineno,
            "severity": f.severity,
            "category": f.category,
            "message": f.message,
            "suggestion": f.suggestion,
            "code_snippet": f.code_snippet,
        }
        for f in report.findings
    ]
    print(json.dumps(findings, indent=2))
    return 1 if report.critical_count > 0 else 0


def _render_scan_table(report: Any, console: Any, target_base: str) -> None:
    table = Table(title="Security Findings", show_lines=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Category", width=22)
    table.add_column("File:Line", width=35)
    table.add_column("Message", min_width=30)

    severity_styles = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "dim",
    }
    for f in report.findings:
        rel_path = _try_relative(f.filepath, target_base)
        style = severity_styles.get(f.severity, "")
        sev_str = f"[{style}]{f.severity}[/{style}]" if style else f.severity
        table.add_row(sev_str, f.category, f"{rel_path}:{f.lineno}", f.message)
    console.print(table)


def _render_scan_cli_summary(
    report: Any, print_msg: Any, console: Any, target_base: str
) -> int:
    print_msg(f"\n[bold cyan]Security Scan ({report.files_scanned} files):[/bold cyan]")
    if not report.findings:
        print_msg("  [green]No security issues detected.[/green]")
        return 0

    if has_rich and console:
        _render_scan_table(report, console, target_base)
    else:
        for f in report.findings:
            rel = _try_relative(f.filepath, target_base)
            print_msg(f"  [{f.severity}] {f.category} at {rel}:{f.lineno}: {f.message}")

    categories = sorted({f.category for f in report.findings})
    if categories:
        cat_summary = ", ".join(
            f"{cat} ({len(report.by_category(cat))})" for cat in categories
        )
        print_msg(f"\n  Findings by category: {cat_summary}")

    print_msg(
        f"\n  Total: {report.count} finding(s) — "
        f"[red]{report.critical_count} critical[/red], [red]{report.high_count} high[/red]"
    )
    return 1 if report.critical_count > 0 else 0


def _cmd_scan(
    args: argparse.Namespace, config: PyCleanerConfig, print_msg, console
) -> int:
    """Security scan command."""
    root_dir = Path(args.paths[0]).resolve() if args.paths else Path.cwd()
    if not root_dir.is_dir():
        root_dir = root_dir.parent

    severity = getattr(args, "severity", config.security_severity_threshold)
    scanner = SecurityScanner(
        severity_threshold=severity,
        ignore_rules=set(config.ignore_security_rules),
    )
    report = scanner.scan_project(root_dir, exclude_patterns=config.exclude)

    target_base = args.paths[0] if args.paths else "."
    if getattr(args, "json", False):
        return _render_scan_json(report)
    return _render_scan_cli_summary(report, print_msg, console, target_base)


def _render_complexity_json(violations: Sequence[Any]) -> int:
    data = [
        {
            "file": f.filepath,
            "line": f.lineno,
            "name": f.qualified_name,
            "cyclomatic": f.cyclomatic,
            "cognitive": f.cognitive,
            "lines": f.lines,
            "args": f.args,
            "returns": f.returns,
            "max_nesting": f.max_nesting,
        }
        for f in violations
    ]
    print(json.dumps(data, indent=2))
    return 1 if violations else 0


def _format_cell(val: int, threshold: int) -> str:
    return f"[red]{val}[/red]" if val > threshold else str(val)


def _render_complexity_table(
    violations: Sequence[Any],
    console: Any,
    thresholds: tuple[int, int, int, int],
    target_base: str,
) -> None:
    max_cyc, max_cog, max_lines, max_args = thresholds
    table = Table(title="Threshold Violations", show_lines=True)
    table.add_column("Function", min_width=30)
    table.add_column("File:Line", width=35)
    table.add_column("CC", justify="right", width=5)
    table.add_column("Cog", justify="right", width=5)
    table.add_column("Lines", justify="right", width=6)
    table.add_column("Args", justify="right", width=5)

    for f in violations:
        rel_path = _try_relative(f.filepath, target_base)
        table.add_row(
            f.qualified_name,
            f"{rel_path}:{f.lineno}",
            _format_cell(f.cyclomatic, max_cyc),
            _format_cell(f.cognitive, max_cog),
            _format_cell(f.lines, max_lines),
            _format_cell(f.args, max_args),
        )
    console.print(table)


def _render_complexity_cli_output(
    report: Any,
    violations: Sequence[Any],
    thresholds: tuple[int, int, int, int],
    ui_ctx: tuple[Any, Any, str],
) -> int:
    print_msg, console, target_base = ui_ctx
    max_cyc, max_cog, max_lines, max_args = thresholds
    print_msg(
        f"\n[bold cyan]Complexity Report ({report.files_scanned} files, {report.count} functions):[/bold cyan]"
    )
    print_msg(
        f"  Avg cyclomatic: {report.average_cyclomatic:.1f} | Avg cognitive: {report.average_cognitive:.1f}"
    )
    if not violations:
        print_msg(
            f"  [green]All functions within thresholds (CC<={max_cyc}, Cog<={max_cog}, Ln<={max_lines}, Args<={max_args})[/green]"
        )
        return 0

    if has_rich and console:
        _render_complexity_table(violations, console, thresholds, target_base)
    else:
        for f in violations:
            print_msg(
                f"  {f.qualified_name} — CC:{f.cyclomatic} Cog:{f.cognitive} Ln:{f.lines} Args:{f.args}"
            )
    print_msg(f"\n  {len(violations)} function(s) exceed threshold(s).")
    return 1


def _cmd_complexity(
    args: argparse.Namespace, config: PyCleanerConfig, print_msg, console
) -> int:
    """Complexity analysis command."""
    root_dir = Path(args.paths[0]).resolve() if args.paths else Path.cwd()
    if not root_dir.is_dir():
        root_dir = root_dir.parent

    analyzer = ComplexityAnalyzer()
    report = analyzer.analyze_project(root_dir, exclude_patterns=config.exclude)

    thresholds = (
        getattr(args, "max_cyclomatic", config.max_cyclomatic_complexity),
        getattr(args, "max_cognitive", config.max_cognitive_complexity),
        getattr(args, "max_lines", config.max_function_length),
        getattr(args, "max_args", config.max_arguments),
    )
    violations = report.above_threshold(*thresholds)
    if getattr(args, "json", False):
        return _render_complexity_json(violations)

    target_base = args.paths[0] if args.paths else "."
    return _render_complexity_cli_output(
        report, violations, thresholds, (print_msg, console, target_base)
    )


def _render_dead_code_json(items: Sequence[Any]) -> int:
    data = [
        {
            "file": item.filepath,
            "line": item.lineno,
            "name": item.name,
            "kind": item.kind,
            "reason": item.reason,
            "confidence": item.confidence,
        }
        for item in items
    ]
    print(json.dumps(data, indent=2))
    return 1 if items else 0


def _render_dead_code_kind_group(
    kind_items: Sequence[Any], label: str, print_msg: Any, target_base: str
) -> None:
    print_msg(f"\n  [bold yellow]{label} ({len(kind_items)}):[/bold yellow]")
    for item in kind_items[:20]:
        rel_path = _try_relative(item.filepath, target_base)
        conf_tag = f" [{item.confidence}]" if item.confidence != "high" else ""
        print_msg(
            f"    L{item.lineno} {rel_path}: {item.name} — {item.reason}{conf_tag}"
        )
    if len(kind_items) > 20:
        print_msg(f"    ... and {len(kind_items) - 20} more")


def _render_dead_code_cli_summary(report: Any, print_msg: Any, target_base: str) -> int:
    print_msg(
        f"\n[bold cyan]Dead Code Report ({report.files_scanned} files, {report.total_definitions} definitions):[/bold cyan]"
    )
    if not report.items:
        print_msg("  [green]No dead code detected.[/green]")
        return 0

    for kind in ("unreachable", "function", "class", "variable", "empty-branch"):
        kind_items = report.by_kind(kind)
        if kind_items:
            label = kind.replace("-", " ").title()
            _render_dead_code_kind_group(kind_items, label, print_msg, target_base)

    print_msg(f"\n  Total: {report.count} dead code item(s) detected.")
    return 1


def _cmd_dead_code(
    args: argparse.Namespace, config: PyCleanerConfig, print_msg, console
) -> int:
    """Dead code detection command."""
    root_dir = Path(args.paths[0]).resolve() if args.paths else Path.cwd()
    if not root_dir.is_dir():
        root_dir = root_dir.parent

    detector = DeadCodeDetector(
        ignore_decorators=set(config.ignore_decorators),
        ignore_names=set(config.ignore_names),
    )
    if getattr(args, "fix", False):
        print_msg(f"[bold green]Pruning dead code across {root_dir}...[/bold green]")
        fix_results = detector.fix_project(root_dir, exclude_patterns=config.exclude)
        total_pruned = sum(len(res.pruned_items) for res in fix_results.values())
        print_msg(
            f"[green]Successfully fixed {len(fix_results)} file(s), pruned {total_pruned} dead code item(s).[/green]"
        )
        for p, res in fix_results.items():
            try:
                rel_p = p.relative_to(root_dir)
            except ValueError:
                rel_p = p
            print_msg(f"  [cyan]{rel_p}[/cyan]: {len(res.pruned_items)} pruned")
        return 0

    report = detector.scan_project(root_dir, exclude_patterns=config.exclude)

    if getattr(args, "json", False):
        return _render_dead_code_json(report.items)

    target_base = args.paths[0] if args.paths else "."
    return _render_dead_code_cli_summary(report, print_msg, target_base)


def _render_types_json(findings: Sequence[Any], has_errors: bool) -> int:
    data = [
        {
            "file": f.filepath,
            "line": f.lineno,
            "column": f.column,
            "severity": f.severity,
            "category": f.category,
            "message": f.message,
            "expected": f.expected_type,
            "actual": f.actual_type,
            "code_snippet": f.code_snippet,
        }
        for f in findings
    ]
    print(json.dumps(data, indent=2))
    return 1 if has_errors else 0


def _render_types_table(
    findings: Sequence[Any], console: Any, target_base: str
) -> None:
    table = Table(title="Type Inconsistencies & Violations", show_lines=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("File:Line:Col", width=38)
    table.add_column("Expected", width=15)
    table.add_column("Actual", width=15)
    table.add_column("Message", min_width=30)

    for f in findings:
        rel_path = _try_relative(f.filepath, target_base)
        style = "bold red" if f.severity == "error" else "yellow"
        table.add_row(
            f"[{style}]{f.severity.upper()}[/{style}]",
            f"{rel_path}:{f.lineno}:{f.column}",
            f.expected_type or "-",
            f.actual_type or "-",
            f.message,
        )
    console.print(table)


def _render_types_cli_summary(
    report: Any, print_msg: Any, console: Any, target_base: str
) -> int:
    print_msg(
        f"\n[bold cyan]Type Check Report ({report.files_scanned} files, {report.functions_checked} functions):[/bold cyan]"
    )
    if not report.findings:
        print_msg(
            "  [green]Zero type errors detected across all checked modules.[/green]"
        )
        return 0

    if has_rich and console:
        _render_types_table(report.findings, console, target_base)
    else:
        for f in report.findings:
            rel = _try_relative(f.filepath, target_base)
            print_msg(
                f"  [{f.severity.upper()}] {rel}:{f.lineno} — {f.message} (expected {f.expected_type}, got {f.actual_type})"
            )

    print_msg(f"\n  Total: {report.count} type finding(s) detected.")
    return 1 if report.has_errors else 0


def _cmd_types(
    args: argparse.Namespace, config: PyCleanerConfig, print_msg, console
) -> int:
    """Bidirectional type checking and inference with Typeshed stubs."""
    root_dir = Path(args.paths[0]).resolve() if args.paths else Path.cwd()
    if not root_dir.is_dir():
        root_dir = root_dir.parent

    checker = TypeChecker(strict=config.strict_types)
    report = checker.check_project(root_dir, exclude_patterns=config.exclude)

    target_base = args.paths[0] if args.paths else "."
    if getattr(args, "json", False):
        return _render_types_json(report.findings, report.has_errors)
    return _render_types_cli_summary(report, print_msg, console, target_base)


def _render_taint_json(findings: Sequence[Any], count: int) -> int:
    data = [
        {
            "file": f.filepath,
            "line": f.lineno,
            "col": f.col_offset,
            "severity": f.severity,
            "sink_type": f.sink_type,
            "sink": f.sink_call,
            "source": f.source_desc,
            "source_line": f.source_lineno,
            "path": f.propagation_path,
            "message": f.message,
            "suggestion": f.suggestion,
        }
        for f in findings
    ]
    print(json.dumps(data, indent=2))
    return 1 if count > 0 else 0


def _render_taint_table(
    findings: Sequence[Any], console: Any, target_base: str
) -> None:
    table = Table(title="Dataflow Taint Vulnerabilities", show_lines=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Vulnerability Type", width=20)
    table.add_column("File:Line", width=35)
    table.add_column("Sink Call", width=22)
    table.add_column("Remediation", min_width=30)

    for f in findings:
        rel_path = _try_relative(f.filepath, target_base)
        style = "bold red" if f.severity == "CRITICAL" else "red"
        table.add_row(
            f"[{style}]{f.severity}[/{style}]",
            f.sink_type,
            f"{rel_path}:{f.lineno}",
            f.sink_call,
            f.suggestion,
        )
    console.print(table)


def _render_taint_cli_summary(
    report: Any, print_msg: Any, console: Any, target_base: str
) -> int:
    print_msg(
        f"\n[bold cyan]Taint Analysis Report ({report.files_scanned} files, {report.sinks_checked} sinks, {report.sources_detected} sources):[/bold cyan]"
    )
    if not report.findings:
        print_msg("  [green]Zero dataflow taint vulnerabilities detected.[/green]")
        return 0

    if has_rich and console:
        _render_taint_table(report.findings, console, target_base)
    else:
        print_msg(report.format_summary())

    sink_types = sorted({f.sink_type for f in report.findings})
    if sink_types:
        by_sink = ", ".join(
            f"{st} ({len(report.by_sink_type(st))})" for st in sink_types
        )
        print_msg(f"\n  Vulnerabilities by sink type: {by_sink}")

    status_tag = (
        " [bold red](critical vulnerabilities found)[/bold red]"
        if report.has_critical
        else ""
    )
    print_msg(
        f"\n  Total: {report.count} taint vulnerability finding(s) detected.{status_tag}"
    )
    return 1 if report.count > 0 else 0


def _cmd_taint(
    args: argparse.Namespace, config: PyCleanerConfig, print_msg, console
) -> int:
    """Interprocedural SAST dataflow and taint vulnerability analysis."""
    root_dir = Path(args.paths[0]).resolve() if args.paths else Path.cwd()
    if not root_dir.is_dir():
        root_dir = root_dir.parent

    engine = TaintEngine()
    report = engine.scan_path(root_dir, exclude_patterns=config.exclude)

    target_base = args.paths[0] if args.paths else "."
    if getattr(args, "json", False):
        return _render_taint_json(report.findings, report.count)
    return _render_taint_cli_summary(report, print_msg, console, target_base)


def _cmd_test_gen(args: argparse.Namespace, config: PyCleanerConfig, print_msg) -> int:
    """Automated behavioral contract test generator."""
    root_dir = Path(args.paths[0]).resolve() if args.paths else Path.cwd()
    output_dir = getattr(args, "output_dir", None)
    preview = getattr(args, "preview", False)

    generator = TestGenerator()
    suites = generator.generate_for_project(root_dir, output_dir=output_dir)

    if getattr(args, "json", False):
        data = [
            {
                "module": s.module_name,
                "target_file": s.target_filepath,
                "tests_generated": s.test_count,
            }
            for s in suites
        ]
        print(json.dumps(data, indent=2))
        return 0

    total_tests = sum(s.test_count for s in suites)
    print_msg("\n[bold cyan]Behavioral Test Synthesizer:[/bold cyan]")
    print_msg(
        f"  Generated [bold green]{total_tests}[/bold green] test(s) across {len(suites)} suite(s)."
    )

    if preview:
        for s in suites:
            print_msg(
                f"\n[bold yellow]--- {s.module_name} (tests: {s.test_count}) ---[/bold yellow]"
            )
            print(s.rendered_code)

    if output_dir:
        print_msg(f"  Saved test suites to [bold]{output_dir}[/bold]")
    elif not preview:
        print_msg(
            "  [dim]Tip: Pass --output-dir <DIR> to save test suites or --preview to inspect.[/dim]"
        )

    return 0


def _run_ultimate_phases(
    args: argparse.Namespace,
    config: PyCleanerConfig,
    print_msg: Any,
    console: Any,
) -> tuple[int, int, int, int, int]:
    print_msg(
        "[bold blue]Phase 1: Syntax Healing, Import Resolution, & Canonical Formatting[/bold blue]"
    )
    fix_rc = _cmd_fix(
        args,
        config,
        print_msg,
        console,
        _FixOptions(
            apply_changes=True,
            show_diff=getattr(args, "diff", False),
        ),
    )
    print_msg(
        "\n[bold blue]Phase 2: Project Dependency Audit & Reconciliation[/bold blue]"
    )
    audit_rc = _cmd_audit(args, config, print_msg)
    print_msg(
        "\n[bold blue]Phase 3: Bidirectional Type Verification & Typeshed Resolution[/bold blue]"
    )
    type_rc = _cmd_types(args, config, print_msg, console)
    print_msg(
        "\n[bold blue]Phase 4: Interprocedural SAST Dataflow & Taint Analysis[/bold blue]"
    )
    taint_rc = _cmd_taint(args, config, print_msg, console)
    print_msg("\n[bold blue]Phase 5: AST Security Pattern Scan[/bold blue]")
    scan_rc = _cmd_scan(args, config, print_msg, console)
    return fix_rc, audit_rc, type_rc, taint_rc, scan_rc


def _cmd_ultimate(
    args: argparse.Namespace, config: PyCleanerConfig, print_msg: Any, console: Any
) -> int:
    """The Ultimate Python Tool flagship runner: executes full multi-layer analysis."""
    print_msg(
        "[bold magenta]=== PyCleaner Ultimate: Full Spectrum Analysis & Healing ===[/bold magenta]\n"
    )
    fix_rc, audit_rc, type_rc, taint_rc, scan_rc = _run_ultimate_phases(
        args, config, print_msg, console
    )
    print_msg(
        "\n[bold blue]Phase 6: Structural Complexity & Dead Code Discovery[/bold blue]"
    )
    _cmd_complexity(args, config, print_msg, console)
    _cmd_dead_code(args, config, print_msg, console)
    print_msg(
        "\n[bold magenta]=== Ultimate Python Tool: Analysis Complete ===[/bold magenta]"
    )
    return max(fix_rc, audit_rc, type_rc, taint_rc, scan_rc)


def _collect_file_mtimes(files: Sequence[Path]) -> dict[Path, float]:
    mtimes: dict[Path, float] = {}
    for f in files:
        try:
            mtimes[f] = f.stat().st_mtime
        except OSError:
            mtimes[f] = 0.0
    return mtimes


def _describe_watch_changes(result: CleanResult) -> str:
    changes: list[str] = []
    if result.syntax_repairs:
        changes.append(f"{len(result.syntax_repairs)} syntax")
    if result.resolved_imports:
        changes.append(f"{len(result.resolved_imports)} import")
    if result.lint_changed:
        changes.append("lint")
    if result.format_changed:
        changes.append("format")
    return ", ".join(changes)


def _process_watch_change(
    py_file: Path,
    pipeline: CleanPipeline,
    backup: bool,
    print_msg: Any,
) -> None:
    result = pipeline.process_file(py_file, apply_changes=True, backup=backup)
    if result.changed:
        detail = _describe_watch_changes(result)
        print_msg(f"  [green]Fixed:[/green] {py_file.name} ({detail})")
    elif result.error:
        print_msg(f"  [red]Error:[/red] {py_file.name}: {result.error}")


def _scan_watch_changes(
    current_files: Sequence[Path],
    mtimes: dict[Path, float],
    pipeline: CleanPipeline,
    backup: bool,
    print_msg: Any,
) -> None:
    for py_file in current_files:
        try:
            current_mtime = py_file.stat().st_mtime
        except OSError:
            continue
        if current_mtime > mtimes.get(py_file, 0.0):
            mtimes[py_file] = current_mtime
            _process_watch_change(py_file, pipeline, backup, print_msg)


def _cmd_watch(
    args: argparse.Namespace, config: PyCleanerConfig, print_msg: Any
) -> int:
    """Watch mode: monitor files for changes and re-run pipeline on save."""
    interval = getattr(args, "interval", 1.0)
    root_dir = Path(args.paths[0]).resolve() if args.paths else Path.cwd()
    if not root_dir.is_dir():
        root_dir = root_dir.parent

    py_files = discover_python_files(args.paths, config=config, root=root_dir)
    if not py_files:
        print_msg("No Python files found to watch.", style="yellow")
        return 0

    print_msg(
        f"[bold blue]Watching {len(py_files)} file(s) for changes (poll every {interval}s)...[/bold blue]"
    )
    print_msg("[dim]Press Ctrl+C to stop.[/dim]")

    pipeline = CleanPipeline(
        enable_syntax_healing=not getattr(args, "no_syntax_fix", False),
        enable_import_resolution=not getattr(args, "no_missing_imports", False),
        enable_lint_fixing=not getattr(args, "no_lint_fix", False),
        enable_formatting=not getattr(args, "no_format", False),
        config=config,
    )
    backup = config.backup and not getattr(args, "no_backup", False)
    mtimes = _collect_file_mtimes(py_files)

    try:
        while True:
            time.sleep(interval)
            current_files = discover_python_files(
                args.paths, config=config, root=root_dir
            )
            _scan_watch_changes(current_files, mtimes, pipeline, backup, print_msg)
    except KeyboardInterrupt:
        print_msg("\n[bold]Watch mode stopped.[/bold]")
        return 0


def _cmd_hook(args: argparse.Namespace, print_msg) -> int:
    """Output pre-commit hook configuration and setup instructions."""
    from pycleaner import __version__

    hook_yaml = (
        "- id: pycleaner\n"
        "  name: pycleaner\n"
        "  description: Static Python code cleanup, analysis, and security suite\n"
        "  entry: pycleaner fix\n"
        "  language: python\n"
        "  types: [python]\n"
        "  require_serial: true\n"
    )
    if getattr(args, "json", False):
        print(
            json.dumps(
                {
                    "pre_commit_hook": hook_yaml,
                    "status": "ok",
                },
                indent=2,
            )
        )
        return 0

    print_msg("[bold cyan]Pre-commit Hook Integration:[/bold cyan]\n")
    print_msg(
        "To integrate pycleaner with pre-commit, add the following to [bold].pre-commit-hooks.yaml[/bold]:\n"
    )
    print_msg(hook_yaml.replace("[", "\\["))
    print_msg("Then in your repository's [bold].pre-commit-config.yaml[/bold], add:\n")
    print_msg(
        "  repos:\n"
        "    - repo: https://github.com/moonrox420/ball-python\n"
        f"      rev: v{__version__}\n"
        "      hooks:\n"
        "        - id: pycleaner\n"
        '          args: ["check"]  # Use check for non-mutating validation\n'
    )
    return 0


def _try_relative(filepath: str, base: str) -> str:
    """Attempt to make a path relative for display."""
    try:
        return str(Path(filepath).relative_to(Path(base).resolve()))
    except ValueError:
        return Path(filepath).name


if __name__ == "__main__":
    sys.exit(main())
