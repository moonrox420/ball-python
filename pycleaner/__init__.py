"""
pycleaner - The Ultimate Static Python Intelligence, Healing, and Verification Suite.

Automatically heals syntax errors, resolves missing imports, prunes unused imports,
fixes linting violations, applies canonical formatting, audits project dependencies,
detects dead code, scans for security vulnerabilities, analyzes code complexity,
performs bidirectional type inference against Typeshed stubs, traces interprocedural
dataflow taint vulnerabilities, and synthesizes automated behavioral test suites.
"""

from __future__ import annotations

from pycleaner.discovery import (
    DEFAULT_IGNORED_DIRS,
    PROTECTED_FILE_PATTERNS,
    collect_project_python_files,
    is_ignored_directory,
    is_protected_file,
)

__version__ = "2.0.5"
__all__ = [
    "DEFAULT_IGNORED_DIRS",
    "PROTECTED_FILE_PATTERNS",
    "BaselineFingerprint",
    "BaselineManager",
    "CleanPipeline",
    "CleanResult",
    "ComplexityAnalyzer",
    "ComplexityReport",
    "ContentAddressableCache",
    "CounterExample",
    "DeadCodeDetector",
    "DeadCodeFixResult",
    "DeadCodeFixer",
    "DeadCodeReport",
    "DependencyAuditor",
    "GeneratedTestSuite",
    "ImportResolver",
    "IsolatedDifferentialVerifier",
    "LinterFormatter",
    "ModernizeResult",
    "Modernizer",
    "ProofReceipt",
    "PyCleanerConfig",
    "RuleExplanation",
    "SecurityReport",
    "SecurityScanner",
    "SyntaxHealer",
    "TaintEngine",
    "TaintFinding",
    "TaintReport",
    "TestCase",
    "TestGenerator",
    "TypeChecker",
    "TypeFinding",
    "TypeReport",
    "TypeshedResolver",
    "VerificationTier",
    "collect_project_python_files",
    "get_explanation",
    "is_ignored_directory",
    "is_protected_file",
    "list_rules",
    "load_config",
]

from pycleaner.baseline import BaselineFingerprint, BaselineManager
from pycleaner.cache import ContentAddressableCache
from pycleaner.complexity_analyzer import ComplexityAnalyzer, ComplexityReport
from pycleaner.config import PyCleanerConfig, load_config
from pycleaner.dead_code_detector import (
    DeadCodeDetector,
    DeadCodeFixer,
    DeadCodeFixResult,
    DeadCodeReport,
)
from pycleaner.dependency_auditor import DependencyAuditor
from pycleaner.explanations import RuleExplanation, get_explanation, list_rules
from pycleaner.import_resolver import ImportResolver
from pycleaner.linter_formatter import LinterFormatter
from pycleaner.modernizer import Modernizer, ModernizeResult
from pycleaner.pipeline import CleanPipeline, CleanResult
from pycleaner.security_scanner import SecurityReport, SecurityScanner
from pycleaner.syntax_healer import SyntaxHealer
from pycleaner.taint_engine import TaintEngine, TaintFinding, TaintReport
from pycleaner.test_generator import GeneratedTestSuite, TestCase, TestGenerator
from pycleaner.type_checker import TypeChecker, TypeFinding, TypeReport
from pycleaner.typeshed_resolver import TypeshedResolver
from pycleaner.verifier import (
    CounterExample,
    IsolatedDifferentialVerifier,
    ProofReceipt,
    VerificationTier,
)
