"""
Static security pattern scanner for Python source code.

Detects dangerous function calls (eval, exec, pickle), hardcoded secrets,
SQL injection patterns, subprocess shell injection, insecure defaults,
and assert statements used for input validation.
"""

from __future__ import annotations

from pycleaner.discovery import collect_project_python_files

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class SecurityFinding:
    """A single security issue detected in source code."""

    filepath: str
    lineno: int
    end_lineno: int | None
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    category: str
    message: str
    suggestion: str
    code_snippet: str = ""


@dataclass(slots=True)
class SecurityReport:
    """Full security scan results."""

    findings: list[SecurityFinding] = field(default_factory=list)
    files_scanned: int = 0

    @property
    def count(self) -> int:
        return len(self.findings)

    def by_severity(self, severity: str) -> list[SecurityFinding]:
        return [f for f in self.findings if f.severity == severity]

    def by_category(self, category: str) -> list[SecurityFinding]:
        return [f for f in self.findings if f.category == category]

    @property
    def critical_count(self) -> int:
        return len(self.by_severity("CRITICAL"))

    @property
    def high_count(self) -> int:
        return len(self.by_severity("HIGH"))


# Regex patterns for detecting hardcoded secrets
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "AWS Access Key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "Use environment variables or a secrets manager",
    ),
    (
        "AWS Secret Key",
        re.compile(
            r"(?i)(?:aws_secret|secret_key|secret_access)\s*=\s*['\"][A-Za-z0-9/+=]{20,}['\"]"
        ),
        "Use environment variables or AWS credentials file",
    ),
    (
        "Generic API Key",
        re.compile(
            r"(?i)(?:api_key|apikey|api_secret)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]"
        ),
        "Use environment variables or a secrets manager",
    ),
    (
        "Generic Password",
        re.compile(r"(?i)(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]"),
        "Use environment variables or a secrets manager",
    ),
    (
        "Generic Secret",
        re.compile(
            r"(?i)(?:secret|token|bearer)\s*=\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]"
        ),
        "Use environment variables or a secrets manager",
    ),
    (
        "JWT Token",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "Never hardcode JWT tokens; load from secure storage",
    ),
    (
        "Private Key Header",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
        "Store private keys in files with restricted permissions, not in source code",
    ),
    (
        "GitHub Token",
        re.compile(r"gh[ps]_[A-Za-z0-9_]{36}"),
        "Use environment variables or GitHub's OIDC",
    ),
    (
        "Slack Token",
        re.compile(r"xox[bpras]-[A-Za-z0-9\-]{10,}"),
        "Use environment variables for Slack tokens",
    ),
]


_DANGEROUS_CALL_SPECS: dict[str, tuple[str, str, str, str]] = {
    "eval": (
        "CRITICAL",
        "dangerous-eval",
        "eval() executes arbitrary Python code",
        "Avoid eval() with untrusted input; use safe alternatives",
    ),
    "exec": (
        "CRITICAL",
        "dangerous-exec",
        "exec() executes arbitrary Python code",
        "Avoid exec() with untrusted input; use safe alternatives",
    ),
    "compile": (
        "HIGH",
        "dangerous-compile",
        "compile() can enable code execution",
        "Avoid compile() with untrusted input; use safe alternatives",
    ),
    "__import__": (
        "MEDIUM",
        "dynamic-import",
        "__import__() enables dynamic module loading",
        "Avoid __import__() with untrusted input; use safe alternatives",
    ),
    "pickle.loads": (
        "CRITICAL",
        "insecure-deserialization",
        "pickle.loads() deserializes arbitrary objects and can execute arbitrary code",
        "Use json.loads() or a restricted deserializer instead",
    ),
    "pickle.load": (
        "CRITICAL",
        "insecure-deserialization",
        "pickle.load() deserializes arbitrary objects and can execute arbitrary code",
        "Use json.loads() or a restricted deserializer instead",
    ),
    "cPickle.loads": (
        "CRITICAL",
        "insecure-deserialization",
        "cPickle.loads() deserializes arbitrary objects and can execute arbitrary code",
        "Use json.loads() or a restricted deserializer instead",
    ),
    "cPickle.load": (
        "CRITICAL",
        "insecure-deserialization",
        "cPickle.load() deserializes arbitrary objects and can execute arbitrary code",
        "Use json.loads() or a restricted deserializer instead",
    ),
    "marshal.loads": (
        "HIGH",
        "insecure-deserialization",
        "marshal.loads() can crash the interpreter with malformed input",
        "Use json.loads() for data interchange",
    ),
    "marshal.load": (
        "HIGH",
        "insecure-deserialization",
        "marshal.load() can crash the interpreter with malformed input",
        "Use json.loads() for data interchange",
    ),
    "os.system": (
        "HIGH",
        "shell-injection",
        "os.system() passes commands through the shell and is vulnerable to injection",
        "Use subprocess.run() with a list of arguments (no shell=True)",
    ),
}


class _DangerousCallDetector(ast.NodeVisitor):
    """Detects dangerous function calls and insecure patterns in Python AST."""

    def __init__(self, filepath: str, source_lines: list[str]) -> None:
        self.filepath = filepath
        self.source_lines = source_lines
        self.findings: list[SecurityFinding] = []

    def _get_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._get_call_name(node)
        if func_name:
            self._check_dangerous_calls(node, func_name)
            self._check_insecure_defaults(node, func_name)
            self._check_sql_injection(node, func_name)
            self._check_subprocess_shell(node, func_name)
            self._check_yaml_unsafe_load(node, func_name)
        self.generic_visit(node)

    @staticmethod
    def _is_test_path(filepath: str) -> bool:
        parts = [p.lower() for p in Path(filepath).parts[:-1]]
        return any(p in ("tests", "test", "testing") for p in parts)

    def visit_Assert(self, node: ast.Assert) -> None:
        if self._is_test_path(self.filepath):
            return
        self.findings.append(
            SecurityFinding(
                filepath=self.filepath,
                lineno=node.lineno,
                end_lineno=getattr(node, "end_lineno", None),
                severity="LOW",
                category="assert-in-production",
                message="'assert' used for validation; assert statements are stripped when Python runs with -O flag",
                suggestion="Use 'if not condition: raise ValueError(...)' for input validation",
                code_snippet=self._get_snippet(node.lineno),
            )
        )
        self.generic_visit(node)

    def _get_call_name(self, node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            value_name = self._get_dotted_name(node.func.value)
            if value_name:
                return f"{value_name}.{node.func.attr}"
            return node.func.attr
        return None

    @staticmethod
    def _get_dotted_name(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = _DangerousCallDetector._get_dotted_name(node.value)
            if parent:
                return f"{parent}.{node.attr}"
        return None

    def _check_dangerous_calls(self, node: ast.Call, func_name: str) -> None:
        spec = _DANGEROUS_CALL_SPECS.get(func_name)
        if spec:
            severity, category, msg, suggestion = spec
            self.findings.append(
                SecurityFinding(
                    filepath=self.filepath,
                    lineno=node.lineno,
                    end_lineno=getattr(node, "end_lineno", None),
                    severity=severity,
                    category=category,
                    message=msg,
                    suggestion=suggestion,
                    code_snippet=self._get_snippet(node.lineno),
                )
            )

    def _check_subprocess_shell(self, node: ast.Call, func_name: str) -> None:
        subprocess_funcs = {
            "subprocess.call",
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.check_output",
            "subprocess.check_call",
        }
        if func_name not in subprocess_funcs:
            return

        for kw in node.keywords:
            if (
                kw.arg == "shell"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
            ):
                self.findings.append(
                    SecurityFinding(
                        filepath=self.filepath,
                        lineno=node.lineno,
                        end_lineno=getattr(node, "end_lineno", None),
                        severity="HIGH",
                        category="shell-injection",
                        message=f"{func_name}(shell=True) is vulnerable to shell injection",
                        suggestion="Pass arguments as a list without shell=True",
                        code_snippet=self._get_snippet(node.lineno),
                    )
                )

    def _check_insecure_tls(self, node: ast.Call, func_name: str) -> None:
        http_funcs = {
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.delete",
            "requests.patch",
            "requests.head",
            "requests.options",
            "requests.request",
            "httpx.get",
            "httpx.post",
            "httpx.put",
            "httpx.delete",
            "httpx.patch",
            "httpx.head",
            "httpx.options",
            "httpx.request",
        }
        if func_name in http_funcs:
            for kw in node.keywords:
                if (
                    kw.arg == "verify"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is False
                ):
                    self.findings.append(
                        SecurityFinding(
                            filepath=self.filepath,
                            lineno=node.lineno,
                            end_lineno=getattr(node, "end_lineno", None),
                            severity="HIGH",
                            category="insecure-tls",
                            message=f"{func_name}(verify=False) disables TLS certificate verification",
                            suggestion="Remove verify=False or use a custom CA bundle",
                            code_snippet=self._get_snippet(node.lineno),
                        )
                    )

    def _check_debug_mode(self, node: ast.Call, func_name: str) -> None:
        if func_name in ("app.run", "application.run"):
            for kw in node.keywords:
                if (
                    kw.arg == "debug"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    self.findings.append(
                        SecurityFinding(
                            filepath=self.filepath,
                            lineno=node.lineno,
                            end_lineno=getattr(node, "end_lineno", None),
                            severity="MEDIUM",
                            category="debug-mode",
                            message="Running with debug=True exposes debugger and stack traces in production",
                            suggestion="Set debug=False for production deployments",
                            code_snippet=self._get_snippet(node.lineno),
                        )
                    )

    def _check_insecure_defaults(self, node: ast.Call, func_name: str) -> None:
        self._check_insecure_tls(node, func_name)
        self._check_debug_mode(node, func_name)

    def _check_yaml_unsafe_load(self, node: ast.Call, func_name: str) -> None:
        if func_name in ("yaml.load", "yaml.unsafe_load"):
            has_safe_loader = False
            for kw in node.keywords:
                if kw.arg == "Loader" and (
                    (
                        isinstance(kw.value, ast.Attribute)
                        and kw.value.attr in ("SafeLoader", "FullLoader", "BaseLoader")
                    )
                    or (
                        isinstance(kw.value, ast.Name)
                        and kw.value.id in ("SafeLoader", "FullLoader", "BaseLoader")
                    )
                ):
                    has_safe_loader = True
            if not has_safe_loader and func_name == "yaml.load":
                self.findings.append(
                    SecurityFinding(
                        filepath=self.filepath,
                        lineno=node.lineno,
                        end_lineno=getattr(node, "end_lineno", None),
                        severity="CRITICAL",
                        category="insecure-deserialization",
                        message="yaml.load() without SafeLoader can execute arbitrary Python objects",
                        suggestion="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
                        code_snippet=self._get_snippet(node.lineno),
                    )
                )

    @staticmethod
    def _is_dynamic_sql_arg(arg: ast.AST) -> bool:
        if isinstance(arg, ast.JoinedStr):
            return True
        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
            return True
        if isinstance(arg, ast.Call):
            return isinstance(arg.func, ast.Attribute) and arg.func.attr == "format"
        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
            return isinstance(arg.left, ast.Constant) and isinstance(
                arg.left.value, str
            )
        return False

    def _check_sql_injection(self, node: ast.Call, func_name: str) -> None:
        sql_methods = {"execute", "executemany", "executescript"}
        method_name = func_name.split(".")[-1] if "." in func_name else ""
        if method_name not in sql_methods or not node.args:
            return

        if self._is_dynamic_sql_arg(node.args[0]):
            self.findings.append(
                SecurityFinding(
                    filepath=self.filepath,
                    lineno=node.lineno,
                    end_lineno=getattr(node, "end_lineno", None),
                    severity="CRITICAL",
                    category="sql-injection",
                    message="SQL query built with string formatting is vulnerable to SQL injection",
                    suggestion="Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=?', (id,))",
                    code_snippet=self._get_snippet(node.lineno),
                )
            )


class SecurityScanner:
    """Scans Python source code for security vulnerabilities."""

    IGNORE_DIRS = frozenset(
        {
            ".git",
            ".venv",
            "venv",
            "env",
            "__pycache__",
            "build",
            "dist",
            ".tox",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            "site-packages",
        }
    )

    def __init__(
        self,
        severity_threshold: str = "LOW",
        ignore_rules: set[str] | None = None,
    ) -> None:
        self.severity_threshold = severity_threshold
        self.ignore_rules = ignore_rules or set()
        self._severity_order = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "INFO": 0,
        }

    def scan_source(self, source: str, filename: str = "<unknown>") -> SecurityReport:
        """Scan a single source string for security issues."""
        findings: list[SecurityFinding] = []

        try:
            tree = ast.parse(source, filename=filename)
            source_lines = source.splitlines()
            detector = _DangerousCallDetector(filename, source_lines)
            detector.visit(tree)
            findings.extend(detector.findings)
        except SyntaxError:
            # Code with syntax errors cannot be AST-parsed; regex checks still run
            pass

        findings.extend(self._detect_secrets(source, filename))

        filtered = self._filter_findings(findings)
        filtered.sort(
            key=lambda f: (self._severity_order.get(f.severity, 0) * -1, f.lineno)
        )

        return SecurityReport(findings=filtered, files_scanned=1)

    def _discover_project_py_files(self, root: Path) -> list[Path]:
        return collect_project_python_files(root)

    def scan_project(self, root_dir: Path | str) -> SecurityReport:
        """Scan all Python files in a project for security issues."""
        root = Path(root_dir).resolve()
        py_files = self._discover_project_py_files(root)
        all_findings: list[SecurityFinding] = []

        for fpath in py_files:
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
                report = self.scan_source(content, filename=str(fpath))
                all_findings.extend(report.findings)
            except OSError:
                continue

        all_findings.sort(
            key=lambda f: (
                self._severity_order.get(f.severity, 0) * -1,
                f.filepath,
                f.lineno,
            )
        )
        return SecurityReport(findings=all_findings, files_scanned=len(py_files))

    @staticmethod
    def _is_test_placeholder_line(filename: str, line_lower: str) -> bool:
        if "test" not in filename.lower():
            return False
        placeholders = ("mock", "fake", "dummy", "example")
        return any(p in line_lower for p in placeholders)

    def _detect_secrets(self, source: str, filename: str) -> list[SecurityFinding]:
        """Detect hardcoded secrets using regex patterns."""
        if _DangerousCallDetector._is_test_path(filename):
            return []

        findings: list[SecurityFinding] = []
        for i, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or self._is_test_placeholder_line(
                filename, stripped.lower()
            ):
                continue

            for name, pattern, suggestion in _SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        SecurityFinding(
                            filepath=filename,
                            lineno=i,
                            end_lineno=i,
                            severity="HIGH",
                            category="hardcoded-secret",
                            message=f"Potential {name} found hardcoded in source",
                            suggestion=suggestion,
                            code_snippet=stripped[:120],
                        )
                    )

        return findings

    def _filter_findings(
        self, findings: list[SecurityFinding]
    ) -> list[SecurityFinding]:
        """Filter findings by severity threshold and ignored rules."""
        threshold = self._severity_order.get(self.severity_threshold, 0)
        return [
            f
            for f in findings
            if self._severity_order.get(f.severity, 0) >= threshold
            and f.category not in self.ignore_rules
        ]
