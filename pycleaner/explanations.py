"""
pycleaner.explanations
======================

Comprehensive diagnostic explanations, remediation guides, and architectural
rationale for PyCleaner rules, security findings, and verification tiers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class RuleExplanation:
    code: str
    title: str
    category: str
    severity: str
    description: str
    vulnerable_example: str
    remediated_example: str
    remediation_details: str


_RULES_REGISTRY: Dict[str, RuleExplanation] = {
    "DC001": RuleExplanation(
        code="DC001",
        title="Unused Local Variable",
        category="Dead Code Elimination",
        severity="Low",
        description=(
            "A variable is assigned or bound in a local function scope but is never referenced, "
            "read, or returned anywhere within that scope. This clutters code, consumes memory, "
            "and often signals incomplete logic or leftover debugging artifacts."
        ),
        vulnerable_example=(
            "def calculate_total(items: list[float]) -> float:\n"
            "    tax_rate = 0.08  # DC001: assigned but never used\n"
            "    return sum(items)\n"
        ),
        remediated_example=(
            "def calculate_total(items: list[float]) -> float:\n"
            "    return sum(items)\n"
        ),
        remediation_details=(
            "PyCleaner prunes the unused assignment statement if it is side-effect free. "
            "If the expression on the right-hand side has potential side effects (such as a function call), "
            "PyCleaner preserves the call and removes only the unused variable binding."
        ),
    ),
    "DC002": RuleExplanation(
        code="DC002",
        title="Unused Import",
        category="Dead Code Elimination",
        severity="Low",
        description=(
            "A module or symbol is imported at the module level or within a function, but is never "
            "referenced across the AST. Unused imports slow down process startup time, introduce "
            "unnecessary coupling, and complicate dependency auditing."
        ),
        vulnerable_example=(
            "import os\n"
            "import sys  # DC002: sys is never referenced\n"
            "from pathlib import Path\n\n"
            "print(os.getcwd())\n"
        ),
        remediated_example=(
            "import os\n"
            "from pathlib import Path\n\n"
            "print(os.getcwd())\n"
        ),
        remediation_details=(
            "PyCleaner cleanly removes the unused alias or entire import line without altering "
            "unrelated imports or docstrings."
        ),
    ),
    "DC003": RuleExplanation(
        code="DC003",
        title="Unused Private Function or Method",
        category="Dead Code Elimination",
        severity="Medium",
        description=(
            "A private helper function or method (prefixed with an underscore '_') is defined within "
            "a module or class, but has zero internal call references throughout the workspace. "
            "Because private functions cannot be part of the public API contract, unreferenced private "
            "functions represent dead code."
        ),
        vulnerable_example=(
            "def _internal_helper(x: int) -> int:  # DC003: never called\n"
            "    return x * 2\n\n"
            "def public_api(val: int) -> int:\n"
            "    return val + 1\n"
        ),
        remediated_example=(
            "def public_api(val: int) -> int:\n"
            "    return val + 1\n"
        ),
        remediation_details=(
            "PyCleaner identifies dead private callables across the project graph and prunes them, "
            "while respecting framework entry points (e.g. pytest hooks, FastAPI routes, and dataclass fields)."
        ),
    ),
    "SEC001": RuleExplanation(
        code="SEC001",
        title="SQL Injection Vulnerability",
        category="Security & Taint Analysis",
        severity="Critical",
        description=(
            "Dynamic string interpolation or concatenation is used to construct a SQL query using "
            "untrusted parameters. This allows attackers to manipulate query structure, bypass "
            "authentication, or extract unauthorized database records."
        ),
        vulnerable_example=(
            "def get_user(db_cursor, username: str):\n"
            "    query = f\"SELECT * FROM users WHERE username = '{username}'\"  # SEC001\n"
            "    db_cursor.execute(query)\n"
        ),
        remediated_example=(
            "def get_user(db_cursor, username: str):\n"
            "    query = \"SELECT * FROM users WHERE username = %s\"\n"
            "    db_cursor.execute(query, (username,))\n"
        ),
        remediation_details=(
            "Always use parameterized queries or ORM abstractions (SQLAlchemy, Django ORM). "
            "Never construct SQL statements via f-strings, %, or str.format."
        ),
    ),
    "SEC002": RuleExplanation(
        code="SEC002",
        title="Command Injection via Subprocess",
        category="Security & Taint Analysis",
        severity="Critical",
        description=(
            "Executing shell commands using `shell=True` or string interpolation with `subprocess.Popen`, "
            "`subprocess.run`, or `os.system`. Attackers can append shell metacharacters (;, &, |) to execute "
            "arbitrary OS binaries with the privileges of the running process."
        ),
        vulnerable_example=(
            "import subprocess\n\n"
            "def ping_host(host: str):\n"
            "    subprocess.run(f\"ping -c 1 {host}\", shell=True)  # SEC002\n"
        ),
        remediated_example=(
            "import subprocess\n\n"
            "def ping_host(host: str):\n"
            "    subprocess.run([\"ping\", \"-c\", \"1\", host], shell=False, check=True)\n"
        ),
        remediation_details=(
            "Pass command arguments strictly as a list of strings and set `shell=False`. "
            "This bypasses the shell interpreter entirely, immunizing against metacharacter injection."
        ),
    ),
    "SEC003": RuleExplanation(
        code="SEC003",
        title="Path Traversal Vulnerability",
        category="Security & Taint Analysis",
        severity="High",
        description=(
            "Filesystem paths constructed using unsanitized user inputs allow directory traversal sequences "
            "('../') to read, overwrite, or delete arbitrary files outside the intended root folder."
        ),
        vulnerable_example=(
            "from pathlib import Path\n\n"
            "def read_file(root_dir: Path, user_filename: str) -> str:\n"
            "    target = root_dir / user_filename  # SEC003: e.g. '../../etc/passwd'\n"
            "    return target.read_text()\n"
        ),
        remediated_example=(
            "from pathlib import Path\n\n"
            "def read_file(root_dir: Path, user_filename: str) -> str:\n"
            "    target = (root_dir / user_filename).resolve()\n"
            "    if not target.is_relative_to(root_dir.resolve()):\n"
            "        raise PermissionError('Path traversal attempt detected')\n"
            "    return target.read_text()\n"
        ),
        remediation_details=(
            "Canonicalize paths with `.resolve()` and verify that the target path is strictly relative "
            "to the root boundary using `path.is_relative_to(base_dir)`."
        ),
    ),
    "CMP001": RuleExplanation(
        code="CMP001",
        title="Excessive Cyclomatic Complexity",
        category="Cognitive & Complexity Architecture",
        severity="Medium",
        description=(
            "The cyclomatic complexity of a function exceeds the configured threshold (default: 10). "
            "Functions with too many independent linear execution paths are difficult to reason about, "
            "prone to regression bugs, and hard to test exhaustively."
        ),
        vulnerable_example=(
            "def dispatch_event(event_type: str, data: dict):\n"
            "    if event_type == 'A':\n"
            "        ...\n"
            "    elif event_type == 'B':\n"
            "        ...\n"
            "    # 15 additional elif branches...\n"
        ),
        remediated_example=(
            "HANDLERS = {'A': handle_a, 'B': handle_b}\n\n"
            "def dispatch_event(event_type: str, data: dict):\n"
            "    handler = HANDLERS.get(event_type, default_handler)\n"
            "    return handler(data)\n"
        ),
        remediation_details=(
            "Refactor complex nested branching using lookup tables, dictionary dispatch, polymorphism, "
            "or by decomposing into smaller cohesive helper functions."
        ),
    ),
    "SYN001": RuleExplanation(
        code="SYN001",
        title="Unclosed Delimiter / Syntax Error Healing",
        category="Syntax Healing",
        severity="High",
        description=(
            "The source file contains an unclosed bracket, brace, parenthesis, or incomplete block "
            "that prevents Python from compiling the file (`SyntaxError`)."
        ),
        vulnerable_example=(
            "items = [\n"
            "    {'id': 1, 'name': 'test'\n"
            "print('hello')\n"
        ),
        remediated_example=(
            "items = [\n"
            "    {'id': 1, 'name': 'test'}\n"
            "]\n"
            "print('hello')\n"
        ),
        remediation_details=(
            "PyCleaner's Syntax Healer uses token-stream stack analysis to detect unclosed delimiters "
            "and automatically synthesizes minimal, correct closure tokens at the appropriate line boundaries."
        ),
    ),
    "TYPE001": RuleExplanation(
        code="TYPE001",
        title="Incompatible Type Assignment",
        category="Static Type Checking",
        severity="High",
        description=(
            "An expression of one type is assigned to a variable annotated with an incompatible type "
            "(e.g. assigning a `str` to an `int`), violating static type contracts."
        ),
        vulnerable_example=(
            "count: int = 0\n"
            "count = 'none'  # TYPE001: incompatible assignment\n"
        ),
        remediated_example=(
            "count: int | None = 0\n"
            "count = None\n"
        ),
        remediation_details=(
            "Update variable type annotations to represent the full union of allowable states, or "
            "convert the assigned value to the expected type."
        ),
    ),
    "PROVE001": RuleExplanation(
        code="PROVE001",
        title="Verification Tier A: Proven Invariant-Preserving",
        category="Differential Equivalence Proof",
        severity="Info",
        description=(
            "The transformation has been verified against a suite of deterministically synthesized input "
            "permutations in an isolated process sandbox. The original and transformed callables produced "
            "100% identical outputs and exception behaviors across all fuzz iterations."
        ),
        vulnerable_example="# Baseline transformation before proof",
        remediated_example="# Verified transformation guaranteed safe for production application",
        remediation_details=(
            "Transformations achieving Tier A are marked safe for automatic disk application (`--apply`). "
            "A deterministic proof receipt is recorded with seed, execution duration, and iterations."
        ),
    ),
    "PROVE002": RuleExplanation(
        code="PROVE002",
        title="Verification Tier B: Suggested Transformation",
        category="Differential Equivalence Proof",
        severity="Info",
        description=(
            "The transformation passed static syntax and lint validation, but cannot be dynamically fuzzed "
            "in an isolated sandbox (e.g. the callable depends on database connections, hardware sockets, "
            "external modules, or cannot be dynamically isolated)."
        ),
        vulnerable_example="# File with module-level side effects or unresolvable imports",
        remediated_example="# Suggested change for manual or test-suite verification",
        remediation_details=(
            "Tier B changes are suggested to the user. They can be applied with `pycleaner fix` or reviewed "
            "via `pycleaner prove --diff`."
        ),
    ),
    "PROVE003": RuleExplanation(
        code="PROVE003",
        title="Verification Tier C: Refused & Rolled Back",
        category="Differential Equivalence Proof",
        severity="Critical",
        description=(
            "A candidate transformation was falsified by the differential execution fuzzer. On at least one "
            "synthesized input vector, the transformed function produced a different return value or error "
            "than the original function."
        ),
        vulnerable_example=(
            "# Original:\n"
            "def is_positive(x: int) -> bool:\n"
            "    if x >= 0:\n"
            "        return True\n"
            "    return False\n\n"
            "# Flawed candidate:\n"
            "def is_positive(x: int) -> bool:\n"
            "    if x > 0:\n"
            "        return True\n"
            "    return False\n"
        ),
        remediated_example=(
            "# PyCleaner automatically rejects the candidate and rolls back the file:\n"
            "def is_positive(x: int) -> bool:\n"
            "    if x >= 0:\n"
            "        return True\n"
            "    return False\n"
        ),
        remediation_details=(
            "Tier C guarantees zero silent regressions. The file is immediately restored to its exact original "
            "state, and the falsifying counterexample (input arguments, original output, transformed output, "
            "and seed) is logged to stdout and `.pycleaner/verification-report.json`."
        ),
    ),
}


def get_explanation(code_or_topic: str) -> Optional[RuleExplanation]:
    """Retrieves the explanation for a given rule code or alias."""
    key = code_or_topic.strip().upper()
    return _RULES_REGISTRY.get(key)


def list_rules() -> list[RuleExplanation]:
    """Returns all available rule explanations sorted by code."""
    return sorted(_RULES_REGISTRY.values(), key=lambda r: r.code)
