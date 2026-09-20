# ballpython (pycleaner)

[![PyPI version](https://img.shields.io/pypi/v/ballpython.svg)](https://pypi.org/project/ballpython/)
[![Python Versions](https://img.shields.io/pypi/pyversions/ballpython.svg)](https://pypi.org/project/ballpython/)
[![CI](https://github.com/moonrox420/ball-python/actions/workflows/ci.yml/badge.svg)](https://github.com/moonrox420/ball-python/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**The Ultimate Static Python Intelligence, Healing, Type Verification, and Security Suite.**

A production-grade, offline Python static analysis engine, automated syntax repair tool, bidirectional type verifier, SAST dataflow taint tracer, differential execution prover, security scanner, cognitive complexity analyzer, dead code eliminator, and project dependency auditor.

Zero external LLM dependencies, zero mock abstractions, and engineered for high-concurrency developer workflows and deterministic CI/CD release gates.

Both `ballpython` and `pycleaner` CLI commands are provided as first-class, identical entrypoints.

---

## Key Architectural Capabilities

### 1. Syntax Healer (`SyntaxHealer`)
* **Compound Statement Repair:** Appends missing colons to compound statement headers (`def`, `class`, `if`, `elif`, `else`, `for`, `while`, `try`, `except`, `finally`, `with`, `async def`, `match`, `case`).
* **Conditional Assignment Healing:** Corrects accidental single `=` assignments in conditionals (`if x = 1:` $\to$ `if x == 1:`) while preserving keyword arguments (`func(x=1)`), augmented assignments (`x += 1`), and walrus expressions (`if (n := len(items)) > 0:`).
* **Python 2 Legacy Syntax Healing:** Modernizes legacy Python 2 print statements (`print "..."` $\to$ `print(...)`) and legacy except clauses (`except Exception, e:` $\to$ `except Exception as e:`), including comma-separated multi-exception tuples (`except (ValueError, ZeroDivisionError), err:` $\to$ `except (ValueError, ZeroDivisionError) as err:`).
* **Delimiter Reconstruction:** Token-level automatic closure of unclosed parentheses, brackets, and curly braces.
* **Indentation Repair:** Re-indents under-indented statement bodies following compound headers and normalizes tab characters to 4 spaces.
* **Compiler-Grade Diagnostics:** Emits Rust/Clang-style source code snippets with exact line, column, and caret pointers when syntax is unrecoverable.

### 2. Missing Import Resolver (`ImportResolver`)
* **AST Scope Traversal:** Traverses module, function, class, and comprehension scopes to detect undefined loaded symbols.
* **Standard Library & Alias Mapping:** Resolves missing identifiers across standard library modules (`os`, `sys`, `json`, `re`, `subprocess`, `pathlib`, etc.), collections, typing constructs, dataclasses, concurrent primitives (`ThreadPoolExecutor`, `Lock`, `Queue`), and popular third-party aliases (`np` $\to$ `numpy`, `pd` $\to$ `pandas`, `plt` $\to$ `matplotlib.pyplot`, `tf` $\to$ `tensorflow`).
* **`TYPE_CHECKING` Guarding:** Injects typing-only imports into `if TYPE_CHECKING:` conditional blocks to prevent circular runtime dependencies and injects `from __future__ import annotations` when type hints require postponed evaluation.
* **Custom Symbol Mapping:** Supports user-defined symbol-to-import mappings in `pyproject.toml`.

### 3. Linter & Canonical Formatter (`LinterFormatter`, `Modernizer`)
* **Dual-Engine Execution:** Drives high-performance Rust-based `ruff` via in-memory stream processing (`--stdin-filename`) with pure-Python fallbacks.
* **Dead Import & Variable Removal:** Cleans unused imports (`F401`) and unused local variables (`F841`).
* **Import Sorting & Organization:** Groups imports into standard library, third-party, and first-party local packages (PEP 8 / `isort`).
* **Type Annotation Modernization:** Transforms legacy typing constructs to modern PEP 585/604 syntax (`List[T]` $\to$ `list[T]`, `Dict[K, V]` $\to$ `dict[K, V]`, `Optional[T]` $\to$ `T | None`, `Union[A, B]` $\to$ `A | B`).
* **Legacy Construct Modernization:** Eliminates explicit `class X(object):` inheritance, cleans legacy `u"..."` unicode prefixes, and normalizes singleton identity comparisons (`== None` $\to$ `is None`).

### 4. Bidirectional Type Verifier (`TypeChecker`)
* **Typeshed Stubs Integration:** Bundles static typing stubs from Typeshed for standard library validation without requiring external type-checker daemons.
* **Cross-Function Argument Verification:** Inspects call sites against declared parameter types, keyword arguments, and default values.
* **Bidirectional Inference:** Propagates return types across calls, assignments, and container initializations, flagging incompatible type mutations.

### 5. Interprocedural SAST Dataflow & Taint Engine (`TaintEngine`)
* **Source-to-Sink Dataflow Graphs:** Traces untrusted user inputs (request parameters, environment variables, command-line arguments, file inputs) through function boundaries, assignments, and attribute accesses.
* **Vulnerability Sanitization Checks:** Flags unsanitized propagation into high-risk security sinks:
  - **SQL Injection:** Dynamic interpolation into `cursor.execute()`, `session.execute()`.
  - **Command Injection:** Untrusted strings passed to `subprocess.Popen(..., shell=True)` or `os.system()`.
  - **Path Traversal:** Unsanitized file paths passed to `open()`, `pathlib.Path()`, or `os.remove()`.
  - **Insecure Deserialization:** Untrusted payloads routed to `pickle.loads()`.

### 6. Static Security Pattern Scanner (`SecurityScanner`)
* **Dangerous Call Detection:** Flags `eval()`, `exec()`, `compile()`, and unsafe `yaml.load()` lacking `SafeLoader`.
* **Hardcoded Secret Detection:** Scans for AWS access keys, GitHub personal access tokens, Slack tokens, JWT secrets, and private key headers.
* **Production Assertion Warnings:** Flags `assert` statements used for business validation (which are stripped when Python executes under the `-O` optimization flag).
* **Multiline Comment Suppression:** Full support for `# nosec`, `# noqa`, and `# pycleaner: ignore` across single-line and multiline formatted call statements.

### 7. Proof-Carrying Differential Verifier (`IsolatedDifferentialVerifier`)
* **Isolated Worker Sandboxes:** Spawns isolated worker processes to differentially execute the original code and transformed code side-by-side using synthesised inputs.
* **Automated Rollback (Tier C):** If a transformed AST alters runtime behavior, causes a crash, or changes output return values, the modification is immediately refused and rolled back to preserve source code integrity.
* **Verification Tiers:**
  - **Tier A (Proven Invariant-Preserving):** Semantics identical under differential fuzzing.
  - **Tier B (Suggested Transformation):** Syntactically valid, lint-clean, but unverified by runtime execution.
  - **Tier C (Refused & Reverted):** Semantic divergence detected; modification rejected.

### 8. Behavioral Contract Test Generator (`BehavioralTestGenerator`)
* **Automated Pytest Synthesis:** Inspects function signatures, type annotations, and docstrings to synthesize robust, self-contained unit tests.
* **Mutation & Boundary Testing:** Generates test cases for boundary values (`0`, `-1`, `""`, `None`, empty collections, large inputs) and asserts invariant stability.

### 9. Complexity & Cognitive Analyzer (`ComplexityAnalyzer`)
* **McCabe Cyclomatic Complexity:** Measures independent execution paths ($E - N + 2$).
* **Sonar-Style Cognitive Complexity:** Evaluates human maintainability by weighting nested control structures, compound boolean expressions, and recursive routines.
* **Structural Metrics:** Computes function line counts, parameter counts, return statement counts, and maximum nesting depths with configurable threshold alerts.

### 10. Dead Code Discovery & Elimination (`DeadCodeDetector`, `DeadCodeFixer`)
* **Project-Wide Symbol Call Graph:** Builds a cross-module reference graph to isolate unused functions, methods, classes, and global constants.
* **Framework-Aware Protection:** Automatically preserves web route handlers (`@app.route`, `@router.get`), test fixtures (`@pytest.fixture`), interface methods (`@abstractmethod`), and explicit public exports (`__all__`).
* **Unreachable Code Elimination:** Prunes dead statements immediately following unconditional `return`, `raise`, `break`, `continue`, or `sys.exit()` calls.

### 11. Project Dependency Auditor (`DependencyAuditor`)
* **Import-to-Distribution Mapping:** Maps imported top-level modules to canonical PyPI distribution names (e.g., `yaml` $\to$ `PyYAML`, `PIL` $\to$ `pillow`, `cv2` $\to$ `opencv-python`).
* **Configuration Reconciliation:** Reconciles detected imports against `pyproject.toml` (`dependencies` and `optional-dependencies`) and `requirements.txt`.
* **Automated Syncing:** Appends missing third-party packages (`--fix-deps`) and prunes unreferenced packages (`--prune-deps`).

### 12. Content-Addressable Cache (`ContentAddressableCache`)
* **SQLite-Backed Hash Invalidation:** Hashes AST content, file metadata, and rule configuration to skip unmodified files during subsequent runs.
* **Sub-Millisecond Incremental Analysis:** Eliminates redundant linting, type-checking, and security scanning on unchanged codebases.

### 13. Technical Debt Ratchet (`BaselineManager`)
* **Baseline Generation:** Records current warnings, complexity outliers, and linting debts into a persistent fingerprint file (`.pycleaner/baseline.json`).
* **Zero Regression Enforcement:** Enforces that new commits introduce zero new issues without blocking developers on historical legacy debt.

---

## Installation

### From PyPI

```bash
# Standard installation
pip install ballpython

# With optional security and development tooling
pip install "ballpython[dev,security]"
```

### From Source (Editable Mode)

```bash
git clone https://github.com/moonrox420/ball-python.git
cd ball-python
pip install -e ".[dev,security]"
```

---

## CLI Usage

`ballpython` and `pycleaner` can be used interchangeably:

```bash
ballpython <command> [options] [targets...]
pycleaner  <command> [options] [targets...]
```

### Primary Commands

#### 1. `fix` / Default Action (Healing, Linting, & Formatting)
Heals syntax, resolves missing imports, modernizes legacy typing, prunes dead code, and formats code:
```bash
# Clean the entire repository
ballpython .

# Clean a specific file or directory
ballpython fix src/
ballpython fix path/to/script.py

# Preview changes without modifying files (colorized diff)
ballpython fix --diff src/

# Run across multiple CPU cores
ballpython fix --parallel --workers 4 src/

# Disable specific transformations
ballpython fix --no-modernize --no-dead-code src/
```

#### 2. `check` (Dry-Run CI Verification)
Inspects files without writing modifications to disk. Exits with code `1` if repairs or lint violations are found:
```bash
ballpython check src/
ballpython check --diff src/
```

#### 3. `ultimate` (Full Spectrum Analysis & Healing)
Runs the entire 6-phase analysis and healing pipeline in sequence:
```bash
ballpython ultimate .
```

#### 4. `types` (Bidirectional Type Checking)
Checks function call argument types, return types, and Typeshed stubs:
```bash
ballpython types src/
ballpython types --json src/
```

#### 5. `taint` (Interprocedural SAST Dataflow Analysis)
Traces dataflow sources to security sinks across module boundaries:
```bash
ballpython taint src/
ballpython taint --json src/
```

#### 6. `scan` (Security Vulnerability Audit)
Scans for hardcoded secrets, injection vulnerabilities, and dangerous calls:
```bash
ballpython scan .
ballpython scan --severity HIGH .
ballpython scan --json .
```

#### 7. `complexity` (Cognitive & Cyclomatic Metrics)
Evaluates code maintainability and flags functions exceeding complexity thresholds:
```bash
ballpython complexity .
ballpython complexity --max-cyclomatic 10 --max-cognitive 15 .
ballpython complexity --json .
```

#### 8. `dead-code` (Unused Symbol Detection & Pruning)
Discovers unused functions, methods, classes, and unreachable statements:
```bash
# Report dead code
ballpython dead-code .

# Automatically prune unreachable code and redundant pass statements
ballpython dead-code --fix .
```

#### 9. `audit` (Project Dependency Verification)
Audits imported third-party libraries against `pyproject.toml` and `requirements.txt`:
```bash
# Audit dependencies
ballpython audit .

# Automatically append missing dependencies
ballpython audit --fix-deps .

# Reconcile dependencies: add missing and prune unimported packages
ballpython audit --fix-deps --prune-deps .
```

#### 10. `prove` (Differential Execution Fuzzing)
Verifies that code transformations preserve runtime invariants in isolated worker processes:
```bash
ballpython prove path/to/file.py
```

#### 11. `test-gen` (Behavioral Contract Test Generator)
Synthesizes automated pytest test suites for Python modules:
```bash
ballpython test-gen src/core.py --output tests/test_core_generated.py
```

#### 12. `baseline` (Technical Debt Ratchet)
Manages technical debt baselines to prevent regressions:
```bash
# Generate baseline fingerprint
ballpython baseline --generate

# Verify changes against baseline (fails only if new issues are introduced)
ballpython baseline --check
```

#### 13. `cache` (Content-Addressable Cache Management)
Inspects or clears the persistent SQLite cache database:
```bash
# View cache utilization statistics
ballpython cache --stats

# Invalidate and wipe cache
ballpython cache --clear
```

#### 14. `explain` (Diagnostic Catalog & Rule Guide)
Displays detailed descriptions, root causes, and remediation code examples:
```bash
# List all rules and diagnostic topics
ballpython explain

# View guide for a specific rule
ballpython explain SEC001
ballpython explain PROVE001
```

#### 15. `watch` (Continuous File Watcher)
Monitors files for filesystem modifications and auto-cleans on save:
```bash
ballpython watch src/ --interval 1.0
```

#### 16. `hook` (Pre-Commit Integration)
Outputs a pre-configured `.pre-commit-hooks.yaml` block:
```bash
ballpython hook
```

---

## Configuration (`pyproject.toml`)

`ballpython` automatically discovers configuration from `pyproject.toml` under `[tool.pycleaner]` or from `.pycleaner.toml`. An explicit configuration file can be supplied using `--config path/to/file.toml`.

```toml
[tool.pycleaner]
# Target filtering
include = ["src/", "tests/"]
exclude = ["migrations/", "generated/", "*_pb2.py", "*_pb2_grpc.py"]

# Syntax healing
fix-py2-syntax = true
fix-conditional-assignments = true

# Import resolution
auto-add-future-annotations = false
custom-import-map = { "logger" = "from myapp.core.logging import logger" }

# Linting & formatting
line-length = 88
select-rules = "F401,F841,I,UP,E,W,B,SIM,RUF"

# Dead code detection
ignore-decorators = ["@app.route", "@pytest.fixture", "@abstractmethod"]
ignore-names = ["_*", "test_*"]

# Security scanning
security-severity-threshold = "LOW"
ignore-security-rules = []

# Complexity thresholds
max-cyclomatic-complexity = 10
max-cognitive-complexity = 15
max-function-length = 50
max-arguments = 5

# Runtime behavior
backup = true
parallel = false
max-workers = 4
```

---

## Programmatic Python API

All engines can be imported directly into Python applications:

### Cleaning Source Code In-Memory
```python
from pycleaner import CleanPipeline, load_config

config = load_config(project_root=".")
pipeline = CleanPipeline(config=config)

dirty_code = """
def calculate(x)
    if x = 0
        return Path('.')
    return Path(str(x))
"""

result = pipeline.process_source(dirty_code, filename="example.py")
print(result.cleaned_code)
print("Repairs applied:", result.syntax_repairs)
print("Imports added:", result.resolved_imports)
```

### Running the Static Security Scanner
```python
from pycleaner import SecurityScanner

scanner = SecurityScanner(severity_threshold="MEDIUM")
report = scanner.scan_project("src/")

for finding in report.findings:
    print(f"[{finding.severity}] {finding.category} at {finding.filepath}:{finding.lineno}")
    print(f"  Fix: {finding.suggestion}")
```

### Bidirectional Type Verification
```python
from pycleaner.type_checker import TypeChecker

checker = TypeChecker()
report = checker.check_project("src/")

for error in report.errors:
    print(f"[{error.severity}] {error.message} at {error.filepath}:{error.lineno}")
```

### Cognitive & Cyclomatic Complexity Analysis
```python
from pycleaner import ComplexityAnalyzer

analyzer = ComplexityAnalyzer()
report = analyzer.analyze_project("src/")

print(f"Scanned {report.files_scanned} files across {report.count} functions.")
print(f"Average Cyclomatic: {report.average_cyclomatic:.2f}")

for func in report.above_threshold(max_cyclomatic=10, max_cognitive=15):
    print(f"{func.qualified_name} (CC={func.cyclomatic}, Cognitive={func.cognitive})")
```

---

## Pre-Commit Hook Integration

Add the following to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/moonrox420/ball-python
    rev: v2.0.2
    hooks:
      - id: pycleaner
        args: ["check"]  # Use "check" for CI gate or "fix" for auto-cleanup
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | Clean execution: all files valid, zero errors, or modifications successfully applied |
| `1` | Violations detected: check mode found modifications, test suite failed, or critical security vulnerabilities flagged |
| `2` | Configuration error: malformed TOML syntax, invalid keys, or mismatched type options |

---

## License

MIT License. Engineered and maintained for high-reliability Python engineering.
