# pycleaner — Ultimate Static Python Code Quality Suite

A production-grade, offline Python static analysis, syntax healing, linting, formatting, security scanning, complexity evaluation, dead code detection, and dependency auditing suite.

Zero external LLM dependencies, zero mock modes, and built for deterministic developer workflows and CI/CD pipelines.

---

## Key Capabilities

1. **Syntax Healer (`SyntaxHealer`)**:
   - Statically repairs missing colons on compound statement headers (`def`, `class`, `if`, `elif`, `else`, `for`, `while`, `try`, `except`, `finally`, `with`, `async def`, `match`, `case`).
   - Corrects accidental single `=` assignments in conditionals (`if x = 1:` $\to$ `if x == 1:`) without corrupting keyword arguments (`func(x=1)`), augmented assignments, or walrus expressions (`x := 1`).
   - Modernizes legacy Python 2 statements (`print "..."` $\to$ `print(...)`, `except Error, e:` $\to$ `except Error as e:`, and multi-exception tuples `except (E1, E2), e:` on Python 3.12+).
   - Automatically closes unclosed parentheses, brackets, and braces.
   - Normalizes mixed tab characters into 4 spaces.

2. **Missing Import Resolver (`ImportResolver`)**:
   - Walks Python AST to extract undefined loaded symbols across local, function, class, and comprehension scopes.
   - Resolves undefined identifiers to standard library modules (`os`, `sys`, `json`, `re`, `subprocess`, `pathlib`, etc.), collections, typing constructs, dataclasses, concurrent primitives (`ThreadPoolExecutor`, `ProcessPoolExecutor`, `Lock`, `Queue`), and popular aliases (`np`, `pd`, `plt`, `sns`, `tf`, `nn`).
   - **`TYPE_CHECKING` Awareness**: Injects typing-only imports into `if TYPE_CHECKING:` guards and adds `from __future__ import annotations` when symbols are used strictly in type annotations.
   - **Custom Import Mapping**: Configurable mapping from symbol names to exact import statements.

3. **Linter & Formatter (`LinterFormatter`)**:
   - Integrates Rust-based `ruff` via in-memory stream processing (`--stdin-filename`).
   - Automatically removes unused imports (`F401`) and unused variables (`F841`).
   - Sorts and groups imports via `isort` / `ruff` or an internal pure-Python 3-tier sorter (stdlib $\to$ third-party $\to$ local).
   - Modernizes deprecated syntax via `pyupgrade` (`UP`).
   - Applies deterministic PEP 8 formatting (`ruff format` / `black` / pure-Python formatter).
   - Wraps long `from ... import (...)` statements exceeding configured `line-length`.
   - Modernizes legacy typing to PEP 585/604 syntax (`List[T]` -> `list[T]`, `Optional[T]` -> `T | None`), singleton comparisons, and `class X(object)` inheritance via `Modernizer` (disable with `--no-modernize`).

4. **Dead Code Detector (`DeadCodeDetector`)**:
   - Builds a cross-file symbol definition and reference graph across a project.
   - Identifies unused functions, methods, classes, module-level constants, and class attributes.
   - Respects public exports in `__all__` and framework decorators (`@app.route`, `@pytest.fixture`, `@abstractmethod`, etc.).
   - Detects unreachable code following unconditional `return`, `raise`, `break`, `continue`, or `sys.exit()`.
   - Identifies empty pass blocks with no comments.
   - Auto-prunes unreachable code, redundant `pass` statements, and `if False:` branches via `DeadCodeFixer` (enable with `dead-code --fix`, disable in the pipeline with `--no-dead-code`).

5. **Static Security Scanner (`SecurityScanner`)**:
   - Detects dangerous function calls: `eval()`, `exec()`, `compile()`, `pickle.loads()`, `os.system()`, and unsafe `yaml.load()` lacking `SafeLoader`.
   - Flags SQL injection patterns (string concatenation, f-strings, `%`-formatting, or `.format()` inside `cursor.execute()`).
   - Flags subprocess command injection (`shell=True`).
   - Flags insecure transport (`verify=False` in `requests` or `httpx`).
   - Scans for hardcoded secrets: AWS access/secret keys, GitHub tokens, Slack tokens, JWT tokens, private key headers, and generic passwords/API keys.
   - Flags production `assert` statements used for input validation (which get stripped under `python -O`).

6. **Complexity Analyzer (`ComplexityAnalyzer`)**:
   - McCabe Cyclomatic Complexity per function ($E - N + 2$).
   - Sonar-style Cognitive Complexity scoring (penalizing nested control flow, compound boolean conditions, and break in linear flow).
   - Metrics tracked: line count, argument count, return statement count, and maximum nesting depth.
   - Configurable thresholds with tabular and JSON reporting.

7. **Dependency Auditor (`DependencyAuditor`)**:
   - Statically scans all `.py` files across a repository to discover external third-party imports.
   - Maps module import names to PyPI distribution package names (e.g., `yaml` $\to$ `PyYAML`, `PIL` $\to$ `pillow`, `cv2` $\to$ `opencv-python`).
   - Compares imported dependencies against `requirements.txt` and `pyproject.toml`.
   - Synchronizes `requirements.txt` with `--fix-deps` and prunes unused packages with `--prune-deps`.

8. **Safety & Concurrency**:
   - Backup creation (`.pycleaner.bak`) before overwriting files (enabled by default).
   - Parallel multi-core file processing via `ProcessPoolExecutor`.
   - Continuous file watching (`watch` mode) with automatic re-healing on save.
   - Pre-commit configuration generator (`hook` subcommand).

---

## Installation

```bash
# Editable install
pip install -e .

# Core dependencies
pip install ruff rich

# Optional security and development packages
pip install -e ".[dev,security]"
```

---

## CLI Usage

### Subcommands

#### `fix` (Default Action)
Heals syntax, modernizes legacy typing (PEP 585/604), prunes dead code, resolves imports, fixes lint violations, and formats code:
```bash
py -m pycleaner fix src/
py -m pycleaner fix --diff path/to/script.py
py -m pycleaner fix --no-backup src/
py -m pycleaner fix --parallel --workers 4 src/
py -m pycleaner fix --no-modernize --no-dead-code src/
```

#### `check` (Dry-Run CI Verification)
Inspects files without writing modifications to disk. Exits with code `1` if changes or errors are detected:
```bash
py -m pycleaner check src/
py -m pycleaner check --diff src/
```

#### `scan` (Security Vulnerability Audit)
Scans Python files for hardcoded secrets, dangerous calls, and injection vulnerabilities:
```bash
py -m pycleaner scan .
py -m pycleaner scan --severity HIGH .
py -m pycleaner scan --json .
```

#### `complexity` (Function Complexity Metrics)
Calculates Cyclomatic Complexity, Cognitive Complexity, and architectural metrics:
```bash
py -m pycleaner complexity .
py -m pycleaner complexity --max-cyclomatic 10 --max-cognitive 15 .
py -m pycleaner complexity --json .
```

#### `dead-code` (Unused Symbols & Unreachable Branches)
Finds unused functions, unused classes, empty pass branches, and dead code:
```bash
py -m pycleaner dead-code .
py -m pycleaner dead-code --json .
py -m pycleaner dead-code --fix .
```

#### `audit` (Project Dependency Verification)
Audits imported third-party libraries against `requirements.txt`:
```bash
# Audit only
py -m pycleaner audit .

# Automatically append missing dependencies
py -m pycleaner audit --fix-deps .

# Append missing and remove unimported dependencies
py -m pycleaner audit --fix-deps --prune-deps .
```

#### `all` (Complete Quality Sweep)
Executes all engines in one command (fix + dependency audit + security scan + complexity + dead code):
```bash
py -m pycleaner all .
```

#### `watch` (Continuous File Watcher)
Watches files for filesystem modifications and auto-cleans on save:
```bash
py -m pycleaner watch src/ --interval 1.0
```

#### `hook` (Pre-Commit Integration)
Outputs a ready-to-use `.pre-commit-hooks.yaml` configuration block:
```bash
py -m pycleaner hook
```

---

### Backward-Compatible Flat Invocations

Legacy invocations continue to work seamlessly:
```bash
pycleaner -a .                     # Equivalent to: pycleaner all .
pycleaner --check --diff src/      # Equivalent to: pycleaner check --diff src/
pycleaner --deps-only .            # Equivalent to: pycleaner audit .
pycleaner path/to/file.py          # Equivalent to: pycleaner fix path/to/file.py
```

---

## Configuration

`pycleaner` automatically reads configuration from `pyproject.toml` under `[tool.pycleaner]` or from `.pycleaner.toml`. An explicit file can be forced with `pycleaner --config path/to/pyproject.toml <command> ...`, which overrides target-path auto-discovery.

### `pyproject.toml` Example

```toml
[tool.pycleaner]
# File targeting
exclude = ["migrations/", "generated/", "*_pb2.py", "*_pb2_grpc.py"]
include = ["src/", "tests/"]

# Syntax healing
fix-py2-syntax = true
fix-conditional-assignments = true

# Import resolution
custom-import-map = { "logger" = "from myapp.core.logging import logger" }
auto-add-future-annotations = false

# Linting & formatting
line-length = 88
select-rules = "F401,F841,I,UP,E,W,B,SIM,RUF"

# Dead code
ignore-decorators = ["@app.route", "@pytest.fixture", "@override"]
ignore-names = ["_*", "test_*"]

# Security
security-severity-threshold = "LOW"
ignore-security-rules = []

# Complexity thresholds
max-cyclomatic-complexity = 10
max-cognitive-complexity = 15
max-function-length = 50
max-arguments = 5

# Behavior
backup = true
parallel = false
max-workers = 4
```

---

## Programmatic API

### 1. Cleaning Source Code or Files
```python
from pathlib import Path
from pycleaner import CleanPipeline, load_config

# Load config with project overrides
config = load_config(project_root=".")
pipeline = CleanPipeline(config=config)

# In-memory code processing
dirty_code = """
import math

def calculate(x)
    if x = 0
        return Path('.')
    return Path(str(x))
"""
result = pipeline.process_source(dirty_code, filename="example.py")
print("Cleaned code:\n", result.cleaned_code)
print("Repairs applied:", result.syntax_repairs)
print("Imports added:", result.resolved_imports)

# File processing with automatic backup
file_result = pipeline.process_file("example.py", apply_changes=True, backup=True)
```

### 2. Security Vulnerability Scanning
```python
from pycleaner import SecurityScanner

scanner = SecurityScanner(severity_threshold="MEDIUM")
report = scanner.scan_project("src/")

for finding in report.findings:
    print(f"[{finding.severity}] {finding.category} at {finding.filepath}:{finding.lineno}")
    print(f"  Message: {finding.message}")
    print(f"  Fix: {finding.suggestion}")
```

### 3. Complexity Analysis
```python
from pycleaner import ComplexityAnalyzer

analyzer = ComplexityAnalyzer()
report = analyzer.analyze_project("src/")

print(f"Scanned {report.files_scanned} files, {report.count} functions.")
print(f"Average Cyclomatic: {report.average_cyclomatic:.2f}")

violations = report.above_threshold(max_cyclomatic=10, max_cognitive=15)
for func in violations:
    print(f"{func.qualified_name} (CC={func.cyclomatic}, Cog={func.cognitive})")
```

### 4. Dead Code Detection
```python
from pycleaner import DeadCodeDetector

detector = DeadCodeDetector()
report = detector.scan_project("src/")

print(f"{report.count} dead code item(s) across {report.files_scanned} file(s).")

for item in report.items:
    print(f"Dead {item.kind} '{item.name}' at {item.filepath}:{item.lineno}")

for item in report.by_kind("unreachable"):
    print(f"Unreachable code at {item.filepath}:{item.lineno} ({item.reason})")
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | Clean run: all files valid, no errors, or changes cleanly written |
| `1` | Issues found: check mode detected modifications, errors occurred, or critical security findings flagged |
| `2` | Configuration error: invalid TOML syntax, invalid configuration keys, or mismatched types |

---

## License

MIT License.
# ball-python
# ball-python
