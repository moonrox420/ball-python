# ballpython

[![PyPI version](https://img.shields.io/pypi/v/ballpython.svg)](https://pypi.org/project/ballpython/)
[![Python Versions](https://img.shields.io/pypi/pyversions/ballpython.svg)](https://pypi.org/project/ballpython/)
[![CI](https://github.com/moonrox420/ball-python/actions/workflows/ci.yml/badge.svg)](https://github.com/moonrox420/ball-python/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**The zero-config Python code cleaner, syntax healer, and quality suite.**

`ballpython` automatically repairs broken syntax, resolves missing imports, prunes dead code, scans for security vulnerabilities, and formats your code in a single command. Zero LLM dependencies, 100% offline, and fast.

Both `ballpython` and `pycleaner` CLI commands are identical.

---

## Installation

```bash
pip install ballpython
```

---

## Quickstart

### 1. Fix and format your code
Run `ballpython` on any file or directory. It automatically heals syntax errors, resolves missing imports, removes unused variables, and applies canonical formatting:

```bash
ballpython .
```

### 2. Check code in CI (Dry Run)
Check for syntax errors, security vulnerabilities, dead code, and linting violations without modifying any files on disk:

```bash
ballpython check .
```

---

## What It Does Automatically

When you run `ballpython`, all engines run under the hood in one pass:

* **Syntax Healing:** Repairs missing statement colons (`def`, `class`, `if`), accidental `=` assignments in conditionals, unclosed parentheses/brackets, tab/space mixups, and legacy Python 2 except/print statements.
* **Smart Import Resolution:** Resolves undefined symbols to standard library modules and common aliases, inserts `TYPE_CHECKING` guards, and prunes unused imports.
* **Formatting & Modernization:** Formats code to PEP 8 standards (powered by `ruff`), modernizes legacy type annotations (PEP 585/604), and removes redundant `object` inheritance.
* **Dead Code Pruning:** Discovers and eliminates unreachable code, empty pass blocks, and unused private definitions.
* **Security & Taint Audit:** Detects hardcoded API secrets, SQL/command injection patterns, and unsafe `eval`/`exec`/`pickle` calls.
* **Type Verification:** Verifies function call signatures against bundled Typeshed stubs.

---

## Pre-Commit Hook

Add `ballpython` to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/moonrox420/ball-python
    rev: v2.0.2
    hooks:
      - id: pycleaner
        args: ["check"]
```

---

## Configuration

Optional configuration can be placed in `pyproject.toml` under `[tool.pycleaner]`:

```toml
[tool.pycleaner]
exclude = ["migrations/", "generated/"]
line-length = 88
```

---

## License

MIT License.
