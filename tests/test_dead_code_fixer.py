"""
Unit tests for DeadCodeFixer engine.
"""

from __future__ import annotations

import ast

from pycleaner.dead_code_detector import DeadCodeDetector, DeadCodeFixer


class TestDeadCodeFixer:
    def test_prune_unreachable_after_return(self) -> None:
        source = (
            "def compute(val: int) -> int:\n"
            "    if val < 0:\n"
            "        return 0\n"
            "        print('negative')\n"
            "        val = -val\n"
            "    return val * 2\n"
        )
        fixer = DeadCodeFixer()
        res = fixer.fix(source)
        assert res.changed
        assert "print('negative')" not in res.code
        assert "val = -val" not in res.code
        assert "return 0" in res.code
        assert "return val * 2" in res.code
        ast.parse(res.code)

    def test_prune_unreachable_after_raise(self) -> None:
        source = (
            "def validate(name: str) -> None:\n"
            "    if not name:\n"
            "        raise ValueError('empty')\n"
            "        cleanup()\n"
            "    print(name)\n"
        )
        fixer = DeadCodeFixer()
        res = fixer.fix(source)
        assert res.changed
        assert "cleanup()" not in res.code
        assert "raise ValueError('empty')" in res.code
        ast.parse(res.code)

    def test_prune_redundant_pass_when_statements_exist(self) -> None:
        source = "def task():\n    do_step_1()\n    do_step_2()\n    pass\n"
        fixer = DeadCodeFixer()
        res = fixer.fix(source)
        assert res.changed
        assert "pass" not in res.code
        assert "do_step_2()" in res.code
        ast.parse(res.code)

    def test_preserve_pass_when_only_statement(self) -> None:
        source = "def empty_hook():\n    pass\n"
        fixer = DeadCodeFixer()
        res = fixer.fix(source)
        assert not res.changed
        assert "pass" in res.code
        ast.parse(res.code)

    def test_prune_dead_if_false_branch(self) -> None:
        source = (
            "def run():\n"
            "    init()\n"
            "    if False:\n"
            "        unreachable_work()\n"
            "    finalize()\n"
        )
        fixer = DeadCodeFixer()
        res = fixer.fix(source)
        assert res.changed
        assert "unreachable_work()" not in res.code
        assert "init()" in res.code
        assert "finalize()" in res.code
        ast.parse(res.code)

    def test_detector_fix_file(self, tmp_path) -> None:
        f = tmp_path / "dead.py"
        f.write_text(
            "def foo():\n    return 1\n    dead()\n",
            encoding="utf-8",
        )
        detector = DeadCodeDetector()
        res = detector.fix_file(f, apply_changes=True)
        assert res.changed
        cleaned = f.read_text(encoding="utf-8")
        assert "dead()" not in cleaned
        assert "return 1" in cleaned

    def test_heal_empty_except_block_with_logging(self) -> None:
        source = "try:\n    do_risky_io()\nexcept Exception:\n    pass\n"
        fixer = DeadCodeFixer()
        res = fixer.fix(source)
        assert res.changed
        assert "import logging" in res.code
        assert (
            "logging.getLogger(__name__).debug('Suppressed exception', exc_info=True)"
            in res.code
        )
        assert "pass" not in res.code
        ast.parse(res.code)

    def test_heal_empty_except_when_logging_already_imported(self) -> None:
        source = (
            "import logging\n\n"
            "try:\n"
            "    step()\n"
            "except (ValueError, KeyError):\n"
            "    pass\n"
        )
        fixer = DeadCodeFixer()
        res = fixer.fix(source)
        assert res.changed
        # Must not duplicate import logging
        assert res.code.count("import logging") == 1
        assert (
            "logging.getLogger(__name__).debug('Suppressed exception', exc_info=True)"
            in res.code
        )
        ast.parse(res.code)

    def test_prune_pure_unused_local_variable(self) -> None:
        source = (
            "def setup():\n    style = 'dark'\n    active = True\n    return active\n"
        )
        fixer = DeadCodeFixer()
        res = fixer.fix(source)
        assert res.changed
        assert "style = 'dark'" not in res.code
        assert "active = True" in res.code
        ast.parse(res.code)

    def test_prune_pure_unused_local_variable_leaves_pass_when_empty(self) -> None:
        source = "def config():\n    theme = 'midnight'\n"
        fixer = DeadCodeFixer()
        res = fixer.fix(source)
        assert res.changed
        assert "theme = 'midnight'" not in res.code
        assert "pass" in res.code
        ast.parse(res.code)

    def test_prefix_impure_unused_local_variable_with_underscore(self) -> None:
        source = (
            "def load_app():\n"
            "    style = get_style()\n"
            "    theme = create_theme('light')\n"
            "    return 42\n"
        )
        fixer = DeadCodeFixer()
        res = fixer.fix(source)
        assert res.changed
        assert "_style = get_style()" in res.code
        assert "_theme = create_theme('light')" in res.code
        assert "return 42" in res.code
        ast.parse(res.code)

    def test_prefix_annotated_impure_variable(self) -> None:
        source = "def run():\n    theme: Theme = load_theme()\n    return 1\n"
        fixer = DeadCodeFixer()
        res = fixer.fix(source)
        assert res.changed
        assert "_theme: Theme = load_theme()" in res.code
        ast.parse(res.code)

    def test_prefix_tuple_unpacking_unused_variable(self) -> None:
        source = "def pair():\n    style, count = get_pair()\n    return count\n"
        fixer = DeadCodeFixer()
        res = fixer.fix(source)
        assert res.changed
        assert "_style, count = get_pair()" in res.code
        ast.parse(res.code)
