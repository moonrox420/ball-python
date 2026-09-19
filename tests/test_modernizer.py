"""
Unit tests for the Modernizer engine.
"""

from __future__ import annotations

import ast
from pycleaner.modernizer import Modernizer


class TestModernizer:
    def test_pep585_builtins(self) -> None:
        source = (
            "def fetch(x: List[str], mapping: Dict[str, Set[int]]) -> Tuple[int, ...]:\n"
            "    return (1, 2)\n"
        )
        modernizer = Modernizer()
        res = modernizer.modernize(source)
        assert res.changed
        assert "x: list[str]" in res.code
        assert "mapping: dict[str, set[int]]" in res.code
        assert "-> tuple[int, ...]:" in res.code
        assert "from __future__ import annotations" in res.code
        ast.parse(res.code)

    def test_pep604_unions(self) -> None:
        source = (
            "def parse(val: Union[int, str], flag: Optional[bool] = None) -> Union[int, float, None]:\n"
            "    return val\n"
        )
        modernizer = Modernizer()
        res = modernizer.modernize(source)
        assert res.changed
        assert "val: int | str" in res.code
        assert "flag: bool | None = None" in res.code
        assert "-> int | float | None:" in res.code
        ast.parse(res.code)

    def test_singleton_comparisons(self) -> None:
        source = (
            "def check(x, y, z, w):\n"
            "    if x == None:\n"
            "        return 1\n"
            "    if y != None:\n"
            "        return 2\n"
            "    if z == True:\n"
            "        return 3\n"
            "    if w != False:\n"
            "        return 4\n"
        )
        modernizer = Modernizer()
        res = modernizer.modernize(source)
        assert res.changed
        assert "if x is None:" in res.code
        assert "if y is not None:" in res.code
        assert "if z is True:" in res.code
        assert "if w is not False:" in res.code
        ast.parse(res.code)

    def test_legacy_object_inheritance(self) -> None:
        source = (
            "class BaseService(object):\n"
            "    def run(self):\n"
            "        pass\n"
        )
        modernizer = Modernizer()
        res = modernizer.modernize(source)
        assert res.changed
        assert "class BaseService:\n" in res.code
        ast.parse(res.code)

    def test_unicode_prefix_pruning(self) -> None:
        source = 'msg = u"hello world"\nother = u\'test\'\n'
        modernizer = Modernizer()
        res = modernizer.modernize(source)
        assert res.changed
        assert 'msg = "hello world"' in res.code
        assert "other = 'test'" in res.code
        ast.parse(res.code)

    def test_future_annotations_placement_with_docstring(self) -> None:
        source = (
            '"""Module docstring."""\n'
            '\n'
            'def foo(x: List[int]) -> None:\n'
            '    pass\n'
        )
        modernizer = Modernizer()
        res = modernizer.modernize(source)
        assert res.changed
        lines = res.code.splitlines()
        assert lines[0] == '"""Module docstring."""'
        assert lines[1] == "from __future__ import annotations"
        ast.parse(res.code)

    def test_idempotent_when_already_modern(self) -> None:
        source = (
            "from __future__ import annotations\n"
            "\n"
            "class ModernService:\n"
            "    def run(self, val: int | None = None) -> list[str]:\n"
            "        if val is None:\n"
            "            return []\n"
            "        return ['ok']\n"
        )
        modernizer = Modernizer()
        res = modernizer.modernize(source)
        assert not res.changed
        assert res.code == source
