"""Unit tests for SyntaxHealer."""

import unittest

from pycleaner.syntax_healer import SyntaxHealer


class TestSyntaxHealer(unittest.TestCase):
    def setUp(self) -> None:
        self.healer = SyntaxHealer()

    def test_valid_code_untouched(self) -> None:
        code = "def add(a: int, b: int) -> int:\n    return a + b\n"
        res = self.healer.heal(code)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.code, code)
        self.assertEqual(len(res.repairs), 0)

    def test_missing_colons(self) -> None:
        code = (
            "def compute(x)\n"
            "    if x > 10\n"
            "        return x * 2\n"
            "    else\n"
            "        return x\n"
        )
        res = self.healer.heal(code)
        self.assertTrue(res.is_valid)
        self.assertIn("def compute(x):", res.code)
        self.assertIn("if x > 10:", res.code)
        self.assertIn("else:", res.code)
        self.assertTrue(any("Appended missing ':'" in r for r in res.repairs))

    def test_single_equal_in_conditional(self) -> None:
        code = "def check(status):\n    if status = 1:\n        return True\n    return False\n"
        res = self.healer.heal(code)
        self.assertTrue(res.is_valid)
        self.assertIn("if status == 1:", res.code)

    def test_python_2_print_statement(self) -> None:
        code = "def greet(name):\n    print 'Hello ' + name\n"
        res = self.healer.heal(code)
        self.assertTrue(res.is_valid)
        self.assertIn("print('Hello ' + name)", res.code)

    def test_python_2_except_clause(self) -> None:
        code = "try:\n    x = 1 / 0\nexcept ZeroDivisionError, err:\n    x = 0\n"
        res = self.healer.heal(code)
        self.assertTrue(res.is_valid)
        self.assertIn("except ZeroDivisionError as err:", res.code)

    def test_unclosed_brackets(self) -> None:
        code = "numbers = [1, 2, 3, 4\n"
        res = self.healer.heal(code)
        self.assertTrue(res.is_valid)
        self.assertTrue(res.code.strip().endswith("]"))

    def test_tabs_expanded(self) -> None:
        code = "def foo():\n\treturn 42\n"
        res = self.healer.heal(code)
        self.assertTrue(res.is_valid)
        self.assertNotIn("\t", res.code)
        self.assertIn("    return 42", res.code)

    def test_kanban_code_snippet_not_mangled(self) -> None:
        kanban_code = (
            "def bad_style_function( a,b,c ):\n"
            "   if a>b:\n"
            "     return a\n"
            "   else: return b\n"
            "\n"
            "def another_bad_one(x,y,z=None):\n"
            "   print(x,y,z)\n"
            "   if x==y:return True\n"
            "   return False\n"
            "\n"
            "def print_card_priority(card):\n"
            "    print(card.priority.upper())  # assumes card always has priority and is str\n"
        )
        res = self.healer.heal(kanban_code)
        self.assertTrue(res.is_valid)
        self.assertNotIn("else: return b:", res.code)
        self.assertNotIn("if x==y:return True:", res.code)
        self.assertNotIn("is str)", res.code)
        self.assertEqual(res.code, kanban_code)

    def test_one_liners_preserved_even_when_other_functions_are_healed(self) -> None:
        mixed_code = (
            "def valid_one_liner(x):\n"
            "    if x > 0: return x\n"
            "    else: return 0\n"
            "\n"
            "def broken_function(y)\n"
            "    return y\n"
        )
        res = self.healer.heal(mixed_code)
        self.assertTrue(res.is_valid)
        self.assertIn("def broken_function(y):", res.code)
        self.assertNotIn("if x > 0: return x:", res.code)
        self.assertNotIn("else: return 0:", res.code)
        self.assertIn("else: return 0", res.code)

    def test_comments_with_quotes_and_brackets_not_corrupted(self) -> None:
        code = (
            "def calculate(items):\n"
            "    # don't break if items is empty (or None)\n"
            "    total = sum(items)\n"
            "    return total  # user's total\n"
        )
        res = self.healer.heal(code)
        self.assertTrue(res.is_valid)
        self.assertNotIn("user's total)", res.code)
        self.assertEqual(res.code, code)

    def test_keyword_argument_in_conditional_not_corrupted(self) -> None:
        code = (
            "def check(x):\n    if func(x=1):\n        return True\n    return False\n"
        )
        res = self.healer.heal(code)
        self.assertTrue(res.is_valid)
        self.assertIn("func(x=1)", res.code)
        self.assertNotIn("func(x==1)", res.code)

    def test_augmented_assignment_in_conditional_not_corrupted(self) -> None:
        code = (
            "def check(items):\n"
            "    total = 0\n"
            "    total += len(items)\n"
            "    if total == 0:\n"
            "        return False\n"
            "    return True\n"
        )
        res = self.healer.heal(code)
        self.assertTrue(res.is_valid)
        self.assertIn("total += len(items)", res.code)

    def test_py2_except_with_multiple_exceptions(self) -> None:
        code = (
            "try:\n"
            "    x = 1 / 0\n"
            "except (ValueError, ZeroDivisionError), err:\n"
            "    x = 0\n"
        )
        res = self.healer.heal(code)
        self.assertTrue(res.is_valid)
        self.assertIn("except (ValueError, ZeroDivisionError) as err:", res.code)

    def test_walrus_operator_preserved(self) -> None:
        code = "items = [1, 2, 3]\nif (n := len(items)) > 0:\n    print(n)\n"
        res = self.healer.heal(code)
        self.assertTrue(res.is_valid)
        self.assertIn("(n := len(items)) > 0:", res.code)

    def test_multiline_def_no_phantom_colon(self) -> None:
        code = "def process(\n    a: int,\n    b: str,\n) -> bool:\n    return True\n"
        res = self.healer.heal(code)
        self.assertTrue(res.is_valid)
        self.assertNotIn("def process(:", res.code)
        self.assertNotIn("def process(\n:", res.code)
        self.assertEqual(res.code, code)

    def test_unindented_block_after_function_definition(self) -> None:
        raw_code = (
            "class Bot:\n"
            "    def plugin_add(self, name: str, path: str):\n"
            '    """\n'
            "Load a local plugin from an explicitly supplied Python file.\n"
            '"""\n'
            "    safe_name = name\n"
            "\n"
            "    def next_func(self):\n"
            "        pass\n"
        )
        res = self.healer.heal(raw_code)
        self.assertTrue(res.is_valid)
        self.assertTrue(any("under-indented block" in r for r in res.repairs))
        self.assertIn("        safe_name = name", res.code)

    def test_compiler_grade_diagnostic_formatting(self) -> None:
        broken_code = "def foo(x)\n    return x +\n"
        res = self.healer.heal(broken_code, filename="example.py")
        self.assertFalse(res.is_valid)
        self.assertIsNotNone(res.diagnostic)
        assert res.diagnostic is not None
        self.assertIn("SyntaxError in example.py", res.diagnostic)
        self.assertIn("^", res.diagnostic)

    def test_combined_python2_defects_fully_healed(self) -> None:
        code = (
            "def legacy_parse(value)\n"
            "\ttry:\n"
            "\t\treturn int(value\n"
            "\texcept ValueError, error:\n"
            '\t\tprint "bad value", error\n'
            "\t\treturn None\n"
        )
        res = self.healer.heal(code)
        self.assertTrue(res.is_valid)
        self.assertIn("def legacy_parse(value):", res.code)
        self.assertIn("except ValueError as error:", res.code)
        self.assertIn('print("bad value", error)', res.code)
        self.assertIn("return int(value)", res.code)

    def test_missing_colon_and_unclosed_paren_healed_together(self) -> None:
        code = "def broken(value)\n    return int(value\n"
        res = self.healer.heal(code)
        self.assertTrue(res.is_valid)
        self.assertIn("def broken(value):", res.code)
        self.assertIn("return int(value)", res.code)

    def test_partial_repairs_reported_when_unfixable(self) -> None:
        code = "def foo(x)\n    return x +\n"
        res = self.healer.heal(code)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("missing ':'" in repair for repair in res.repairs))
        self.assertIn("def foo(x):", res.code)


if __name__ == "__main__":
    unittest.main()
