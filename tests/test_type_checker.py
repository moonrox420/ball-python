"""Tests for pycleaner.type_checker and pycleaner.typeshed_resolver modules."""

from __future__ import annotations

import textwrap
from pathlib import Path

from pycleaner.type_checker import (
    AnyType,
    DictType,
    ListType,
    NoneType,
    PrimitiveType,
    TypeChecker,
    UnionType,
    parse_type_annotation,
)
from pycleaner.typeshed_resolver import TypeshedResolver


class TestAlgebraicTypes:
    """Test algebraic type hierarchy and assignability rules."""

    def test_primitive_assignability(self) -> None:
        int_t = PrimitiveType("int")
        float_t = PrimitiveType("float")
        str_t = PrimitiveType("str")

        # Identity
        assert int_t.is_assignable_to(int_t)
        # Numeric promotion
        assert int_t.is_assignable_to(float_t)
        # Incompatible
        assert not str_t.is_assignable_to(int_t)

    def test_union_assignability(self) -> None:
        int_t = PrimitiveType("int")
        str_t = PrimitiveType("str")
        union_t = UnionType([int_t, str_t])

        assert int_t.is_assignable_to(union_t)
        assert str_t.is_assignable_to(union_t)
        assert not PrimitiveType("float").is_assignable_to(union_t)

    def test_generic_containers(self) -> None:
        list_int = ListType(PrimitiveType("int"))
        list_str = ListType(PrimitiveType("str"))
        list_any = ListType(AnyType())

        assert list_int.is_assignable_to(list_any)
        assert not list_str.is_assignable_to(list_int)

        dict_t = DictType(PrimitiveType("str"), PrimitiveType("int"))
        assert str(dict_t) == "dict[str, int]"


class TestTypeAnnotationParser:
    """Test parsing AST annotations to algebraic types."""

    def test_parse_primitives(self) -> None:
        assert isinstance(parse_type_annotation("int"), PrimitiveType)
        assert isinstance(parse_type_annotation("str"), PrimitiveType)
        assert isinstance(parse_type_annotation("None"), NoneType)

    def test_parse_union_and_optional(self) -> None:
        u1 = parse_type_annotation("int | str")
        assert isinstance(u1, UnionType)
        assert len(u1.types) == 2

        u2 = parse_type_annotation("Optional[int]")
        assert isinstance(u2, UnionType)
        assert any(isinstance(t, NoneType) for t in u2.types)

    def test_parse_generics(self) -> None:
        l_type = parse_type_annotation("list[str]")
        assert isinstance(l_type, ListType)
        assert isinstance(l_type.item_type, PrimitiveType)


class TestTypeChecker:
    """Test full static type checking engine."""

    def test_return_type_mismatch(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            def compute_value(x: int) -> int:
                return "this is a string, not an int"
        """)
        f = tmp_path / "sample.py"
        f.write_text(code, encoding="utf-8")

        checker = TypeChecker()
        findings = checker.check_file(f)

        assert len(findings) == 1
        assert findings[0].expected_type == "int"
        assert findings[0].actual_type == "str"
        assert findings[0].lineno == 3

    def test_return_type_valid(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            def compute_value(x: int) -> int:
                return 42
        """)
        f = tmp_path / "valid.py"
        f.write_text(code, encoding="utf-8")

        checker = TypeChecker()
        findings = checker.check_file(f)
        assert len(findings) == 0

    def test_annotated_variable_assignment(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            count: int = "invalid_string"
        """)
        f = tmp_path / "bad_assign.py"
        f.write_text(code, encoding="utf-8")

        checker = TypeChecker()
        findings = checker.check_file(f)

        assert len(findings) == 1
        assert findings[0].expected_type == "int"
        assert findings[0].actual_type == "str"

    def test_call_site_argument_mismatch(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            def greet(name: str) -> str:
                return "Hello " + name

            def main() -> None:
                greet(12345)
        """)
        f = tmp_path / "bad_call.py"
        f.write_text(code, encoding="utf-8")

        checker = TypeChecker()
        findings = checker.check_file(f)
        assert any("expects 'str' but received 'int'" in f.message for f in findings)

    def test_object_accepts_all_types(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            def run() -> None:
                x = input("Enter prompt: ")
        """)
        f = tmp_path / "object_call.py"
        f.write_text(code, encoding="utf-8")

        checker = TypeChecker()
        findings = checker.check_file(f)
        assert len(findings) == 0

    def test_terminal_control_flow_constructs(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            class Manager:
                def __enter__(self): return self
                def __exit__(self, *args): pass

            def with_return(m: Manager) -> bool:
                with m as x:
                    return True

            def try_except_return() -> int:
                try:
                    return 1
                except Exception:
                    return 0

            def if_else_return(flag: bool) -> str:
                if flag:
                    return "yes"
                else:
                    return "no"

            def while_true_return() -> float:
                while True:
                    return 3.14
        """)
        f = tmp_path / "terminal_flows.py"
        f.write_text(code, encoding="utf-8")

        checker = TypeChecker()
        findings = checker.check_file(f)
        missing_returns = [f for f in findings if "Missing return path" in f.message]
        assert len(missing_returns) == 0

    def test_method_calls_isolated_from_local_functions(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            import os

            DEFAULT_DSN: str = os.environ.get("URL", "postgresql://localhost")

            class Store:
                def get(self, key: str) -> dict:
                    return {"key": key}
        """)
        f = tmp_path / "method_isol.py"
        f.write_text(code, encoding="utf-8")

        checker = TypeChecker()
        findings = checker.check_file(f)
        assert len(findings) == 0

    def test_attribute_method_calls_not_shadowed_by_builtins(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            class Dataset:
                def map(self, fn):
                    return self

            def process(ds: Dataset) -> Dataset:
                result: Dataset = ds.map(lambda x: x)
                return result
        """)
        f = tmp_path / "map_isol.py"
        f.write_text(code, encoding="utf-8")

        checker = TypeChecker()
        findings = checker.check_file(f)
        assert len(findings) == 0

    def test_sorted_accepts_zip_iterable(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            def sort_pairs(a: list[int], b: list[str]) -> list:
                return sorted(zip(a, b))
        """)
        f = tmp_path / "sorted_zip.py"
        f.write_text(code, encoding="utf-8")

        checker = TypeChecker()
        findings = checker.check_file(f)
        assert len(findings) == 0

    def test_typevar_assignable(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""
            import statistics

            avg_total: float = statistics.mean([1.0, 2.0, 3.0])
        """)
        f = tmp_path / "typevar.py"
        f.write_text(code, encoding="utf-8")

        checker = TypeChecker()
        findings = checker.check_file(f)
        assert len(findings) == 0



class TestTypeshedResolver:
    """Test Typeshed stub parsing and resolution."""

    def test_builtins_fast_path(self) -> None:
        resolver = TypeshedResolver()
        fn = resolver.resolve_function("len")
        assert fn is not None
        assert fn.return_type == "int"

    def test_module_function_lookup(self) -> None:
        resolver = TypeshedResolver()
        fn = resolver.resolve_function("math.sqrt")
        assert fn is not None
        assert fn.return_type == "float"
