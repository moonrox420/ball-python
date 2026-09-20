"""
Code modernizer engine for upgrading Python source to modern Python idioms (PEP 585, PEP 604).

Performs AST-driven modernization:
- PEP 585 built-in collection generics (List[T] -> list[T], Dict[K, V] -> dict[K, V], etc.)
- PEP 604 union syntax (Union[A, B] -> A | B, Optional[A] -> A | None)
- Automatic injection of 'from __future__ import annotations' when type syntax is modernized
- Singleton equality comparison healing (== None -> is None, == True/False -> is True/False)
- Redundant (object) class inheritance pruning (class Foo(object): -> class Foo:)
- Redundant unicode literal prefix pruning ("..." -> "...")
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from dataclasses import dataclass, field


@dataclass(slots=True)
class ModernizeResult:
    """Result of modernizing Python source code."""

    code: str
    changed: bool
    transformations: list[str] = field(default_factory=list)


class _AnnotationTransformer(ast.NodeTransformer):
    """Transforms legacy typing annotations to PEP 585 and PEP 604 syntax."""

    _PEP_585_MAP = {
        "List": "list",
        "Dict": "dict",
        "Set": "set",
        "Tuple": "tuple",
        "FrozenSet": "frozenset",
        "Type": "type",
    }

    def __init__(self, typing_imports: set[str] | None = None) -> None:
        self.changed = False
        self.transformations: list[str] = []
        self.typing_imports = typing_imports if typing_imports is not None else set()

    def visit_Subscript(self, node: ast.Subscript) -> ast.AST:
        self.generic_visit(node)
        name: str | None = None
        if isinstance(node.value, ast.Name):
            # Only rewrite bare names if they were imported from typing or if typing imports exist
            if not self.typing_imports or node.value.id in self.typing_imports:
                name = node.value.id
        elif (
            isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "typing"
        ):
            name = node.value.attr

        if not name:
            return node

        if name in self._PEP_585_MAP:
            self.changed = True
            new_id = self._PEP_585_MAP[name]
            self.transformations.append(f"PEP 585: typing.{name} -> {new_id}")
            node.value = ast.Name(id=new_id, ctx=ast.Load())
            return node

        if name == "Optional":
            self.changed = True
            self.transformations.append("PEP 604: typing.Optional[T] -> T | None")
            return ast.BinOp(
                left=node.slice, op=ast.BitOr(), right=ast.Constant(value=None)
            )

        if name == "Union":
            self.changed = True
            self.transformations.append("PEP 604: typing.Union[...] -> ... | ...")
            if isinstance(node.slice, ast.Tuple) and node.slice.elts:
                cur: ast.expr = node.slice.elts[0]
                for nxt in node.slice.elts[1:]:
                    cur = ast.BinOp(left=cur, op=ast.BitOr(), right=nxt)
                return cur
            return node.slice

        return node


class Modernizer:
    """Modernizes Python codebases to canonical modern syntax (PEP 585 / 604 / 695)."""

    def __init__(
        self,
        enable_pep585: bool = True,
        enable_pep604: bool = True,
        enable_singleton_is: bool = True,
        enable_object_inheritance_pruning: bool = True,
        enable_unicode_prefix_pruning: bool = True,
    ) -> None:
        self.enable_pep585 = enable_pep585
        self.enable_pep604 = enable_pep604
        self.enable_singleton_is = enable_singleton_is
        self.enable_object_inheritance_pruning = enable_object_inheritance_pruning
        self.enable_unicode_prefix_pruning = enable_unicode_prefix_pruning

    def modernize(self, source: str, filename: str = "<stdin>") -> ModernizeResult:
        """Modernize Python source string with surgical preservation."""
        try:
            ast.parse(source, filename=filename)
        except SyntaxError:
            return ModernizeResult(code=source, changed=False)

        current_code = source
        all_transforms: list[str] = []

        # 1. Class (object) pruning
        if self.enable_object_inheritance_pruning:
            current_code, t_obj = self._prune_object_inheritance(current_code)
            all_transforms.extend(t_obj)

        # 2. Singleton comparisons (== None -> is None, == True/False)
        if self.enable_singleton_is:
            current_code, t_cmp = self._modernize_singleton_comparisons(current_code)
            all_transforms.extend(t_cmp)

        # 3. Unicode literal prefixes ("..." -> "...")
        if self.enable_unicode_prefix_pruning:
            current_code, t_u = self._prune_unicode_prefixes(current_code)
            all_transforms.extend(t_u)

        # 4. PEP 585 / PEP 604 Annotations
        if self.enable_pep585 or self.enable_pep604:
            current_code, t_ann = self._modernize_annotations(current_code)
            all_transforms.extend(t_ann)

        changed = current_code != source
        return ModernizeResult(
            code=current_code,
            changed=changed,
            transformations=all_transforms,
        )

    def _prune_object_inheritance(self, source: str) -> tuple[str, list[str]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        transforms: list[str] = []
        lines = source.splitlines(keepends=True)
        edits: list[tuple[int, int, str]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and len(node.bases) == 1:
                base = node.bases[0]
                if isinstance(base, ast.Name) and base.id == "object":
                    line_idx = node.lineno - 1
                    line_str = lines[line_idx]
                    pattern = re.compile(
                        rf"(class\s+{re.escape(node.name)})\s*\(\s*object\s*\)\s*:"
                    )
                    if pattern.search(line_str):
                        new_line = pattern.sub(rf"class {node.name}:", line_str)
                        edits.append((line_idx, line_idx + 1, new_line))
                        transforms.append(
                            f"Pruned legacy (object) inheritance from class {node.name}"
                        )

        if not edits:
            return source, []

        for start, end, new_text in sorted(edits, key=lambda x: x[0], reverse=True):
            lines[start:end] = [new_text]

        return "".join(lines), transforms

    def _modernize_singleton_comparisons(self, source: str) -> tuple[str, list[str]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        lines = source.splitlines(keepends=True)
        transforms: list[str] = []
        edits: list[tuple[int, int, int, int, str]] = []

        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and len(node.comparators) == 1
                and node.end_lineno is not None
                and node.end_col_offset is not None
            ):
                op = node.ops[0]
                comparator = node.comparators[0]
                # Only modernize explicit None comparisons (never bool comparisons, which break vectorized/ORM masks)
                if isinstance(comparator, ast.Constant) and comparator.value is None:
                    if isinstance(op, ast.Eq):
                        replacement_op = "is"
                        transforms.append("Modernized '== None' to 'is None'")
                    elif isinstance(op, ast.NotEq):
                        replacement_op = "is not"
                        transforms.append("Modernized '!= None' to 'is not None'")
                    else:
                        continue

                    left_unparsed = ast.unparse(node.left)
                    new_expr = f"{left_unparsed} {replacement_op} None"
                    edits.append(
                        (
                            node.lineno,
                            node.col_offset,
                            node.end_lineno,
                            node.end_col_offset,
                            new_expr,
                        )
                    )
                elif isinstance(node.left, ast.Constant) and node.left.value is None:
                    if isinstance(op, ast.Eq):
                        replacement_op = "is"
                        transforms.append("Modernized 'None ==' to 'is None'")
                    elif isinstance(op, ast.NotEq):
                        replacement_op = "is not"
                        transforms.append("Modernized 'None !=' to 'is not None'")
                    else:
                        continue

                    comp_unparsed = ast.unparse(comparator)
                    new_expr = f"{comp_unparsed} {replacement_op} None"
                    edits.append(
                        (
                            node.lineno,
                            node.col_offset,
                            node.end_lineno,
                            node.end_col_offset,
                            new_expr,
                        )
                    )
                elif (
                    isinstance(comparator, ast.Constant)
                    and isinstance(comparator.value, bool)
                    and isinstance(node.left, ast.Name)
                ):
                    # Only modernize simple scalar identifier bool comparisons (never subscripts, attributes, or calls)
                    val = comparator.value
                    if isinstance(op, ast.Eq):
                        replacement_op = "is"
                        transforms.append(f"Modernized '== {val}' to 'is {val}'")
                    elif isinstance(op, ast.NotEq):
                        replacement_op = "is not"
                        transforms.append(f"Modernized '!= {val}' to 'is not {val}'")
                    else:
                        continue

                    left_unparsed = ast.unparse(node.left)
                    new_expr = f"{left_unparsed} {replacement_op} {val}"
                    edits.append(
                        (
                            node.lineno,
                            node.col_offset,
                            node.end_lineno,
                            node.end_col_offset,
                            new_expr,
                        )
                    )

        if not edits:
            return source, []

        edits.sort(key=lambda e: (e[0], e[1]), reverse=True)
        for lineno, col_offset, end_lineno, end_col_offset, new_text in edits:
            if lineno == end_lineno:
                idx = lineno - 1
                line = lines[idx]
                lines[idx] = line[:col_offset] + new_text + line[end_col_offset:]
            elif lineno < end_lineno:
                start_idx = lineno - 1
                end_idx = end_lineno - 1
                prefix = lines[start_idx][:col_offset]
                suffix = lines[end_idx][end_col_offset:]
                lines[start_idx : end_idx + 1] = [prefix + new_text + suffix]

        return "".join(lines), transforms

    def _prune_unicode_prefixes(self, source: str) -> tuple[str, list[str]]:
        try:
            tokens = list(
                tokenize.tokenize(io.BytesIO(source.encode("utf-8")).readline)
            )
        except tokenize.TokenError:
            return source, []

        edits: list[tuple[int, int, int, int]] = []
        for tok in tokens:
            if tok.type == tokenize.STRING:
                if tok.string.startswith(
                    ('u"', "u'", 'u"""', "u'''", 'U"', "U'", 'U"""', "U'''")
                ):
                    s_line, s_col = tok.start
                    edits.append((s_line, s_col, s_line, s_col + 1))

        if not edits:
            return source, []

        lines = source.splitlines(keepends=True)
        edits.sort(key=lambda e: (e[0], e[1]), reverse=True)
        for s_line, s_col, _e_line, e_col in edits:
            idx = s_line - 1
            if 0 <= idx < len(lines):
                line = lines[idx]
                lines[idx] = line[:s_col] + line[e_col:]

        new_source = "".join(lines)
        return new_source, ["Pruned obsolete unicode literal prefixes"]

    def _modernize_annotations(self, source: str) -> tuple[str, list[str]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, []

        lines = source.splitlines(keepends=True)
        edits: list[tuple[int, int, int, int, str]] = []

        typing_imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "typing":
                for alias in node.names:
                    if alias.name == "*":
                        typing_imports.update(
                            _AnnotationTransformer._PEP_585_MAP.keys()
                        )
                        typing_imports.update({"Optional", "Union"})
                    else:
                        typing_imports.add(alias.asname or alias.name)

        transformer = _AnnotationTransformer(typing_imports=typing_imports)

        def process_annotation(node: ast.AST | None) -> None:
            if not isinstance(node, ast.expr):
                return
            if node.end_lineno is None or node.end_col_offset is None:
                return
            sub = _AnnotationTransformer(typing_imports=typing_imports)
            new_node = sub.visit(node)
            if sub.changed:
                transformer.changed = True
                transformer.transformations.extend(sub.transformations)
                new_repr = ast.unparse(new_node)
                edits.append(
                    (
                        node.lineno,
                        node.col_offset,
                        node.end_lineno,
                        node.end_col_offset,
                        new_repr,
                    )
                )

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                process_annotation(node.returns)
                for arg in (
                    node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                ):
                    process_annotation(arg.annotation)
                if node.args.vararg:
                    process_annotation(node.args.vararg.annotation)
                if node.args.kwarg:
                    process_annotation(node.args.kwarg.annotation)
            elif isinstance(node, ast.AnnAssign):
                process_annotation(node.annotation)

        if not edits:
            return source, []

        edits.sort(key=lambda e: (e[0], e[1]), reverse=True)
        for lineno, col_offset, end_lineno, end_col_offset, new_text in edits:
            if lineno == end_lineno:
                idx = lineno - 1
                line = lines[idx]
                lines[idx] = line[:col_offset] + new_text + line[end_col_offset:]
            elif lineno < end_lineno:
                start_idx = lineno - 1
                end_idx = end_lineno - 1
                prefix = lines[start_idx][:col_offset]
                suffix = lines[end_idx][end_col_offset:]
                lines[start_idx : end_idx + 1] = [prefix + new_text + suffix]

        res = "".join(lines)

        if transformer.changed and "from __future__ import annotations" not in res:
            res = self._inject_future_annotations(res)
            transformer.transformations.append(
                "Injected 'from __future__ import annotations'"
            )

        return res, transformer.transformations

    @staticmethod
    def _inject_future_annotations(source: str) -> str:
        lines = source.splitlines(keepends=True)
        insert_idx = 0
        try:
            tree = ast.parse(source)
            if (
                tree.body
                and isinstance(tree.body[0], ast.Expr)
                and isinstance(tree.body[0].value, ast.Constant)
                and isinstance(tree.body[0].value.value, str)
            ):
                insert_idx = getattr(tree.body[0], "end_lineno", 1)
        except SyntaxError:
            pass  # Fall back to default index if docstring extraction fails

        future_stmt = "from __future__ import annotations\n\n"
        if insert_idx < len(lines):
            lines.insert(insert_idx, future_stmt)
        else:
            lines.append(future_stmt)

        return "".join(lines)
