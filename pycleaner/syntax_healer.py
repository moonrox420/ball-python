"""
Syntax healing engine for statically repairing common Python syntax errors.

Handles missing colons, single '=' comparison errors, legacy Python 2 syntax,
unbalanced parentheses/brackets/braces, and tab/indentation normalization.
"""

from __future__ import annotations

import ast
import io
import logging
import re
import tokenize
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class SyntaxHealResult:
    """Result of attempting to heal syntax errors in source code."""

    code: str
    is_valid: bool
    repairs: list[str] = field(default_factory=list)
    error_message: str | None = None
    error_lineno: int | None = None
    error_offset: int | None = None
    diagnostic: str | None = None


class SyntaxHealer:
    """Repairs common static syntax errors and validates compilation."""

    # Headers that must end with a colon
    _COMPOUND_HEADER_PATTERN = re.compile(
        r"^(?P<indent>[ \t]*)"
        r"(?P<header>"
        r"(?:async\s+)?(?:def|class|for|while|with)\b.*"
        r"|if\b.*"
        r"|elif\b.*"
        r"|else\b\s*"
        r"|try\b\s*"
        r"|except\b.*"
        r"|finally\b\s*"
        r"|match\b.*"
        r"|case\b.*"
        r")"
        r"(?P<trailing_comment>\s*#.*)?$",
        re.MULTILINE,
    )

    # Compound-statement keywords whose header must end in ':'.
    _COMPOUND_KEYWORDS = frozenset(
        {
            "def",
            "class",
            "if",
            "elif",
            "else",
            "for",
            "while",
            "try",
            "except",
            "finally",
            "with",
            "match",
            "case",
        }
    )

    _NON_HEADER_FOLLOWERS = frozenset(
        {
            "=",
            "+=",
            "-=",
            "*=",
            "/=",
            "//=",
            "%=",
            "**=",
            "&=",
            "|=",
            "^=",
            ">>=",
            "<<=",
            ":=",
            ".",
            ",",
        }
    )

    # Assignment `=` used instead of `==` inside if/elif/while
    _ASSIGNMENT_IN_CONDITIONAL = re.compile(
        r"^([ \t]*(?:if|elif|while)\s+)(.+?)(:?\s*(?:#.*)?)$",
        re.MULTILINE,
    )

    # Python 2 print statement without parentheses: print "hello", "world"
    _PY2_PRINT_PATTERN = re.compile(
        r"^([ \t]*)print\s+([\"'a-zA-Z0-9_\(\[\{].*?)$",
        re.MULTILINE,
    )

    # Python 2 except statement: except Exception, e: or except (E1, E2), e:
    _PY2_EXCEPT_PATTERN = re.compile(
        r"^([ \t]*except\s+(?:\((?:[^()]|\([^()]*\))*\)|[\w\.\s]+)),\s*([a-zA-Z_]\w*)\s*:(.*)$",
        re.MULTILINE,
    )

    def __init__(
        self,
        fix_py2_syntax: bool = True,
        fix_conditional_assignments: bool = True,
    ) -> None:
        """
        Args:
            fix_py2_syntax: Enable Python-2-era syntax repairs.
            fix_conditional_assignments: Enable rewriting an accidental '=' to '==' in conditions.
        """
        self.fix_py2_syntax = fix_py2_syntax
        self.fix_conditional_assignments = fix_conditional_assignments

    def _heal_valid_code(self, source: str, filename: str) -> tuple[str, list[str]]:
        cleaned = source
        repairs: list[str] = []
        if "\t" in source:
            tab_cleaned = source.expandtabs(4)
            if self._check_syntax(tab_cleaned, filename) is None:
                cleaned = tab_cleaned
                repairs.append("Normalized tab characters to 4 spaces")

        if self.fix_py2_syntax:
            py2_fixed, py2_count = self._fix_py2_except_ast(cleaned, filename)
            if py2_count > 0:
                cleaned = py2_fixed
                repairs.append(
                    f"Converted {py2_count} legacy Python 2 except clause(s) to 'as'"
                )
        return cleaned, repairs

    def _execute_healing_steps(
        self, source: str, filename: str
    ) -> tuple[str, list[str]]:
        code = source
        repairs: list[str] = []

        def apply_step(fn: Any, msg_fmt: str) -> None:
            nonlocal code
            try:
                prev_err = self._check_syntax(code, filename)
                new_code, count = fn(code)
                if count > 0 and new_code != code:
                    new_err = self._check_syntax(new_code, filename)
                    # If previously valid code was broken by this repair pass, roll back:
                    if prev_err is None and new_err is not None:
                        logging.getLogger(__name__).warning(
                            "Healing step %s introduced a syntax error; rolling back",
                            getattr(fn, "__name__", str(fn)),
                        )
                        return
                    if prev_err is not None and new_err is not None:
                        if "::" in new_code and "::" not in code:
                            cleaned = re.sub(r"(?<!:)::(?!:)", ":", new_code)
                            c_err = self._check_syntax(cleaned, filename)
                            if c_err is None or c_err != new_err:
                                new_code = cleaned
                                new_err = c_err
                        if prev_err is not None and new_err is not None:
                            if new_err[1] < prev_err[1]:
                                logging.getLogger(__name__).warning(
                                    "Healing step %s broke earlier line %d (previous error was line %d); rolling back",
                                    getattr(fn, "__name__", str(fn)),
                                    new_err[1],
                                    prev_err[1],
                                )
                                return
                    code = new_code
                    repairs.append(msg_fmt.format(count=count))
            except Exception:
                logging.getLogger(__name__).debug(
                    "Suppressed exception in syntax healing step", exc_info=True
                )

        if "\t" in code:
            code = code.expandtabs(4)
            repairs.append("Normalized tab characters to 4 spaces")

        if self.fix_py2_syntax:
            apply_step(
                self._fix_py2_except,
                "Converted {count} legacy Python 2 except clause(s) to 'as'",
            )
            apply_step(
                self._fix_py2_print,
                "Converted {count} legacy print statement(s) to print() calls",
            )

        if self.fix_conditional_assignments:
            apply_step(
                self._fix_conditional_assignments,
                "Replaced {count} accidental '=' assignment(s) with '==' in conditionals",
            )

        apply_step(
            self._fix_double_colons,
            "Normalized {count} duplicate colon(s) on compound statement header(s)",
        )

        apply_step(
            self._fix_missing_colons,
            "Appended missing ':' to {count} compound statement header(s)",
        )

        apply_step(
            self._fix_unindented_blocks,
            "Re-indented {count} under-indented block(s) following compound statement headers",
        )

        try:
            prev_err = self._check_syntax(code, filename)
            d_code, d_repairs = self._fix_unbalanced_delimiters(code, filename=filename)
            if d_code != code:
                d_err = self._check_syntax(d_code, filename)
                if prev_err is None and d_err is not None:
                    logging.getLogger(__name__).warning(
                        "Delimiter healing broke valid syntax; rolling back"
                    )
                else:
                    code = d_code
                    repairs.extend(d_repairs)
        except Exception:
            logging.getLogger(__name__).debug(
                "Suppressed exception closing delimiters", exc_info=True
            )

        return code, repairs

    def heal(self, source: str, filename: str = "<unknown>") -> SyntaxHealResult:
        """Attempt to statically repair syntax errors in the given Python source."""
        if self._check_syntax(source, filename) is None:
            cleaned, repairs = self._heal_valid_code(source, filename)
            return SyntaxHealResult(code=cleaned, is_valid=True, repairs=repairs)

        repaired, repairs = self._execute_healing_steps(source, filename)
        final_error = self._check_syntax(repaired, filename)
        if final_error is None:
            return SyntaxHealResult(code=repaired, is_valid=True, repairs=repairs)

        err_msg, lineno, offset = final_error
        diag = self.format_diagnostic(source, filename=filename, error=final_error)
        return SyntaxHealResult(
            code=repaired,
            is_valid=False,
            repairs=repairs,
            error_message=err_msg,
            error_lineno=lineno,
            error_offset=offset,
            diagnostic=diag,
        )

    def _fix_unindented_blocks(self, source: str) -> tuple[str, int]:
        """
        Auto-heal under-indented blocks following compound statement headers.
        Repairs situations where docstrings or body statements were not indented
        relative to def, class, if, while, for, with, try, except, etc.
        """
        lines = source.splitlines()
        repaired_count = 0
        max_passes = 10

        for _ in range(max_passes):
            try:
                ast.parse("\n".join(lines))
                break
            except IndentationError as err:
                msg = err.msg or ""
                if "expected an indented block" not in msg:
                    break

                header_idx = None
                m = re.search(r"on line (\d+)", msg)
                if m:
                    header_idx = int(m.group(1)) - 1
                else:
                    target_idx = (err.lineno or 2) - 1
                    for i in range(target_idx - 1, -1, -1):
                        stripped = lines[i].strip()
                        if stripped and not stripped.startswith("#"):
                            header_idx = i
                            break

                if header_idx is None or header_idx < 0 or header_idx >= len(lines):
                    break

                header_line = lines[header_idx]
                header_indent = len(header_line) - len(header_line.lstrip())
                desired_indent = header_indent + 4
                start_idx = header_idx + 1

                i = start_idx
                in_multiline_str = False
                multiline_quote = ""

                while i < len(lines):
                    line = lines[i]
                    stripped = line.strip()

                    if not stripped:
                        i += 1
                        continue

                    curr_indent = len(line) - len(line.lstrip())

                    was_in_multiline = in_multiline_str
                    if in_multiline_str:
                        if multiline_quote in stripped:
                            in_multiline_str = False
                    else:
                        if stripped.startswith(('"""', chr(39) * 3)):
                            quote = stripped[:3]
                            if stripped.count(quote) % 2 == 1:
                                in_multiline_str = True
                                multiline_quote = quote

                    is_sibling_declaration = (
                        curr_indent <= header_indent
                        and stripped.startswith(("def ", "class ", "async def ", "@"))
                    )
                    is_outer_scope = (
                        header_indent > 0
                        and curr_indent == 0
                        and not was_in_multiline
                        and not stripped.startswith(('"""', chr(39) * 3))
                    )

                    if (
                        not was_in_multiline
                        and not in_multiline_str
                        and (is_sibling_declaration or is_outer_scope)
                    ):
                        break

                    if curr_indent < desired_indent:
                        shift = desired_indent - curr_indent
                        lines[i] = (" " * shift) + line
                    i += 1

                repaired_count += 1
            except SyntaxError:
                break

        return "\n".join(lines), repaired_count

    def format_diagnostic(
        self,
        source: str,
        filename: str = "<unknown>",
        error: tuple[str, int, int] | None = None,
    ) -> str:
        """Format an unhealed syntax error into a rich, compiler-grade diagnostic banner."""
        err = error or self._check_syntax(source, filename)
        if err is None:
            return ""
        msg, lineno, offset = err
        lines = source.splitlines()
        line_idx = max(0, min(lineno - 1, len(lines) - 1)) if lines else 0
        error_line = lines[line_idx] if lines else ""
        pointer_indent = " " * max(0, offset - 1)

        diagnostic_lines = [
            f"[!] SyntaxError in {filename}:{lineno}:{offset}",
            f"   --> {filename}:{lineno}:{offset}",
            "    |",
            f"{lineno:3d} | {error_line}",
            f"    | {pointer_indent}^",
            f"    = Error: {msg}",
        ]
        return "\n".join(diagnostic_lines)

    def _check_syntax(self, code: str, filename: str) -> tuple[str, int, int] | None:
        """Parse source code into AST. Returns None on success, or (msg, lineno, offset) on error."""
        try:
            ast.parse(code, filename=filename)
            return None
        except SyntaxError as err:
            return (
                err.msg or "SyntaxError",
                err.lineno or 1,
                err.offset or 1,
            )

    def _inspect_except_handler(
        self, node: ast.ExceptHandler
    ) -> tuple[str, str, int] | None:
        if node.name is not None or not isinstance(node.type, ast.Tuple):
            return None
        elts = node.type.elts
        if len(elts) < 2 or not isinstance(elts[-1], ast.Name):
            return None

        exc_strs: list[str] = []
        for e in elts[:-1]:
            s = self._ast_name_to_str(e)
            if s == "<unknown>":
                return None
            exc_strs.append(s)

        if not exc_strs:
            return None

        exc_str = exc_strs[0] if len(exc_strs) == 1 else f"({', '.join(exc_strs)})"
        return exc_str, elts[-1].id, node.lineno

    def _format_py2_except_line(
        self, line: str, exc_str: str, var_name: str
    ) -> str | None:
        indent_match = re.match(r"^([ \t]*)", line)
        indent = indent_match.group(1) if indent_match else ""
        pattern = re.compile(r"^([ \t]*except\s+)(.+?)\s*:(.*?)(\s*#.*)?$")
        m = pattern.match(line.rstrip("\r\n"))
        if not m:
            return None

        trailing = m.group(3).strip()
        comment = m.group(4) or ""
        ending = (
            "\r\n" if line.endswith("\r\n") else ("\n" if line.endswith("\n") else "")
        )
        if trailing:
            return (
                f"{indent}except {exc_str} as {var_name}: {trailing}{comment}{ending}"
            )
        return f"{indent}except {exc_str} as {var_name}:{comment}{ending}"

    def _collect_py2_except_fixes(
        self, tree: ast.Module, lines: Sequence[str]
    ) -> list[tuple[int, str]]:
        fixes: list[tuple[int, str]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                info = self._inspect_except_handler(node)
                if info and 1 <= info[2] <= len(lines):
                    exc_str, var_name, lineno = info
                    new_line = self._format_py2_except_line(
                        lines[lineno - 1], exc_str, var_name
                    )
                    if new_line:
                        fixes.append((lineno, new_line))
        return fixes

    def _fix_py2_except_ast(
        self, code: str, filename: str = "<unknown>"
    ) -> tuple[str, int]:
        """Detect Python 2 'except X, e:' patterns via AST on syntactically valid code."""
        try:
            tree = ast.parse(code, filename=filename)
        except SyntaxError:
            return code, 0

        lines = code.splitlines(keepends=True)
        fixes = self._collect_py2_except_fixes(tree, lines)
        if not fixes:
            return code, 0

        fixes.sort(key=lambda f: f[0], reverse=True)
        for lineno, new_line in fixes:
            lines[lineno - 1] = new_line

        candidate = "".join(lines)
        if self._check_syntax(candidate, filename) is None:
            return candidate, len(fixes)

        return code, 0

    @staticmethod
    def _ast_name_to_str(node: ast.AST) -> str:
        """Convert an ast.Name, ast.Attribute, or ast.Tuple node to a string representation."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            value_str = SyntaxHealer._ast_name_to_str(node.value)
            return f"{value_str}.{node.attr}"
        if isinstance(node, ast.Tuple):
            parts = [SyntaxHealer._ast_name_to_str(sub) for sub in node.elts]
            if any(p == "<unknown>" for p in parts):
                return "<unknown>"
            return f"({', '.join(parts)})"
        return "<unknown>"

    @staticmethod
    def _is_async_prefix(tokens: Sequence[tokenize.TokenInfo]) -> bool:
        if len(tokens) < 2:
            return False
        first = tokens[0]
        return first.type == tokenize.NAME and first.string == "async"

    def _is_valid_header_token(
        self, tokens: Sequence[tokenize.TokenInfo], idx: int
    ) -> bool:
        if idx >= len(tokens):
            return False
        tok = tokens[idx]
        if tok.type != tokenize.NAME or tok.string not in self._COMPOUND_KEYWORDS:
            return False
        if tok.string in ("match", "case") and idx + 1 < len(tokens):
            nxt = tokens[idx + 1]
            return (
                nxt.type != tokenize.OP or nxt.string not in self._NON_HEADER_FOLLOWERS
            )
        return True

    def _get_compound_header_idx(
        self, tokens: Sequence[tokenize.TokenInfo]
    ) -> int | None:
        idx = 1 if self._is_async_prefix(tokens) else 0
        return idx if self._is_valid_header_token(tokens, idx) else None

    @staticmethod
    def _has_colon_at_depth_zero(
        tokens: Sequence[tokenize.TokenInfo], start_idx: int
    ) -> bool:
        depth = 0
        for tok in tokens[start_idx:]:
            if tok.type == tokenize.OP:
                if tok.string in ("(", "[", "{"):
                    depth += 1
                elif tok.string in (")", "]", "}"):
                    depth = max(0, depth - 1)
                elif tok.string == ":" and depth == 0:
                    return True
        return False

    def _find_missing_colon_insertions(
        self, tokens: Sequence[tokenize.TokenInfo]
    ) -> list[tuple[int, int]]:
        insertions: list[tuple[int, int]] = []
        logical_tokens: list[tokenize.TokenInfo] = []

        def flush() -> None:
            if not logical_tokens:
                return
            header_idx = self._get_compound_header_idx(logical_tokens)
            if header_idx is None:
                return
            if self._has_colon_at_depth_zero(logical_tokens, header_idx + 1):
                return
            # If the last token is already a colon, do not append another one
            if logical_tokens[-1].string == ":":
                return
            last = logical_tokens[-1]
            insertions.append((last.end[0] - 1, last.end[1]))

        skip_types = {
            tokenize.NL,
            tokenize.COMMENT,
            tokenize.INDENT,
            tokenize.DEDENT,
            tokenize.ENCODING,
            tokenize.ENDMARKER,
        }
        for tok in tokens:
            if tok.type in skip_types:
                continue
            if tok.type == tokenize.NEWLINE:
                flush()
                logical_tokens = []
            else:
                logical_tokens.append(tok)
        flush()
        return insertions

    _DOUBLE_COLON_RE = re.compile(
        r"^([ \t]*(?:async\s+)?(?:def\s+[a-zA-Z_]\w*|class\s+[a-zA-Z_]\w*|if\b|elif\b|else\b|for\b|while\b|try\b|except\b|finally\b|with\b)[^\n#]*?):{2,}(\s*(?:#.*)?)$"
    )

    def _fix_double_colons(self, code: str) -> tuple[str, int]:
        """Normalize multiple consecutive colons on compound statement headers."""
        if "::" not in code:
            return code, 0
        lines = code.splitlines(keepends=True)
        count = 0
        new_lines: list[str] = []
        for line in lines:
            m = self._DOUBLE_COLON_RE.match(line.rstrip("\r\n"))
            if m:
                header = m.group(1).rstrip()
                suffix = m.group(2)
                ending = (
                    "\r\n"
                    if line.endswith("\r\n")
                    else ("\n" if line.endswith("\n") else "")
                )
                new_lines.append(f"{header}:{suffix}{ending}")
                count += 1
            else:
                new_lines.append(line)
        return "".join(new_lines), count

    _COMPOUND_HEADER_FALLBACK = re.compile(
        r"^([ \t]*(?:async\s+)?(?:def\s+[a-zA-Z_]\w*|class\s+[a-zA-Z_]\w*|if\b|elif\b|else\b|for\b|while\b|try\b|except\b|finally\b|with\b)[^\n#]*?)(?<!:)(\s*(?:#.*)?)$"
    )

    def _fix_missing_colons_fallback(self, code: str) -> tuple[str, int]:
        """Line-by-line regex fallback to append missing colons to compound statements."""
        lines = code.splitlines(keepends=True)
        count = 0
        new_lines: list[str] = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                new_lines.append(line)
                continue

            # If the non-comment portion of the line already ends with ':', skip it
            clean_line = re.sub(r"#.*$", "", line.rstrip("\r\n")).rstrip()
            if clean_line.endswith(":"):
                new_lines.append(line)
                continue

            m = self._COMPOUND_HEADER_FALLBACK.match(line.rstrip("\r\n"))
            if m:
                header = m.group(1).rstrip()
                # Before appending ':', check that the header does not already end with ':'
                if header.endswith(":"):
                    new_lines.append(line)
                    continue

                # If this line already has a colon at depth 0 (e.g. one-liner: if cond: return x, or else: return 0), skip it!
                depth = 0
                has_colon_at_depth_0 = False
                in_quote = False
                quote_char = ""
                for char in header:
                    if in_quote:
                        if char == quote_char:
                            in_quote = False
                    elif char in ("'", '"'):
                        in_quote = True
                        quote_char = char
                    elif char in "([{":
                        depth += 1
                    elif char in ")]}":
                        depth = max(0, depth - 1)
                    elif char == ":" and depth == 0:
                        has_colon_at_depth_0 = True
                        break

                if has_colon_at_depth_0:
                    new_lines.append(line)
                    continue

                # If brackets on this line are unbalanced (e.g. def foo(\n), skip appending colon to this line
                open_cnt = sum(header.count(c) for c in "([{")
                close_cnt = sum(header.count(c) for c in ")]}")
                if open_cnt > close_cnt:
                    new_lines.append(line)
                    continue

                suffix = m.group(2)
                ending = (
                    "\r\n"
                    if line.endswith("\r\n")
                    else ("\n" if line.endswith("\n") else "")
                )
                new_lines.append(f"{header}:{suffix}{ending}")
                count += 1
            else:
                new_lines.append(line)
        return "".join(new_lines), count

    def _fix_missing_colons(self, code: str) -> tuple[str, int]:
        """Detect compound statement headers without trailing colons and append them."""
        tokens: list[tokenize.TokenInfo] | None = None
        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(code).readline))
        except tokenize.TokenError:
            tokens = self._tokenize_with_recovered_delimiters(code)

        cur_code = code
        total_count = 0

        if tokens is not None:
            insertions = self._find_missing_colon_insertions(tokens)
            if insertions:
                lines = cur_code.splitlines(keepends=True)
                insertions.sort(key=lambda pos: (pos[0], pos[1]), reverse=True)
                applied_insertions = 0
                for line_idx, col in insertions:
                    if 0 <= line_idx < len(lines):
                        target = lines[line_idx]
                        before = target[:col].rstrip()
                        after = target[col:].lstrip()
                        if before.endswith(":") or after.startswith(":"):
                            continue
                        clean_line = re.sub(r"#.*$", "", target).rstrip()
                        if clean_line.endswith(":"):
                            continue
                        lines[line_idx] = target[:col] + ":" + target[col:]
                        applied_insertions += 1
                cur_code = "".join(lines)
                total_count += applied_insertions

        # Also run fallback to catch any compound headers missed (e.g. disrupted by unclosed delimiters)
        cur_code, fb_count = self._fix_missing_colons_fallback(cur_code)
        total_count += fb_count

        # Clean up any accidental double colons created on compound headers
        if "::" in cur_code and "::" not in code:
            cur_code = re.sub(r"(?<!:)::(?!:)", ":", cur_code)

        return cur_code, total_count

    def _tokenize_with_recovered_delimiters(
        self, code: str
    ) -> list[tokenize.TokenInfo] | None:
        """Tokenize code that fails tokenization only due to unclosed delimiters."""
        unclosed = self._scan_unclosed_delimiters(code)
        if not unclosed:
            return None
        closers = "".join(item[0] for item in reversed(unclosed))
        padded = code if code.endswith("\n") else code + "\n"
        padded = padded + closers + "\n"
        try:
            return list(tokenize.generate_tokens(io.StringIO(padded).readline))
        except tokenize.TokenError:
            return None

    @staticmethod
    def _is_standalone_assignment(chars: Sequence[str], i: int, in_call: bool) -> bool:
        if chars[i] != "=" or in_call:
            return False
        prev_c = chars[i - 1] if i > 0 else ""
        next_c = chars[i + 1] if i + 1 < len(chars) else ""
        if prev_c in ("=", "!", "<", ">", ":") or next_c == "=":
            return False
        return prev_c not in ("+", "-", "*", "/", "%", "&", "|", "^")

    @staticmethod
    def _update_quote_flag(c: str, in_s: bool, in_d: bool) -> tuple[bool, bool]:
        if c == "'" and not in_d:
            return not in_s, in_d
        if c == '"' and not in_s:
            return in_s, not in_d
        return in_s, in_d

    @classmethod
    def _replace_condition_equals(cls, condition: str) -> tuple[str, int]:
        chars = list(condition)
        call_bracket_stack: list[bool] = []
        in_s = False
        in_d = False
        escaped = False
        count = 0
        i = 0
        while i < len(chars):
            c = chars[i]
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif in_s or in_d or c in ("'", '"'):
                in_s, in_d = cls._update_quote_flag(c, in_s, in_d)
            elif c in "([{":
                prev_non_ws = ""
                for j in range(i - 1, -1, -1):
                    if not chars[j].isspace():
                        prev_non_ws = chars[j]
                        break
                is_call_or_subscript = bool(
                    prev_non_ws
                    and (prev_non_ws.isalnum() or prev_non_ws in ("_", ")", "]"))
                )
                call_bracket_stack.append(is_call_or_subscript)
            elif c in ")]}":
                if call_bracket_stack:
                    call_bracket_stack.pop()
            else:
                in_call = any(call_bracket_stack)
                if cls._is_standalone_assignment(chars, i, in_call):
                    chars[i] = "=="
                    count += 1
            i += 1
        return "".join(chars), count

    def _fix_conditional_assignments(self, code: str) -> tuple[str, int]:
        """Replace single '=' with '==' in condition statements."""
        count = 0

        def replacer(match: re.Match[str]) -> str:
            nonlocal count
            prefix, cond, suffix = match.group(1), match.group(2), match.group(3)
            repaired_cond, local_count = self._replace_condition_equals(cond)
            if local_count == 0:
                return match.group(0)

            test_code = f"{prefix}{repaired_cond}{suffix}".strip()
            if not test_code.endswith(":"):
                test_code += ":"
            test_code += "\n    pass\n"
            try:
                ast.parse(test_code)
                count += local_count
                return f"{prefix}{repaired_cond}{suffix}"
            except SyntaxError:
                return match.group(0)

        new_code = self._ASSIGNMENT_IN_CONDITIONAL.sub(replacer, code)
        return new_code, count

    def _fix_py2_print(self, code: str) -> tuple[str, int]:
        """Convert Python 2 print statements to Python 3 function calls."""
        count = 0

        def replacer(match: re.Match[str]) -> str:
            nonlocal count
            indent = match.group(1)
            content = match.group(2).strip()

            # Skip if already parenthesized like print(...)
            if content.startswith("(") and content.endswith(")"):
                return match.group(0)

            # Skip print >> stream redirection or complex prints for safety
            if content.startswith(">>"):
                return match.group(0)

            count += 1
            return f"{indent}print({content})"

        new_code = self._PY2_PRINT_PATTERN.sub(replacer, code)
        return new_code, count

    def _fix_py2_except(self, code: str) -> tuple[str, int]:
        """Convert 'except Error, e:' to 'except Error as e:'."""
        count = 0

        def replacer(match: re.Match[str]) -> str:
            nonlocal count
            prefix = match.group(1)
            var_name = match.group(2)
            trailing = match.group(3)
            count += 1
            return f"{prefix} as {var_name}:{trailing}"

        new_code = self._PY2_EXCEPT_PATTERN.sub(replacer, code)
        return new_code, count

    @staticmethod
    def _scan_unclosed_delimiters(code: str) -> list[tuple[str, int, int]]:
        stack: list[tuple[str, int, int]] = []
        pairs = {"(": ")", "[": "]", "{": "}"}
        closing = {")": "(", "]": "[", "}": "{"}
        try:
            for tok in tokenize.generate_tokens(io.StringIO(code).readline):
                if tok.type == tokenize.OP:
                    if tok.string in pairs:
                        stack.append((pairs[tok.string], tok.start[0], tok.start[1]))
                    elif tok.string in closing and stack and stack[-1][0] == tok.string:
                        stack.pop()
        except tokenize.TokenError:
            # Incomplete token stream will be healed by delimiter reconstruction
            logging.getLogger(__name__).debug("Suppressed exception", exc_info=True)
        return stack

    @staticmethod
    def _append_delimiters_to_last_line(code: str, closing_str: str) -> str:
        lines = code.splitlines(keepends=True)
        if not lines:
            return code.rstrip() + closing_str + "\n"

        last_line = lines[-1]
        comment_idx = last_line.find("#")
        if comment_idx != -1:
            pre = last_line[:comment_idx].rstrip()
            post = last_line[comment_idx:]
            lines[-1] = f"{pre}{closing_str} {post}"
        else:
            ending = (
                "\r\n"
                if last_line.endswith("\r\n")
                else ("\n" if last_line.endswith("\n") else "")
            )
            lines[-1] = f"{last_line.rstrip()}{closing_str}{ending}"
        return "".join(lines)

    def _append_delimiters_to_line(
        self, code: str, lineno: int, closing_str: str
    ) -> str:
        """Append closing delimiters at the end of a specific 1-based line."""
        lines = code.splitlines(keepends=True)
        if not 1 <= lineno <= len(lines):
            return code

        target_line = lines[lineno - 1]
        comment_idx = target_line.find("#")
        if comment_idx != -1:
            pre = target_line[:comment_idx].rstrip()
            post = target_line[comment_idx:]
            lines[lineno - 1] = f"{pre}{closing_str} {post}"
            return "".join(lines)

        ending = (
            "\r\n"
            if target_line.endswith("\r\n")
            else ("\n" if target_line.endswith("\n") else "")
        )
        lines[lineno - 1] = f"{target_line.rstrip()}{closing_str}{ending}"
        return "".join(lines)

    def _fix_unbalanced_delimiters(
        self, code: str, filename: str = "<unknown>"
    ) -> tuple[str, list[str]]:
        """Identify unclosed delimiters across lines and append closing delimiters if it restores valid syntax."""
        stack = self._scan_unclosed_delimiters(code)
        if not stack:
            return code, []

        closing_str = "".join(item[0] for item in reversed(stack))
        candidate = self._append_delimiters_to_last_line(code, closing_str)
        if self._check_syntax(candidate, filename) is None:
            return candidate, [f"Closed unclosed delimiter(s): {closing_str}"]

        inline_candidate = self._append_delimiters_to_line(
            code, stack[-1][1], closing_str
        )
        if (
            inline_candidate != code
            and self._check_syntax(inline_candidate, filename) is None
        ):
            return inline_candidate, [f"Closed unclosed delimiter(s): {closing_str}"]

        return code, []
