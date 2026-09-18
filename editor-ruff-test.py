"""Code editor, syntax highlighter, completion popup, and tab manager.

This module provides high-performance components for Python code editing
within the PipViper IDE. The editor integrates tightly with local Jedi services
to provide autocomplete, hover, signature documentation, and reference lookup.
It also embeds a self-healing dependency warning banner atop the editor canvas.
"""

from __future__ import annotations

import importlib.util
import logging
import re
import sys
from pathlib import Path
from typing import Any, ClassVar

from PySide6.QtCore import QPoint, QRect, QSize, Qt, QTimer, Signal, Slot
from PySide6.QtGui import (
    QCloseEvent,
    QColor,
    QFont,
    QKeyEvent,
    QMouseEvent,
    QPainter,
    QPaintEvent,
    QResizeEvent,
    QShowEvent,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextCursor,
    QTextDocument,
    QTextFormat,
)
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QToolTip,
    QVBoxLayout,
    QWidget,
)

from .code_tools import CodeIssue
from .diagnostics import DiagnosticIssue
from .pip_viper import (
    AppConfig,
    ColorPalette,
    JediCompletion,
    JediResult,
    JediService,
    JediTaskType,
)
from .vcs import GitDiffHunk, GitDiffType

_LOGGER: logging.Logger = logging.getLogger("src.editor")
_DEDENT_TRIGGER_PATTERN: re.Pattern[str] = re.compile(
    r"^\s*(return|break|continue|pass|raise|elif|else|except|finally)\b"
)


# -----------------------------------------------------------------------------
# Code Folding & Scope Extraction
# -----------------------------------------------------------------------------


def _utf8_col_to_char_offset(line_text: str, utf8_col: int) -> int:
    """Convert a 1-based UTF-8 byte column into a 0-based character index.

    Ruff reports column numbers as 1-based byte offsets into the UTF-8 encoded line.
    This safely translates that into a character offset within QString/Python str
    without overflowing line length or splitting multi-byte sequences.
    """
    if utf8_col <= 1:
        return 0
    target_byte_offset = utf8_col - 1
    current_byte_count = 0
    for char_idx, char in enumerate(line_text):
        if current_byte_count >= target_byte_offset:
            return char_idx
        current_byte_count += len(char.encode("utf-8"))
    return len(line_text)


def calculate_fold_ranges(doc: QTextDocument) -> dict[int, int]:
    """Compute foldable code blocks for Python source code within doc.

    Returns a mapping from 1-indexed start line to 1-indexed end line.
    Foldable blocks include functions, classes, compound control statements,
    and multi-line docstrings.
    """
    fold_ranges: dict[int, int] = {}
    total_blocks = doc.blockCount()
    if total_blocks <= 1:
        return fold_ranges

    lines_info: list[tuple[int, str, int]] = []
    block = doc.begin()
    line_num = 1
    while block.isValid():
        text = block.text()
        stripped = text.strip()
        if stripped and not stripped.startswith("#"):
            expanded = text[: len(text) - len(text.lstrip())].expandtabs(4)
            indent = len(expanded)
            lines_info.append((line_num, text, indent))
        else:
            lines_info.append((line_num, "", -1))
        block = block.next()
        line_num += 1

    n = len(lines_info)
    for idx in range(n):
        l_num, text, indent = lines_info[idx]
        if indent == -1:
            continue
        next_non_empty_idx = -1
        for j in range(idx + 1, n):
            if lines_info[j][2] != -1:
                next_non_empty_idx = j
                break

        if next_non_empty_idx != -1 and lines_info[next_non_empty_idx][2] > indent:
            target_indent = indent
            last_block_line = lines_info[next_non_empty_idx][0]
            for k in range(next_non_empty_idx + 1, n):
                k_line, _, k_indent = lines_info[k]
                if k_indent == -1:
                    continue
                if k_indent <= target_indent:
                    break
                last_block_line = k_line
            if last_block_line > l_num:
                fold_ranges[l_num] = last_block_line

    # Also detect multi-line strings and docstrings
    in_triple_double = False
    in_triple_single = False
    triple_start_line = -1
    block = doc.begin()
    line_num = 1
    while block.isValid():
        text = block.text()
        count_d = text.count('"""')
        count_s = text.count("'''")
        if not in_triple_double and not in_triple_single:
            if count_d % 2 == 1:
                in_triple_double = True
                triple_start_line = line_num
            elif count_s % 2 == 1:
                in_triple_single = True
                triple_start_line = line_num
        elif in_triple_double and count_d % 2 == 1:
            in_triple_double = False
            if line_num > triple_start_line:
                fold_ranges[triple_start_line] = line_num
        elif in_triple_single and count_s % 2 == 1:
            in_triple_single = False
            if line_num > triple_start_line:
                fold_ranges[triple_start_line] = line_num
        block = block.next()
        line_num += 1

    return fold_ranges


def get_enclosing_scopes(
    doc: QTextDocument, line_number: int
) -> list[tuple[str, str, int]]:
    """Return the hierarchy of enclosing class and def declarations for line_number.

    Returns a list of tuples: (kind, header_text, line_number_1_indexed),
    ordered from outermost scope to innermost scope.
    """
    scopes: list[tuple[str, str, int]] = []
    if line_number <= 0 or doc.blockCount() == 0:
        return scopes

    lines: list[tuple[int, str, int]] = []
    block = doc.begin()
    curr_line = 1
    while block.isValid() and curr_line <= line_number:
        text = block.text()
        stripped = text.strip()
        if stripped and not stripped.startswith("#"):
            indent = len(text[: len(text) - len(text.lstrip())].expandtabs(4))
            lines.append((curr_line, stripped, indent))
        else:
            lines.append((curr_line, "", -1))
        block = block.next()
        curr_line += 1

    if not lines:
        return scopes

    target_indent = 999999
    for idx in range(len(lines) - 1, -1, -1):
        if lines[idx][2] != -1:
            target_indent = lines[idx][2]
            break

    curr_indent_bound = target_indent + 1
    for idx in range(len(lines) - 1, -1, -1):
        l_num, stripped, indent = lines[idx]
        if indent == -1:
            continue
        if indent < curr_indent_bound:
            if stripped.startswith(("def ", "async def ", "class ")):
                kind = "class" if stripped.startswith("class ") else "function"
                header = stripped.split(":")[0].strip()
                scopes.append((kind, header, l_num))
                curr_indent_bound = indent
            elif indent == 0:
                curr_indent_bound = 0

    scopes.reverse()
    return scopes


# -----------------------------------------------------------------------------
# Syntax Highlighter
# -----------------------------------------------------------------------------


class PythonSyntaxHighlighter(QSyntaxHighlighter):
    """Highlight Python source according to the active ColorPalette."""

    KEYWORDS: ClassVar[frozenset[str]] = frozenset(
        {
            "False",
            "None",
            "True",
            "and",
            "as",
            "assert",
            "async",
            "await",
            "break",
            "class",
            "continue",
            "def",
            "del",
            "elif",
            "else",
            "except",
            "finally",
            "for",
            "from",
            "global",
            "if",
            "import",
            "in",
            "is",
            "lambda",
            "nonlocal",
            "not",
            "or",
            "pass",
            "raise",
            "return",
            "try",
            "while",
            "with",
            "yield",
            "match",
            "case",
            "self",
            "cls",
        }
    )

    BUILTINS: ClassVar[frozenset[str]] = frozenset(
        {
            "print",
            "len",
            "range",
            "int",
            "str",
            "float",
            "list",
            "dict",
            "set",
            "tuple",
            "bool",
            "open",
            "type",
            "isinstance",
            "hasattr",
            "getattr",
            "setattr",
            "delattr",
            "super",
            "enumerate",
            "zip",
            "map",
            "filter",
            "sorted",
            "reversed",
            "min",
            "max",
            "sum",
            "abs",
            "all",
            "any",
            "iter",
            "next",
            "repr",
            "input",
            "id",
            "hex",
            "oct",
            "bin",
            "ord",
            "chr",
            "exec",
            "eval",
            "compile",
            "globals",
            "locals",
            "vars",
            "dir",
            "help",
            "object",
            "bytes",
        }
    )

    _STRING_PATTERN: re.Pattern[str] = re.compile(
        r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\''
    )
    _COMMENT_PATTERN: re.Pattern[str] = re.compile(r"#[^\n]*")
    _DECORATOR_PATTERN: re.Pattern[str] = re.compile(r"@[A-Za-z_][A-Za-z0-9_]*")
    _NUMBER_PATTERN: re.Pattern[str] = re.compile(r"\b\d+(?:\.\d+)?\b")
    _KEYWORD_PATTERN: re.Pattern[str] = re.compile(
        r"\b(?:" + "|".join(KEYWORDS) + r")\b"
    )
    _BUILTIN_PATTERN: re.Pattern[str] = re.compile(
        r"\b(?:" + "|".join(BUILTINS) + r")\b"
    )
    _FUNCTION_DEF_PATTERN: re.Pattern[str] = re.compile(
        r"\bdef\s+([A-Za-z_][A-Za-z0-9_]*)"
    )
    _CLASS_DEF_PATTERN: re.Pattern[str] = re.compile(
        r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)"
    )

    def __init__(self, document: QTextDocument, palette: ColorPalette) -> None:
        super().__init__(document)
        self._palette: ColorPalette = palette
        self._formats: dict[str, QTextCharFormat] = {}
        self._build_formats()

    def set_palette(self, palette: ColorPalette) -> None:
        """Rebuild the format map and re-highlight the entire document."""
        self._palette = palette
        self._build_formats()
        self.rehighlight()

    def _build_formats(self) -> None:
        palette_reference = self._palette
        self._formats = {
            "keyword": self._create_text_char_format(
                palette_reference.keyword, bold=True
            ),
            "string": self._create_text_char_format(palette_reference.string),
            "comment": self._create_text_char_format(
                palette_reference.comment, italic=True
            ),
            "number": self._create_text_char_format(palette_reference.number),
            "builtin": self._create_text_char_format(palette_reference.builtin),
            "function": self._create_text_char_format(palette_reference.function_name),
            "decorator": self._create_text_char_format(palette_reference.decorator),
            "class": self._create_text_char_format(
                palette_reference.class_name, bold=True
            ),
        }

    @staticmethod
    def _create_text_char_format(
        color_hex: str, *, bold: bool = False, italic: bool = False
    ) -> QTextCharFormat:
        char_format = QTextCharFormat()
        char_format.setForeground(QColor(color_hex))
        if bold:
            char_format.setFontWeight(QFont.Weight.Bold)
        if italic:
            char_format.setFontItalic(True)
        return char_format

    def highlightBlock(self, text: str) -> None:  # type: ignore[override]
        """Highlight a block of Python text using robust state-aware layering."""
        if not text:
            return

        # 1. Paint underlying lexical tokens (structural, functional, and literal)
        self._apply_pattern(text, self._BUILTIN_PATTERN, self._formats["builtin"])
        self._apply_pattern(text, self._NUMBER_PATTERN, self._formats["number"])
        self._apply_pattern(text, self._DECORATOR_PATTERN, self._formats["decorator"])
        self._apply_pattern(text, self._KEYWORD_PATTERN, self._formats["keyword"])
        self._apply_pattern(text, self._FUNCTION_DEF_PATTERN, self._formats["function"])
        self._apply_pattern(text, self._CLASS_DEF_PATTERN, self._formats["class"])

        # Overwrite with higher specificity single-line literals & comments
        self._apply_pattern(text, self._STRING_PATTERN, self._formats["string"])
        self._apply_pattern(text, self._COMMENT_PATTERN, self._formats["comment"])

        # 2. Overwrite multiline triple-quoted strings using a solid state machine
        # Block State Map: 0 = Normal context, 1 = Inside triple double-quotes ("""), 2 = Inside triple single-quotes (''')
        state = self.previousBlockState()
        state = max(state, 0)

        start_idx = 0
        i = 0
        length = len(text)
        while i < length:
            if state == 0:
                if text.startswith('"""', i):
                    start_idx = i
                    state = 1
                    i += 3
                elif text.startswith("'''", i):
                    start_idx = i
                    state = 2
                    i += 3
                else:
                    i += 1
            elif state == 1:
                if text.startswith('"""', i):
                    token_len = i + 3 - start_idx
                    self.setFormat(start_idx, token_len, self._formats["string"])
                    state = 0
                    i += 3
                else:
                    i += 1
            elif state == 2:
                if text.startswith("'''", i):
                    token_len = i + 3 - start_idx
                    self.setFormat(start_idx, token_len, self._formats["string"])
                    state = 0
                    i += 3
                else:
                    i += 1

        if state > 0:
            self.setFormat(start_idx, length - start_idx, self._formats["string"])

        self.setCurrentBlockState(state)

    def _apply_pattern(
        self, text: str, pattern: re.Pattern[str], char_format: QTextCharFormat
    ) -> None:
        for match_object in pattern.finditer(text):
            start_index = match_object.start()
            length = match_object.end() - start_index
            self.setFormat(start_index, length, char_format)


# -----------------------------------------------------------------------------
# Line Number Area & Git Diff Hunk Popup
# -----------------------------------------------------------------------------


class DiffHunkPopup(QDialog):
    """Floating micro-popup displaying original Git HEAD code with a 1-click Revert action."""

    def __init__(
        self,
        parent: QWidget,
        hunk: GitDiffHunk,
        editor: CodeEditor,
        global_pos: QPoint,
    ) -> None:
        super().__init__(
            parent, Qt.WindowType.Popup | Qt.WindowType.FramelessWindowHint
        )
        self._hunk = hunk
        self._editor = editor
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        palette = editor._palette
        self.setStyleSheet(
            f"QDialog {{ background-color: {palette.panel}; border: 1px solid {palette.border}; border-radius: 4px; }}"
            f"QLabel {{ color: {palette.text}; }}"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # Header with type badge and line range
        header_layout = QHBoxLayout()
        type_str = hunk.diff_type.value.upper()
        type_color = (
            palette.green
            if hunk.diff_type == GitDiffType.ADDED
            else (
                palette.blue if hunk.diff_type == GitDiffType.MODIFIED else palette.red
            )
        )
        lbl_type = QLabel(
            f"<b><font color='{type_color}'>{type_str}</font></b> (Lines {hunk.start_line}-{hunk.start_line + hunk.line_count - 1})"
        )
        header_layout.addWidget(lbl_type)
        header_layout.addStretch(1)

        btn_close = QPushButton("✕", self)
        btn_close.setMaximumWidth(22)
        btn_close.clicked.connect(self.close)
        header_layout.addWidget(btn_close)
        layout.addLayout(header_layout)

        # Show original code if modified or deleted
        if hunk.original_content:
            lbl_orig_title = QLabel("Original from HEAD:", self)
            lbl_orig_title.setStyleSheet(f"color: {palette.muted}; font-size: 11px;")
            layout.addWidget(lbl_orig_title)

            orig_view = QPlainTextEdit(self)
            orig_view.setReadOnly(True)
            orig_view.setPlainText(hunk.original_content)
            orig_view.setFont(QFont("Consolas", 10))
            orig_view.setStyleSheet(
                f"background-color: {palette.background}; color: {palette.text}; border: 1px solid {palette.border};"
            )
            line_count = min(8, max(2, len(hunk.original_content.splitlines())))
            orig_view.setFixedHeight(line_count * 20 + 10)
            orig_view.setMinimumWidth(300)
            layout.addWidget(orig_view)

        # Revert button
        btn_revert = QPushButton("↺ Revert Change", self)
        btn_revert.setProperty("role", "primary")
        btn_revert.clicked.connect(self._on_revert)
        layout.addWidget(btn_revert)

        self.adjustSize()
        self.move(global_pos.x() + 10, global_pos.y() - 10)

    def _on_revert(self) -> None:
        self._editor.revert_git_diff_hunk(self._hunk)
        self.close()


class LineNumberArea(QWidget):
    """Sidebar that paints line numbers, breakpoint markers, fold chevrons, and git diffs next to a CodeEditor."""

    def __init__(self, editor: CodeEditor) -> None:
        super().__init__(editor)
        self._editor: CodeEditor = editor

    def sizeHint(self) -> QSize:  # type: ignore[override]
        """Provide sizing details for the line number area."""
        return QSize(self._editor.line_number_area_width(), 0)

    def paintEvent(self, event: QPaintEvent) -> None:  # type: ignore[override]
        """Paint line numbers, breakpoint markers, and git diff markers inside the sidebar."""
        self._editor.paint_line_numbers(event)

    def mousePressEvent(self, event: QMouseEvent) -> None:  # type: ignore[override]
        """Toggle a fold, breakpoint, git diff revert popup, or trigger a test run when clicking in the gutter area."""
        if event.button() == Qt.MouseButton.LeftButton:
            pos_y = (
                event.position().toPoint().y()
                if hasattr(event, "position")
                else event.pos().y()
            )
            pos_x = (
                event.position().toPoint().x()
                if hasattr(event, "position")
                else event.pos().x()
            )
            cursor = self._editor.cursorForPosition(QPoint(0, int(pos_y)))
            block = cursor.block()
            if block.isValid():
                line_number = block.blockNumber() + 1

                # If clicked in the rightmost diff margin strip, show diff popup!
                if pos_x >= self.width() - 8:
                    hunk = self._editor._git_diff_by_line.get(line_number)
                    if hunk is not None:
                        global_pos = (
                            event.globalPosition().toPoint()
                            if hasattr(event, "globalPosition")
                            else event.globalPos()
                        )
                        popup = DiffHunkPopup(self, hunk, self._editor, global_pos)
                        popup.show()
                        return

                # If clicked in fold chevron area (x >= 18 and < width - 8), toggle fold!
                if pos_x >= 18 and (
                    line_number in self._editor.get_fold_ranges()
                    or line_number in self._editor.get_folded_blocks()
                ):
                    self._editor.toggle_fold(line_number)
                    return

                # Otherwise handle breakpoint or test runner trigger in the left margin (x < 18)
                if (
                    line_number in self._editor._test_declaration_lines
                    and line_number not in self._editor._breakpoints
                ):
                    test_name = self._editor._test_declaration_lines[line_number]
                    self._editor.test_run_requested.emit(
                        self._editor._file_path, test_name, line_number
                    )
                else:
                    self._editor.toggle_breakpoint(line_number)
        super().mousePressEvent(event)


# -----------------------------------------------------------------------------
# Code Editor Widget
# -----------------------------------------------------------------------------


class CodeEditor(QPlainTextEdit):
    """A high-performance code editor with rich local features.

    Features line numbers, dynamic color palettes, indentation tracking,
    parenthesis closure handling, and integration with local background Jedi.
    """

    completions_requested = Signal(int, str, int, int)
    signatures_requested = Signal(int, str, int, int)
    hover_requested = Signal(int, str, int, int)
    definition_requested = Signal(int, str, int, int)
    references_requested = Signal(int, str, int, int)
    cursor_moved = Signal(int, int)
    send_to_repl_requested = Signal(str)
    open_file_requested = Signal(
        str, int, int
    )  # file_path (str), line_number (int), column (int)
    breakpoint_toggled = Signal(
        object, int, bool
    )  # file_path (Path), line_number (int), is_set (bool)
    test_run_requested = Signal(
        object, str, int
    )  # file_path (Path), test_name (str), line_number (int)
    quick_fix_requested = Signal(object)  # DiagnosticIssue
    missing_package_install_requested = Signal(str)  # package_name (str)
    fold_toggled = Signal(int, bool)  # line_number (int), is_folded (bool)

    def __init__(
        self,
        palette: ColorPalette,
        jedi_service: JediService,
        config: AppConfig | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._palette: ColorPalette = palette
        self._jedi: JediService = jedi_service
        self._config: AppConfig = config if config is not None else AppConfig()
        self._file_path: Path = Path("untitled.py")
        self._completion_token: int = 0
        self._auto_indent_enabled: bool = True
        self._syntax_issues_by_line: dict[int, CodeIssue] = {}
        self._test_declaration_lines: dict[int, str] = {}
        self._diagnostic_issues: list[DiagnosticIssue] = []
        self._diagnostic_issues_by_line: dict[int, list[DiagnosticIssue]] = {}
        self._breakpoints: set[int] = set()
        self._execution_line: int | None = None
        self._folded_blocks: dict[int, int] = {}
        self._cached_fold_ranges: dict[int, int] | None = None
        self._extra_cursors: list[QTextCursor] = []
        self._git_diff_hunks: list[GitDiffHunk] = []
        self._git_diff_by_line: dict[int, GitDiffHunk] = {}

        self.textChanged.connect(self._invalidate_fold_ranges)

        self._test_scan_timer: QTimer = QTimer(self)

        self._test_scan_timer.setSingleShot(True)
        self._test_scan_timer.timeout.connect(self._scan_test_declarations)
        self.textChanged.connect(self._schedule_test_scan)

        self._hover_timer: QTimer = QTimer(self)
        self._hover_timer.setSingleShot(True)
        self._hover_timer.timeout.connect(self._trigger_hover)
        self._last_hover_position: QPoint | None = None

        self._completion_timer: QTimer = QTimer(self)
        self._completion_timer.setSingleShot(True)
        self._completion_timer.timeout.connect(self._emit_completion_request)

        self._line_number_area: LineNumberArea = LineNumberArea(self)
        self._highlighter: PythonSyntaxHighlighter = PythonSyntaxHighlighter(
            self.document(), palette
        )

        font = QFont(self._config.font_family)
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setPointSize(self._config.font_size)
        self.setFont(font)
        self.setTabStopDistance(4 * self.fontMetrics().horizontalAdvance(" "))
        self.setFrameShape(QPlainTextEdit.Shape.NoFrame)

        self.blockCountChanged.connect(self._update_line_number_area_width)
        self.updateRequest.connect(self._update_line_number_area)
        self.cursorPositionChanged.connect(self._highlight_current_line)
        self.cursorPositionChanged.connect(self._emit_cursor_position)
        self.cursorPositionChanged.connect(self._schedule_hover)

        self._update_line_number_area_width(0)
        self._highlight_current_line()

        self._popup: CompletionPopup | None = None
        self._signature_widget: SignatureWidget | None = None

    def set_palette(self, palette: ColorPalette) -> None:
        """Apply a new ColorPalette to this editor and update all components."""
        self._palette = palette
        self._highlighter.set_palette(palette)
        self._apply_palette()

    def _apply_palette(self) -> None:
        css = (
            f"QPlainTextEdit {{ background-color: {self._palette.background};"
            f" color: {self._palette.text};"
            f" selection-background-color: {self._palette.selection};"
            f" selection-color: {self._palette.background}; }}"
        )
        self.setStyleSheet(css)
        self._line_number_area.setStyleSheet(
            f"background-color: {self._palette.background};"
            f" color: {self._palette.muted};"
        )
        self._highlight_current_line()

    def attach_completion_popup(self, popup: CompletionPopup) -> None:
        """Attach a completion popup window to the editor."""
        self._popup = popup
        popup.item_chosen.connect(self._insert_completion)

    def attach_signature_widget(self, widget: SignatureWidget) -> None:
        """Attach a signature assistance widget to the editor."""
        self._signature_widget = widget

    def set_file_path(self, file_path: Path) -> None:
        """Set the active workspace file path for this editor tab."""
        self._file_path = file_path

    def file_path(self) -> Path:
        """Return the active workspace file path of this editor tab."""
        return self._file_path

    def line_number_area_width(self) -> int:
        """Calculate the width in pixels needed for the line number, breakpoint, and fold gutter."""
        digit_count = max(2, len(str(max(1, self.blockCount()))))
        # 18px breakpoint margin + 14px fold chevron column + digit count + 8px padding
        return 18 + 14 + 8 + self.fontMetrics().horizontalAdvance("9") * digit_count

    def _update_line_number_area_width(self, _new_block_count: int) -> None:
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def _update_line_number_area(self, rect: QRect, vertical_offset: int) -> None:
        if vertical_offset != 0:
            self._line_number_area.update()
        else:
            self._line_number_area.update(
                0, rect.y(), self._line_number_area.width(), rect.height()
            )
        if rect.contains(self.viewport().rect()):
            self._update_line_number_area_width(0)

    def resizeEvent(self, event: QResizeEvent) -> None:  # type: ignore[override]
        """Reposition the line number sidebar when the viewport resizing occurs."""
        super().resizeEvent(event)
        contents_rectangle = self.contentsRect()
        self._line_number_area.setGeometry(
            QRect(
                contents_rectangle.left(),
                contents_rectangle.top(),
                self.line_number_area_width(),
                contents_rectangle.height(),
            )
        )

    def paint_line_numbers(self, event: QPaintEvent) -> None:
        """Draw line numbers, circular breakpoints, fold chevrons, and execution pointers."""
        painter = QPainter(self._line_number_area)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.fillRect(event.rect(), QColor(self._palette.background))
        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = self.blockBoundingGeometry(block).translated(self.contentOffset()).top()
        bottom = top + self.blockBoundingRect(block).height()
        right_pad = 4

        fold_ranges = self.get_fold_ranges()

        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                line_number = block_number + 1
                number_string = str(line_number)
                has_issue = (
                    line_number in self._syntax_issues_by_line
                    or line_number in self._diagnostic_issues_by_line
                )
                has_breakpoint = line_number in self._breakpoints
                is_exec_line = line_number == self._execution_line
                has_test_decl = line_number in self._test_declaration_lines
                is_foldable = line_number in fold_ranges
                is_folded = line_number in self._folded_blocks

                mid_y = int(top) + (self.fontMetrics().height() // 2)

                # Draw breakpoint indicator (solid red circular badge)
                if has_breakpoint:
                    painter.setPen(Qt.PenStyle.NoPen)
                    painter.setBrush(QColor(self._palette.red))
                    painter.drawEllipse(3, mid_y - 5, 10, 10)

                # Draw execution pointer (glowing amber triangle ▶)
                elif is_exec_line:
                    painter.setPen(QColor(self._palette.yellow))
                    painter.setBrush(QColor(self._palette.yellow))
                    arrow_points = [
                        QPoint(2, mid_y - 5),
                        QPoint(11, mid_y),
                        QPoint(2, mid_y + 5),
                    ]
                    painter.drawPolygon(arrow_points)

                # Draw test runner trigger (vibrant green play button ▶)
                elif has_test_decl:
                    painter.setPen(QColor(self._palette.green))
                    painter.setBrush(QColor(self._palette.green))
                    arrow_points = [
                        QPoint(4, mid_y - 5),
                        QPoint(12, mid_y),
                        QPoint(4, mid_y + 5),
                    ]
                    painter.drawPolygon(arrow_points)

                # Draw fold chevron indicator in fold column (x: 18..30)
                if is_folded:
                    # Collapsed block: right-pointing arrow ▶ in vibrant accent color
                    painter.setPen(Qt.PenStyle.NoPen)
                    painter.setBrush(QColor(self._palette.blue))
                    chevron_points = [
                        QPoint(19, mid_y - 4),
                        QPoint(26, mid_y),
                        QPoint(19, mid_y + 4),
                    ]
                    painter.drawPolygon(chevron_points)
                elif is_foldable:
                    # Expandable block: downward-pointing chevron ▼ in subtle muted color
                    painter.setPen(Qt.PenStyle.NoPen)
                    fold_col = QColor(self._palette.muted)
                    fold_col.setAlpha(150)
                    painter.setBrush(fold_col)
                    chevron_points = [
                        QPoint(18, mid_y - 3),
                        QPoint(26, mid_y - 3),
                        QPoint(22, mid_y + 3),
                    ]
                    painter.drawPolygon(chevron_points)

                painter.setPen(
                    QColor(self._palette.red)
                    if has_issue
                    else QColor(self._palette.muted)
                )
                if (
                    has_issue
                    and not has_breakpoint
                    and not is_exec_line
                    and not has_test_decl
                ):
                    marker_radius = 3
                    marker_y = mid_y - marker_radius
                    painter.setBrush(QColor(self._palette.red))
                    painter.drawEllipse(
                        2, marker_y, marker_radius * 2, marker_radius * 2
                    )

                # Draw Git diff indicator bar at the far right edge of the line number area
                hunk = self._git_diff_by_line.get(line_number)
                if hunk is not None:
                    diff_w = 3
                    diff_x = self._line_number_area.width() - diff_w
                    if hunk.diff_type == GitDiffType.ADDED:
                        painter.fillRect(
                            QRect(diff_x, int(top), diff_w, int(bottom - top)),
                            QColor(self._palette.green),
                        )
                    elif hunk.diff_type == GitDiffType.MODIFIED:
                        painter.fillRect(
                            QRect(diff_x, int(top), diff_w, int(bottom - top)),
                            QColor(self._palette.blue),
                        )
                    elif hunk.diff_type == GitDiffType.DELETED:
                        painter.setPen(Qt.PenStyle.NoPen)
                        painter.setBrush(QColor(self._palette.red))
                        arrow_points = [
                            QPoint(diff_x - 3, int(top)),
                            QPoint(diff_x + diff_w, int(top)),
                            QPoint(diff_x + diff_w, int(top) + 5),
                        ]
                        painter.drawPolygon(arrow_points)

                painter.drawText(
                    0,
                    int(top),
                    self._line_number_area.width() - right_pad - 2,
                    self.fontMetrics().height(),
                    Qt.AlignmentFlag.AlignRight,
                    number_string,
                )
            block = block.next()
            top = bottom
            bottom = top + self.blockBoundingRect(block).height()
            block_number += 1

    def set_git_diff_hunks(self, hunks: list[GitDiffHunk]) -> None:
        """Store git diff hunks and map each affected line to its hunk."""
        self._git_diff_hunks = list(hunks)
        self._git_diff_by_line = {}
        for hunk in hunks:
            if hunk.diff_type == GitDiffType.DELETED:
                self._git_diff_by_line[hunk.start_line] = hunk
            else:
                for offset in range(hunk.line_count):
                    self._git_diff_by_line[hunk.start_line + offset] = hunk
        self._line_number_area.update()

    def git_diff_hunks(self) -> list[GitDiffHunk]:
        """Return the current git diff hunks."""
        return list(self._git_diff_hunks)

    def revert_git_diff_hunk(self, hunk: GitDiffHunk) -> None:
        """Revert the specified diff hunk back to the original HEAD content."""
        doc = self.document()
        start_block = doc.findBlockByNumber(max(0, hunk.start_line - 1))
        if not start_block.isValid():
            return

        cursor = QTextCursor(start_block)
        cursor.beginEditBlock()

        if hunk.diff_type == GitDiffType.ADDED:
            for _ in range(hunk.line_count):
                cursor.movePosition(
                    QTextCursor.MoveOperation.EndOfBlock,
                    QTextCursor.MoveMode.KeepAnchor,
                )
                if not cursor.atEnd():
                    cursor.movePosition(
                        QTextCursor.MoveOperation.NextCharacter,
                        QTextCursor.MoveMode.KeepAnchor,
                    )
            cursor.removeSelectedText()

        elif hunk.diff_type in (GitDiffType.MODIFIED, GitDiffType.DELETED):
            if hunk.diff_type == GitDiffType.MODIFIED:
                for _ in range(hunk.line_count):
                    cursor.movePosition(
                        QTextCursor.MoveOperation.EndOfBlock,
                        QTextCursor.MoveMode.KeepAnchor,
                    )
                    if not cursor.atEnd():
                        cursor.movePosition(
                            QTextCursor.MoveOperation.NextCharacter,
                            QTextCursor.MoveMode.KeepAnchor,
                        )
            replacement = hunk.original_content
            if (
                hunk.diff_type == GitDiffType.DELETED
                and replacement
                and not replacement.endswith("\n")
            ):
                replacement += "\n"
            cursor.insertText(replacement)

        cursor.endEditBlock()
        self.setTextCursor(cursor)

    def _highlight_current_line(self) -> None:

        extra_selections = []
        if not self.isReadOnly():
            extra_selection = QTextEdit.ExtraSelection()
            extra_selection.format.setBackground(QColor(self._palette.current_line))
            extra_selection.format.setProperty(
                QTextFormat.Property.FullWidthSelection, True
            )
            extra_selection.cursor = self.textCursor()
            extra_selection.cursor.clearSelection()
            extra_selections.append(extra_selection)

        # Highlight active execution line with translucent amber tint when paused in debugger
        if self._execution_line is not None:
            exec_block = self.document().findBlockByNumber(
                max(0, self._execution_line - 1)
            )
            if exec_block.isValid():
                exec_selection = QTextEdit.ExtraSelection()
                exec_color = QColor(self._palette.yellow)
                exec_color.setAlpha(60)
                exec_selection.format.setBackground(exec_color)
                exec_selection.format.setProperty(
                    QTextFormat.Property.FullWidthSelection, True
                )
                exec_cursor = QTextCursor(exec_block)
                exec_cursor.clearSelection()
                exec_selection.cursor = exec_cursor
                extra_selections.append(exec_selection)

        # Render auxiliary cursors and selections for multi-cursor editing
        for ec in self._extra_cursors:
            if ec.hasSelection():
                sel = QTextEdit.ExtraSelection()
                sel.format.setBackground(QColor(self._palette.selection))
                sel.cursor = ec
                extra_selections.append(sel)
            else:
                caret_sel = QTextEdit.ExtraSelection()
                caret_cursor = QTextCursor(ec)
                caret_cursor.movePosition(
                    QTextCursor.MoveOperation.Right, QTextCursor.MoveMode.KeepAnchor, 1
                )
                fmt = QTextCharFormat()
                fmt.setBackground(QColor(self._palette.blue))
                fmt.setForeground(QColor(self._palette.background))
                caret_sel.format = fmt
                caret_sel.cursor = caret_cursor
                extra_selections.append(caret_sel)

        extra_selections.extend(self._build_syntax_issue_selections())
        extra_selections.extend(self._build_diagnostic_selections())
        self.setExtraSelections(extra_selections)

    def _invalidate_fold_ranges(self) -> None:
        """Invalidate the cached foldable block ranges."""
        self._cached_fold_ranges = None

    def get_fold_ranges(self) -> dict[int, int]:
        """Compute and return the current foldable block ranges, using cache."""
        if self._cached_fold_ranges is None:
            self._cached_fold_ranges = calculate_fold_ranges(self.document())
        return self._cached_fold_ranges

    def get_folded_blocks(self) -> dict[int, int]:
        """Return a copy of currently folded blocks {start_line: end_line}."""
        return dict(self._folded_blocks)

    def toggle_fold(self, line_number: int) -> bool:
        """Toggle folding of the block starting at line_number (1-indexed).

        Returns True if now folded, False if unfolded.
        """
        if line_number in self._folded_blocks:
            # Unfold
            end_line = self._folded_blocks.pop(line_number)
            for k in range(line_number + 1, end_line + 1):
                is_still_hidden = any(
                    s < k <= e for s, e in self._folded_blocks.items()
                )
                b = self.document().findBlockByNumber(k - 1)
                if b.isValid():
                    b.setVisible(not is_still_hidden)
            start_b = self.document().findBlockByNumber(line_number - 1)
            end_b = self.document().findBlockByNumber(end_line - 1)
            if start_b.isValid() and end_b.isValid():
                self.document().markContentsDirty(
                    start_b.position(),
                    end_b.position() + end_b.length() - start_b.position(),
                )
            self.viewport().update()
            self._line_number_area.update()
            self.fold_toggled.emit(line_number, False)
            return False

        fold_ranges = self.get_fold_ranges()
        if line_number in fold_ranges:
            end_line = fold_ranges[line_number]
            self._folded_blocks[line_number] = end_line
            for k in range(line_number + 1, end_line + 1):
                b = self.document().findBlockByNumber(k - 1)
                if b.isValid():
                    b.setVisible(False)
            start_b = self.document().findBlockByNumber(line_number - 1)
            end_b = self.document().findBlockByNumber(end_line - 1)
            if start_b.isValid() and end_b.isValid():
                self.document().markContentsDirty(
                    start_b.position(),
                    end_b.position() + end_b.length() - start_b.position(),
                )
            # If current cursor is within the folded lines, move cursor to the fold header
            cur_line = self.textCursor().blockNumber() + 1
            if line_number < cur_line <= end_line:
                self.jump_to_line(line_number, 0)
            self.viewport().update()
            self._line_number_area.update()
            self.fold_toggled.emit(line_number, True)
            return True

        return False

    def fold_all(self) -> None:
        """Fold all foldable code blocks across the entire document."""
        fold_ranges = self.get_fold_ranges()
        for start_line, end_line in fold_ranges.items():
            self._folded_blocks[start_line] = end_line
            for k in range(start_line + 1, end_line + 1):
                b = self.document().findBlockByNumber(k - 1)
                if b.isValid():
                    b.setVisible(False)
        self.document().markContentsDirty(0, self.document().characterCount())
        self.viewport().update()
        self._line_number_area.update()

    def unfold_all(self) -> None:
        """Unfold all blocks, restoring visibility to every line in the document."""
        self._folded_blocks.clear()
        b = self.document().begin()
        while b.isValid():
            b.setVisible(True)
            b = b.next()
        self.document().markContentsDirty(0, self.document().characterCount())
        self.viewport().update()
        self._line_number_area.update()

    def fold_current(self) -> bool:
        """Fold the innermost block enclosing the current cursor position."""
        cur_line = self.textCursor().blockNumber() + 1
        fold_ranges = self.get_fold_ranges()
        best_start = -1
        min_span = 999999
        for start, end in fold_ranges.items():
            if start <= cur_line <= end:
                span = end - start
                if span < min_span:
                    min_span = span
                    best_start = start
        if best_start != -1 and best_start not in self._folded_blocks:
            return self.toggle_fold(best_start)
        return False

    def unfold_current(self) -> bool:
        """Unfold the block enclosing the current cursor position."""
        cur_line = self.textCursor().blockNumber() + 1
        for start, end in list(self._folded_blocks.items()):
            if start <= cur_line <= end:
                return not self.toggle_fold(start)
        return False

    def select_next_occurrence(self) -> bool:
        """Select the next occurrence of the current word or selection (Ctrl+D)."""
        main_cur = self.textCursor()
        if not main_cur.hasSelection():
            main_cur.select(QTextCursor.SelectionType.WordUnderCursor)
            if not main_cur.selectedText().strip():
                return False
            self.setTextCursor(main_cur)
            self._highlight_current_line()
            return True

        target_text = main_cur.selectedText()
        if not target_text:
            return False

        all_positions = [main_cur.selectionEnd()] + [
            c.selectionEnd() for c in self._extra_cursors
        ]
        search_pos = max(all_positions)

        found = self.document().find(
            target_text, search_pos, QTextDocument.FindFlag.FindCaseSensitively
        )
        if found.isNull():
            found = self.document().find(
                target_text, 0, QTextDocument.FindFlag.FindCaseSensitively
            )

        if not found.isNull():
            is_dup = (
                found.selectionStart() == main_cur.selectionStart()
                and found.selectionEnd() == main_cur.selectionEnd()
            ) or any(
                found.selectionStart() == ec.selectionStart()
                and found.selectionEnd() == ec.selectionEnd()
                for ec in self._extra_cursors
            )
            if not is_dup:
                self._extra_cursors.append(found)
                self._highlight_current_line()
                return True
        return False

    def clear_extra_cursors(self) -> None:
        """Clear all auxiliary cursors and return to single cursor mode."""
        if self._extra_cursors:
            self._extra_cursors.clear()
            self._highlight_current_line()

    def extra_cursor_count(self) -> int:
        """Return the count of auxiliary multi-cursors active."""
        return len(self._extra_cursors)

    def extra_cursors(self) -> list[QTextCursor]:
        """Return a copy of the auxiliary multi-cursors list."""
        return list(self._extra_cursors)

    def toggle_breakpoint(self, line: int) -> bool:
        """Toggle a breakpoint on the specified line, returning the new state."""
        if line in self._breakpoints:
            self._breakpoints.remove(line)
            is_set = False
        else:
            self._breakpoints.add(line)
            is_set = True
        self._line_number_area.update()
        self.breakpoint_toggled.emit(self._file_path, line, is_set)
        return is_set

    def set_breakpoints(self, lines: set[int]) -> None:
        """Assign the active breakpoints collection to this editor."""
        self._breakpoints = set(lines)
        self._line_number_area.update()

    def get_breakpoints(self) -> set[int]:
        """Return the set of line numbers where breakpoints are set."""
        return set(self._breakpoints)

    def set_execution_line(self, line: int | None) -> None:
        """Highlight or clear the current active execution line pointer."""
        self._execution_line = line
        self._highlight_current_line()
        self._line_number_area.update()

    def _build_syntax_issue_selections(self) -> list[QTextEdit.ExtraSelection]:
        """Build wavy-underline extra selections for each active syntax issue."""
        selections: list[QTextEdit.ExtraSelection] = []
        if not self._syntax_issues_by_line:
            return selections
        underline_format = QTextCharFormat()
        underline_format.setUnderlineStyle(
            QTextCharFormat.UnderlineStyle.SpellCheckUnderline
        )
        underline_format.setUnderlineColor(QColor(self._palette.red))
        for line_number in self._syntax_issues_by_line:
            block = self.document().findBlockByNumber(max(0, line_number - 1))
            if not block.isValid():
                continue
            selection = QTextEdit.ExtraSelection()
            selection.format = underline_format
            cursor = QTextCursor(block)
            cursor.select(QTextCursor.SelectionType.LineUnderCursor)
            selection.cursor = cursor
            selections.append(selection)
        return selections

    def set_syntax_issues(self, issues: list[CodeIssue]) -> None:
        """Update the set of active syntax diagnostics rendered on this editor."""
        self._syntax_issues_by_line = {issue.line: issue for issue in issues}
        self._highlight_current_line()
        self._line_number_area.update()

    def syntax_issue_count(self) -> int:
        """Return the number of active syntax diagnostics on this editor."""
        return len(self._syntax_issues_by_line)

    def _schedule_test_scan(self) -> None:
        self._test_scan_timer.start(100)

    _TEST_DECL_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"^\s*(?:async\s+)?def\s+(test_[a-zA-Z0-9_]+)|^\s*class\s+(Test[a-zA-Z0-9_]*)"
    )

    def _scan_test_declarations(self) -> None:
        """Scan document for test function/class declarations to render gutter play markers."""
        decl_lines: dict[int, str] = {}
        block = self.document().begin()
        while block.isValid():
            line_str = block.text()
            match = self._TEST_DECL_PATTERN.match(line_str)
            if match:
                test_name = match.group(1) or match.group(2)
                decl_lines[block.blockNumber() + 1] = test_name
            block = block.next()
        if decl_lines != self._test_declaration_lines:
            self._test_declaration_lines = decl_lines
            self._line_number_area.update()

    def set_diagnostics(self, issues: list[DiagnosticIssue]) -> None:
        """Update live diagnostic issues and rebuild editor squiggles."""
        self._diagnostic_issues = list(issues)
        by_line: dict[int, list[DiagnosticIssue]] = {}
        for issue in issues:
            by_line.setdefault(issue.line, []).append(issue)
        self._diagnostic_issues_by_line = by_line
        self._highlight_current_line()
        self._line_number_area.update()

    def get_diagnostics(self) -> list[DiagnosticIssue]:
        """Return the current collection of active diagnostic issues."""
        return list(self._diagnostic_issues)

    def _build_diagnostic_selections(self) -> list[QTextEdit.ExtraSelection]:
        """Build wavy-underline extra selections for active Ruff/Mypy diagnostics."""
        selections: list[QTextEdit.ExtraSelection] = []
        if not self._diagnostic_issues:
            return selections

        doc = self.document()
        for issue in self._diagnostic_issues:
            block = doc.findBlockByNumber(max(0, issue.line - 1))
            if not block.isValid():
                continue

            underline_format = QTextCharFormat()
            underline_format.setUnderlineStyle(
                QTextCharFormat.UnderlineStyle.SpellCheckUnderline
            )
            color = (
                QColor(self._palette.red)
                if issue.severity == "error"
                else QColor(self._palette.yellow)
            )
            underline_format.setUnderlineColor(color)

            cursor = QTextCursor(block)
            line_text = block.text()
            block_start = block.position()

            if 1 <= issue.column <= len(line_text) + 1:
                start_pos = block_start + (issue.column - 1)
                end_pos = (
                    block_start + max(issue.column, issue.end_column - 1)
                    if issue.end_line == issue.line
                    else block_start + len(line_text)
                )
                cursor.setPosition(start_pos)
                cursor.setPosition(
                    min(end_pos, block_start + len(line_text)),
                    QTextCursor.MoveMode.KeepAnchor,
                )
            else:
                cursor.select(QTextCursor.SelectionType.LineUnderCursor)

            selection = QTextEdit.ExtraSelection()
            selection.format = underline_format
            selection.cursor = cursor
            selections.append(selection)

        return selections

    def apply_quick_fix(self, issue: DiagnosticIssue) -> bool:
        """Apply a diagnostic auto-fix using undoable QTextCursor edits."""
        if not issue.fix or not issue.fix.edits:
            return False

        doc = self.document()
        cursor = self.textCursor()

        def edit_start_pos(edit: Any) -> int:
            start_row = max(1, edit.location.row)
            block = doc.findBlockByNumber(start_row - 1)
            if not block.isValid():
                return doc.characterCount() - 1
            col_offset = _utf8_col_to_char_offset(block.text(), edit.location.column)
            return block.position() + col_offset

        sorted_edits = sorted(issue.fix.edits, key=edit_start_pos, reverse=True)

        cursor.beginEditBlock()
        try:
            for edit in sorted_edits:
                start_row = max(1, edit.location.row)
                end_row = max(1, edit.end_location.row)

                start_block = doc.findBlockByNumber(start_row - 1)
                if not start_block.isValid():
                    continue

                start_char = _utf8_col_to_char_offset(
                    start_block.text(), edit.location.column
                )
                start_pos = start_block.position() + start_char

                if end_row == start_row:
                    end_char = _utf8_col_to_char_offset(
                        start_block.text(), edit.end_location.column
                    )
                    # If this is a full-line deletion or extends past line text, safely delete the line including separator
                    if (
                        edit.content == ""
                        and start_char == 0
                        and end_char >= len(start_block.text())
                    ):
                        end_pos = start_block.position() + start_block.length()
                    else:
                        end_char = min(len(start_block.text()), end_char)
                        end_pos = start_block.position() + end_char
                else:
                    if end_row - 1 < doc.blockCount():
                        end_block = doc.findBlockByNumber(end_row - 1)
                        if end_block.isValid():
                            end_char = _utf8_col_to_char_offset(
                                end_block.text(), edit.end_location.column
                            )
                            end_pos = end_block.position() + min(
                                len(end_block.text()), end_char
                            )
                        else:
                            end_pos = doc.characterCount() - 1
                    else:
                        end_pos = doc.characterCount() - 1

                max_len = doc.characterCount() - 1
                start_pos = max(0, min(start_pos, max_len))
                end_pos = max(0, min(end_pos, max_len))

                if start_pos <= end_pos:
                    edit_cursor = QTextCursor(doc)
                    edit_cursor.setPosition(start_pos)
                    edit_cursor.setPosition(end_pos, QTextCursor.MoveMode.KeepAnchor)
                    edit_cursor.insertText(edit.content)
        finally:
            cursor.endEditBlock()

        self.quick_fix_requested.emit(issue)
        return True

    def apply_quick_fix_at_cursor(self) -> bool:
        """Apply the first available diagnostic auto-fix on the active line."""
        cursor = self.textCursor()
        line = cursor.blockNumber() + 1
        issues = self._diagnostic_issues_by_line.get(line, [])
        for issue in issues:
            if issue.has_fix:
                return self.apply_quick_fix(issue)
        return False

    def _suppress_issue(self, code: str) -> None:
        """Add `# noqa: <code>` to the end of the current line."""
        cursor = self.textCursor()
        cursor.beginEditBlock()
        try:
            cursor.movePosition(QTextCursor.MoveOperation.EndOfLine)
            line_text = cursor.block().text()
            if "# noqa" in line_text:
                cursor.insertText(f", {code}")
            else:
                cursor.insertText(f"  # noqa: {code}")
        finally:
            cursor.endEditBlock()

    def show_quick_fix_menu(self) -> None:
        """Display an interactive Quick Fix popup menu at the cursor."""
        cursor = self.textCursor()
        line = cursor.blockNumber() + 1
        issues = self._diagnostic_issues_by_line.get(line, [])
        line_text = cursor.block().text().strip()

        # Check if line contains an import statement referencing an uninstalled module
        missing_pkg: str | None = None
        if line_text.startswith(("import ", "from ")):
            parts = line_text.split()
            if len(parts) >= 2:
                candidate = parts[1].split(".")[0].strip(",;")
                if candidate and candidate not in sys.builtin_module_names:
                    try:
                        spec = importlib.util.find_spec(candidate)
                        if spec is None:
                            missing_pkg = candidate
                    except (ImportError, ValueError):
                        missing_pkg = candidate

        if not issues and not missing_pkg:
            QToolTip.showText(
                self.mapToGlobal(self.cursorRect().bottomLeft()),
                f"No diagnostic issues on line {line}",
                self,
            )
            return

        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu {{ background-color: {self._palette.surface}; color: {self._palette.text}; "
            f"border: 1px solid {self._palette.border}; padding: 4px; font-size: 12px; }}"
            f"QMenu::item {{ padding: 6px 16px; }}"
            f"QMenu::item:selected {{ background-color: {self._palette.accent}; color: #ffffff; }}"
        )

        has_any_action = False

        # If an uninstalled module was imported, offer pip install FIRST!
        if missing_pkg:
            pkg_action = menu.addAction(f"📦 Install '{missing_pkg}' via pip")
            pkg_action.triggered.connect(
                lambda checked=False, p=missing_pkg: (
                    self.missing_package_install_requested.emit(p)
                )
            )
            has_any_action = True

        for issue in issues:
            if issue.has_fix and issue.fix:
                is_removal = any(
                    word in issue.fix.message.lower()
                    for word in ("remove", "delete", "drop", "unused")
                )
                icon = "🗑️" if is_removal else "💡"
                action_text = f"{icon} {issue.fix.message} ({issue.code})"
                action = menu.addAction(action_text)
                action.triggered.connect(
                    lambda checked=False, iss=issue: self.apply_quick_fix(iss)
                )
                has_any_action = True

            noqa_text = f"🛡️ Suppress {issue.code} on this line (# noqa: {issue.code})"
            noqa_action = menu.addAction(noqa_text)
            noqa_action.triggered.connect(
                lambda checked=False, cd=issue.code: self._suppress_issue(cd)
            )
            has_any_action = True

        if not has_any_action:
            QToolTip.showText(
                self.mapToGlobal(self.cursorRect().bottomLeft()),
                f"No quick fixes available on line {line}",
                self,
            )
            return

        menu.addSeparator()
        menu.addAction("✕ Cancel")

        pos = self.mapToGlobal(self.cursorRect().bottomLeft())
        menu.exec(pos)

    def _emit_cursor_position(self) -> None:
        cursor = self.textCursor()
        self.cursor_moved.emit(cursor.blockNumber() + 1, cursor.columnNumber() + 1)

    def _apply_auto_indent(self) -> None:
        """Surgically compute and insert standard indentation on Enter key events."""
        cursor = self.textCursor()
        current_block_idx = cursor.blockNumber()
        if current_block_idx == 0:
            return

        previous_block = self.document().findBlockByNumber(current_block_idx - 1)
        previous_text = previous_block.text()
        leading_spaces = len(previous_text) - len(previous_text.lstrip(" "))

        if previous_text.rstrip().endswith(":"):
            leading_spaces += 4

        match_object = _DEDENT_TRIGGER_PATTERN.match(previous_text.lstrip())
        if match_object and leading_spaces >= 4:
            leading_spaces -= 4

        indentation = " " * max(0, leading_spaces)
        if indentation:
            self._auto_indent_enabled = False
            try:
                cursor.insertText(indentation)
            finally:
                self._auto_indent_enabled = True

    def _schedule_hover(self) -> None:
        self._hover_timer.start(self._config.hover_delay_ms)

    def _trigger_hover(self) -> None:
        cursor = self.textCursor()
        line = cursor.blockNumber() + 1
        column = cursor.columnNumber()
        self._completion_token += 1
        self._last_hover_position = self.mapToGlobal(self.cursorRect().topRight())

        # Check if line has active diagnostic issues and render formatted tooltip
        if line in self._diagnostic_issues_by_line:
            issues = self._diagnostic_issues_by_line[line]
            parts = []
            for iss in issues:
                icon = "🔴" if iss.severity == "error" else "🟡"
                msg_html = (
                    f"<div style='margin-bottom: 4px;'>"
                    f"{icon} <b>{iss.code}</b>: {iss.message}"
                )
                if iss.has_fix and iss.fix_message:
                    msg_html += f"<br/><span style='color: #4CAF50;'>💡 Quick Fix (Alt+Enter): {iss.fix_message}</span>"
                msg_html += "</div>"
                parts.append(msg_html)
            tooltip_html = (
                "<div style='font-family: sans-serif; font-size: 12px; max-width: 400px;'>"
                + "".join(parts)
                + "</div>"
            )
            QToolTip.showText(self._last_hover_position, tooltip_html, self)

        self.hover_requested.emit(
            self._completion_token, self.toPlainText(), line, column
        )

    def keyPressEvent(self, event: QKeyEvent) -> None:  # type: ignore[override]
        """Handle user keyboard input, dispatching to completions or signatures."""
        key = event.key()
        text = event.text()

        # Multi-cursor synchronous editing
        if self._extra_cursors:
            if key == Qt.Key.Key_Escape:
                self.clear_extra_cursors()
                event.accept()
                return

            if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                all_cursors = [self.textCursor()] + self._extra_cursors
                all_cursors.sort(key=lambda c: c.selectionStart(), reverse=True)
                main_cur = self.textCursor()
                main_cur.beginEditBlock()
                try:
                    for c in all_cursors:
                        if c.hasSelection():
                            c.removeSelectedText()
                        c.insertText("\n")
                finally:
                    main_cur.endEditBlock()
                self._highlight_current_line()
                event.accept()
                return

            if key == Qt.Key.Key_Backspace:
                all_cursors = [self.textCursor()] + self._extra_cursors
                all_cursors.sort(key=lambda c: c.selectionStart(), reverse=True)
                main_cur = self.textCursor()
                main_cur.beginEditBlock()
                try:
                    for c in all_cursors:
                        if c.hasSelection():
                            c.removeSelectedText()
                        else:
                            c.deletePreviousChar()
                finally:
                    main_cur.endEditBlock()
                self._highlight_current_line()
                event.accept()
                return

            if key == Qt.Key.Key_Delete:
                all_cursors = [self.textCursor()] + self._extra_cursors
                all_cursors.sort(key=lambda c: c.selectionStart(), reverse=True)
                main_cur = self.textCursor()
                main_cur.beginEditBlock()
                try:
                    for c in all_cursors:
                        if c.hasSelection():
                            c.removeSelectedText()
                        else:
                            c.deleteChar()
                finally:
                    main_cur.endEditBlock()
                self._highlight_current_line()
                event.accept()
                return

            if (
                text
                and (text.isprintable() or text in " \t")
                and not (
                    event.modifiers()
                    & (
                        Qt.KeyboardModifier.ControlModifier
                        | Qt.KeyboardModifier.MetaModifier
                    )
                )
            ):
                all_cursors = [self.textCursor()] + self._extra_cursors
                all_cursors.sort(key=lambda c: c.selectionStart(), reverse=True)
                main_cur = self.textCursor()
                main_cur.beginEditBlock()
                try:
                    for c in all_cursors:
                        if c.hasSelection():
                            c.insertText(text)
                        else:
                            c.insertText(text)
                finally:
                    main_cur.endEditBlock()
                self._highlight_current_line()
                event.accept()
                return

        # Intercept Ctrl+D for multi-cursor select next occurrence
        if (
            key == Qt.Key.Key_D
            and (event.modifiers() == Qt.KeyboardModifier.ControlModifier)
            and self.select_next_occurrence()
        ):
            return

        # Intercept Ctrl+Shift+[ for fold current block
        if (
            key == Qt.Key.Key_BracketLeft
            and (
                event.modifiers()
                == (
                    Qt.KeyboardModifier.ControlModifier
                    | Qt.KeyboardModifier.ShiftModifier
                )
            )
            and self.fold_current()
        ):
            return

        # Intercept Ctrl+Shift+] for unfold current block
        if (
            key == Qt.Key.Key_BracketRight
            and (
                event.modifiers()
                == (
                    Qt.KeyboardModifier.ControlModifier
                    | Qt.KeyboardModifier.ShiftModifier
                )
            )
            and self.unfold_current()
        ):
            return

        if (
            self._popup is not None
            and self._popup.is_visible()
            and key
            in (
                Qt.Key.Key_Down,
                Qt.Key.Key_Up,
                Qt.Key.Key_Tab,
                Qt.Key.Key_Return,
                Qt.Key.Key_Escape,
            )
            and self._popup.handle_key(event)
        ):
            return

        # Intercept Alt+Enter or Ctrl+. for interactive diagnostic quick-fix menu
        is_alt_enter = key in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and bool(
            event.modifiers() & Qt.KeyboardModifier.AltModifier
        )
        is_ctrl_dot = key == Qt.Key.Key_Period and bool(
            event.modifiers() & Qt.KeyboardModifier.ControlModifier
        )
        if is_alt_enter or is_ctrl_dot:
            event.accept()
            self.show_quick_fix_menu()
            return

        # Intercept Ctrl+Enter or Shift+Enter to send selection or current line to REPL
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and (
            event.modifiers()
            & (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier)
        ):
            cursor = self.textCursor()
            selected_text = cursor.selectedText().replace("\u2029", "\n").strip()
            if not selected_text:
                selected_text = cursor.block().text().strip()
            if selected_text:
                self.send_to_repl_requested.emit(selected_text)
            return

        # Direct block-break intercepts for high-performance auto-indentation execution
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            super().keyPressEvent(event)
            if self._auto_indent_enabled:
                self._apply_auto_indent()
            return

        # Intercept F12 for Go-to-Definition
        if key == Qt.Key.Key_F12:
            self._request_definition()
            return

        super().keyPressEvent(event)

        if text and (text.isalnum() or text in "._"):
            self._request_completion()
        elif text == "(":
            self._request_signature()
        elif text in (")", "]") and self._signature_widget is not None:
            self._signature_widget.hide()

    def _request_completion(self) -> None:
        """Debounce a completion request behind ``completion_delay_ms``."""
        self._completion_timer.start(self._config.completion_delay_ms)

    def _emit_completion_request(self) -> None:
        cursor = self.textCursor()
        self._completion_token += 1
        self.completions_requested.emit(
            self._completion_token,
            self.toPlainText(),
            cursor.blockNumber() + 1,
            cursor.columnNumber(),
        )

    def _request_signature(self) -> None:
        cursor = self.textCursor()
        self._completion_token += 1
        self.signatures_requested.emit(
            self._completion_token,
            self.toPlainText(),
            cursor.blockNumber() + 1,
            cursor.columnNumber(),
        )

    def _insert_completion(self, name: str) -> None:
        cursor = self.textCursor()
        cursor.movePosition(
            QTextCursor.MoveOperation.StartOfWord, QTextCursor.MoveMode.KeepAnchor
        )
        cursor.insertText(name)

    @Slot(int, object)
    def apply_jedi_result(self, token: int, result: JediResult) -> None:
        """Handle background Jedi results, updating local assistance widgets."""
        if token != self._completion_token:
            return
        if result.error:
            _LOGGER.warning("Jedi operation failed internally: %s", result.error)
            return

        if result.task_type == JediTaskType.COMPLETION and self._popup is not None:
            self._popup.show_completions(
                result.completions, self.cursorRect().bottomRight()
            )
        elif (
            result.task_type == JediTaskType.SIGNATURE
            and self._signature_widget is not None
            and result.signature
        ):
            self._signature_widget.show_signature(
                result.signature, self.cursorRect().bottomRight()
            )
        elif (
            result.task_type == JediTaskType.HOVER
            and result.hover_text
            and self._last_hover_position is not None
        ):
            QToolTip.showText(self._last_hover_position, result.hover_text, self)
        elif (
            result.task_type == JediTaskType.DEFINITION
            and result.definition_line is not None
        ):
            if (
                result.definition_path
                and Path(result.definition_path).resolve() != self._file_path.resolve()
            ):
                self.open_file_requested.emit(
                    result.definition_path,
                    result.definition_line,
                    result.definition_column or 0,
                )
            else:
                self.jump_to_line(result.definition_line, result.definition_column or 0)
        elif result.task_type == JediTaskType.REFERENCES and result.references:
            _LOGGER.info("Located %d file references.", len(result.references))
            target_line, target_column = result.references[0]
            self.jump_to_line(target_line, target_column)

    def mousePressEvent(self, event: QMouseEvent) -> None:  # type: ignore[override]
        """Handle mouse clicks, supporting Ctrl+Click for Go-to-Def and Alt+Click for multi-cursor."""
        if event.button() == Qt.MouseButton.LeftButton:
            pos_point = (
                event.position().toPoint()
                if hasattr(event, "position")
                else event.pos()
            )
            # Alt+Click: Add auxiliary cursor at click position
            if event.modifiers() & Qt.KeyboardModifier.AltModifier:
                cursor = self.cursorForPosition(pos_point)
                self._extra_cursors.append(cursor)
                self._highlight_current_line()
                event.accept()
                return

            # Ctrl+Click: Go to Definition
            if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
                cursor = self.cursorForPosition(pos_point)
                self.setTextCursor(cursor)
                self._request_definition()
                return

            # Normal click: clear extra cursors if any
            if self._extra_cursors:
                self.clear_extra_cursors()

        super().mousePressEvent(event)

    def _request_definition(self) -> None:
        """Trigger background Jedi Go-to-Definition lookup at the current cursor."""
        cursor = self.textCursor()
        self._completion_token += 1
        self.definition_requested.emit(
            self._completion_token,
            self.toPlainText(),
            cursor.blockNumber() + 1,
            cursor.columnNumber(),
        )

    def jump_to_line(self, line: int, column: int) -> None:
        """Move the text cursor to a 1-based line and 0-based column, and center it."""
        # Unfold any folded blocks containing this line so the line is visible
        for fold_start, fold_end in list(self._folded_blocks.items()):
            if fold_start < line <= fold_end:
                self.toggle_fold(fold_start)

        block = self.document().findBlockByNumber(max(0, line - 1))
        if not block.isValid():
            return
        cursor = QTextCursor(block)
        cursor.movePosition(
            QTextCursor.MoveOperation.Right,
            QTextCursor.MoveMode.MoveAnchor,
            max(0, column),
        )
        self.setTextCursor(cursor)
        self.centerCursor()

    def is_modified(self) -> bool:
        """Return True if the buffer has unsaved changes."""
        return self.document().isModified()

    def mark_saved(self) -> None:
        """Clear the document's modification flag after a successful save."""
        self.document().setModified(False)

    def replace_content(self, text: str) -> None:
        """Replace the entire buffer with ``text`` and mark it as unsaved."""
        self._auto_indent_enabled = False
        try:
            self.setPlainText(text)
        finally:
            self._auto_indent_enabled = True
        self.document().setModified(True)

    def showEvent(self, event: QShowEvent) -> None:  # type: ignore[override]
        """Re-apply visual layout and themes on editor visual showing."""
        super().showEvent(event)
        self._apply_palette()

    def closeEvent(self, event: QCloseEvent) -> None:  # type: ignore[override]
        """Stop active background timers on closing to ensure thread-safe destruction."""
        self._test_scan_timer.stop()
        self._hover_timer.stop()
        self._completion_timer.stop()
        super().closeEvent(event)


# -----------------------------------------------------------------------------
# Completion Popup Widget
# -----------------------------------------------------------------------------

_COMPLETION_ICONS: dict[str, str] = {
    "function": "ƒ",
    "class": "C",
    "instance": "◇",
    "module": "M",
    "statement": "▶",
    "keyword": "K",
    "param": "P",
    "property": "≡",
}


class CompletionPopup(QListWidget):
    """A frameless list of completions anchored directly to the code editor."""

    item_chosen = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.ToolTip)
        self.setUniformItemSizes(True)
        self.setMaximumHeight(200)
        self.setMaximumWidth(480)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.itemClicked.connect(self._on_clicked)

    def is_visible(self) -> bool:
        """Return True if the popup is currently visible."""
        return self.isVisible()

    def show_completions(
        self, completions: list[JediCompletion], anchor: QPoint
    ) -> None:
        """Display autocompletion options at the specified cursor coordinates."""
        self.clear()
        if not completions:
            self.hide()
            return
        for completion in completions:
            icon = _COMPLETION_ICONS.get(completion.kind, "•")
            item = QListWidgetItem(
                f"{icon}  {completion.name}    {completion.description}"
            )
            item.setData(Qt.ItemDataRole.UserRole, completion.name)
            self.addItem(item)
        self.setCurrentRow(0)
        self.move(anchor)
        self.show()

    def hide(self) -> None:  # type: ignore[override]
        """Hide the completion popup from the layout."""
        super().hide()

    def handle_key(self, event: QKeyEvent) -> bool:
        """Handle navigational keyboard keys forwarded by CodeEditor."""
        key = event.key()
        if key == Qt.Key.Key_Down:
            self.setCurrentRow((self.currentRow() + 1) % self.count())
            return True
        if key == Qt.Key.Key_Up:
            self.setCurrentRow((self.currentRow() - 1) % self.count())
            return True
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Tab):
            self._accept_current()
            return True
        if key == Qt.Key.Key_Escape:
            self.hide()
            return True
        return False

    def _on_clicked(self, item: QListWidgetItem) -> None:
        self._accept_current()

    def _accept_current(self) -> None:
        item = self.currentItem()
        if item is None:
            return
        name = item.data(Qt.ItemDataRole.UserRole)
        self.item_chosen.emit(name)
        self.hide()


# -----------------------------------------------------------------------------
# Signature Assistance Tooltip
# -----------------------------------------------------------------------------


class SignatureWidget(QWidget):
    """A small overlay widget showing the active call signature."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._label = QLabel(self)
        self._label.setWordWrap(True)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.addWidget(self._label)
        self.setWindowFlags(Qt.WindowType.ToolTip)
        self.hide()

    def show_signature(self, text: str, anchor: QPoint) -> None:
        """Display the signature text at the specified anchor point."""
        self._label.setText(text)
        self.adjustSize()
        self.move(anchor)
        self.show()

    def hide(self) -> None:  # type: ignore[override]
        """Hide the signature widget."""
        super().hide()


# -----------------------------------------------------------------------------
# Self-Healing Warning Banner & Container
# -----------------------------------------------------------------------------


class SelfHealingBanner(QWidget):
    """A context-sensitive warning banner prompting users to auto-install missing modules."""

    install_requested = Signal(list)  # Emits uninstalled modules list

    def __init__(self, palette: ColorPalette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette: ColorPalette = palette
        self._missing_modules: list[str] = []

        self._label: QLabel = QLabel(self)
        self._label.setStyleSheet("font-weight: bold;")

        self._install_button: QPushButton = QPushButton("Install via pip", self)
        self._install_button.clicked.connect(self._on_install)

        self._close_button: QPushButton = QPushButton("✕", self)
        self._close_button.setFlat(True)
        self._close_button.setFixedWidth(30)
        self._close_button.clicked.connect(self.hide)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.addWidget(self._label)
        layout.addWidget(self._install_button)
        layout.addStretch(1)
        layout.addWidget(self._close_button)

        self._apply_palette()

    def set_palette(self, palette: ColorPalette) -> None:
        """Set active styling palette colors on theme updates."""
        self._palette = palette
        self._apply_palette()

    def _apply_palette(self) -> None:
        self.setStyleSheet(
            f"QWidget {{ background-color: {self._palette.panel}; border-bottom: 1px solid {self._palette.border}; }}"
            f"QLabel {{ color: {self._palette.yellow}; }}"
            f"QPushButton {{ background-color: {self._palette.selection}; color: {self._palette.text}; border: 1px solid {self._palette.border}; border-radius: 3px; padding: 4px 10px; }}"
            f"QPushButton:hover {{ background-color: {self._palette.background}; }}"
        )

    def show_warnings(self, missing_modules: list[str]) -> None:
        """Populate list details and draw warning alert canvas."""
        self._missing_modules = missing_modules
        if not missing_modules:
            self.hide()
            return

        modules_string = ", ".join(f"'{module}'" for module in missing_modules)
        self._label.setText(f"⚠ Unresolved imports detected: {modules_string}")

        # PRD U5: Offline mode aware installation button
        try:
            from .services.offline_service import OfflineService

            offline_service = OfflineService.get_instance()
            is_offline = offline_service.is_offline()
            has_wheelhouse = bool(offline_service.get_local_wheelhouse_dir())
        except Exception:
            is_offline = False
            has_wheelhouse = False

        if is_offline and not has_wheelhouse:
            self._install_button.setText("Install (Requires Network)")
            self._install_button.setToolTip(
                "PipViper is in Offline Mode. Package installation requires network access or local wheels.\n"
                "Switch to Online Mode via the status bar to install from PyPI."
            )
        elif has_wheelhouse:
            self._install_button.setText("Install from Local Wheels")
            self._install_button.setToolTip(
                "Install missing packages from configured local wheelhouse"
            )
        else:
            self._install_button.setText("Install via pip (Requires Network)")
            self._install_button.setToolTip(
                "Download and install missing packages from PyPI"
            )

        self.show()

    def _on_install(self) -> None:
        self.install_requested.emit(self._missing_modules)
        self.hide()


class StickyScopeBar(QWidget):
    """Pinned breadcrumb bar showing enclosing class and def scopes for the active viewport."""

    def __init__(
        self, editor: CodeEditor, palette: ColorPalette, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self._editor: CodeEditor = editor
        self._palette: ColorPalette = palette
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(10, 2, 10, 2)
        self._layout.setSpacing(6)
        self.setFixedHeight(26)
        self._current_scopes: list[tuple[str, str, int]] = []
        self._current_file: str = ""

        self._debounce_timer: QTimer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.setInterval(30)
        self._debounce_timer.timeout.connect(self._do_update_scopes)

        self._editor.verticalScrollBar().valueChanged.connect(
            self._debounce_timer.start
        )
        self._editor.textChanged.connect(self._debounce_timer.start)
        self._apply_palette()
        self._do_update_scopes()

    def set_palette(self, palette: ColorPalette) -> None:
        """Update active ColorPalette styles."""
        self._palette = palette
        self._apply_palette()
        self._current_scopes = []
        self._do_update_scopes()

    def _apply_palette(self) -> None:
        self.setStyleSheet(
            f"QWidget {{ background-color: {self._palette.panel}; border-bottom: 1px solid {self._palette.border}; }}"
            f"QPushButton {{ background: transparent; border: none; color: {self._palette.blue}; font-weight: bold; font-size: 11px; padding: 2px 5px; border-radius: 3px; }}"
            f"QPushButton:hover {{ background-color: {self._palette.selection}; color: {self._palette.text}; }}"
            f"QLabel {{ color: {self._palette.muted}; font-size: 11px; }}"
        )

    def update_scopes(self) -> None:
        """Schedule scope update behind a 30ms debounce timer to prevent scroll stutter."""
        self._debounce_timer.start()

    def _do_update_scopes(self) -> None:
        """Query enclosing scopes for the first visible block and update breadcrumbs."""
        first_block = self._editor.firstVisibleBlock()
        if not first_block.isValid():
            return

        target_line = first_block.blockNumber() + 1
        scopes = get_enclosing_scopes(self._editor.document(), target_line)
        file_name = self._editor.file_path().name

        # If scopes and file haven't changed, skip layout reconstruction
        if scopes == self._current_scopes and file_name == self._current_file:
            return

        self._current_scopes = scopes
        self._current_file = file_name

        while self._layout.count() > 0:
            item = self._layout.takeAt(0)
            if item is not None:
                widget = item.widget()
                if widget is not None:
                    widget.setParent(None)
                    widget.deleteLater()
        if not scopes:
            lbl = QLabel(f"📄 {file_name}")
            lbl.setStyleSheet(
                f"color: {self._palette.muted}; font-size: 11px; font-style: italic;"
            )
            self._layout.addWidget(lbl)
            self._layout.addStretch(1)
            return

        for idx, (kind, header, line_num) in enumerate(scopes):
            if idx > 0:
                sep = QLabel("›")
                sep.setStyleSheet(f"color: {self._palette.muted}; font-size: 11px;")
                self._layout.addWidget(sep)

            icon = "🏷️" if kind == "class" else "⚡"
            btn = QPushButton(f"{icon} {header}")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setToolTip(f"Jump to line {line_num}")
            btn.clicked.connect(
                lambda _c=False, l=line_num: self._editor.jump_to_line(l, 0)
            )
            self._layout.addWidget(btn)

        self._layout.addStretch(1)


class EditorContainer(QWidget):
    """Encapsulates a CodeEditor alongside its dynamic SelfHealingBanner and StickyScopeBar elements."""

    def __init__(
        self, editor: CodeEditor, palette: ColorPalette, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.editor: CodeEditor = editor
        self.banner: SelfHealingBanner = SelfHealingBanner(palette, self)
        self.banner.hide()
        self.sticky_scope: StickyScopeBar = StickyScopeBar(editor, palette, self)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.banner)
        layout.addWidget(self.sticky_scope)
        layout.addWidget(self.editor)

    def set_palette(self, palette: ColorPalette) -> None:
        """Dispatch visual refresh coordinates downward across children."""
        self.banner.set_palette(palette)
        self.sticky_scope.set_palette(palette)
        self.editor.set_palette(palette)


# -----------------------------------------------------------------------------
# Code Editor Tab Manager
# -----------------------------------------------------------------------------


class EditorTabs(QWidget):
    """A tabbed container widget managing primary and split EditorContainer instances."""

    editor_changed = Signal(object)  # Emits the current CodeEditor or None
    editor_closed = Signal(str)  # Emits the closed file path string
    unsaved_close_requested = Signal(int)  # Emits the tab index; caller decides
    send_to_repl_requested = Signal(str)
    breakpoint_toggled = Signal(object, int, bool)  # file_path, line, is_set
    test_run_requested = Signal(
        object, str, int
    )  # file_path (Path), test_name (str), line (int)
    open_file_requested = Signal(str, int, int)  # file_path, line, col
    fold_toggled = Signal(object, int, bool)  # file_path, line, is_folded
    install_requested = Signal(list)  # Emits list of uninstalled modules to install

    def __init__(
        self,
        palette: ColorPalette,
        jedi_service: JediService,
        config: AppConfig | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._palette: ColorPalette = palette
        self._jedi: JediService = jedi_service
        self._config: AppConfig = config if config is not None else AppConfig()

        self._tab_widget = QTabWidget(self)
        self._tab_widget.setTabsClosable(True)
        self._tab_widget.setMovable(True)
        self._tab_widget.setDocumentMode(True)
        self._tab_widget.currentChanged.connect(self._on_current_changed)
        self._tab_widget.tabCloseRequested.connect(self._on_close_requested)

        self._secondary_tab_widget = QTabWidget(self)
        self._secondary_tab_widget.setTabsClosable(True)
        self._secondary_tab_widget.setMovable(True)
        self._secondary_tab_widget.setDocumentMode(True)
        self._secondary_tab_widget.currentChanged.connect(
            self._on_secondary_current_changed
        )
        self._secondary_tab_widget.tabCloseRequested.connect(
            self._on_secondary_close_requested
        )
        self._secondary_tab_widget.hide()

        self._splitter = QSplitter(Qt.Orientation.Horizontal, self)
        self._splitter.addWidget(self._tab_widget)
        self._splitter.addWidget(self._secondary_tab_widget)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._splitter)

        self._editors: dict[str, CodeEditor] = {}
        self._secondary_editors: dict[str, CodeEditor] = {}
        self._active_editor: CodeEditor | None = None

    def add_editor(self, file_path: Path, content: str = "") -> CodeEditor:
        """Instantiate and attach a new CodeEditor tab mapped to file_path."""
        key = str(file_path)
        existing_editor = self._editors.get(key)
        if existing_editor is not None:
            container = self.container_for(existing_editor)
            if container is not None:
                self._tab_widget.setCurrentWidget(container)
            self._active_editor = existing_editor
            return existing_editor

        editor = CodeEditor(self._palette, self._jedi, self._config, self._tab_widget)
        editor.set_file_path(file_path)
        editor.setPlainText(content)
        editor.mark_saved()

        popup = CompletionPopup(self)
        editor.attach_completion_popup(popup)

        signature_widget = SignatureWidget(self)
        editor.attach_signature_widget(signature_widget)
        editor.send_to_repl_requested.connect(self.send_to_repl_requested)
        editor.breakpoint_toggled.connect(self.breakpoint_toggled)
        editor.test_run_requested.connect(self.test_run_requested)
        editor.open_file_requested.connect(self.open_file_requested)
        editor.fold_toggled.connect(
            lambda line, folded, p=file_path: self.fold_toggled.emit(p, line, folded)
        )
        editor.cursor_moved.connect(lambda l, c, ed=editor: self._set_active_editor(ed))

        # Wrap editor in its container
        container = EditorContainer(editor, self._palette, self._tab_widget)
        container.banner.install_requested.connect(self.install_requested.emit)

        self._tab_widget.addTab(container, file_path.name)
        editor.document().modificationChanged.connect(
            lambda modified, ed=editor: self._on_modification_changed(ed, modified)
        )
        self._editors[key] = editor
        self._tab_widget.setCurrentWidget(container)
        self._active_editor = editor
        return editor

    def split_right(self) -> None:
        """Split editor layout horizontally (side-by-side)."""
        self._splitter.setOrientation(Qt.Orientation.Horizontal)
        self._secondary_tab_widget.show()
        cur = self.current_editor()
        if cur is not None:
            self.open_in_secondary(cur.file_path())
        half = max(200, self.width() // 2)
        self._splitter.setSizes([half, half])

    def split_down(self) -> None:
        """Split editor layout vertically (top-and-bottom)."""
        self._splitter.setOrientation(Qt.Orientation.Vertical)
        self._secondary_tab_widget.show()
        cur = self.current_editor()
        if cur is not None:
            self.open_in_secondary(cur.file_path())
        half = max(150, self.height() // 2)
        self._splitter.setSizes([half, half])

    def close_split(self) -> None:
        """Close secondary split pane and collapse layout back to single pane."""
        while self._secondary_tab_widget.count() > 0:
            self._secondary_tab_widget.removeTab(0)
        self._secondary_editors.clear()
        self._secondary_tab_widget.hide()
        self._active_editor = self.current_editor()

    def is_split(self) -> bool:
        """Return True if split view is currently active."""
        return not self._secondary_tab_widget.isHidden()

    def open_in_secondary(self, file_path: Path) -> CodeEditor:
        """Open or mirror file_path in the secondary tab pane."""
        key = str(file_path)
        existing = self._secondary_editors.get(key)
        if existing is not None:
            container = self.container_for(existing)
            if container is not None:
                self._secondary_tab_widget.setCurrentWidget(container)
            self._active_editor = existing
            return existing

        editor = CodeEditor(
            self._palette, self._jedi, self._config, self._secondary_tab_widget
        )
        editor.set_file_path(file_path)

        primary_editor = self._editors.get(key)
        if primary_editor is not None:
            editor.setDocument(primary_editor.document())
        else:
            try:
                editor.setPlainText(file_path.read_text(encoding="utf-8"))
            except Exception:
                editor.setPlainText("")
        editor.mark_saved()

        popup = CompletionPopup(self)
        editor.attach_completion_popup(popup)

        signature_widget = SignatureWidget(self)
        editor.attach_signature_widget(signature_widget)
        editor.send_to_repl_requested.connect(self.send_to_repl_requested)
        editor.breakpoint_toggled.connect(self.breakpoint_toggled)
        editor.test_run_requested.connect(self.test_run_requested)
        editor.open_file_requested.connect(self.open_file_requested)
        editor.fold_toggled.connect(
            lambda line, folded, p=file_path: self.fold_toggled.emit(p, line, folded)
        )
        editor.cursor_moved.connect(lambda l, c, ed=editor: self._set_active_editor(ed))

        container = EditorContainer(editor, self._palette, self._secondary_tab_widget)
        container.banner.install_requested.connect(self.install_requested.emit)
        self._secondary_tab_widget.addTab(container, file_path.name)
        editor.document().modificationChanged.connect(
            lambda modified, ed=editor: self._on_modification_changed(ed, modified)
        )
        self._secondary_editors[key] = editor
        self._secondary_tab_widget.setCurrentWidget(container)
        self._active_editor = editor
        return editor

    def current_editor(self) -> CodeEditor | None:
        """Return the active CodeEditor instance, if available."""
        if self._active_editor is not None and (
            self._active_editor in self._editors.values()
            or self._active_editor in self._secondary_editors.values()
        ):
            return self._active_editor
        current_widget = self._tab_widget.currentWidget()
        if isinstance(current_widget, EditorContainer):
            return current_widget.editor
        return None

    def _set_active_editor(self, editor: CodeEditor) -> None:
        if self._active_editor is not editor:
            self._active_editor = editor
            self.editor_changed.emit(editor)

    def get_all_breakpoints(self) -> dict[Path, set[int]]:
        """Collect all active breakpoints across all open editors."""
        all_bps: dict[Path, set[int]] = {}
        for editor in list(self._editors.values()) + list(
            self._secondary_editors.values()
        ):
            bps = editor.get_breakpoints()
            if bps:
                all_bps[editor.file_path().resolve()] = bps
        return all_bps

    def set_execution_line(self, file_path: Path, line: int | None) -> None:
        """Set the execution pointer in the editor corresponding to file_path."""
        resolved = file_path.resolve()
        for ed in list(self._editors.values()) + list(self._secondary_editors.values()):
            if ed.file_path().resolve() == resolved:
                if line is not None:
                    container = self.container_for(ed)
                    if container:
                        if self._tab_widget.indexOf(container) != -1:
                            self._tab_widget.setCurrentWidget(container)
                        elif self._secondary_tab_widget.indexOf(container) != -1:
                            self._secondary_tab_widget.setCurrentWidget(container)
                    block = ed.document().findBlockByNumber(max(0, line - 1))
                    if block.isValid():
                        cursor = QTextCursor(block)
                        ed.setTextCursor(cursor)
                        ed.centerCursor()
                ed.set_execution_line(line)
            else:
                ed.set_execution_line(None)

    def clear_all_execution_lines(self) -> None:
        """Clear execution line markers across all open editors."""
        for ed in list(self._editors.values()) + list(self._secondary_editors.values()):
            ed.set_execution_line(None)

    def set_diagnostics_for_path(
        self, file_path: Path, issues: list[DiagnosticIssue]
    ) -> None:
        """Update live diagnostic squiggles for the editor tab matching file_path."""
        resolved = file_path.resolve()
        for editor in list(self._editors.values()) + list(
            self._secondary_editors.values()
        ):
            if editor.file_path().resolve() == resolved:
                editor.set_diagnostics(issues)

    def set_git_diff_for_path(self, file_path: Path, hunks: list[GitDiffHunk]) -> None:
        """Update live Git gutter diff markers for the editor tab matching file_path."""
        resolved = file_path.resolve()
        for editor in list(self._editors.values()) + list(
            self._secondary_editors.values()
        ):
            if editor.file_path().resolve() == resolved:
                editor.set_git_diff_hunks(hunks)

    def show_missing_imports_for_path(
        self, file_path: Path, missing_modules: list[str]
    ) -> None:
        """Show self-healing warning banner for the editor matching file_path."""
        editor = self.editor_for_path(file_path)
        if editor is not None:
            container = self.container_for(editor)
            if container is not None:
                container.banner.show_warnings(missing_modules)

    def hide_missing_imports_for_path(self, file_path: Path) -> None:
        """Hide self-healing warning banner for the editor matching file_path."""
        editor = self.editor_for_path(file_path)
        if editor is not None:
            container = self.container_for(editor)
            if container is not None:
                container.banner.hide()

    def editor_count(self) -> int:
        """Return the number of currently open editor tabs."""
        return len(self._editors) + len(self._secondary_editors)

    def editor_for_path(self, file_path: Path) -> CodeEditor | None:
        """Return the already-open editor for ``file_path``, if any."""
        return self._editors.get(str(file_path)) or self._secondary_editors.get(
            str(file_path)
        )

    def container_for(self, editor: CodeEditor) -> EditorContainer | None:
        """Return the EditorContainer wrapping the given editor, if it is open."""
        for tab_widget in (self._tab_widget, self._secondary_tab_widget):
            for tab_index in range(tab_widget.count()):
                widget = tab_widget.widget(tab_index)
                if isinstance(widget, EditorContainer) and widget.editor is editor:
                    return widget
        return None

    def container_at(self, index: int) -> EditorContainer | None:
        """Return the EditorContainer at a specific tab index, if valid."""
        widget = self._tab_widget.widget(index)
        return widget if isinstance(widget, EditorContainer) else None

    def widget(self, index: int) -> CodeEditor | None:
        """Return the CodeEditor at index for compatibility with QTabWidget."""
        container = self.container_at(index)
        return container.editor if container else None

    def removeTab(self, index: int) -> None:
        """Close tab at index for compatibility with QTabWidget."""
        self.close_tab(index)

    def setCurrentIndex(self, index: int) -> None:
        """Set the active tab index for compatibility with QTabWidget."""
        self._tab_widget.setCurrentIndex(index)

    def open_file(self, file_path: Path) -> CodeEditor:
        """Open or switch to a file in an editor tab."""
        existing = self.editor_for_path(file_path)
        if existing is not None:
            container = self.container_for(existing)
            if container is not None:
                self._tab_widget.setCurrentWidget(container)
            self._active_editor = existing
            return existing
        content = ""
        if file_path.is_file():
            try:
                content = file_path.read_text(encoding="utf-8")
            except Exception:
                content = ""
        return self.add_editor(file_path, content)

    def tab_index_for(self, editor: CodeEditor) -> int | None:
        """Return the current tab index hosting the given editor, if open in primary tabs."""
        container = self.container_for(editor)
        if container is None:
            return None
        index = self._tab_widget.indexOf(container)
        return index if index != -1 else None

    def set_current_editor(self, editor: CodeEditor) -> None:
        """Bring the tab containing the given editor to the front, if it is open."""
        container = self.container_for(editor)
        if container is not None:
            if self._tab_widget.indexOf(container) != -1:
                self._tab_widget.setCurrentWidget(container)
            elif self._secondary_tab_widget.indexOf(container) != -1:
                self._secondary_tab_widget.setCurrentWidget(container)
            self._active_editor = editor

    def modified_editors(self) -> list[CodeEditor]:
        """Return every open editor that currently has unsaved changes."""
        all_eds = list(self._editors.values()) + list(self._secondary_editors.values())
        return [editor for editor in all_eds if editor.is_modified()]

    def has_unsaved_changes(self) -> bool:
        """Return True if any open editor currently has unsaved changes."""
        all_eds = list(self._editors.values()) + list(self._secondary_editors.values())
        return any(editor.is_modified() for editor in all_eds)

    def notify_saved(self, editor: CodeEditor) -> None:
        """Clear an editor's dirty state and refresh its tab title."""
        editor.mark_saved()
        container = self.container_for(editor)
        if container is not None:
            for tab_widget in (self._tab_widget, self._secondary_tab_widget):
                idx = tab_widget.indexOf(container)
                if idx != -1:
                    tab_widget.setTabText(idx, editor.file_path().name)

    def close_tab(self, index: int) -> None:
        """Unconditionally close the tab at ``index``, discarding any unsaved changes."""
        widget = self._tab_widget.widget(index)
        if isinstance(widget, EditorContainer):
            key = str(widget.editor.file_path())
            self._tab_widget.removeTab(index)
            self._editors.pop(key, None)
            self.editor_closed.emit(key)
            self._active_editor = self.current_editor()

    def set_palette(self, palette: ColorPalette) -> None:
        """Update the active ColorPalette across all open editor tabs."""
        self._palette = palette
        for tab_widget in (self._tab_widget, self._secondary_tab_widget):
            for tab_index in range(tab_widget.count()):
                container = tab_widget.widget(tab_index)
                if isinstance(container, EditorContainer):
                    container.set_palette(palette)

    def _on_current_changed(self, index: int) -> None:
        editor = self.current_editor()
        if editor is not None:
            self._active_editor = editor
            self.editor_changed.emit(editor)
            editor.setFocus()

    def _on_secondary_current_changed(self, index: int) -> None:
        widget = self._secondary_tab_widget.widget(index)
        if isinstance(widget, EditorContainer):
            self._active_editor = widget.editor
            self.editor_changed.emit(widget.editor)
            widget.editor.setFocus()

    def _on_close_requested(self, index: int) -> None:
        widget = self._tab_widget.widget(index)
        if not isinstance(widget, EditorContainer):
            return
        if widget.editor.is_modified():
            self.unsaved_close_requested.emit(index)
            return
        self.close_tab(index)

    def _on_secondary_close_requested(self, index: int) -> None:
        widget = self._secondary_tab_widget.widget(index)
        if isinstance(widget, EditorContainer):
            key = str(widget.editor.file_path())
            self._secondary_tab_widget.removeTab(index)
            self._secondary_editors.pop(key, None)
            if self._secondary_tab_widget.count() == 0:
                self._secondary_tab_widget.hide()
            self._active_editor = self.current_editor()

    def _on_modification_changed(self, editor: CodeEditor, modified: bool) -> None:
        container = self.container_for(editor)
        if container is None:
            return
        for tab_widget in (self._tab_widget, self._secondary_tab_widget):
            tab_index = tab_widget.indexOf(container)
            if tab_index != -1:
                base_name = editor.file_path().name
                tab_widget.setTabText(
                    tab_index, f"● {base_name}" if modified else base_name
                )
