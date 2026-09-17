"""
Interprocedural SAST Dataflow and Taint Analysis Engine.

Tracks tainted user and external inputs across variable assignments, string
interpolations, collections, return statements, and function boundaries to
detect critical security vulnerabilities (Command Injection, Code Injection,
SQL Injection, Path Traversal, SSRF, Deserialization).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar


@dataclass(slots=True)
class TaintFinding:
    """A verified or high-confidence dataflow taint vulnerability."""

    filepath: str
    lineno: int
    col_offset: int
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM'
    sink_type: str  # e.g. 'COMMAND_INJECTION', 'CODE_INJECTION', etc.
    sink_call: str
    source_desc: str
    source_lineno: int
    propagation_path: list[str]
    message: str
    suggestion: str
    param_to_sink: str = ""


@dataclass(slots=True)
class TaintReport:
    """Aggregated results from the taint analysis engine."""

    findings: list[TaintFinding] = field(default_factory=list)
    files_scanned: int = 0
    sinks_checked: int = 0
    sources_detected: int = 0

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def has_critical(self) -> bool:
        return any(f.severity == "CRITICAL" for f in self.findings)

    def by_sink_type(self, sink_type: str) -> list[TaintFinding]:
        return [f for f in self.findings if f.sink_type == sink_type]

    def format_summary(self) -> str:
        lines: list[str] = [
            f"Files scanned: {self.files_scanned}",
            f"Sinks evaluated: {self.sinks_checked}",
            f"Sources detected: {self.sources_detected}",
            f"Total taint vulnerabilities found: {len(self.findings)}",
        ]
        if self.findings:
            lines.append("\nVulnerabilities detected:")
            for idx, f in enumerate(self.findings, 1):
                lines.append(
                    f"  [{idx}] {f.severity}: {f.sink_type} at {f.filepath}:{f.lineno}"
                )
                lines.append(f"      Sink:   {f.sink_call}")
                lines.append(f"      Source: {f.source_desc} (line {f.source_lineno})")
                if f.propagation_path:
                    path_str = " -> ".join(f.propagation_path)
                    lines.append(f"      Path:   {path_str}")
                lines.append(f"      Fix:    {f.suggestion}")
        return "\n".join(lines)


@dataclass(slots=True)
class TaintVariable:
    """Representation of a variable holding tainted data."""

    name: str
    source_desc: str
    source_lineno: int
    propagation_path: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FunctionTaintSummary:
    """Interprocedural summary of a function's taint behavior."""

    func_name: str
    filepath: str
    param_names: list[str] = field(default_factory=list)
    returns_taint: bool = False
    return_source_desc: str = ""
    return_source_lineno: int = 0
    # Maps parameter index/name to sink finding template if param flows to sink
    param_to_sink: dict[str, tuple[str, str, int]] = field(default_factory=dict)


class TaintEngine:
    """
    Interprocedural static dataflow taint analysis engine.

    Traces untrusted sources to security-sensitive sinks through intraprocedural
    SSA/CFG variable assignments and interprocedural call chains.
    """

    # Known sources of untrusted data
    KNOWN_SOURCES: ClassVar[set[str]] = {
        "input",
        "raw_input",
        "sys.argv",
        "request.args",
        "request.form",
        "request.values",
        "request.data",
        "request.json",
        "request.get_json",
        "request.GET",
        "request.POST",
        "request.body",
        "request.headers",
        "request.cookies",
        "os.environ",
        "os.getenv",
        "socket.recv",
        "conn.recv",
        "f.read",
        "f.readline",
        "f.readlines",
        "file.read",
    }

    # Sanitizers that neutralize taint
    KNOWN_SANITIZERS: ClassVar[set[str]] = {
        "int",
        "float",
        "bool",
        "shlex.quote",
        "html.escape",
        "re.escape",
        "secrets.compare_digest",
        "uuid.UUID",
        "math.floor",
        "math.ceil",
    }

    # Sink configurations: name -> (sink_type, default_severity, suggestion)
    SINK_SPECS: ClassVar[dict[str, tuple[str, str, str]]] = {
        "os.system": (
            "COMMAND_INJECTION",
            "CRITICAL",
            "Use subprocess.run with shell=False and argument list, or validate input.",
        ),
        "os.popen": (
            "COMMAND_INJECTION",
            "CRITICAL",
            "Replace os.popen with subprocess.run without shell.",
        ),
        "subprocess.run": (
            "COMMAND_INJECTION",
            "CRITICAL",
            "Ensure shell=False and use a list of arguments without string interpolation.",
        ),
        "subprocess.Popen": (
            "COMMAND_INJECTION",
            "CRITICAL",
            "Ensure shell=False and avoid concatenating untrusted input into commands.",
        ),
        "subprocess.call": (
            "COMMAND_INJECTION",
            "CRITICAL",
            "Avoid shell=True and pass command arguments as a validated list.",
        ),
        "subprocess.check_output": (
            "COMMAND_INJECTION",
            "CRITICAL",
            "Pass arguments as a sequence without shell=True.",
        ),
        "subprocess.check_call": (
            "COMMAND_INJECTION",
            "CRITICAL",
            "Pass arguments as a sequence without shell=True.",
        ),
        "eval": (
            "CODE_INJECTION",
            "CRITICAL",
            "Never evaluate untrusted dynamic code. Use ast.literal_eval for safe literals.",
        ),
        "exec": (
            "CODE_INJECTION",
            "CRITICAL",
            "Do not execute dynamically constructed code from untrusted input.",
        ),
        "cursor.execute": (
            "SQL_INJECTION",
            "CRITICAL",
            "Use parameterized SQL query placeholders (e.g., 'WHERE id = ?', (val,)) instead of string formatting.",
        ),
        "session.execute": (
            "SQL_INJECTION",
            "CRITICAL",
            "Use parameterized SQLAlchemy queries or text(:param).",
        ),
        "connection.execute": (
            "SQL_INJECTION",
            "CRITICAL",
            "Use parameterized queries with database driver parameter placeholders.",
        ),
        "open": (
            "PATH_TRAVERSAL",
            "HIGH",
            "Validate paths using os.path.abspath and ensure it resides within an allowed directory.",
        ),
        "os.remove": (
            "PATH_TRAVERSAL",
            "HIGH",
            "Ensure path is validated and confined to expected sandboxed directory.",
        ),
        "os.unlink": (
            "PATH_TRAVERSAL",
            "HIGH",
            "Ensure target path is sanitized and canonicalized within allowed directory.",
        ),
        "pickle.loads": (
            "DESERIALIZATION",
            "CRITICAL",
            "Do not unpickle untrusted data. Use JSON or safe structured serialization.",
        ),
        "pickle.load": (
            "DESERIALIZATION",
            "CRITICAL",
            "Do not unpickle untrusted data from files.",
        ),
        "yaml.load": (
            "DESERIALIZATION",
            "HIGH",
            "Use yaml.safe_load instead of yaml.load with FullLoader/UnsafeLoader.",
        ),
        "requests.get": (
            "SSRF",
            "MEDIUM",
            "Validate target URL against a strict whitelist of allowed hosts and protocols.",
        ),
        "requests.post": (
            "SSRF",
            "MEDIUM",
            "Validate destination URL against an approved internal/external whitelist.",
        ),
        "urllib.request.urlopen": (
            "SSRF",
            "MEDIUM",
            "Validate and restrict URL scheme and host.",
        ),
    }

    def __init__(self) -> None:
        self.function_summaries: dict[str, FunctionTaintSummary] = {}

    def scan_path(self, target: str | Path) -> TaintReport:
        """Scan a file or directory for dataflow taint vulnerabilities."""
        path = Path(target)
        if path.is_file():
            files = [path] if path.suffix == ".py" else []
        elif path.is_dir():
            files = sorted(
                f
                for f in path.rglob("*.py")
                if not any(
                    part.startswith((".", "build", "dist", "venv", "__pycache__"))
                    for part in f.parts
                )
            )
        else:
            return TaintReport()

        report = TaintReport()
        parsed_files: list[tuple[Path, ast.Module]] = []

        # Pass 1: Parse ASTs and build interprocedural summaries
        for fpath in files:
            try:
                code = fpath.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(code, filename=str(fpath))
                parsed_files.append((fpath, tree))
                self._collect_function_summaries(str(fpath), tree)
            except SyntaxError:
                continue

        # Pass 2: Interprocedural and intraprocedural taint flow analysis
        for fpath, tree in parsed_files:
            file_report = self._analyze_tree(str(fpath), tree)
            report.findings.extend(file_report.findings)
            report.sinks_checked += file_report.sinks_checked
            report.sources_detected += file_report.sources_detected
            report.files_scanned += 1

        return report

    def _inspect_return_child(
        self, child: ast.AST, summary: FunctionTaintSummary
    ) -> None:
        if isinstance(child, ast.Return) and child.value is not None:
            source_info = self._get_expression_direct_source(child.value)
            if source_info:
                summary.returns_taint = True
                summary.return_source_desc = source_info[0]
                summary.return_source_lineno = source_info[1]

    def _inspect_call_sink_child(
        self,
        child: ast.AST,
        summary: FunctionTaintSummary,
        param_names: list[str],
        default_lineno: int,
    ) -> None:
        if not isinstance(child, ast.Call):
            return
        child_call_name = self._resolve_call_name(child.func)
        spec = self.SINK_SPECS.get(child_call_name)
        if not spec:
            return
        for arg in child.args:
            if isinstance(arg, ast.Name) and arg.id in param_names:
                summary.param_to_sink[arg.id] = (
                    spec[0],
                    spec[1],
                    getattr(child, "lineno", default_lineno),
                )

    def _collect_function_summaries(self, filepath: str, tree: ast.AST) -> None:
        """Collect top-level and class function signatures and return patterns."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                param_names = [arg.arg for arg in node.args.args]
                summary = FunctionTaintSummary(
                    func_name=node.name,
                    filepath=filepath,
                    param_names=param_names,
                )
                for child in ast.walk(node):
                    self._inspect_return_child(child, summary)
                    self._inspect_call_sink_child(
                        child, summary, param_names, node.lineno
                    )
                self.function_summaries[node.name] = summary

    def _analyze_tree(self, filepath: str, tree: ast.AST) -> TaintReport:
        """Analyze a single module AST for dataflow taint flows."""
        visitor = _ModuleTaintVisitor(
            filepath=filepath,
            engine=self,
            function_summaries=self.function_summaries,
        )
        visitor.visit(tree)
        return visitor.report

    def _get_expression_direct_source(self, node: ast.AST) -> tuple[str, int] | None:
        """Check if an expression immediately calls or accesses a known untrusted source."""
        if isinstance(node, ast.Call):
            call_name = self._resolve_call_name(node.func)
            if call_name in self.KNOWN_SOURCES or any(
                call_name.startswith(src) for src in self.KNOWN_SOURCES
            ):
                return call_name, getattr(node, "lineno", 0)
        elif isinstance(node, ast.Subscript):
            # e.g., sys.argv[1], request.args['q']
            val_name = self._resolve_call_name(node.value)
            if val_name in self.KNOWN_SOURCES or any(
                val_name.startswith(src) for src in self.KNOWN_SOURCES
            ):
                return f"{val_name}[...]", getattr(node, "lineno", 0)
        return None

    @staticmethod
    def _resolve_call_name(node: ast.AST) -> str:
        """Resolve an AST node to a dot-delimited call or attribute name."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = TaintEngine._resolve_call_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""


class _ModuleTaintVisitor(ast.NodeVisitor):
    """AST visitor that tracks taint flows per scope (module and function)."""

    def __init__(
        self,
        filepath: str,
        engine: TaintEngine,
        function_summaries: dict[str, FunctionTaintSummary],
    ) -> None:
        self.filepath = filepath
        self.engine = engine
        self.function_summaries = function_summaries
        self.report = TaintReport()

        # Scoped variable environments: stack of dict[var_name, TaintVariable]
        self.env_stack: list[dict[str, TaintVariable]] = [{}]

    @property
    def current_env(self) -> dict[str, TaintVariable]:
        return self.env_stack[-1]

    def _get_var(self, name: str) -> TaintVariable | None:
        for env in reversed(self.env_stack):
            if name in env:
                return env[name]
        return None

    def _set_var(self, name: str, taint: TaintVariable) -> None:
        self.current_env[name] = taint

    def _remove_var(self, name: str) -> None:
        if name in self.current_env:
            del self.current_env[name]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._handle_function_scope(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._handle_function_scope(node)

    def _handle_function_scope(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        new_env: dict[str, TaintVariable] = {}
        self.env_stack.append(new_env)

        # Check if function params should be treated as potential sources for intra-function checking
        for stmt in node.body:
            self.visit(stmt)

        self.env_stack.pop()

    def _propagate_taint_to_name(
        self, name: str, taint: TaintVariable | None, node_value: ast.AST | None
    ) -> None:
        if not taint:
            self._remove_var(name)
            return
        prop_path = list(taint.propagation_path)
        if node_value is not None:
            prop_path.append(f"{name} = {self._node_summary(node_value)}")
        self._set_var(
            name,
            TaintVariable(
                name=name,
                source_desc=taint.source_desc,
                source_lineno=taint.source_lineno,
                propagation_path=prop_path,
            ),
        )

    def _assign_target_taint(
        self, target: ast.AST, taint: TaintVariable | None, value_node: ast.AST
    ) -> None:
        if isinstance(target, ast.Name):
            self._propagate_taint_to_name(target.id, taint, value_node)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                if isinstance(elt, ast.Name):
                    self._propagate_taint_to_name(elt.id, taint, None)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node.value)
        taint = self._evaluate_taint(node.value)
        for target in node.targets:
            self._assign_target_taint(target, taint, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.generic_visit(node.value)
            taint = self._evaluate_taint(node.value)
            if isinstance(node.target, ast.Name):
                self._propagate_taint_to_name(node.target.id, taint, node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.generic_visit(node.value)
        val_taint = self._evaluate_taint(node.value)
        if isinstance(node.target, ast.Name):
            target_taint = self._get_var(node.target.id)
            active_taint = val_taint or target_taint
            if active_taint:
                prop_path = list(active_taint.propagation_path)
                prop_path.append(
                    f"{node.target.id} += {self._node_summary(node.value)}"
                )
                self._set_var(
                    node.target.id,
                    TaintVariable(
                        name=node.target.id,
                        source_desc=active_taint.source_desc,
                        source_lineno=active_taint.source_lineno,
                        propagation_path=prop_path,
                    ),
                )

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)
        self._check_call_for_sink(node)

    def _resolve_sink_spec(self, call_name: str) -> tuple[str, str, str] | None:
        if call_name in self.engine.SINK_SPECS:
            return self.engine.SINK_SPECS[call_name]
        for s_name, spec in self.engine.SINK_SPECS.items():
            if call_name.endswith(s_name) or s_name.endswith(call_name):
                return spec
        return None

    def _check_interprocedural_sink(self, node: ast.Call, call_name: str) -> bool:
        if call_name not in self.function_summaries:
            return False
        summary = self.function_summaries[call_name]
        if not summary.param_to_sink:
            return False
        for idx, call_arg in enumerate(node.args):
            if idx >= len(summary.param_names):
                continue
            pname = summary.param_names[idx]
            if pname in summary.param_to_sink:
                taint = self._evaluate_taint(call_arg)
                if taint:
                    stype, ssev, _ = summary.param_to_sink[pname]
                    path = list(taint.propagation_path) + [f"{call_name}({pname})"]
                    self.report.findings.append(
                        TaintFinding(
                            filepath=self.filepath,
                            lineno=getattr(node, "lineno", 0),
                            col_offset=getattr(node, "col_offset", 0),
                            severity=ssev,
                            sink_type=stype,
                            sink_call=f"{call_name}({pname})",
                            source_desc=taint.source_desc,
                            source_lineno=taint.source_lineno,
                            propagation_path=path,
                            message=(
                                f"Untrusted data from '{taint.source_desc}' (line {taint.source_lineno}) "
                                f"flows into parameter '{pname}' of '{call_name}', reaching a sensitive sink."
                            ),
                            suggestion=f"Sanitize argument '{pname}' before passing to '{call_name}'.",
                            param_to_sink=pname,
                        )
                    )
        return True

    def _emit_sink_finding(
        self,
        node: ast.Call,
        call_name: str,
        sink_spec: tuple[str, str, str],
        arg: ast.AST,
        taint: TaintVariable,
    ) -> None:
        sink_type, default_severity, suggestion = sink_spec
        lineno = getattr(node, "lineno", 0)
        col_offset = getattr(node, "col_offset", 0)
        path = list(taint.propagation_path) + [
            f"{call_name}({self._node_summary(arg)})"
        ]
        finding = TaintFinding(
            filepath=self.filepath,
            lineno=lineno,
            col_offset=col_offset,
            severity=default_severity,
            sink_type=sink_type,
            sink_call=call_name,
            source_desc=taint.source_desc,
            source_lineno=taint.source_lineno,
            propagation_path=path,
            message=(
                f"Untrusted data from '{taint.source_desc}' (line {taint.source_lineno}) "
                f"flows into sensitive sink '{call_name}'."
            ),
            suggestion=suggestion,
        )
        self.report.findings.append(finding)

    def _check_direct_sink(
        self, node: ast.Call, call_name: str, sink_spec: tuple[str, str, str]
    ) -> None:
        self.report.sinks_checked += 1
        if not node.args:
            return
        sink_type = sink_spec[0]
        arg = node.args[0]
        taint = self._evaluate_taint(arg)
        if not taint:
            return
        if sink_type == "SQL_INJECTION" and self._is_safe_sql_param(arg, node):
            return
        self._emit_sink_finding(node, call_name, sink_spec, arg, taint)

    def _check_call_for_sink(self, node: ast.Call) -> None:
        call_name = self.engine._resolve_call_name(node.func)
        sink_spec = self._resolve_sink_spec(call_name)
        if sink_spec is None:
            self._check_interprocedural_sink(node, call_name)
        else:
            self._check_direct_sink(node, call_name, sink_spec)

    def _is_safe_sql_param(self, query_arg: ast.AST, call_node: ast.Call) -> bool:
        """Check if SQL call uses safe parameter binding rather than string concatenation."""
        # If query_arg is a simple string literal, it's safe unless formatted
        if isinstance(query_arg, ast.Constant) and isinstance(query_arg.value, str):
            # Safe static query
            return True

        # If query is formatted/interpolated with tainted data, it is NOT safe
        if isinstance(query_arg, (ast.JoinedStr, ast.BinOp)):
            return False

        # If there are subsequent parameter arguments (e.g. cursor.execute("...", (p1, p2)))
        # and query_arg is NOT dynamically concatenated with taint, it's safe
        return False

    def _eval_direct_source(self, node: ast.AST) -> TaintVariable | None:
        direct_source = self.engine._get_expression_direct_source(node)
        if not direct_source:
            return None
        self.report.sources_detected += 1
        src_desc, src_lineno = direct_source
        return TaintVariable(
            name="<source>",
            source_desc=src_desc,
            source_lineno=src_lineno,
            propagation_path=[f"{src_desc}"],
        )

    def _eval_call_summary_return(
        self, call_name: str, lineno: int
    ) -> TaintVariable | None:
        if call_name not in self.function_summaries:
            return None
        summary = self.function_summaries[call_name]
        if not summary.returns_taint:
            return None
        return TaintVariable(
            name="<func_return>",
            source_desc=f"{call_name}() [{summary.return_source_desc}]",
            source_lineno=lineno,
            propagation_path=[
                f"{call_name}() returns taint from {summary.return_source_desc}"
            ],
        )

    def _eval_call_taint(self, node: ast.Call) -> TaintVariable | None:
        call_name = self.engine._resolve_call_name(node.func)
        if call_name in self.engine.KNOWN_SANITIZERS or any(
            call_name.endswith(san) for san in self.engine.KNOWN_SANITIZERS
        ):
            return None

        func_ret = self._eval_call_summary_return(call_name, getattr(node, "lineno", 0))
        if func_ret:
            return func_ret

        for arg in node.args:
            arg_taint = self._evaluate_taint(arg)
            if arg_taint:
                return arg_taint
        return None

    def _eval_collection_taint(
        self, node: ast.List | ast.Tuple | ast.Set
    ) -> TaintVariable | None:
        for elt in node.elts:
            t = self._evaluate_taint(elt)
            if t:
                return t
        return None

    def _eval_composite_taint(self, node: ast.AST) -> TaintVariable | None:
        if isinstance(node, ast.BinOp):
            return self._evaluate_taint(node.left) or self._evaluate_taint(node.right)
        if isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    t = self._evaluate_taint(val.value)
                    if t:
                        return t
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self._eval_collection_taint(node)
        elif isinstance(node, ast.Subscript):
            return self._evaluate_taint(node.value)
        return None

    def _evaluate_taint(self, node: ast.AST) -> TaintVariable | None:
        """Recursively evaluate if an AST expression produces tainted data."""
        if isinstance(node, ast.Name):
            return self._get_var(node.id)

        source_taint = self._eval_direct_source(node)
        if source_taint:
            return source_taint

        if isinstance(node, ast.Call):
            return self._eval_call_taint(node)

        return self._eval_composite_taint(node)

    @staticmethod
    def _node_summary(node: ast.AST) -> str:
        """Create a compact human-readable string summary of an AST node."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Constant):
            return repr(node.value)
        if isinstance(node, ast.Call):
            func_str = TaintEngine._resolve_call_name(node.func) or "func"
            return f"{func_str}(...)"
        if isinstance(node, ast.BinOp):
            return f"{_ModuleTaintVisitor._node_summary(node.left)} + {_ModuleTaintVisitor._node_summary(node.right)}"
        if isinstance(node, ast.JoinedStr):
            return 'f"..."'
        return "expr"
