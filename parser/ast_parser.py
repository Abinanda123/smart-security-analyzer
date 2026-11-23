"""AST Parser for Python static application security testing.

Traverses Python ASTs to detect potential security hotspots matching
registered vulnerability rules. Emits structured Finding objects adhering to
the project schema (file, line, rule_id, category, code, source, sink).
"""

import ast
import os
import sys
from pathlib import Path
from typing import List, Optional

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from parser.models import Finding
from parser.rules import (
    RULES,
    check_eval_call,
    check_exec_call,
    check_os_system,
    check_os_popen,
    check_subprocess_shell,
    check_sql_injection,
    check_unsafe_pickle,
    check_weak_hash,
    check_hardcoded_secrets,
)


def extract_snippet_context(lines: List[str], target_line_1idx: int, window: int = 3) -> str:
    """Extract surrounding lines to supply code context for LLM/RAG."""
    total = len(lines)
    start = max(1, target_line_1idx - window)
    end = min(total, target_line_1idx + window)
    
    snippet_lines = []
    for idx in range(start, end + 1):
        prefix = "-> " if idx == target_line_1idx else "   "
        line_content = lines[idx - 1].rstrip("\r\n")
        snippet_lines.append(f"{prefix}{idx:4d} | {line_content}")
    return "\n".join(snippet_lines)


class SecurityASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.findings: List[Finding] = []
        self.env: dict = {}

    def _get_exact_line_code(self, node: ast.AST) -> str:
        if hasattr(node, "lineno") and 1 <= node.lineno <= len(self.source_lines):
            return self.source_lines[node.lineno - 1].strip()
        try:
            return ast.unparse(node)
        except Exception:
            return "<code unavailable>"

    def _add_finding(self, node: ast.AST, rule_id: str, source: str, sink: str):
        rule = RULES.get(rule_id)
        if not rule:
            return

        line_no = getattr(node, "lineno", 1)
        code_line = self._get_exact_line_code(node)
        context = extract_snippet_context(self.source_lines, line_no, window=3)

        finding = Finding(
            file=self.file_path,
            line=line_no,
            rule_id=rule.rule_id,
            category=rule.category,
            code=code_line,
            source=source,
            sink=sink,
            cwe=rule.cwe,
            severity_hint=rule.severity_hint,
            snippet_context=context,
            finding_id=f"VULN-{len(self.findings) + 1:03d}",
        )
        self.findings.append(finding)

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.env[target.id] = node.value
        res = check_hardcoded_secrets(node)
        if res:
            self._add_finding(node, *res)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        for check in (
            check_eval_call,
            check_exec_call,
            check_os_system,
            check_os_popen,
            check_subprocess_shell,
            check_unsafe_pickle,
            check_weak_hash,
        ):
            res = check(node)
            if res:
                self._add_finding(node, *res)

        # SQL injection with local environment awareness
        res = check_sql_injection(node, env=self.env)
        if res:
            self._add_finding(node, *res)

        self.generic_visit(node)


def parse_code(code_str: str, file_path: str = "<string>") -> List[Finding]:
    """Parse raw code string directly into Findings."""
    try:
        tree = ast.parse(code_str, filename=file_path)
    except SyntaxError as e:
        print(f"[!] SyntaxError parsing {file_path} at line {e.lineno}: {e.msg}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[!] Error parsing {file_path}: {e}", file=sys.stderr)
        return []

    visitor = SecurityASTVisitor(file_path=file_path, source_code=code_str)
    visitor.visit(tree)
    return visitor.findings


def parse_file(file_path: str) -> List[Finding]:
    """Read a python file from disk and return Findings."""
    path = Path(file_path)
    if not path.is_file():
        print(f"[!] File not found: {file_path}", file=sys.stderr)
        return []

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"[!] Failed to read {file_path}: {e}", file=sys.stderr)
        return []

    return parse_code(source, file_path=str(path))
