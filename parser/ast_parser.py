"""AST Parser for Python static application security testing.

Traverses Python ASTs to detect potential security hotspots matching
registered vulnerability rules. Emits structured Finding objects adhering to
the project schema (file, line, rule_id, category, code, source, sink).
"""

import ast
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

# Configure stdout for UTF-8 compatibility on Windows terminals
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
    """Extract surrounding lines around target line to supply context for LLM/RAG."""
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
    """AST NodeVisitor that scans Python code for potential security vulnerabilities."""

    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.findings: List[Finding] = []
        self.env: dict = {}

    def _get_exact_line_code(self, node: ast.AST) -> str:
        """Get the single line or node code from the source file."""
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
        )
        self.findings.append(finding)

    def visit_Assign(self, node: ast.Assign):
        # Record assigned variable expressions into environment for data-flow awareness
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.env[target.id] = node.value

        # Check hardcoded secrets
        res = check_hardcoded_secrets(node)
        if res:
            self._add_finding(node, *res)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # 1. Check eval()
        res = check_eval_call(node)
        if res:
            self._add_finding(node, *res)

        # 2. Check exec()
        res = check_exec_call(node)
        if res:
            self._add_finding(node, *res)

        # 3. Check os.system()
        res = check_os_system(node)
        if res:
            self._add_finding(node, *res)

        # 4. Check os.popen()
        res = check_os_popen(node)
        if res:
            self._add_finding(node, *res)

        # 5. Check subprocess with shell=True
        res = check_subprocess_shell(node)
        if res:
            self._add_finding(node, *res)

        # 6. Check SQL injection
        res = check_sql_injection(node, env=self.env)
        if res:
            self._add_finding(node, *res)

        # 7. Check unsafe pickle
        res = check_unsafe_pickle(node)
        if res:
            self._add_finding(node, *res)

        # 8. Check weak hash
        res = check_weak_hash(node)
        if res:
            self._add_finding(node, *res)

        # Continue traversing children
        self.generic_visit(node)


def parse_code(code_str: str, file_path: str = "<string>") -> List[Finding]:
    """Parse a code string directly and return list of Finding objects."""
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
    """Read a python file from disk, parse AST, and return list of Finding objects."""
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


def print_findings_table(findings: List[Finding]):
    """Pretty prints findings to terminal for human-readable inspection."""
    if not findings:
        print("\n[OK] No potential security issues detected by AST analysis.")
        return

    print(f"\n[FINDINGS] Found {len(findings)} potential security finding(s):")
    print("=" * 80)
    for i, f in enumerate(findings, 1):
        print(f"[{i}] {f.category} ({f.rule_id} | {f.cwe}) - Severity: {f.severity_hint}")
        print(f"    File: {f.file}:{f.line}")
        print(f"    Sink: {f.sink}  |  Source: {f.source}")
        print(f"    Code: {f.code}")
        print("-" * 80)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="AST Static Security Analyzer — Extract potential vulnerabilities for RAG/LLM triage."
    )
    parser.add_argument("target", help="Path to Python file to scan")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON")
    parser.add_argument("--out", type=str, default=None, help="Save JSON findings to specified output file")

    args = parser.parse_args()

    results = parse_file(args.target)

    if args.json or args.out:
        json_output = json.dumps([f.to_dict() for f in results], indent=2)
        if args.out:
            Path(args.out).write_text(json_output, encoding="utf-8")
            print(f"[*] Findings written to {args.out}")
        else:
            print(json_output)
    else:
        print_findings_table(results)
