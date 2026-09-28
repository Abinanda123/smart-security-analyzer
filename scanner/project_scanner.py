"""Project Scanner module for Smart Security Analyzer.

Recursively discovers Python files in a target directory (ignoring virtualenvs,
git, and cache directories), runs AST static analysis via parser, and collects
potential security findings into a standardized JSON report.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Any

# Configure stdout for UTF-8 compatibility on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from parser.models import Finding
from parser.ast_parser import parse_file, print_findings_table


# Directories to ignore during scanning
IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "venv",
    ".venv",
    "env",
    ".env",
    "node_modules",
    "build",
    "dist",
    "site-packages",
}


def find_python_files(target_path: Path) -> List[Path]:
    """Recursively collect all .py files under target_path while skipping noise directories."""
    python_files: List[Path] = []
    
    if target_path.is_file():
        if target_path.suffix == ".py":
            return [target_path]
        return []

    for root, dirs, files in os.walk(target_path):
        # In-place modify dirs to avoid traversing into ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]

        for file in files:
            if file.endswith(".py"):
                full_path = Path(root) / file
                python_files.append(full_path)

    return sorted(python_files)


def scan_project(target_path: str) -> Dict[str, Any]:
    """Scan a target path (file or project directory) and return detailed findings and metrics."""
    path = Path(target_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {target_path}")

    start_time = time.time()
    files_to_scan = find_python_files(path)
    
    all_findings: List[Finding] = []
    failed_files: List[str] = []

    for py_file in files_to_scan:
        try:
            findings = parse_file(str(py_file))
            all_findings.extend(findings)
        except Exception as e:
            failed_files.append(str(py_file))

    elapsed_time = round(time.time() - start_time, 3)

    # Calculate statistics
    by_category: Dict[str, int] = {}
    by_cwe: Dict[str, int] = {}
    for f in all_findings:
        by_category[f.category] = by_category.get(f.category, 0) + 1
        if f.cwe:
            by_cwe[f.cwe] = by_cwe.get(f.cwe, 0) + 1

    return {
        "status": "success",
        "target": str(path),
        "files_scanned": len(files_to_scan),
        "failed_files": failed_files,
        "elapsed_seconds": elapsed_time,
        "total_findings": len(all_findings),
        "summary_by_category": by_category,
        "summary_by_cwe": by_cwe,
        "findings": [f.to_dict() for f in all_findings],
    }


def cli_main():
    """Terminal CLI entry point for project scanner."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Smart Security Analyzer — AST Static Code Scanner CLI"
    )
    parser.add_argument("path", help="Directory or Python file to scan")
    parser.add_argument("--json", action="store_true", help="Output raw JSON (for RAG/LLM pipelines)")
    parser.add_argument("--out", type=str, default=None, help="Save scan report to a JSON file")

    args = parser.parse_args()

    try:
        report = scan_project(args.path)
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    if args.json or args.out:
        json_str = json.dumps(report, indent=2)
        if args.out:
            Path(args.out).write_text(json_str, encoding="utf-8")
            print(f"[*] Report successfully written to {args.out}")
        else:
            print(json_str)
    else:
        # Terminal visual report
        print("\n" + "=" * 60)
        print("[REPORT] SMART SECURITY ANALYZER - AST SCAN REPORT")
        print("=" * 60)
        print(f"Target:          {report['target']}")
        print(f"Files Scanned:   {report['files_scanned']}")
        print(f"Time Taken:      {report['elapsed_seconds']}s")
        print(f"Total Findings:  {report['total_findings']}")
        print("-" * 60)
        
        if report['summary_by_category']:
            print("Breakdown by Vulnerability Category:")
            for cat, count in report['summary_by_category'].items():
                print(f"  * {cat:<24}: {count}")
            print("-" * 60)

        findings_list = report['findings']
        if not findings_list:
            print("[OK] No potential security vulnerabilities found by AST analysis.")
        else:
            print(f"Details of {len(findings_list)} Potential Finding(s):\n")
            for i, f in enumerate(findings_list, 1):
                print(f"[{i}] [{f['rule_id']}] {f['category']} ({f.get('cwe')}) - {f.get('severity_hint')}")
                print(f"    File:   {f['file']}:{f['line']}")
                print(f"    Sink:   {f['sink']} | Source: {f['source']}")
                print(f"    Code:   {f['code']}")
                if "snippet_context" in f:
                    print("    Context:")
                    for line in f["snippet_context"].splitlines():
                        print(f"      {line}")
                print()
        print("=" * 60)


if __name__ == "__main__":
    cli_main()
