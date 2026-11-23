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

from parser.models import Finding
from parser.ast_parser import parse_file


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

    # Assign sequential IDs across findings (e.g. VULN-001, VULN-002)
    for idx, f in enumerate(all_findings, 1):
        f.finding_id = f"VULN-{idx:03d}"

    elapsed_time = round(time.time() - start_time, 3)

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
