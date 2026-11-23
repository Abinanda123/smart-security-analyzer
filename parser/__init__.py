"""Parser package for AST static application security analysis.

Stage 1 of the Smart Security Analyzer pipeline.
Extracts candidate vulnerability hotspots and produces structured findings
for Stage 2 (RAG) and Stage 3 (Agent) verification.
"""

from parser.models import Finding, Rule
from parser.rules import RULES
from parser.ast_parser import parse_file, parse_code
from parser.scanner import scan_project, find_python_files

__all__ = [
    "Finding",
    "Rule",
    "RULES",
    "parse_file",
    "parse_code",
    "scan_project",
    "find_python_files",
]
