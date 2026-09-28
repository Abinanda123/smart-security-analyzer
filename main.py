"""Smart Security Analyzer — Top-Level Terminal CLI Entry Point.

Allows Sushanth and team members to scan files or projects, inspect rules,
and export AST findings for RAG retrieval and LLM triage.
"""

import argparse
import json
import sys
from pathlib import Path

# Configure stdout for UTF-8 compatibility on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add project root to sys.path to ensure module imports work reliably
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from parser.rules import RULES
from scanner.project_scanner import scan_project


def print_rules_catalog():
    """Display all registered AST detection rules."""
    print("\n" + "=" * 70)
    print("[RULES] SMART SECURITY ANALYZER - REGISTERED AST RULES CATALOG")
    print("=" * 70)
    print(f"{'ID':<8} {'Category':<22} {'CWE':<10} {'Severity':<10} {'Rule Name'}")
    print("-" * 70)
    for rule_id, rule in sorted(RULES.items()):
        print(f"{rule.rule_id:<8} {rule.category:<22} {rule.cwe:<10} {rule.severity_hint:<10} {rule.name}")
        print(f"         ↳ Description: {rule.description}")
    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="🛡️ Smart Security Analyzer — AST Static Vulnerability Scanner",
        epilog="Designed for team collaboration: pipe output to RAG knowledge retriever & LLM verification.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Scan a Python file or project directory")
    scan_parser.add_argument("path", help="File or folder path to scan")
    scan_parser.add_argument("--json", action="store_true", help="Print findings strictly in JSON format")
    scan_parser.add_argument("--out", type=str, default=None, help="Save findings directly to a JSON file")

    # Command: rules
    subparsers.add_parser("rules", help="Display all supported AST security rules and CWEs")

    args = parser.parse_args()

    if args.command == "rules":
        print_rules_catalog()
    elif args.command == "scan":
        try:
            report = scan_project(args.path)
        except Exception as e:
            print(f"[!] Scan error: {e}", file=sys.stderr)
            sys.exit(1)

        if args.json or args.out:
            json_str = json.dumps(report, indent=2)
            if args.out:
                Path(args.out).write_text(json_str, encoding="utf-8")
                print(f"[*] Report saved to {args.out}")
            else:
                print(json_str)
        else:
            print("\n" + "=" * 70)
            print("[REPORT] SMART SECURITY ANALYZER - AST STATIC ANALYSIS REPORT")
            print("=" * 70)
            print(f"Target Scanned:    {report['target']}")
            print(f"Files Evaluated:   {report['files_scanned']}")
            print(f"Execution Time:    {report['elapsed_seconds']}s")
            print(f"Total Findings:    {report['total_findings']}")
            print("-" * 70)

            if report["summary_by_category"]:
                print("Findings by Category:")
                for cat, count in report["summary_by_category"].items():
                    print(f"  * {cat:<24}: {count}")
                print("-" * 70)

            findings = report["findings"]
            if not findings:
                print("[OK] No suspicious security patterns identified.")
            else:
                print(f"Detected {len(findings)} Potential Security Hotspot(s):\n")
                for i, f in enumerate(findings, 1):
                    print(f"[{i}] [{f['rule_id']}] {f['category']} ({f.get('cwe')}) — Severity: {f.get('severity_hint')}")
                    print(f"    Location: {f['file']}:{f['line']}")
                    print(f"    Sink:     {f['sink']}")
                    print(f"    Source:   {f['source']}")
                    print(f"    Code:     {f['code']}")
                    if "snippet_context" in f:
                        print("    Context:")
                        for line in f["snippet_context"].splitlines():
                            print(f"      {line}")
                    print()
            print("=" * 70)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
