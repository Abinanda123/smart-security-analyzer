"""CLI interface for AST static analysis parser and scanner.

Allows running scans and inspecting rules directly without colliding
with any top-level pipeline runner scripts.
"""

import argparse
import json
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from parser.rules import RULES
from parser.scanner import scan_project


def print_rules_catalog():
    """Display all registered AST detection rules."""
    print("\n" + "=" * 70)
    print("[RULES] SMART SECURITY ANALYZER - REGISTERED AST RULES CATALOG")
    print("=" * 70)
    print(f"{'ID':<8} {'Category':<24} {'CWE':<10} {'Severity':<10} {'Rule Name'}")
    print("-" * 70)
    for rule_id, rule in sorted(RULES.items()):
        print(f"{rule.rule_id:<8} {rule.category:<24} {rule.cwe:<10} {rule.severity_hint:<10} {rule.name}")
        print(f"         ↳ Description: {rule.description}")
    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        prog="python -m parser",
        description="🛡️ Smart Security Analyzer — Stage 1: AST Static Vulnerability Scanner",
        epilog="Extracts candidate findings and prepares structured JSON for RAG & Agent verification.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Scan a Python file or project directory")
    scan_parser.add_argument("path", help="File or folder path to scan")
    scan_parser.add_argument("--json", action="store_true", help="Print findings strictly in JSON format")
    scan_parser.add_argument("--output", "-o", type=str, default=None, help="Save findings directly to a JSON file")
    scan_parser.add_argument("--full-report", action="store_true", help="Save full scan metadata report instead of list of findings")

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

        findings = report["findings"]

        # Output payload: default to list of findings for direct compatibility with agent
        output_payload = report if args.full_report else findings

        if args.json or args.output:
            json_str = json.dumps(output_payload, indent=2)
            if args.output:
                Path(args.output).write_text(json_str, encoding="utf-8")
                print(f"[*] Findings written to '{args.output}' ({len(findings)} items ready for RAG/Agent)")
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

            if not findings:
                print("[OK] No suspicious security patterns identified.")
            else:
                print(f"Detected {len(findings)} Potential Security Hotspot(s):\n")
                for i, f in enumerate(findings, 1):
                    print(f"[{i}] [{f.get('id', 'VULN')}] [{f['rule_id']}] {f['category']} ({f.get('cwe')}) - Severity: {f.get('severity_hint')}")
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
