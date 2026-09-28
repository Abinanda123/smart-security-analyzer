# 🛡️ Smart Security Analyzer — AST Static Analysis Module

> **Component:** AST Parser & Project Scanner  
> **Owner:** Person 1 (Sushanth Watham — Python + AST)  
> **Target Python Version:** Python 3.9+  
> **Dependencies:** Pure Python Standard Library (`ast`, `pathlib`, `dataclasses`, `json`, `argparse`)

---

## 📌 Overview

This module is **Step 1** of the Smart Security Analyzer pipeline.  
As established in **Section 2.3** of the Master Plan:
> *"The AST parser doesn't decide vulnerability truth. It only produces: **Potential security findings**."*

The parser traverses Python Abstract Syntax Trees (ASTs), extracts potential security hotspots with surrounding context, and produces structured findings conforming to the team's shared JSON schema (Section 2.4). These findings are then consumed by:
1. **RAG Knowledge Retriever** (Abinanda) — queries Pinecone with the finding's `category`, `cwe`, and code.
2. **LLM Verification Agent** (Anuranjan) — evaluates the AST finding + code context + retrieved RAG guidance to render a `TRUE_POSITIVE` or `FALSE_POSITIVE` verdict.

---

## 🚀 Terminal Usage (For Teammates)

### 1. View Registered AST Rules Catalog
To inspect supported vulnerability rules, severity hints, and corresponding CWE identifiers:
```bash
python main.py rules
```

### 2. Scan a Single Python File (Human-Readable)
```bash
python main.py scan tests/test_samples/vulnerable_sample.py
```

### 3. Scan an Entire Project Directory (Human-Readable)
Scans all `.py` files recursively while automatically ignoring `.git`, `venv`, `node_modules`, and cache folders:
```bash
python main.py scan ./my_target_project
```

### 4. Export Findings as Standard JSON (For RAG / LLM Integration)
Print raw JSON to stdout:
```bash
python main.py scan tests/test_samples/vulnerable_sample.py --json
```

Or save findings directly to a file:
```bash
python main.py scan ./my_target_project --out findings.json
```

### 5. Running via Python Module Names directly
You can also invoke the submodules directly:
```bash
# Direct AST parser on a file
python -m parser.ast_parser tests/test_samples/vulnerable_sample.py

# Direct Project scanner on a folder
python -m scanner.project_scanner ./tests --json
```

---

## 🐍 Python Import API (Programmatic Usage)

Teammates working on the RAG or LLM modules can import the parser directly in their code:

```python
from parser import parse_file, parse_code
from scanner import scan_project

# 1. Parse a single file
findings = parse_file("app.py")
for finding in findings:
    print(f"Detected {finding.category} at line {finding.line}")
    print(f"Code: {finding.code}")
    print(f"Sink: {finding.sink} | Source: {finding.source}")
    print(f"CWE:  {finding.cwe}")
    
    # Export as standard dict matching Section 2.4 JSON schema:
    finding_dict = finding.to_dict()

# 2. Or scan an entire project directory
report = scan_project("./my_repository")
print(f"Total findings: {report['total_findings']}")
for finding_dict in report["findings"]:
    # Pass finding_dict directly to RAG retriever / LLM prompt
    ...
```

---

## 📋 Data Contract (Standard Finding Schema)

Every finding emitted by this module matches the team's Section 2.4 schema:

```json
{
  "file": "app.py",
  "line": 42,
  "rule_id": "PY003",
  "category": "Command Injection",
  "code": "os.system(user_input)",
  "source": "user_input",
  "sink": "os.system",
  "cwe": "CWE-78",
  "severity_hint": "HIGH",
  "snippet_context": "  40 | def run_tool(user_input):\n  41 |     # execution\n->42 |     os.system(user_input)"
}
```

---

## 🛡️ Implemented Rules (MVP & V1)

| Rule ID | Category | CWE | Severity | Detected Pattern |
|---------|----------|-----|----------|-------------------|
| **PY001** | Code Injection | CWE-94 | HIGH | `eval(...)` |
| **PY002** | Code Injection | CWE-95 | HIGH | `exec(...)` |
| **PY003** | Command Injection | CWE-78 | HIGH | `os.system(...)` |
| **PY004** | Command Injection | CWE-78 | HIGH | `os.popen(...)` |
| **PY005** | Command Injection | CWE-78 | HIGH | `subprocess.*(..., shell=True)` |
| **PY006** | SQL Injection | CWE-89 | HIGH | `execute(...)` with f-string or string formatting (`%`, `+`, `.format`) |
| **PY007** | Unsafe Deserialization | CWE-502 | HIGH | `pickle.loads(...)` / `pickle.load(...)` |
| **PY008** | Weak Cryptography | CWE-328 | MEDIUM | `hashlib.md5(...)`, `hashlib.sha1(...)` |
| **PY009** | Hardcoded Secrets | CWE-798 | MEDIUM | Hardcoded API keys/passwords assigned to credentials variables |

---

## 🧪 Running the Tests

To verify that all AST rules detect vulnerable code and ignore safe code:

```bash
python -m unittest tests/test_rules.py
```
*(All 10 tests should pass cleanly in ~0.005s)*
