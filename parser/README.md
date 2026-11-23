# 🛡️ Stage 1: AST Parser & Scanner Module

> **Component:** AST Static Vulnerability Parser (`parser/`)  
> **Author:** Sushanth Watham (Person 1 — Static Analysis & Parser Architecture)  
> **Role in Pipeline:** Deterministic candidate vulnerability extraction (feeds Stage 2 RAG & Stage 3 Agent)

---

## 📌 Overview

This package performs deterministic static analysis on Python source code using Python's native `ast` module.
It scans source trees, identifies dangerous sinks and sources, resolves local assignment data-flow, and slices code snippets with context.

### 🧩 Output Contract

Every finding emitted by `parser` adheres to the team's standard schema, directly consumable by `agent` and `rag`:

```json
{
  "id": "VULN-001",
  "file": "app.py",
  "line": 42,
  "rule_id": "PY003",
  "category": "Command Injection",
  "code": "os.system(user_input)",
  "source": "user_input",
  "sink": "os.system",
  "cwe": "CWE-78",
  "context": "CWE-78: Command Injection detected at os.system.",
  "snippet_context": "  40 | def run_cmd(user_input):\n->42 |     os.system(user_input)"
}
```

---

## 🚀 Terminal Usage

### 1. View Registered Rule Catalog
```bash
python -m parser rules
```

### 2. Scan a File or Folder (Visual Terminal Report)
```bash
python -m parser scan parser/tests/test_samples/vulnerable_sample.py
```

### 3. Generate Findings for the AI Judge (`scanner_results.json`)
```bash
python -m parser scan ./my_target_project --output scanner_results.json
```
This generates the exact `scanner_results.json` that Anuranjan's `main.py` processes:
```bash
python main.py --input scanner_results.json --output ai_report.json
```

---

## 🐍 Python Import API

```python
from parser import parse_file, parse_code, scan_project

# Parse a single file
findings = parse_file("app.py")
for f in findings:
    print(f.category, f.line, f.code)

# Or scan an entire project directory
report = scan_project("./repo")
findings_list = report["findings"]
```

---

## 🧪 Running Tests

```bash
python -m unittest discover parser/tests
```
