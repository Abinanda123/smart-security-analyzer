"""Data models for AST parser rules and findings.
Follows the team's standard JSON schema agreed upon in Section 2.4,
and directly compatible with downstream agent and RAG consumers.
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class Finding:
    """Represents a potential security finding discovered by AST static analysis.

    Matches schema expected by downstream RAG & LLM modules:
    {
      "id": "VULN-001",
      "file": "app.py",
      "line": 42,
      "rule_id": "PY001",
      "category": "Command Injection",
      "code": "os.system(user_input)",
      "source": "user_input",
      "sink": "os.system",
      "cwe": "CWE-78",
      "context": "CWE-78: Command Injection detected at os.system"
    }
    """
    file: str
    line: int
    rule_id: str
    category: str
    code: str
    source: str
    sink: str
    cwe: Optional[str] = None
    severity_hint: Optional[str] = "MEDIUM"
    snippet_context: Optional[str] = None
    finding_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to standard dictionary format for JSON export."""
        data = {
            "id": self.finding_id or "VULN-UNKNOWN",
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
            "category": self.category,
            "code": self.code,
            "source": self.source,
            "sink": self.sink,
            "cwe": self.cwe,
            "severity_hint": self.severity_hint,
            # 'context' provides immediate context for agent/analyzer.py
            "context": f"{self.cwe}: {self.category} detected at {self.sink}." if self.cwe else self.category,
        }
        if self.snippet_context:
            data["snippet_context"] = self.snippet_context
        return data


@dataclass
class Rule:
    """Rule definition for AST inspection."""
    rule_id: str
    name: str
    category: str
    cwe: str
    severity_hint: str
    description: str
