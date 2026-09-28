"""Data models for AST parser rules and findings.
Follows the team's standard JSON schema agreed upon in Section 2.4.
"""

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any


@dataclass
class Finding:
    """Represents a potential security finding discovered by the AST static analysis.

    Matches the exact schema required by downstream RAG & LLM modules:
    {
      "file": "app.py",
      "line": 42,
      "rule_id": "PY001",
      "category": "Command Injection",
      "code": "os.system(user_input)",
      "source": "user_input",
      "sink": "os.system"
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
    snippet_context: Optional[str] = None  # Surrounding lines for LLM context

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to standard dictionary format for JSON export."""
        data = {
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
            "category": self.category,
            "code": self.code,
            "source": self.source,
            "sink": self.sink,
            "cwe": self.cwe,
            "severity_hint": self.severity_hint,
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
