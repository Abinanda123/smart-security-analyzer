# agent/schemas.py

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["TRUE_POSITIVE", "FALSE_POSITIVE"]},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
        "vulnerability": {"type": "string"},
        "cwe": {"type": "string"},
        "explanation": {"type": "string"},
        "recommendation": {"type": "string"}
    },
    "required": ["verdict", "confidence", "severity", "vulnerability", "cwe", "explanation", "recommendation"]
}