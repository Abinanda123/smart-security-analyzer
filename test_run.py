import json
from agent.analyzer import SecurityAgent

# 1. Mock finding simulating the AST parser
mock_finding = {
    "file": "app.py",
    "line": 42,
    "rule_id": "PY001",
    "category": "Command Injection",
    "code": "os.system(user_input)"
}

# 2. Mock security rule simulating the RAG database
mock_rag_context = """
CWE-78: Improper Neutralization of Special Elements used in an OS Command.
Using os.system() with untrusted user input allows attackers to execute arbitrary shell commands.
Prevention: Use the subprocess module with shell=False instead.
"""

print("Initializing AI Judge...")
agent = SecurityAgent()

print("Analyzing vulnerability with Groq Llama 3.3...")
result = agent.run_analysis(finding=mock_finding, rag_results=mock_rag_context)

print("\n--- FINAL AI VERDICT ---")
print(json.dumps(result, indent=2))