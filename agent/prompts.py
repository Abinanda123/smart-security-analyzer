# agent/prompts.py
import json
from agent.schemas import VERDICT_SCHEMA

def build_security_prompt(code_snippet: str, ast_finding: dict, rag_context: str) -> str:
    return f"""You are an expert static application security testing (SAST) analyzer.
Your task is to determine if a potential vulnerability detected by an AST parser is a TRUE_POSITIVE (a real, exploitable threat) or a FALSE_POSITIVE (safe code, false alarm, or test data).

CRITICAL RULES FOR FALSE POSITIVES:
- If the code snippet is clearly marked as being for local testing, unit tests, or uses explicitly named dummy/mock variables, you MUST flag it as a FALSE_POSITIVE.
- If the vulnerability cannot actually be exploited in a real production environment based on the provided context, it is a FALSE_POSITIVE.

Here is the data:
1. AST Finding: {json.dumps(ast_finding)}

2. Code Snippet:
{code_snippet}

3. Security Guidance (RAG Context):
{rag_context}

Analyze the code snippet using the security guidance and the critical rules above. Return your final analysis strictly as a JSON object matching this exact schema:
{json.dumps(VERDICT_SCHEMA, indent=2)}"""