# agent/provider_base.py
from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseLLMProvider(ABC):
    @abstractmethod
    def analyze_vulnerability(self, code_snippet: str, ast_finding: dict, rag_context: str) -> Dict[str, Any]:
        """
        Sends the code, AST finding, and RAG context to the LLM and returns a strictly formatted JSON dictionary.
        """
        pass