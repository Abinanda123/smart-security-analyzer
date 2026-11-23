# agent/analyzer.py
from dotenv import load_dotenv
from agent.factory import LLMFactory

# Load environment variables (like GROQ_API_KEY) when the analyzer starts
load_dotenv()

class SecurityAgent:
    def __init__(self):
        # Dynamically load Groq via the factory
        self.llm = LLMFactory.get_provider()

    def run_analysis(self, finding: dict, rag_results: str) -> dict:
        """
        The main entry point for the rest of the application.
        """
        # Extract the code snippet from the AST finding, defaulting to empty string if missing
        code_snippet = finding.get("code", "")
        
        return self.llm.analyze_vulnerability(
            code_snippet=code_snippet,
            ast_finding=finding,
            rag_context=rag_results
        )