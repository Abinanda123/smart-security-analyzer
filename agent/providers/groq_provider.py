# agent/providers/groq_provider.py
import os
import json
from groq import Groq
from agent.provider_base import BaseLLMProvider
from agent.prompts import build_security_prompt

class GroqProvider(BaseLLMProvider):
    def __init__(self):
        # Automatically loads the key from your .env file
        self.client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        self.model = "openai/gpt-oss-20b"

    def analyze_vulnerability(self, code_snippet: str, ast_finding: dict, rag_context: str) -> dict:
        prompt = build_security_prompt(code_snippet, ast_finding, rag_context)
        
        response = self.client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are a precise SAST API. You only output valid JSON."},
                {"role": "user", "content": prompt}
            ],
            model=self.model,
            response_format={"type": "json_object"},
            temperature=0.1 # Low temperature keeps the AI analytical and consistent
        )
        
        raw_json = response.choices[0].message.content
        return json.loads(raw_json)