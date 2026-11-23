# agent/factory.py
import os
from agent.providers.groq_provider import GroqProvider

class LLMFactory:
    @staticmethod
    def get_provider():
        # Check the .env file for the preferred provider, default to groq
        provider_name = os.getenv("LLM_PROVIDER", "groq").lower()
        
        providers = {
            "groq": GroqProvider
            # Future providers can be added here
        }
        
        if provider_name not in providers:
            raise ValueError(f"Unsupported LLM provider: {provider_name}")
            
        return providers[provider_name]()