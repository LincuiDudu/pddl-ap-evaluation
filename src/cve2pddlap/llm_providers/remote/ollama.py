"""
Ollama provider for locally hosted models via OpenAI-compatible API.
Ollama runs on port 11434 by default.

Ollama does not support seed/top_k via the OpenAI-compatible endpoint.
temperature=0 is used for reproducibility.
"""

from __future__ import annotations

from openai import OpenAI

from cve2pddlap.llm_providers.llm_provider import LLMProvider
from cve2pddlap.utils.config import settings


class OllamaProvider(LLMProvider):
    """
    Provider for any model served via Ollama.
    temperature=0 by default for reproducibility.
    Note: Ollama does not support seed or top_k via OpenAI-compatible API.
    """

    def __init__(
        self,
        model: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        base_url: str | None = None,
    ):
        super().__init__(model, max_tokens, temperature)
        url = base_url or settings.LLM.endpoints.ollama
        self.client = OpenAI(api_key="ollama", base_url=url)

    def _send_impl(self, messages: list[dict[str, str]]) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
        )
        return response.choices[0].message.content


class DeepSeekR1OllamaProvider(OllamaProvider):
    """DeepSeek-R1 7B via local Ollama."""

    def __init__(self, **kwargs):
        super().__init__(model=settings.LLM.models.deepseek_r1_ollama, **kwargs)
