"""
Ollama provider for locally hosted models via OpenAI-compatible API.
Ollama runs on port 11434 by default.
Supports: temperature, top_p, seed.
"""

from __future__ import annotations

from openai import OpenAI

from cve2pddlap.llm_providers.llm_provider import LLMProvider
from cve2pddlap.utils.config import settings


class OllamaProvider(LLMProvider):
    """
    Provider for any model served via Ollama.
    temperature=0 by default for reproducibility.
    """

    def __init__(
        self,
        model: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        seed: int = 42,
        top_p: float = 1.0,
        base_url: str | None = None,
    ):
        super().__init__(model, max_tokens, temperature, seed, top_p)
        url = base_url or settings.LLM.endpoints.ollama
        self.client = OpenAI(api_key="ollama", base_url=url)

    def _send_impl(self, messages: list[dict[str, str]]) -> str:
        kwargs = dict(
            model=self.model,
            messages=messages,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
        )
        if self.seed is not None:
            kwargs["seed"] = self.seed
        if self.top_p is not None:
            kwargs["top_p"] = self.top_p
        response = self.client.chat.completions.create(**kwargs)
        return response.choices[0].message.content


class DeepSeekR1OllamaProvider(OllamaProvider):
    """DeepSeek-R1 7B via local Ollama."""

    def __init__(self, **kwargs):
        super().__init__(model=settings.LLM.models.deepseek_r1_ollama, **kwargs)
