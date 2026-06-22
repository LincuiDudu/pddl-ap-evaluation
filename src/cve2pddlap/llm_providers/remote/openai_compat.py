"""
OpenAI-compatible providers: DeepSeek, Qwen, Zhipu, GPT-4.
All use the OpenAI SDK with different base_url / api_key / model.
All support: temperature, seed, top_p.
"""

from __future__ import annotations

from openai import OpenAI

from cve2pddlap.llm_providers.llm_provider import LLMProvider
from cve2pddlap.utils.config import get_api_key, settings


class OpenAICompatProvider(LLMProvider):
    """Base for any provider using OpenAI-compatible chat API."""

    def __init__(self, provider_name: str, model: str, max_tokens: int = 4096,
                 base_url: str | None = None,
                 temperature: float | None = None,
                 seed: int | None = None,
                 top_p: float | None = None):
        super().__init__(model, max_tokens, temperature, seed, top_p)
        api_key = get_api_key(provider_name)
        self.client = OpenAI(api_key=api_key, base_url=base_url)

    def _send_impl(self, messages: list[dict[str, str]]) -> str:
        kwargs = dict(model=self.model, messages=messages, max_tokens=self.max_tokens)
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        if self.seed is not None:
            kwargs["seed"] = self.seed
        if self.top_p is not None:
            kwargs["top_p"] = self.top_p
        response = self.client.chat.completions.create(**kwargs)
        return response.choices[0].message.content


class DeepSeekProvider(OpenAICompatProvider):
    def __init__(self, model: str = "deepseek-chat", max_tokens: int = 4096,
                 temperature: float | None = None, seed: int | None = None,
                 top_p: float | None = None):
        super().__init__("deepseek", model, max_tokens,
                         base_url=settings.LLM.endpoints.deepseek,
                         temperature=temperature, seed=seed, top_p=top_p)


class QwenProvider(OpenAICompatProvider):
    def __init__(self, model: str = "qwen-plus", max_tokens: int = 4096,
                 temperature: float | None = None, seed: int | None = None,
                 top_p: float | None = None):
        super().__init__("qwen", model, max_tokens,
                         base_url=settings.LLM.endpoints.qwen,
                         temperature=temperature, seed=seed, top_p=top_p)


class ZhipuProvider(OpenAICompatProvider):
    def __init__(self, model: str = "glm-4-flash", max_tokens: int = 4096,
                 temperature: float | None = None, seed: int | None = None,
                 top_p: float | None = None):
        super().__init__("zhipu", model, max_tokens,
                         base_url=settings.LLM.endpoints.zhipu,
                         temperature=temperature, seed=seed, top_p=top_p)


class GPT4Provider(OpenAICompatProvider):
    def __init__(self, model: str = "gpt-4o", max_tokens: int = 4096,
                 temperature: float | None = None, seed: int | None = None,
                 top_p: float | None = None):
        super().__init__("gpt4", model, max_tokens,
                         temperature=temperature, seed=seed, top_p=top_p)


class MistralProvider(OpenAICompatProvider):
    """Mistral AI — free tier available (mistral-small, open-mistral-7b)."""
    def __init__(self, model: str = "mistral-small-latest", max_tokens: int = 4096,
                 temperature: float | None = None, seed: int | None = None,
                 top_p: float | None = None):
        super().__init__("mistral", model, max_tokens,
                         base_url=settings.LLM.endpoints.mistral,
                         temperature=temperature, seed=seed, top_p=top_p)


class GroqProvider(OpenAICompatProvider):
    """Groq — completely free, high-speed inference (Llama 3.3, Mixtral)."""
    def __init__(self, model: str = "llama-3.3-70b-versatile", max_tokens: int = 4096,
                 temperature: float | None = None, seed: int | None = None,
                 top_p: float | None = None):
        super().__init__("groq", model, max_tokens,
                         base_url=settings.LLM.endpoints.groq,
                         temperature=temperature, seed=seed, top_p=top_p)
