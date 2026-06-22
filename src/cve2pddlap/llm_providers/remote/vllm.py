"""
vLLM provider for locally hosted models via OpenAI-compatible API.
Defaults: temperature=0, top_p=1, top_k=-1 (disabled), seed=42.

Start vLLM server before use:
    bash script/start_vllm.sh              # qwen7b (default)
    MODEL=qwen14b bash script/start_vllm.sh
"""

from __future__ import annotations

import logging

from openai import OpenAI

from cve2pddlap.llm_providers.llm_provider import LLMProvider
from cve2pddlap.utils.config import settings

logger = logging.getLogger(__name__)


class VLLMProvider(LLMProvider):
    """
    Provider for any model served locally via vLLM.
    Defaults to greedy decoding (temperature=0, top_p=1, top_k=-1) + seed=42.
    """

    def __init__(
        self,
        model: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        seed: int = 42,
        top_p: float = 1.0,
        top_k: int = -1,        # -1 = disabled in vLLM
        base_url: str | None = None,
    ):
        super().__init__(model, max_tokens, temperature, seed, top_p)
        self.top_k = top_k
        url = base_url or settings.LLM.endpoints.vllm
        self.client = OpenAI(api_key="EMPTY", base_url=url)
        self._serving_model_id: str | None = None  # populated on first call

    def _resolve_serving_model(self) -> str:
        """
        Query vLLM /v1/models to get the exact serving model ID.
        Used for experiment metadata logging.
        """
        if self._serving_model_id is None:
            try:
                models = self.client.models.list()
                ids = [m.id for m in models.data]
                self._serving_model_id = ids[0] if ids else self.model
                if self._serving_model_id != self.model:
                    logger.warning(
                        "Serving model ID '%s' differs from configured '%s'",
                        self._serving_model_id, self.model,
                    )
            except Exception:
                self._serving_model_id = self.model
        return self._serving_model_id

    def get_metadata(self) -> dict:
        """Return reproducibility metadata for logging with experiment results."""
        return {
            "provider": self.__class__.__name__,
            "configured_model": self.model,
            "serving_model": self._resolve_serving_model(),
            "temperature": self.temperature,
            "top_p": self.top_p,
            "top_k": self.top_k,
            "seed": self.seed,
            "max_tokens": self.max_tokens,
        }

    def _send_impl(self, messages: list[dict[str, str]]) -> str:
        self._resolve_serving_model()
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            top_p=self.top_p,
            seed=self.seed,
            extra_body={"top_k": self.top_k},
        )
        return response.choices[0].message.content

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"model={self.model!r}, "
            f"temperature={self.temperature}, "
            f"top_p={self.top_p}, "
            f"top_k={self.top_k}, "
            f"seed={self.seed})"
        )


class Qwen3BProvider(VLLMProvider):
    """Qwen2.5-3B-Instruct via local vLLM."""
    def __init__(self, **kwargs):
        super().__init__(model=settings.LLM.models.qwen3b, **kwargs)


class Qwen7BProvider(VLLMProvider):
    """Qwen2.5-7B-Instruct via local vLLM."""
    def __init__(self, **kwargs):
        super().__init__(model=settings.LLM.models.qwen7b, **kwargs)


class Qwen14BProvider(VLLMProvider):
    """Qwen2.5-14B-Instruct via local vLLM."""
    def __init__(self, **kwargs):
        super().__init__(model=settings.LLM.models.qwen14b, **kwargs)


class Qwen7BCoderProvider(VLLMProvider):
    """Qwen2.5-Coder-7B-Instruct via local vLLM."""
    def __init__(self, **kwargs):
        super().__init__(model=settings.LLM.models.qwen7b_coder, **kwargs)
