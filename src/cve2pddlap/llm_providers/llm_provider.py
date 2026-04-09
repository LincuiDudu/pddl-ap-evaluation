"""
Abstract base class for LLM providers.
All providers implement send(messages) -> str, where messages is a list
of {"role": ..., "content": ...} dicts.
"""

from __future__ import annotations

import time
import logging
from abc import ABC, abstractmethod
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

logger = logging.getLogger(__name__)


def _is_retryable(exc: BaseException) -> bool:
    """Retry on rate limit (429) and server errors (5xx)."""
    if hasattr(exc, "status_code"):
        return exc.status_code in (429, 500, 502, 503, 504)
    return False


class LLMProvider(ABC):
    """Base class for all LLM providers."""

    def __init__(self, model: str, max_tokens: int = 4096):
        self.model = model
        self.max_tokens = max_tokens
        self.last_prompt: list[dict] | None = None
        self.last_duration: float | None = None

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=60),
        retry=retry_if_exception(_is_retryable),
        reraise=True,
    )
    def send(self, messages: list[dict[str, str]]) -> str:
        """
        Send messages to the LLM and return the response text.

        Args:
            messages: List of {"role": "system"|"user"|"assistant", "content": "..."}
                      First message should be role=system.

        Returns:
            Generated text from the LLM.
        """
        self.last_prompt = messages
        logger.info("Sending request to %s (%s), %d messages",
                     self.__class__.__name__, self.model, len(messages))

        start = time.time()
        result = self._send_impl(messages)
        self.last_duration = time.time() - start

        logger.info("Response received in %.1fs", self.last_duration)
        return result

    @abstractmethod
    def _send_impl(self, messages: list[dict[str, str]]) -> str:
        """Provider-specific implementation. Subclasses must override."""
        ...

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(model={self.model!r})"
