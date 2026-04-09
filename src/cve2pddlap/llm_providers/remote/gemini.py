from __future__ import annotations

from google import genai
from google.genai import types

from cve2pddlap.llm_providers.llm_provider import LLMProvider
from cve2pddlap.utils.config import get_api_key


class GeminiProvider(LLMProvider):

    def __init__(self, model: str = "gemini-2.0-flash", max_tokens: int = 4096):
        super().__init__(model, max_tokens)
        self.client = genai.Client(api_key=get_api_key("gemini"))

    def _send_impl(self, messages: list[dict[str, str]]) -> str:
        # Gemini: system instruction separate, rest as Content objects
        system_prompt = ""
        contents = []
        for msg in messages:
            if msg["role"] == "system":
                system_prompt = msg["content"]
            else:
                # Gemini uses "user" and "model" (not "assistant")
                role = "model" if msg["role"] == "assistant" else "user"
                contents.append(types.Content(
                    role=role,
                    parts=[types.Part(text=msg["content"])],
                ))

        response = self.client.models.generate_content(
            model=self.model,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                max_output_tokens=self.max_tokens,
            ),
            contents=contents,
        )
        return response.text
