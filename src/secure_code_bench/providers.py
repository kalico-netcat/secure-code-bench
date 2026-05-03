from __future__ import annotations

import os
from typing import Optional, Protocol

import httpx

from secure_code_bench.models import ModelResponse, RunOptions

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


class ProviderError(RuntimeError):
    """Raised when model generation fails."""


class ChatProvider(Protocol):
    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        """Generate a response for a single prompt."""


class OpenRouterProvider:
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
        self.base_url = (base_url or os.environ.get("OPENROUTER_BASE_URL") or OPENROUTER_BASE_URL).rstrip(
            "/"
        )
        self.client = client or httpx.Client(timeout=60)

    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        if not self.api_key:
            raise ProviderError("OPENROUTER_API_KEY is required to call OpenRouter models.")

        payload: dict[str, object] = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": options.temperature,
        }
        if options.max_tokens is not None:
            payload["max_tokens"] = options.max_tokens

        try:
            response = self.client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ProviderError(f"Model request failed for {model}: {exc}") from exc

        data = response.json()
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError(f"Unexpected model response shape for {model}: {data}") from exc

        return ModelResponse(text=text, raw=data)
