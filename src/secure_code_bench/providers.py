from __future__ import annotations

import os
from typing import Optional, Protocol

import httpx

from secure_code_bench.models import ModelResponse, RunOptions

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENAI_BASE_URL = "https://api.openai.com/v1"
ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1"
ANTHROPIC_VERSION = "2023-06-01"
ANTHROPIC_DEFAULT_MAX_TOKENS = 4096


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
        timeout: float = 60,
    ) -> None:
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
        self.base_url = (
            base_url or os.environ.get("OPENROUTER_BASE_URL") or OPENROUTER_BASE_URL
        ).rstrip("/")
        self.client = client or httpx.Client(timeout=timeout)

    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        if not self.api_key:
            raise ProviderError("OPENROUTER_API_KEY is required to call OpenRouter models.")

        request_model = normalize_openrouter_model_id(model)
        payload: dict[str, object] = {
            "model": request_model,
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


class OpenAIProvider:
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = 60,
    ) -> None:
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL") or OPENAI_BASE_URL).rstrip(
            "/"
        )
        self.client = client or httpx.Client(timeout=timeout)

    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        if not self.api_key:
            raise MissingProviderKey(
                "OPENAI_API_KEY is required to call first-party OpenAI models."
            )

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


class AnthropicProvider:
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        api_version: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = 60,
    ) -> None:
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.base_url = (
            base_url or os.environ.get("ANTHROPIC_BASE_URL") or ANTHROPIC_BASE_URL
        ).rstrip("/")
        self.api_version = (
            api_version or os.environ.get("ANTHROPIC_VERSION") or ANTHROPIC_VERSION
        )
        self.client = client or httpx.Client(timeout=timeout)

    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        if not self.api_key:
            raise MissingProviderKey(
                "ANTHROPIC_API_KEY is required to call first-party Anthropic models."
            )

        payload: dict[str, object] = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": options.temperature,
            "max_tokens": options.max_tokens or ANTHROPIC_DEFAULT_MAX_TOKENS,
        }

        try:
            response = self.client.post(
                f"{self.base_url}/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": self.api_version,
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ProviderError(f"Model request failed for {model}: {exc}") from exc

        data = response.json()
        try:
            text = "".join(
                part["text"] for part in data["content"] if part.get("type") == "text"
            )
        except (KeyError, TypeError) as exc:
            raise ProviderError(f"Unexpected model response shape for {model}: {data}") from exc
        if not text:
            raise ProviderError(f"Unexpected model response shape for {model}: {data}")

        return ModelResponse(text=text, raw=data)


class MissingProviderKey(ProviderError):
    """Raised when a first-party provider cannot run because its API key is absent."""


class RoutingProvider:
    def __init__(
        self,
        openrouter: Optional[ChatProvider] = None,
        openai: Optional[ChatProvider] = None,
        anthropic: Optional[ChatProvider] = None,
        timeout: float = 60,
    ) -> None:
        self.openrouter = openrouter or OpenRouterProvider(timeout=timeout)
        self.openai = openai or OpenAIProvider(timeout=timeout)
        self.anthropic = anthropic or AnthropicProvider(timeout=timeout)

    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        if model.startswith("openai:"):
            first_party_model = model.removeprefix("openai:")
            try:
                return self.openai.generate(first_party_model, prompt, options)
            except MissingProviderKey:
                return self.openrouter.generate(f"openai/{first_party_model}", prompt, options)
        if model.startswith("anthropic:"):
            first_party_model = model.removeprefix("anthropic:")
            try:
                return self.anthropic.generate(first_party_model, prompt, options)
            except MissingProviderKey:
                return self.openrouter.generate(f"anthropic/{first_party_model}", prompt, options)
        return self.openrouter.generate(model, prompt, options)


def normalize_openrouter_model_id(model: str) -> str:
    if model.startswith("~") or not model.endswith("-latest"):
        return model
    return f"~{model}"
