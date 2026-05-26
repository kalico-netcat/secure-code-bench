from typing import Optional

import httpx
import pytest

from secure_code_bench.models import ModelResponse, RunOptions
from secure_code_bench.providers import (
    ANTHROPIC_DEFAULT_MAX_TOKENS,
    ANTHROPIC_VERSION,
    AnthropicProvider,
    MissingProviderKey,
    OpenAIProvider,
    OpenRouterProvider,
    ProviderError,
    RoutingProvider,
    normalize_openrouter_model_id,
)


class RecordingProvider:
    def __init__(self, response_text: str = "ok", error: Optional[Exception] = None) -> None:
        self.calls: list[tuple[str, str, RunOptions]] = []
        self.response_text = response_text
        self.error = error

    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        self.calls.append((model, prompt, options))
        if self.error is not None:
            raise self.error
        return ModelResponse(text=self.response_text)


def test_normalize_openrouter_model_id_adds_router_prefix_for_latest_aliases() -> None:
    assert normalize_openrouter_model_id("anthropic/claude-sonnet-latest") == (
        "~anthropic/claude-sonnet-latest"
    )
    assert normalize_openrouter_model_id("~anthropic/claude-sonnet-latest") == (
        "~anthropic/claude-sonnet-latest"
    )
    assert normalize_openrouter_model_id("anthropic/claude-sonnet-4.5") == (
        "anthropic/claude-sonnet-4.5"
    )


def test_openrouter_provider_sends_normalized_latest_alias() -> None:
    seen_payloads = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_payloads.append(request.read().decode("utf-8"))
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}}]},
        )

    provider = OpenRouterProvider(
        api_key="test-key",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    provider.generate(
        "anthropic/claude-sonnet-latest",
        "prompt",
        RunOptions(),
    )

    assert '"model":"~anthropic/claude-sonnet-latest"' in seen_payloads[0]


def test_openrouter_provider_accepts_custom_timeout() -> None:
    provider = OpenRouterProvider(api_key="test-key", timeout=300)

    assert provider.client.timeout.connect == 300


def test_openai_provider_sends_chat_completion_payload() -> None:
    seen_requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "openai ok"}}]})

    provider = OpenAIProvider(
        api_key="openai-key",
        base_url="https://openai.test/v1",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    response = provider.generate("gpt-test", "prompt", RunOptions(temperature=0.2, max_tokens=123))

    assert response.text == "openai ok"
    request = seen_requests[0]
    assert str(request.url) == "https://openai.test/v1/chat/completions"
    assert request.headers["Authorization"] == "Bearer openai-key"
    payload = request.read().decode("utf-8")
    assert '"model":"gpt-test"' in payload
    assert '"content":"prompt"' in payload
    assert '"temperature":0.2' in payload
    assert '"max_tokens":123' in payload


def test_openai_provider_requires_api_key(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = OpenAIProvider(
        api_key="",
        client=httpx.Client(transport=httpx.MockTransport(lambda _: None)),
    )

    with pytest.raises(MissingProviderKey):
        provider.generate("gpt-test", "prompt", RunOptions())


def test_anthropic_provider_sends_messages_payload_with_default_max_tokens() -> None:
    seen_requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_requests.append(request)
        return httpx.Response(
            200,
            json={
                "content": [
                    {"type": "text", "text": "anthropic "},
                    {"type": "text", "text": "ok"},
                ]
            },
        )

    provider = AnthropicProvider(
        api_key="anthropic-key",
        base_url="https://anthropic.test/v1",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    response = provider.generate("claude-test", "prompt", RunOptions(temperature=0.3))

    assert response.text == "anthropic ok"
    request = seen_requests[0]
    assert str(request.url) == "https://anthropic.test/v1/messages"
    assert request.headers["x-api-key"] == "anthropic-key"
    assert request.headers["anthropic-version"] == ANTHROPIC_VERSION
    payload = request.read().decode("utf-8")
    assert '"model":"claude-test"' in payload
    assert '"content":"prompt"' in payload
    assert '"temperature":0.3' in payload
    assert f'"max_tokens":{ANTHROPIC_DEFAULT_MAX_TOKENS}' in payload


def test_anthropic_provider_uses_configured_max_tokens() -> None:
    seen_payloads = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_payloads.append(request.read().decode("utf-8"))
        return httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})

    provider = AnthropicProvider(
        api_key="anthropic-key",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    provider.generate("claude-test", "prompt", RunOptions(max_tokens=99))

    assert '"max_tokens":99' in seen_payloads[0]


def test_anthropic_provider_requires_api_key(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = AnthropicProvider(
        api_key="",
        client=httpx.Client(transport=httpx.MockTransport(lambda _: None)),
    )

    with pytest.raises(MissingProviderKey):
        provider.generate("claude-test", "prompt", RunOptions())


def test_routing_provider_sends_openai_prefix_to_first_party() -> None:
    openai = RecordingProvider(response_text="first-party")
    openrouter = RecordingProvider(response_text="router")
    provider = RoutingProvider(openai=openai, openrouter=openrouter)

    response = provider.generate("openai:gpt-test", "prompt", RunOptions())

    assert response.text == "first-party"
    assert openai.calls[0][0] == "gpt-test"
    assert openrouter.calls == []


def test_routing_provider_falls_back_to_openrouter_when_openai_key_missing() -> None:
    openai = RecordingProvider(error=MissingProviderKey("missing"))
    openrouter = RecordingProvider(response_text="router")
    provider = RoutingProvider(openai=openai, openrouter=openrouter)

    response = provider.generate("openai:gpt-test", "prompt", RunOptions())

    assert response.text == "router"
    assert openrouter.calls[0][0] == "openai/gpt-test"


def test_routing_provider_sends_anthropic_prefix_to_first_party() -> None:
    anthropic = RecordingProvider(response_text="first-party")
    openrouter = RecordingProvider(response_text="router")
    provider = RoutingProvider(anthropic=anthropic, openrouter=openrouter)

    response = provider.generate("anthropic:claude-test", "prompt", RunOptions())

    assert response.text == "first-party"
    assert anthropic.calls[0][0] == "claude-test"
    assert openrouter.calls == []


def test_routing_provider_falls_back_to_openrouter_when_anthropic_key_missing() -> None:
    anthropic = RecordingProvider(error=MissingProviderKey("missing"))
    openrouter = RecordingProvider(response_text="router")
    provider = RoutingProvider(anthropic=anthropic, openrouter=openrouter)

    response = provider.generate("anthropic:claude-test", "prompt", RunOptions())

    assert response.text == "router"
    assert openrouter.calls[0][0] == "anthropic/claude-test"


def test_routing_provider_keeps_slash_models_on_openrouter() -> None:
    openrouter = RecordingProvider(response_text="router")
    openai = RecordingProvider(response_text="first-party")
    provider = RoutingProvider(openai=openai, openrouter=openrouter)

    response = provider.generate("openai/gpt-test", "prompt", RunOptions())

    assert response.text == "router"
    assert openrouter.calls[0][0] == "openai/gpt-test"
    assert openai.calls == []


def test_routing_provider_does_not_fallback_after_first_party_error() -> None:
    openai = RecordingProvider(error=ProviderError("first-party failed"))
    openrouter = RecordingProvider(response_text="router")
    provider = RoutingProvider(openai=openai, openrouter=openrouter)

    with pytest.raises(ProviderError, match="first-party failed"):
        provider.generate("openai:gpt-test", "prompt", RunOptions())

    assert openrouter.calls == []
