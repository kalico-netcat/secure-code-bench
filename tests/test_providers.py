import httpx

from secure_code_bench.models import RunOptions
from secure_code_bench.providers import OpenRouterProvider, normalize_openrouter_model_id


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
