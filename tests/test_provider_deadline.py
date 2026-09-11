"""Use real SDK clients with an offline transport to check deadline retries."""
import time
from types import SimpleNamespace

import httpx
import pytest

from src.agent import provider as provider_module
from src.agent.provider import LLMProvider


def sdk_response(provider):
    return {
        "id": "chat_offline", "object": "chat.completion", "created": 1, "model": "offline",
        "choices": [{"index": 0, "finish_reason": "stop", "message": {
            "role": "assistant", "content": "Observed evidence.",
        }}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 3, "total_tokens": 13},
    }


def make_provider(provider, transport):
    module = pytest.importorskip("openai")
    client_class = module.OpenAI
    instance = LLMProvider.__new__(LLMProvider)
    instance.provider = provider
    instance.model = "offline"
    instance._retry_limit = 0
    instance.client = client_class(
        api_key="offline-fixture", base_url="https://example.invalid/v1",
        http_client=httpx.Client(transport=transport),
    )
    return instance, module


@pytest.mark.parametrize("provider", ["local", "minimax", "qwen", "glm"])
@pytest.mark.parametrize("bounded", [False, True])
def test_deadline_avoids_hidden_sdk_retries_and_leaves_unbounded_calls_unchanged(provider, bounded):
    requests = []
    def handle(request):
        requests.append(request)
        if len(requests) == 1:
            raise httpx.ReadTimeout("offline timeout", request=request)
        return httpx.Response(200, json=sdk_response(provider))

    instance, sdk = make_provider(provider, httpx.MockTransport(handle))
    try:
        kwargs = dict(system_prompt="Use supplied evidence.", user_message="Summarize.", tools=[], max_turns=1)
        if bounded:
            with pytest.raises(sdk.APITimeoutError):
                instance.chat_with_tools(**kwargs, deadline=time.monotonic() + 10)
            assert len(requests) == 1
            assert 0 < requests[0].extensions["timeout"]["read"] <= 10
        else:
            assert instance.chat_with_tools(**kwargs) == "Observed evidence."
            assert len(requests) == 2
    finally:
        instance.client.close()


@pytest.mark.parametrize("provider", ["local", "minimax", "qwen", "glm"])
def test_expired_deadline_never_sends_a_request(provider):
    requests = []
    instance, _ = make_provider(provider, httpx.MockTransport(lambda request: requests.append(request)))
    try:
        with pytest.raises(TimeoutError, match="deadline exceeded"):
            instance.chat_with_tools("Evidence", "Summarize", [], 1, deadline=time.monotonic() - 1)
        assert not requests
    finally:
        instance.client.close()


@pytest.mark.parametrize("provider", ["local", "minimax", "qwen", "glm"])
def test_application_retry_recomputes_remaining_timeout(provider, monkeypatch):
    clock = {"now": 100.0}
    timeouts = []
    def handle(request):
        timeouts.append(request.extensions["timeout"]["read"])
        if len(timeouts) == 1:
            clock["now"] += 3
            return httpx.Response(503, json={"error": {"type": "overloaded_error", "message": "busy"}})
        return httpx.Response(200, json=sdk_response(provider))
    instance, _ = make_provider(provider, httpx.MockTransport(handle))
    instance._retry_limit = 1
    monkeypatch.setattr(provider_module, "time", SimpleNamespace(
        monotonic=lambda: clock["now"],
        sleep=lambda delay: clock.update(now=clock["now"] + delay),
    ))
    try:
        assert instance.chat_with_tools("Evidence", "Summarize", [], 1, deadline=120) == "Observed evidence."
        assert timeouts == [20, 12]
    finally:
        instance.client.close()
