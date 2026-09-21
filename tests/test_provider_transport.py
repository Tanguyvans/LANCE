"""Offline contract checks: network retry is not model continuation."""
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest

from src.agent.core import provider_transport as transport
from src.agent.cost_tracker import CostTracker
from src.agent.provider import LLMProvider, _call_with_retry


@pytest.fixture
def clock(monkeypatch):
    state = {"now": 100.0, "delays": []}

    def sleep(delay):
        state["delays"].append(delay)
        state["now"] += delay

    monkeypatch.setattr(transport, "time", SimpleNamespace(
        monotonic=lambda: state["now"], sleep=sleep,
    ))
    return state


class HTTPError(Exception):
    def __init__(self, status, message="offline", *, response_only=False):
        super().__init__(message)
        if response_only:
            self.response = SimpleNamespace(status_code=status)
        else:
            self.status_code = status


def test_provider_keeps_one_shared_retry_implementation():
    assert _call_with_retry is transport.call_with_retry


def test_sdk_timeout_retries_same_request_once_only(clock):
    from openai import APITimeoutError
    error = APITimeoutError(request=httpx.Request("POST", "https://example.invalid"))
    request = {"messages": [{"role": "user", "content": "unchanged"}]}
    call = MagicMock(side_effect=[error, "ok"])
    assert transport.call_with_retry(call, **request) == "ok"
    assert call.call_count == 2
    assert call.call_args_list[0] == call.call_args_list[1]
    failed = MagicMock(side_effect=error)
    with pytest.raises(APITimeoutError):
        transport.call_with_retry(failed, **request)
    assert failed.call_count == 2


def test_sdk_timeout_does_not_retry_after_deadline(clock):
    from openai import APITimeoutError
    error = APITimeoutError(request=httpx.Request("POST", "https://example.invalid"))
    def expired():
        clock["now"] = 110.0
        raise error
    call = MagicMock(side_effect=expired)
    with pytest.raises(TimeoutError):
        transport.call_with_retry(call, deadline=105.0)
    assert call.call_count == 1


def test_timeout_after_tool_result_preserves_history_and_request_limit(monkeypatch):
    import json
    import time
    import openai
    monkeypatch.setattr(transport.time, "sleep", lambda _: None)
    requests = []
    def respond(request):
        requests.append(request)
        if len(requests) == 2:
            raise httpx.ReadTimeout("offline timeout", request=request)
        message = {"role": "assistant", "content": "finished"}
        reason = "stop"
        if len(requests) == 1:
            message = {"role": "assistant", "content": None, "tool_calls": [{
                "id": "call_probe", "type": "function",
                "function": {"name": "probe", "arguments": "{}"},
            }]}
            reason = "tool_calls"
        return httpx.Response(200, json={"id": "offline", "object": "chat.completion", "created": 0,
            "model": "offline", "choices": [{"index": 0, "finish_reason": reason, "message": message}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})
    provider = LLMProvider.__new__(LLMProvider)
    provider.provider, provider.model = "ollama-umons", "offline"
    provider._retry_limit, provider._request_timeout = 5, 12.0
    provider.client = openai.OpenAI(api_key="offline", base_url="https://offline.invalid/v1",
        http_client=httpx.Client(transport=httpx.MockTransport(respond)))
    probe = MagicMock(return_value="recorded observation")
    try:
        provider.chat_with_tools("system", "question", [{"name": "probe", "description": "probe",
            "input_schema": {"type": "object", "properties": {}}, "function": probe}],
            max_turns=3, deadline=time.monotonic() + 60)
    finally:
        provider.client.close()
    assert probe.call_count == 1
    assert len(requests) == 3
    assert requests[1].content == requests[2].content
    messages = json.loads(requests[2].content)["messages"]
    assert any(m.get("tool_call_id") == "call_probe" for m in messages)
    assert all(r.extensions["timeout"]["read"] <= 12 for r in requests)


@pytest.mark.parametrize("status", [429, 500, 502, 503, 529])
@pytest.mark.parametrize("response_only", [False, True])
def test_transient_status_retries_unchanged_request_and_returns_success(clock, status, response_only):
    error = HTTPError(status, response_only=response_only)
    result = object()
    request = {"messages": [{"role": "user", "content": "same request"}]}
    call = MagicMock(side_effect=[error, result])
    attempts, errors = [], []

    assert transport.call_with_retry(
        call, "argument", payload=request, max_retries=1,
        on_attempt=attempts.append, on_error=errors.append,
    ) is result

    assert call.call_count == 2
    assert all(c.args == ("argument",) and c.kwargs["payload"] is request for c in call.call_args_list)
    assert attempts == [0, 1]
    assert errors == [error]
    assert clock["delays"] == [5.0]


@pytest.mark.parametrize("error", [
    HTTPError(400), HTTPError(401), HTTPError(403), HTTPError(404),
    HTTPError(500, "no user query found in messages"),
    ValueError("bad configuration"),
])
def test_nontransient_error_is_preserved_without_retry(clock, error):
    call = MagicMock(side_effect=error)
    with pytest.raises(type(error)) as caught:
        transport.call_with_retry(call)
    assert caught.value is error
    call.assert_called_once_with()
    assert clock["delays"] == []


def test_response_only_missing_user_query_error_is_not_retried(clock):
    error = HTTPError(500, "ignored exception text", response_only=True)
    error.response.json = lambda: {"error": {"message": "no user query found in messages"}}
    call = MagicMock(side_effect=error)

    with pytest.raises(HTTPError) as caught:
        transport.call_with_retry(call, max_retries=5)

    assert caught.value is error
    call.assert_called_once_with()
    assert clock["delays"] == []


def test_deadline_prevents_first_call(clock):
    call = MagicMock()
    with pytest.raises(TimeoutError, match="deadline exceeded"):
        transport.call_with_retry(call, deadline=100.0)
    call.assert_not_called()
    assert clock["delays"] == []


def test_backoff_must_fit_within_deadline(clock):
    error = ConnectionRefusedError("offline")
    call = MagicMock(side_effect=error)
    with pytest.raises(TimeoutError, match="deadline exceeded") as caught:
        transport.call_with_retry(call, deadline=105.0)
    assert caught.value.__cause__ is error
    call.assert_called_once_with()
    assert clock["delays"] == []


def test_failing_diagnostics_do_not_change_retry_or_leak_messages(clock, caplog):
    secret = "private-observer-content"
    callback = MagicMock(side_effect=RuntimeError(secret))
    request_error = ConnectionRefusedError("private-network-content")
    call = MagicMock(side_effect=[request_error, "recovered"])
    assert transport.call_with_retry(
        call, on_attempt=callback, on_error=callback,
    ) == "recovered"
    assert call.call_count == 2
    assert callback.call_count == 3
    assert clock["delays"] == [5.0]
    assert secret not in caplog.text
    assert "private-network-content" not in caplog.text


@pytest.mark.parametrize("observe", [False, True])
def test_refused_connection_through_real_sdk_stops_after_six_calls(clock, observe):
    """Reproduce S1's failure without accessing UMONS or deploying a scenario."""
    openai = pytest.importorskip("openai")
    requests, events = [], []

    def refuse(request):
        requests.append(request)
        raise httpx.ConnectError("[Errno 111] Connection refused", request=request)

    provider = LLMProvider.__new__(LLMProvider)
    provider.provider = "ollama-umons"
    provider.model = "offline"
    provider._retry_limit = 5
    provider.client = openai.OpenAI(
        api_key="offline", base_url="https://offline.invalid/v1",
        http_client=httpx.Client(transport=httpx.MockTransport(refuse)),
    )
    tool = MagicMock(return_value="not executed")
    cost = MagicMock(spec=CostTracker)

    def callback(event):
        events.append(event)

    callback._provider_diagnostics = observe
    try:
        with pytest.raises(openai.APIConnectionError) as caught:
            provider.chat_with_tools(
                "system", "Analyze graph", [{
                    "name": "probe", "description": "Offline probe",
                    "input_schema": {"type": "object", "properties": {}}, "function": tool,
                }], max_turns=3, stream_callback=callback, cost_tracker=cost,
            )
        assert isinstance(caught.value.__cause__, httpx.ConnectError)
    finally:
        provider.client.close()

    assert len(requests) == 6  # No extra implicit SDK retries.
    assert all(r.content == requests[0].content for r in requests)
    assert clock["delays"] == [5.0, 10.0, 20.0, 40.0, 80.0]
    tool.assert_not_called()
    cost.record_turn.assert_not_called()
    cost.record_tool_error.assert_not_called()
    diagnostics = [e for e in events if e.get("type") == "provider_diagnostic"]
    if observe:
        assert [e["attempt"] for e in diagnostics if e["event"] == "request"] == list(range(6))
        errors = [e for e in diagnostics if e["event"] == "response"]
        assert len(errors) == 6
        assert all(e["error_kind"] == "network" and not e["usage_present"] for e in errors)
        assert diagnostics[-1]["event"] == "terminal"
        assert diagnostics[-1]["cause"] == "providererror"
    else:
        assert diagnostics == []
