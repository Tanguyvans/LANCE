"""Offline coverage for bounded recovery of tool-ended conversations."""

import json
import threading
from unittest.mock import MagicMock

import httpx
import pytest

from src.agent.core import provider_transport
from src.agent.cost_tracker import BudgetExceeded
from src.agent.provider import LLMProvider


def _completion(message, *, finish_reason="stop"):
    return {
        "id": "offline",
        "object": "chat.completion",
        "created": 1,
        "model": "offline",
        "choices": [{
            "index": 0,
            "finish_reason": finish_reason,
            "message": message,
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


def _tool_completion(call_id="call-1"):
    return _completion({
        "role": "assistant",
        "content": None,
        "tool_calls": [{
            "id": call_id,
            "type": "function",
            "function": {"name": "probe", "arguments": "{}"},
        }],
    }, finish_reason="tool_calls")


def _error_response(status_code):
    return httpx.Response(
        status_code,
        json={"error": {
            "message": "no user query found in messages",
            "type": "invalid_request_error",
        }},
    )


def _make_provider(transport):
    openai = pytest.importorskip("openai")
    provider = LLMProvider.__new__(LLMProvider)
    provider.provider = "openrouter"
    provider.model = "offline"
    provider._retry_limit = 0
    provider.client = openai.OpenAI(
        api_key="offline",
        base_url="https://offline.invalid/v1",
        http_client=httpx.Client(transport=httpx.MockTransport(transport)),
    )
    return provider


def _tool_spec(tool):
    return [{
        "name": "probe",
        "description": "probe",
        "input_schema": {"type": "object"},
        "function": tool,
    }]


@pytest.mark.parametrize("status_code", [400, 500])
def test_tool_result_recovery_is_one_continuation_with_history_and_one_tool_call(status_code):
    requests = []
    responses = [_tool_completion(), _error_response(status_code), httpx.Response(
        200, json=_completion({"role": "assistant", "content": "Recovered."})
    )]

    def transport(request):
        requests.append(json.loads(request.content))
        response = responses[len(requests) - 1]
        return response if isinstance(response, httpx.Response) else httpx.Response(200, json=response)

    tool = MagicMock(return_value='{"ok":true}')
    provider = _make_provider(transport)
    try:
        assert provider.chat_with_tools("system", "Original request", _tool_spec(tool), max_turns=3) == "Recovered."
    finally:
        provider.client.close()

    tool.assert_called_once_with()
    assert len(requests) == 3
    messages = requests[2]["messages"]
    assert [message["role"] for message in messages] == ["system", "user", "assistant", "tool", "user"]
    assert messages[:-1] == requests[1]["messages"]
    assert messages[1]["content"] == "Original request"
    assert messages[3]["tool_call_id"] == "call-1"
    assert "Continue the original user request" in messages[4]["content"]


def test_distinct_tool_result_turns_each_get_one_bounded_recovery():
    requests = []
    responses = [
        _tool_completion("call-1"),
        _error_response(500),
        _tool_completion("call-2"),
        _error_response(500),
        httpx.Response(200, json=_completion({"role": "assistant", "content": "Done."})),
    ]

    def transport(request):
        requests.append(json.loads(request.content))
        response = responses[len(requests) - 1]
        return response if isinstance(response, httpx.Response) else httpx.Response(200, json=response)

    tool = MagicMock(return_value='{"ok":true}')
    provider = _make_provider(transport)
    try:
        assert provider.chat_with_tools(
            "system", "Original request", _tool_spec(tool), max_turns=5
        ) == "Done."
    finally:
        provider.client.close()

    assert len(requests) == 5
    assert tool.call_count == 2
    assert [message["role"] for message in requests[2]["messages"]] == [
        "system", "user", "assistant", "tool", "user"
    ]
    assert [message["role"] for message in requests[4]["messages"]] == [
        "system", "user", "assistant", "tool", "user", "assistant", "tool", "user"
    ]
    assert all(
        "Continue the original user request" in request["messages"][-1]["content"]
        for request in (requests[2], requests[4])
    )


@pytest.mark.parametrize("status_code", [400, 500])
def test_persistent_rejection_raises_without_recovery_or_retries(status_code, monkeypatch):
    requests = []

    def transport(request):
        requests.append(json.loads(request.content))
        if len(requests) == 1:
            return httpx.Response(200, json=_tool_completion())
        return _error_response(status_code)

    tool = MagicMock(return_value='{"ok":true}')
    provider = _make_provider(transport)
    provider._retry_limit = 5
    monkeypatch.setattr(
        provider_transport.time,
        "sleep",
        lambda delay: pytest.fail(f"unexpected SDK retry sleep: {delay}"),
    )
    try:
        with pytest.raises(Exception, match="no user query found in messages"):
            provider.chat_with_tools("system", "Original request", _tool_spec(tool), max_turns=5)
    finally:
        provider.client.close()
    assert len(requests) == 3
    tool.assert_called_once_with()


@pytest.mark.parametrize("status_code", [400, 500])
def test_first_turn_rejection_does_not_trigger_recovery(status_code, monkeypatch):
    requests = []

    def transport(request):
        requests.append(json.loads(request.content))
        return _error_response(status_code)

    provider = _make_provider(transport)
    provider._retry_limit = 5
    monkeypatch.setattr(
        provider_transport.time,
        "sleep",
        lambda delay: pytest.fail(f"unexpected SDK retry sleep: {delay}"),
    )
    try:
        with pytest.raises(Exception, match="no user query found in messages"):
            provider.chat_with_tools("system", "Original request", _tool_spec(lambda: "ok"), max_turns=3)
    finally:
        provider.client.close()
    assert len(requests) == 1


def test_500_after_no_tool_fallback_fails_fast_without_recovery():
    requests = []

    def transport(request):
        requests.append(json.loads(request.content))
        if len(requests) == 1:
            return httpx.Response(200, json=_completion({
                "role": "assistant", "content": None,
            }, finish_reason="error"))
        return _error_response(500)

    provider = _make_provider(transport)
    try:
        with pytest.raises(Exception, match="no user query found in messages"):
            provider.chat_with_tools("system", "Original request", _tool_spec(lambda: "ok"), max_turns=4)
    finally:
        provider.client.close()

    assert len(requests) == 2


def test_unknown_500_retries_without_model_recovery(monkeypatch):
    requests = []

    def transport(request):
        requests.append(json.loads(request.content))
        if len(requests) == 1:
            return httpx.Response(200, json=_tool_completion())
        return httpx.Response(500, json={"error": {"message": "unrelated server failure"}})

    provider = _make_provider(transport)
    provider._retry_limit = 2
    monkeypatch.setattr(provider_transport.time, "sleep", lambda _delay: None)
    try:
        with pytest.raises(Exception, match="unrelated server failure"):
            provider.chat_with_tools(
                "system", "Original request", _tool_spec(lambda: '{"ok":true}'), max_turns=5
            )
    finally:
        provider.client.close()

    assert len(requests) == 4
    assert all(
        request["messages"] == requests[1]["messages"]
        for request in requests[2:]
    )
    assert all(message["role"] != "user" or message["content"] == "Original request"
               for message in requests[1]["messages"])


def test_recovery_respects_budget_deadline_stop_and_max_turns(monkeypatch):
    def make_tool_and_transport(after_error):
        requests = []

        def transport(request):
            requests.append(json.loads(request.content))
            if len(requests) == 1:
                return httpx.Response(200, json=_tool_completion())
            response = _error_response(400)
            after_error()
            return response

        return requests, transport

    budget_requests, budget_transport = make_tool_and_transport(lambda: None)
    budget_provider = _make_provider(budget_transport)
    tracker = MagicMock()
    tracker.check_budget.side_effect = [None, None, BudgetExceeded("budget limit")]
    try:
        with pytest.raises(BudgetExceeded, match="budget limit"):
            budget_provider.chat_with_tools("system", "request", _tool_spec(lambda: "ok"), max_turns=3, cost_tracker=tracker)
    finally:
        budget_provider.client.close()
    assert len(budget_requests) == 2

    stop_event = threading.Event()
    stop_requests, stop_transport = make_tool_and_transport(stop_event.set)
    stop_provider = _make_provider(stop_transport)
    try:
        assert stop_provider.chat_with_tools("system", "request", _tool_spec(lambda: "ok"), max_turns=3, stop_event=stop_event) == "(stopped by user)"
    finally:
        stop_provider.client.close()
    assert len(stop_requests) == 2

    clock = {"now": 99.0}
    monkeypatch.setattr(provider_transport.time, "monotonic", lambda: clock["now"])
    deadline_requests, deadline_transport = make_tool_and_transport(lambda: clock.update(now=101.0))
    deadline_provider = _make_provider(deadline_transport)
    try:
        with pytest.raises(TimeoutError, match="deadline exceeded"):
            deadline_provider.chat_with_tools("system", "request", _tool_spec(lambda: "ok"), max_turns=3, deadline=100.0)
    finally:
        deadline_provider.client.close()
    assert len(deadline_requests) == 2

    max_turn_requests, max_turn_transport = make_tool_and_transport(lambda: None)
    max_turn_provider = _make_provider(max_turn_transport)
    try:
        with pytest.raises(Exception, match="no user query found in messages"):
            max_turn_provider.chat_with_tools("system", "request", _tool_spec(lambda: "ok"), max_turns=2)
    finally:
        max_turn_provider.client.close()
    assert len(max_turn_requests) == 2


def test_initial_empty_user_message_is_rejected_without_request():
    requests = []
    provider = _make_provider(lambda request: requests.append(request))
    try:
        with pytest.raises(ValueError, match="non-empty user message"):
            provider.chat_with_tools("system", "   ", _tool_spec(lambda: "ok"), max_turns=3)
    finally:
        provider.client.close()
    assert not requests
