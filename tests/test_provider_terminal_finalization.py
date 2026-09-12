"""Focused tests for opt-in OpenAI-compatible terminal-tool finalization."""

import json
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from src.agent.cost_tracker import BudgetExceeded
from src.agent.provider import LLMProvider


def _provider(responses):
    provider = LLMProvider.__new__(LLMProvider)
    provider.provider = "openrouter"
    provider.model = "luna"
    provider._retry_limit = 0
    provider.client = MagicMock()
    # A real SDK client's with_options returns a client; mirror that shape so
    # terminal-mode retry suppression can be asserted without a live network.
    provider.client.with_options.return_value = provider.client
    provider.client.chat.completions.create.side_effect = responses
    return provider


def _text(text):
    message = SimpleNamespace(content=text, tool_calls=None)
    return SimpleNamespace(
        choices=[SimpleNamespace(finish_reason="stop", message=message)],
        usage=None,
    )


def _tool(name, arguments, call_id):
    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name=name, arguments=arguments),
    )


def _tool_response(name, arguments, call_id):
    return _multi_tool_response([_tool(name, arguments, call_id)])


def _multi_tool_response(tool_calls):
    message = SimpleNamespace(
        content=None,
        tool_calls=tool_calls,
    )
    return SimpleNamespace(
        choices=[SimpleNamespace(finish_reason="tool_calls", message=message)],
        usage=None,
    )


def _tools(action, save):
    return [
        {"name": "action", "description": "action", "input_schema": {}, "function": action},
        {
            "name": "save_deliverable",
            "description": "save deliverable",
            "input_schema": {},
            "function": save,
        },
    ]


def _run(provider, tools, **kwargs):
    max_turns = kwargs.pop("max_turns", 20)
    return provider.chat_with_tools(
        system_prompt="sys",
        user_message="go",
        tools=tools,
        required_tool="save_deliverable",
        terminate_after_tool="save_deliverable",
        max_turns=max_turns,
        finalize_required_tool_on_stall=True,
        **kwargs,
    )


def _request_tool_names(request):
    return [item["function"]["name"] for item in request.kwargs.get("tools", [])]


def test_stall_enters_save_only_mode_and_successful_save_terminates():
    action = MagicMock(return_value='{"ok":true}')
    save = MagicMock(return_value='{"ok":true,"status":"saved"}')
    provider = _provider([
        _tool_response("action", "{}", "action-1"),
        _text("I have enough evidence."),
        _tool_response(
            "save_deliverable",
            '{"filename":"result.json","content":"done"}',
            "save-1",
        ),
    ])

    result = _run(provider, _tools(action, save))

    assert result == "I have enough evidence."
    assert action.call_count == 1
    save.assert_called_once_with(filename="result.json", content="done")
    finalization_request = provider.client.chat.completions.create.call_args_list[2]
    assert _request_tool_names(finalization_request) == ["save_deliverable"]
    assert finalization_request.kwargs["tool_choice"] == "required"


def test_repeated_text_is_bounded_and_returns_explicit_unsatisfied_reason():
    action = MagicMock(return_value='{"ok":true}')
    save = MagicMock(return_value='{"ok":true}')
    provider = _provider([_text("stall")] * 4)

    result = _run(provider, _tools(action, save))

    assert "required tool finalization unsatisfied" in result
    assert "completion request budget exhausted" in result
    assert provider.client.chat.completions.create.call_count == 4
    action.assert_not_called()
    save.assert_not_called()
    for request in provider.client.chat.completions.create.call_args_list[1:]:
        assert _request_tool_names(request) == ["save_deliverable"]
        assert request.kwargs["tool_choice"] == "required"


def test_rejected_empty_and_rogue_action_calls_never_reopen_action_tools():
    action = MagicMock(return_value='{"ok":true}')
    save = MagicMock(side_effect=['{"ok":false,"error":"rejected"}', ""])
    provider = _provider([
        _text("stall"),
        _tool_response("action", "{}", "rogue-1"),
        _tool_response("save_deliverable", "{}", "save-1"),
        _tool_response("save_deliverable", "{}", "save-2"),
    ])

    result = _run(provider, _tools(action, save))

    assert "required tool finalization unsatisfied" in result
    assert provider.client.chat.completions.create.call_count == 4
    action.assert_not_called()
    assert save.call_count == 2
    for request in provider.client.chat.completions.create.call_args_list[1:]:
        assert _request_tool_names(request) == ["save_deliverable"]


def test_first_rejected_save_latches_terminal_mode_for_remaining_batch_and_next_turns():
    action = MagicMock(return_value='{"ok":true}')
    save = MagicMock(return_value='{"ok":false,"error":"rejected"}')
    provider = _provider([
        _multi_tool_response([
            _tool("save_deliverable", "{}", "save-1"),
            _tool("action", "{}", "rogue-after-save"),
        ]),
        _tool_response("action", "{}", "rogue-next-turn"),
        _text("stall"),
        _text("stall again"),
    ])

    result = _run(provider, _tools(action, save))

    assert "required tool finalization unsatisfied" in result
    save.assert_called_once_with()
    action.assert_not_called()
    for request in provider.client.chat.completions.create.call_args_list[1:]:
        assert _request_tool_names(request) == ["save_deliverable"]


def test_repeat_guard_latches_opt_in_finalization_and_blocks_same_batch_actions():
    action = MagicMock(return_value='{"ok":true}')
    save = MagicMock(return_value='{"ok":true}')
    repeated = _multi_tool_response([
        _tool("action", "{}", "action-1"),
        _tool("action", "{}", "action-2"),
        _tool("action", "{}", "action-3"),
        _tool("action", '{"different_target":true}', "action-4"),
    ])
    provider = _provider([repeated, _text("stall"), _text("stall"), _text("stall")])

    result = _run(provider, _tools(action, save))

    assert "required tool finalization unsatisfied" in result
    # The third identical call trips repeat_guard; even a different later
    # sibling call must not execute after finalization is latched.
    assert action.call_count == 2
    assert all(
        _request_tool_names(request) == ["save_deliverable"]
        for request in provider.client.chat.completions.create.call_args_list[1:]
    )


def test_opt_in_requires_explicit_success_in_terminal_wrapper_result():
    assert not LLMProvider._terminal_tool_succeeded("{}")
    assert not LLMProvider._terminal_tool_succeeded('{"status":"draft"}')
    assert LLMProvider._terminal_tool_succeeded('{"ok":true}')
    assert LLMProvider._terminal_tool_succeeded('{"status":"saved"}')


def test_opt_in_max_turns_without_entering_finalization_is_explicit_even_at_one():
    action = MagicMock(return_value='{"ok":true}')
    save = MagicMock(return_value='{"ok":true}')
    provider = _provider([_tool_response("action", "{}", "action-1")])

    result = _run(provider, _tools(action, save), max_turns=1)

    assert "required tool finalization unsatisfied" in result
    assert "max turns exhausted" in result
    action.assert_called_once_with()


def test_opt_in_error_finish_uses_next_bounded_terminal_request_without_nested_fallback():
    action = MagicMock()
    save = MagicMock(return_value='{"ok":true,"status":"saved"}')
    error = SimpleNamespace(
        choices=[SimpleNamespace(
            finish_reason="error",
            message=SimpleNamespace(content=None, tool_calls=None),
        )],
        usage=None,
    )
    provider = _provider([
        _text("stall"),
        error,
        _tool_response(
            "save_deliverable",
            '{"filename":"result.json","content":"done"}',
            "save-1",
        ),
    ])

    _run(provider, _tools(action, save))

    assert provider.client.chat.completions.create.call_count == 3
    assert [
        _request_tool_names(request)
        for request in provider.client.chat.completions.create.call_args_list[1:]
    ] == [["save_deliverable"], ["save_deliverable"]]
    assert all(
        request.kwargs.get("tool_choice") == "required"
        for request in provider.client.chat.completions.create.call_args_list[1:]
    )
    save.assert_called_once_with(filename="result.json", content="done")


def test_opt_in_error_finish_before_terminal_mode_latches_save_only_immediately():
    action = MagicMock()
    save = MagicMock(return_value='{"ok":true,"status":"saved"}')
    error = SimpleNamespace(
        choices=[SimpleNamespace(
            finish_reason="error",
            message=SimpleNamespace(content=None, tool_calls=None),
        )],
        usage=None,
    )
    provider = _provider([
        error,
        _tool_response(
            "save_deliverable",
            '{"filename":"result.json","content":"done"}',
            "save-1",
        ),
    ])

    _run(provider, _tools(action, save))

    assert provider.client.chat.completions.create.call_count == 2
    assert _request_tool_names(provider.client.chat.completions.create.call_args_list[1]) == [
        "save_deliverable"
    ]
    assert provider.client.chat.completions.create.call_args_list[1].kwargs["tool_choice"] == "required"
    action.assert_not_called()
    save.assert_called_once_with(filename="result.json", content="done")


def test_empty_choices_latch_bounded_terminal_mode():
    action = MagicMock()
    save = MagicMock(return_value='{"ok":true}')
    empty = SimpleNamespace(choices=[], usage=None)
    provider = _provider([empty, empty, empty, empty])

    result = _run(provider, _tools(action, save))

    assert "required tool finalization unsatisfied" in result
    assert "completion request budget exhausted" in result
    assert provider.client.chat.completions.create.call_count == 4
    for request in provider.client.chat.completions.create.call_args_list[1:]:
        assert _request_tool_names(request) == ["save_deliverable"]
        assert request.kwargs["tool_choice"] == "required"
    action.assert_not_called()
    save.assert_not_called()


def test_empty_choices_record_opt_in_usage_before_latching():
    action = MagicMock()
    save = MagicMock(return_value='{"ok":true}')
    empty = SimpleNamespace(
        choices=[],
        usage=SimpleNamespace(prompt_tokens=7, completion_tokens=3),
    )
    provider = _provider([empty, _tool_response("save_deliverable", "{}", "save")])
    tracker = MagicMock()

    _run(provider, _tools(action, save), cost_tracker=tracker)

    tracker.record_turn.assert_called_once_with(
        input_tokens=7,
        output_tokens=3,
        tool_call_count=0,
    )


def test_malformed_save_arguments_consume_only_bounded_finalization_requests():
    action = MagicMock()
    save = MagicMock(return_value='{"ok":true}')
    malformed = _tool_response("save_deliverable", "{", "save")
    provider = _provider([_text("stall"), malformed, malformed, malformed])

    result = _run(provider, _tools(action, save))

    assert "required tool finalization unsatisfied" in result
    assert provider.client.chat.completions.create.call_count == 4
    action.assert_not_called()
    save.assert_not_called()
    assert all(
        _request_tool_names(request) == ["save_deliverable"]
        for request in provider.client.chat.completions.create.call_args_list[1:]
    )


def test_opt_in_reserves_existing_last_two_turns_for_save_only_mode():
    action = MagicMock(return_value='{"ok":true}')
    save = MagicMock(return_value='{"ok":true}')
    provider = _provider([
        _tool_response("action", "{}", "action-1"),
        _text("stall"),
        _text("still stalled"),
    ])

    result = _run(provider, _tools(action, save), max_turns=3)

    assert "required tool finalization unsatisfied" in result
    assert "max turns exhausted" in result
    assert provider.client.chat.completions.create.call_count == 3
    assert _request_tool_names(provider.client.chat.completions.create.call_args_list[1]) == [
        "save_deliverable"
    ]
    assert _request_tool_names(provider.client.chat.completions.create.call_args_list[2]) == [
        "save_deliverable"
    ]


def test_budget_exceeded_in_finalization_propagates_unchanged():
    action = MagicMock()
    save = MagicMock()
    provider = _provider([_text("stall")])
    tracker = MagicMock()
    tracker.check_budget.side_effect = [None, BudgetExceeded("budget limit")]

    with pytest.raises(BudgetExceeded, match="budget limit"):
        _run(provider, _tools(action, save), cost_tracker=tracker)

    assert provider.client.chat.completions.create.call_count == 1


def test_stop_event_is_checked_before_completion_request():
    action = MagicMock()
    save = MagicMock()
    stop_event = threading.Event()

    def first_request(**kwargs):
        stop_event.set()
        return _text("stall")

    provider = _provider([])
    provider.client.chat.completions.create.side_effect = first_request

    result = _run(provider, _tools(action, save), stop_event=stop_event)

    assert result == "(stopped by user)"
    assert provider.client.chat.completions.create.call_count == 1
    action.assert_not_called()
    save.assert_not_called()


def test_default_behavior_still_exposes_action_tools_after_a_text_stall():
    action = MagicMock(return_value='{"ok":true}')
    save = MagicMock(return_value='{"ok":true}')
    provider = _provider([
        _text("stall"),
        _tool_response("action", "{}", "action-1"),
        _text("done"),
        _text("done"),
    ])

    provider.chat_with_tools(
        system_prompt="sys",
        user_message="go",
        tools=_tools(action, save),
        required_tool="save_deliverable",
        max_turns=4,
    )

    action.assert_called_once_with()
    assert _request_tool_names(provider.client.chat.completions.create.call_args_list[1]) == [
        "action",
        "save_deliverable",
    ]


def test_real_openai_client_with_mock_transport_uses_save_only_finalization():
    httpx = pytest.importorskip("httpx")
    openai = pytest.importorskip("openai")
    requests = []
    responses = [
        {
            "id": "text",
            "object": "chat.completion",
            "created": 1,
            "model": "luna",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {
                "role": "assistant", "content": "stall"
            }}],
        },
        {
            "id": "save",
            "object": "chat.completion",
            "created": 2,
            "model": "luna",
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": None, "tool_calls": [{
                    "id": "save-1", "type": "function", "function": {
                        "name": "save_deliverable",
                        "arguments": '{"filename":"result.json","content":"done"}',
                    },
                }]
            }}],
        },
    ]

    def transport(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json=responses[len(requests) - 1])

    provider = LLMProvider.__new__(LLMProvider)
    provider.provider = "openrouter"
    provider.model = "luna"
    provider._retry_limit = 0
    provider.client = openai.OpenAI(
        api_key="offline",
        base_url="https://offline.invalid/v1",
        http_client=httpx.Client(transport=httpx.MockTransport(transport)),
    )
    provider.client.with_options = MagicMock(wraps=provider.client.with_options)
    action = MagicMock()
    save = MagicMock(return_value='{"ok":true,"status":"saved"}')

    try:
        _run(provider, _tools(action, save))
    finally:
        provider.client.close()

    assert requests[1]["tool_choice"] == "required"
    provider.client.with_options.assert_called_once_with(max_retries=0)
    assert [tool["function"]["name"] for tool in requests[1]["tools"]] == [
        "save_deliverable"
    ]
    action.assert_not_called()
    save.assert_called_once_with(filename="result.json", content="done")
