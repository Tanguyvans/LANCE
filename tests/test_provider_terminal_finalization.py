"""Focused tests for opt-in OpenAI-compatible terminal-tool finalization."""

import json
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, call

import pytest

from src.agent.cost_tracker import BudgetExceeded
from src.agent.core.completion_policy import CompletionPolicy
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


def test_stall_gets_action_capable_continuation_and_successful_save_terminates():
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
    assert _request_tool_names(finalization_request) == ["action", "save_deliverable"]
    assert finalization_request.kwargs["tool_choice"] == "required"


def test_repeated_text_is_bounded_and_returns_explicit_unsatisfied_reason():
    action = MagicMock(return_value='{"ok":true}')
    save = MagicMock(return_value='{"ok":true}')
    provider = _provider([_text("stall")] * 5)

    result = _run(provider, _tools(action, save))

    assert "required tool finalization unsatisfied" in result
    assert "completion request budget exhausted" in result
    assert provider.client.chat.completions.create.call_count == 5
    action.assert_not_called()
    save.assert_not_called()
    assert _request_tool_names(provider.client.chat.completions.create.call_args_list[1]) == [
        "action", "save_deliverable"
    ]
    assert provider.client.chat.completions.create.call_args_list[1].kwargs["tool_choice"] == "required"
    for request in provider.client.chat.completions.create.call_args_list[2:]:
        assert _request_tool_names(request) == ["save_deliverable"]
        assert request.kwargs["tool_choice"] == "required"


def test_action_continuation_resets_incident_before_rejected_save():
    action = MagicMock(return_value='{"ok":true}')
    save = MagicMock(side_effect=['{"ok":false,"error":"rejected"}'] * 4)
    provider = _provider([
        _text("stall"),
        _tool_response("action", "{}", "rogue-1"),
        _text("second stall"),
        _tool_response("save_deliverable", '{"attempt":1}', "save-1"),
        _tool_response("save_deliverable", '{"attempt":2}', "save-2"),
        _tool_response("save_deliverable", '{"attempt":3}', "save-3"),
        _tool_response("save_deliverable", '{"attempt":4}', "save-4"),
    ])

    result = _run(provider, _tools(action, save))

    assert "required tool finalization unsatisfied" in result
    assert provider.client.chat.completions.create.call_count == 7
    action.assert_called_once_with()
    assert save.call_count == 4
    assert _request_tool_names(provider.client.chat.completions.create.call_args_list[1]) == [
        "action", "save_deliverable"
    ]
    assert _request_tool_names(provider.client.chat.completions.create.call_args_list[2]) == [
        "action", "save_deliverable"
    ]
    for request in provider.client.chat.completions.create.call_args_list[4:]:
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
    ] == [["action", "save_deliverable"], ["save_deliverable"]]
    assert all(
        request.kwargs.get("tool_choice") == "required"
        for request in provider.client.chat.completions.create.call_args_list[1:]
    )
    save.assert_called_once_with(filename="result.json", content="done")


def test_opt_in_error_finish_gets_one_action_capable_continuation():
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
        "action", "save_deliverable"
    ]
    assert provider.client.chat.completions.create.call_args_list[1].kwargs["tool_choice"] == "required"
    action.assert_not_called()
    save.assert_called_once_with(filename="result.json", content="done")


def test_empty_choices_latch_bounded_terminal_mode():
    action = MagicMock()
    save = MagicMock(return_value='{"ok":true}')
    empty = SimpleNamespace(choices=[], usage=None)
    provider = _provider([empty, empty, empty, empty, empty])

    result = _run(provider, _tools(action, save))

    assert "required tool finalization unsatisfied" in result
    assert "completion request budget exhausted" in result
    assert provider.client.chat.completions.create.call_count == 5
    assert _request_tool_names(provider.client.chat.completions.create.call_args_list[1]) == [
        "action", "save_deliverable"
    ]
    assert provider.client.chat.completions.create.call_args_list[1].kwargs["tool_choice"] == "required"
    for request in provider.client.chat.completions.create.call_args_list[2:]:
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
    provider = _provider([_text("stall"), malformed, malformed, malformed, malformed])

    result = _run(provider, _tools(action, save))

    assert "required tool finalization unsatisfied" in result
    assert provider.client.chat.completions.create.call_count == 5
    action.assert_not_called()
    save.assert_not_called()
    assert _request_tool_names(provider.client.chat.completions.create.call_args_list[1]) == [
        "action", "save_deliverable"
    ]
    assert all(
        _request_tool_names(request) == ["save_deliverable"]
        for request in provider.client.chat.completions.create.call_args_list[2:]
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
    assert provider.client.with_options.call_count == len(requests)
    provider.client.with_options.assert_has_calls(
        [call(max_retries=0)] * len(requests)
    )
    assert [tool["function"]["name"] for tool in requests[1]["tools"]] == [
        "action", "save_deliverable"
    ]
    action.assert_not_called()
    save.assert_called_once_with(filename="result.json", content="done")


def test_completion_policy_allows_one_continuation_per_incident_and_two_total():
    policy = CompletionPolicy()

    assert policy.request_continuation(budget_reserved=False)
    assert not policy.request_continuation(budget_reserved=False)
    assert policy.finalization_only

    policy = CompletionPolicy()
    assert policy.request_continuation(budget_reserved=False)
    policy.action_executed("action", "save_deliverable", result='{"ok":true}')
    assert policy.request_continuation(budget_reserved=False)
    policy.action_executed("action", "save_deliverable", result='{"ok":true}')
    assert not policy.request_continuation(budget_reserved=False)
    assert policy.continuation_count == 2


@pytest.mark.parametrize("result", [
    '{"ok":false,"error_kind":"intrusion_target_out_of_scope"}',
    '{"ok":false,"error_kind":"intrusion_command_out_of_scope"}',
    '{"ok":false,"error_kind":"unverifiable_execution_scope"}',
    '{"ok":false,"error_kind":"run_stopped"}',
    '{"ok":false,"error_kind":"benchmark_memory_disabled"}',
    "Error executing action: network unavailable",
])
def test_refused_or_unusable_action_result_does_not_reset_incident(result):
    policy = CompletionPolicy()
    assert policy.request_continuation(budget_reserved=False)
    policy.action_executed("action", "save_deliverable", result=result)
    assert not policy.request_continuation(budget_reserved=False)


def test_failed_authentication_result_is_an_observed_action():
    policy = CompletionPolicy()
    assert policy.request_continuation(budget_reserved=False)
    policy.action_executed(
        "action",
        "save_deliverable",
        result='{"ok":false,"authenticated":false}',
    )
    assert policy.request_continuation(budget_reserved=False)


@pytest.mark.parametrize("action_result", [
    '{"ok":false,"error_kind":"intrusion_scope_unavailable"}',
    '{"ok":false,"error_kind":"intrusion_target_unverifiable"}',
    '{"ok":false,"error_kind":"intrusion_target_out_of_scope"}',
    '{"ok":false,"error_kind":"intrusion_command_out_of_scope"}',
])
def test_scope_refusal_does_not_reset_provider_interruption_incident(action_result):
    action = MagicMock(return_value=action_result)
    save = MagicMock(return_value='{"ok":true,"status":"saved"}')
    provider = _provider([
        _text("stall"),
        _tool_response("action", "{}", "action-1"),
        _text("still stalled"),
        _tool_response("save_deliverable", "{}", "save-1"),
    ])

    _run(provider, _tools(action, save))

    action.assert_called_once_with()
    save.assert_called_once_with()
    assert _request_tool_names(provider.client.chat.completions.create.call_args_list[1]) == [
        "action", "save_deliverable"
    ]
    assert _request_tool_names(provider.client.chat.completions.create.call_args_list[3]) == [
        "save_deliverable"
    ]


@pytest.mark.parametrize("tool_name, arguments", [
    ("mqtt_listen", {"broker": "192.0.2.1", "port": 0}),
    ("ssh_login", {}),
])
def test_argument_rejection_before_execution_does_not_reset_incident(
    monkeypatch, tool_name, arguments,
):
    from src.agent.tools.tool_loader import (
        DEFINITIONS_DIR, build_subprocess_function, load_tool_yaml,
    )

    execute = MagicMock(side_effect=AssertionError("No subprocess may execute"))
    monkeypatch.setattr("src.agent.tools.recon_tools._run", execute)
    action = MagicMock(wraps=build_subprocess_function(
        load_tool_yaml(DEFINITIONS_DIR / f"{tool_name}.yaml")
    ))
    save = MagicMock(return_value='{"ok":true,"status":"saved"}')
    provider = _provider([
        _text("stall"),
        _tool_response(tool_name, json.dumps(arguments), "action-1"),
        _text("still stalled"),
        _tool_response("save_deliverable", "{}", "save-1"),
    ])
    tools = _tools(action, save)
    tools[0]["name"] = tool_name
    events = []

    def observe(event):
        events.append(event)

    observe._provider_diagnostics = True
    _run(provider, tools, stream_callback=observe)

    action.assert_called_once_with(**arguments)
    execute.assert_not_called()
    save.assert_called_once_with()
    assert _request_tool_names(provider.client.chat.completions.create.call_args_list[3]) == [
        "save_deliverable"
    ]
    assert len([e for e in events if e.get("event") == "continuation_requested"]) == 1


def test_observed_failed_authentication_rearms_provider_continuation():
    action = MagicMock(return_value='{"ok":false,"authenticated":false}')
    save = MagicMock(return_value='{"ok":true,"status":"saved"}')
    provider = _provider([
        _text("stall"),
        _tool_response("action", "{}", "action-1"),
        _text("new stall after observation"),
        _tool_response("save_deliverable", "{}", "save-1"),
    ])

    _run(provider, _tools(action, save))

    action.assert_called_once_with()
    save.assert_called_once_with()
    assert _request_tool_names(provider.client.chat.completions.create.call_args_list[3]) == [
        "action", "save_deliverable"
    ]


def test_executor_error_does_not_reset_provider_interruption_incident():
    action = MagicMock(side_effect=RuntimeError("network failure"))
    save = MagicMock(return_value='{"ok":true,"status":"saved"}')
    provider = _provider([
        _text("stall"),
        _tool_response("action", "{}", "action-1"),
        _text("still stalled"),
        _tool_response("save_deliverable", "{}", "save-1"),
    ])

    _run(provider, _tools(action, save))

    assert _request_tool_names(provider.client.chat.completions.create.call_args_list[3]) == [
        "save_deliverable"
    ]


@pytest.mark.parametrize("interruption", [
    "text", "emptychoices", "emptymessage", "length", "error"
])
def test_interruption_gets_action_continuation_then_save(interruption):
    action = MagicMock(return_value='{"ok":false,"authenticated":false}')
    save = MagicMock(return_value='{"ok":true,"status":"saved"}')
    if interruption == "text":
        first = _text("stall")
    elif interruption == "emptychoices":
        first = SimpleNamespace(choices=[], usage=None)
    elif interruption == "emptymessage":
        first = _text(None)
    elif interruption == "length":
        first = _text(None)
        first.choices[0].finish_reason = "length"
    else:
        first = SimpleNamespace(
            choices=[SimpleNamespace(
                finish_reason="error",
                message=SimpleNamespace(content=None, tool_calls=None),
            )],
            usage=None,
        )
    provider = _provider([
        first,
        _tool_response("action", "{}", "action-1"),
        _tool_response("save_deliverable", "{}", "save-1"),
    ])

    _run(provider, _tools(action, save))

    action.assert_called_once_with()
    save.assert_called_once_with()
    continuation_request = provider.client.chat.completions.create.call_args_list[1]
    assert _request_tool_names(continuation_request) == ["action", "save_deliverable"]
    assert continuation_request.kwargs["tool_choice"] == "required"


def test_two_incidents_then_third_interruption_enters_finalization():
    action = MagicMock(return_value='{"ok":true}')
    save = MagicMock(return_value='{"ok":true}')
    provider = _provider([
        _text("stall-1"),
        _tool_response("action", "{}", "action-1"),
        _text("stall-2"),
        _tool_response("action", "{}", "action-2"),
        _text("stall-3"),
        _text("closing-1"),
        _text("closing-2"),
        _text("closing-3"),
    ])

    result = _run(provider, _tools(action, save))

    assert "required tool finalization unsatisfied" in result
    action.assert_has_calls([call(), call()])
    save.assert_not_called()
    assert provider.client.chat.completions.create.call_count == 8
    assert _request_tool_names(provider.client.chat.completions.create.call_args_list[1]) == [
        "action", "save_deliverable"
    ]
    assert _request_tool_names(provider.client.chat.completions.create.call_args_list[3]) == [
        "action", "save_deliverable"
    ]
    for request in provider.client.chat.completions.create.call_args_list[5:]:
        assert _request_tool_names(request) == ["save_deliverable"]
        assert request.kwargs["tool_choice"] == "required"
