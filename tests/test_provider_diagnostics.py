"""Focused tests for the provider diagnostic sidecar (model.obs1)."""
from __future__ import annotations

import json
import copy
import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from src.agent.core.provider_diagnostics import (
    append_event,
    sanitize_event,
)
from src.agent.core.runner import AgentRunner
from src.agent.provider import LLMProvider
from src.agent.cost_tracker import BudgetExceeded, CostTracker


def _event(**fields):
    return {
        "event": "response",
        "response_type": "textonly",
        "finish_reason": "stop",
        "usage_present": True,
        "provider": "ignored-by-boundary",
        "model": "ignored-by-boundary",
        "invocation_id": "1234567890abcdef1234567890abcdef",
        **fields,
    }


def test_allowlist_redacts_payloads_and_uses_fixed_enums():
    event = sanitize_event(
        _event(
            response_type="message-with-password-canary",
            finish_reason="private-finish-reason",
            content="private-content",
            reasoning="private-reasoning",
            arguments="password=secret",
            result="secret-result",
            headers="Authorization: secret",
            error_kind="private-error-kind",
        ),
        provider="openrouter",
        model="safe-model",
        invocation_id="1234567890abcdef1234567890abcdef",
        known_tools={"known_tool"},
        phase=3,
        agent="analyze_device",
    )

    serialized = json.dumps(event)
    assert "private" not in serialized
    assert "secret" not in serialized
    assert event["response_type"] == "unknown" if "response_type" in event else True
    assert event["finish_reason"] == "unknown"
    assert "content" not in event and "reasoning" not in event
    assert "arguments" not in event and "result" not in event


@pytest.mark.parametrize(
    "response_type",
    ["emptychoices", "emptymessage", "textonly", "providererror", "finish_reasonerror", "length", "malformedargs"],
)
def test_response_types_are_explicitly_allowlisted(response_type):
    event = sanitize_event(
        _event(response_type=response_type),
        provider="openrouter",
        model="model",
        invocation_id="1234567890abcdef1234567890abcdef",
        known_tools=set(),
    )
    assert event["response_type"] == response_type


def test_unknown_tool_and_metadata_values_are_safe():
    proposed = sanitize_event(
        {
            "event": "tool_proposed",
            "tool_name": "not-advertised",
            "reason": "private-reason",
            "outcome": "private-outcome",
            "turn": 2,
        },
        provider="openrouter",
        model="model",
        invocation_id="1234567890abcdef1234567890abcdef",
        known_tools={"known_tool"},
    )
    assert proposed["tool_name"] == "unknown"
    assert "reason" not in proposed and "outcome" not in proposed


@pytest.mark.parametrize(
    "reason",
    [
        "turn_budget", "textonly", "emptychoices", "finish_reasonerror",
        "malformedargs", "rejected_save", "data_tool_budget", "repeat_guard",
        "phase4_conclusive", "recon_ready", "recon_completion_required",
    ],
)
def test_finalization_reasons_are_fixed_and_unknown_is_not_preserved(reason):
    kwargs = {
        "provider": "openrouter",
        "model": "model",
        "invocation_id": "1234567890abcdef1234567890abcdef",
        "known_tools": set(),
    }
    event = sanitize_event(
        {"event": "finalization_entered", "reason": reason, "turn": 1}, **kwargs
    )
    assert event["reason"] == reason
    unknown = sanitize_event(
        {"event": "finalization_entered", "reason": "secret-reason", "turn": 1}, **kwargs
    )
    assert unknown["reason"] == "unknown"


def test_provider_error_metadata_keeps_only_enum_and_http_status():
    event = sanitize_event(
        _event(
            response_type="providererror",
            error_kind="transient",
            status_code=500,
            message="secret provider body",
        ),
        provider="openrouter",
        model="model",
        invocation_id="1234567890abcdef1234567890abcdef",
        known_tools=set(),
    )
    assert event["error_kind"] == "transient"
    assert event["status_code"] == 500
    assert "message" not in event
    assert "secret" not in json.dumps(event)


def test_transactional_attempt_reference_is_strict():
    base = {
        "event": "save_outcome",
        "accepted": True,
        "attempt_ref": ".attempts/05_intrusion.json/attempt-0123456789abcdef0123456789abcdef.json",
    }
    kwargs = {
        "provider": "openrouter",
        "model": "model",
        "invocation_id": "1234567890abcdef1234567890abcdef",
        "known_tools": {"save_deliverable"},
    }
    assert sanitize_event(base, **kwargs)["attempt_ref"].startswith(".attempts/")
    for bad in (
        ".attempts/../attempt-0123456789abcdef0123456789abcdef.json",
        ".attempts/05_intrusion.json/attempt-not-a-uuid.json",
        "password=secret",
    ):
        result = sanitize_event({**base, "attempt_ref": bad}, **kwargs)
        assert "attempt_ref" not in result


def _runner(tmp_path, downstream=None):
    runner = AgentRunner.__new__(AgentRunner)
    runner.run_dir = tmp_path
    runner._artifact_log_lock = threading.Lock()
    runner.provider = SimpleNamespace(provider="openrouter", model="safe-model")
    return runner._model_stream_callback(downstream, phase=3, agent="analysis_worker")


def _provider(responses):
    provider = LLMProvider.__new__(LLMProvider)
    provider.provider = "openrouter"
    provider.model = "safe-model"
    provider._retry_limit = 1
    provider.client = MagicMock()
    provider.client.with_options.return_value = provider.client
    provider.client.chat.completions.create.side_effect = responses
    return provider


def _response(*, content=None, tool_calls=None, finish_reason="stop", usage=None):
    return SimpleNamespace(
        choices=[SimpleNamespace(
            finish_reason=finish_reason,
            message=SimpleNamespace(content=content, tool_calls=tool_calls),
        )],
        usage=usage,
    )


def _tool_call(name, arguments="{}", call_id="call-1"):
    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name=name, arguments=arguments),
    )


def _records(tmp_path):
    return [
        json.loads(line)
        for line in (tmp_path / "provider_events.jsonl").read_text().splitlines()
    ]


def test_provider_observation_counts_effective_requests_and_terminal_response(tmp_path):
    provider = _provider([_response(content="done")])
    callback = _runner(tmp_path)

    assert provider.chat_with_tools(
        "sys", "go", [], max_turns=3, stream_callback=callback
    ) == "done"

    records = _records(tmp_path)
    assert [record["event"] for record in records] == [
        "invocation_started", "request", "response", "terminal"
    ]
    assert records[1]["request_num"] == 1
    assert records[1]["attempt"] == 0
    assert records[2]["response_type"] == "textonly"
    assert records[2]["finish_reason"] == "stop"
    assert records[-1]["cause"] == "textonly"
    assert all("content" not in record and "arguments" not in record for record in records)


def test_provider_observation_save_outcome_contains_only_real_attempt_ref(tmp_path):
    save_call = _tool_call(
        "save_deliverable",
        '{"filename":"05_intrusion.json","content":"secret"}',
    )
    provider = _provider([])
    provider.client.chat.completions.create.side_effect = [_response(
        content="saved", tool_calls=[save_call], finish_reason="tool_calls"
    )]
    saved = MagicMock(return_value=(
        '{"ok":true,"status":"saved",'
        '"attempt_ref":".attempts/05_intrusion.json/'
        'attempt-0123456789abcdef0123456789abcdef.json"}'
    ))
    callback = _runner(tmp_path)

    result = provider.chat_with_tools(
        "sys", "go", [{
            "name": "save_deliverable", "description": "save", "input_schema": {},
            "function": saved,
        }],
        max_turns=3,
        stream_callback=callback,
        required_tool="save_deliverable",
        terminate_after_tool="save_deliverable",
    )

    assert result == "saved"
    records = _records(tmp_path)
    save_records = [record for record in records if record["event"] == "save_outcome"]
    assert save_records == [{
        **save_records[0],
        "outcome": "accepted",
        "attempt_ref": ".attempts/05_intrusion.json/attempt-0123456789abcdef0123456789abcdef.json",
    }]
    assert records[-1]["cause"] == "accepted_save"
    saved.assert_called_once_with(filename="05_intrusion.json", content="secret")


def test_provider_observation_retries_are_provider_errors_then_reset_on_success(tmp_path, monkeypatch):
    class ProviderHTTPError(Exception):
        status_code = 500

    monkeypatch.setattr("src.agent.provider.time.sleep", lambda _seconds: None)
    provider = _provider([
        ProviderHTTPError("secret response body"),
        _response(content="recovered"),
    ])
    callback = _runner(tmp_path)

    assert provider.chat_with_tools(
        "sys", "go", [], max_turns=3, stream_callback=callback
    ) == "recovered"

    records = _records(tmp_path)
    requests = [record for record in records if record["event"] == "request"]
    responses = [record for record in records if record["event"] == "response"]
    assert [record["request_num"] for record in requests] == [1, 2]
    assert responses[0]["response_type"] == "providererror"
    assert responses[0]["error_kind"] == "transient"
    assert responses[0]["status_code"] == 500
    assert responses[1]["response_type"] == "textonly"
    assert records[-1]["cause"] == "textonly"
    assert "secret response body" not in json.dumps(records)


def test_retry_backoff_deadline_is_terminal_deadline_after_observed_sdk_error(tmp_path):
    class ProviderHTTPError(Exception):
        status_code = 500

    provider = _provider([ProviderHTTPError("secret response body")])
    callback = _runner(tmp_path)
    with pytest.raises(TimeoutError):
        provider.chat_with_tools(
            "sys", "go", [], max_turns=3, stream_callback=callback,
            deadline=time.monotonic() + 1,
        )

    records = _records(tmp_path)
    assert len([record for record in records if record["event"] == "request"]) == 1
    assert len([record for record in records if record["event"] == "response"]) == 1
    assert records[-1]["cause"] == "deadline"


def test_deadline_before_http_has_no_request_or_provider_response(tmp_path):
    provider = _provider([_response(content="must not be called")])
    callback = _runner(tmp_path)
    with pytest.raises(TimeoutError):
        provider.chat_with_tools(
            "sys", "go", [], max_turns=3, stream_callback=callback,
            deadline=time.monotonic() - 1,
        )

    records = _records(tmp_path)
    assert not [record for record in records if record["event"] == "request"]
    assert not [record for record in records if record["event"] == "response"]
    assert records[-1]["cause"] == "deadline"


def test_provider_observation_does_not_fabricate_provider_response_after_callback_error(tmp_path):
    callback_error = RuntimeError("legacy callback failure")

    def downstream(_event):
        raise callback_error

    provider = _provider([_response(content="done")])
    callback = _runner(tmp_path, downstream=downstream)
    with pytest.raises(RuntimeError) as caught:
        provider.chat_with_tools("sys", "go", [], stream_callback=callback)

    assert caught.value is callback_error
    records = _records(tmp_path)
    assert not [record for record in records if record.get("response_type") == "providererror"]
    assert records[-1]["cause"] == "internal"


def test_runner_persists_without_downstream_and_adds_run_context(tmp_path):
    callback = _runner(tmp_path)
    callback({
        "type": "provider_diagnostic",
        "event": "save_outcome",
        "provider": "openrouter",
        "model": "safe-model",
        "invocation_id": "1234567890abcdef1234567890abcdef",
        "_known_tools": ["save_deliverable"],
        "accepted": True,
        "attempt_ref": ".attempts/05_intrusion.json/attempt-0123456789abcdef0123456789abcdef.json",
        "turn": 9,
        "request_num": 13,
    })
    record = json.loads((tmp_path / "provider_events.jsonl").read_text().strip())
    assert record["schema_version"] == "model.obs1"
    assert record["run_id"] == tmp_path.name
    assert record["phase"] == "3"  # phase is bounded metadata, not prompt data
    assert record["agent"] == "analysis_worker"
    assert record["outcome"] == "accepted"
    assert record["attempt_ref"].endswith(".json")
    assert record["timestamp"].endswith("Z")


def test_runner_diagnostic_write_failure_is_best_effort(tmp_path, monkeypatch):
    callback = _runner(tmp_path)
    monkeypatch.setattr("src.agent.core.runner.append_event", lambda *args, **kwargs: False)
    callback({
        "type": "provider_diagnostic",
        "event": "terminal",
        "invocation_id": "1234567890abcdef1234567890abcdef",
        "cause": "internal",
    })


def test_runner_preserves_legacy_downstream_exception(tmp_path):
    error = RuntimeError("legacy callback failure")
    callback = _runner(tmp_path, downstream=lambda _event: (_ for _ in ()).throw(error))
    with pytest.raises(RuntimeError) as caught:
        callback({"type": "text_chunk", "text": "legacy"})
    assert caught.value is error


def test_append_refuses_symlinked_root_and_file(tmp_path):
    record = {"schema_version": "model.obs1", "event": "terminal", "cause": "internal"}
    real_root = tmp_path / "real-run"
    real_root.mkdir()
    root_link = tmp_path / "root-link"
    root_link.symlink_to(real_root, target_is_directory=True)
    assert not append_event(root_link, record)

    sidecar = real_root / "provider_events.jsonl"
    outside = tmp_path / "outside"
    outside.write_text("outside", encoding="utf-8")
    sidecar.symlink_to(outside)
    assert not append_event(real_root, record)
    assert outside.read_text(encoding="utf-8") == "outside"


def test_append_refuses_fifo_and_reports_short_write(tmp_path, monkeypatch):
    record = {"schema_version": "model.obs1", "event": "terminal", "cause": "internal"}
    fifo_root = tmp_path / "fifo-run"
    fifo_root.mkdir()
    os.mkfifo(fifo_root / "provider_events.jsonl")
    assert not append_event(fifo_root, record)

    short_root = tmp_path / "short-run"
    short_root.mkdir()
    real_write = os.write
    monkeypatch.setattr(os, "write", lambda fd, payload: max(0, len(payload) - 1))
    assert not append_event(short_root, record)
    monkeypatch.setattr(os, "write", real_write)


def test_concurrent_runner_callbacks_remain_line_delimited(tmp_path):
    callback = _runner(tmp_path)
    threads = [
        threading.Thread(
            target=callback,
            args=({
                "type": "provider_diagnostic",
                "event": "request",
                "invocation_id": f"{index:032x}",
                "request_num": index,
                "attempt": 0,
                "turn": index,
            },),
        )
        for index in range(1, 21)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    lines = (tmp_path / "provider_events.jsonl").read_text().splitlines()
    assert len(lines) == 20
    assert all(json.loads(line)["event"] == "request" for line in lines)


def _tools(action=None, save=None):
    return [
        {"name": name, "description": name, "input_schema": {}, "function": fn}
        for name, fn in (
            ("action", action or MagicMock(return_value='{"ok":true}')),
            ("save_deliverable", save or MagicMock(return_value='{"status":"saved"}')),
        )
    ]


@pytest.mark.parametrize("kind", ["textonly", "emptychoices", "finish_reasonerror"])
def test_thirteen_requests_nine_actions_parity_with_observer_on_and_off(tmp_path, monkeypatch, kind):
    monkeypatch.setattr("src.agent.cost_tracker.get_dynamic_pricing", lambda _: None)
    outcomes = []
    for observe in (False, True):
        root = tmp_path / str(observe)
        root.mkdir()
        usage = SimpleNamespace(prompt_tokens=100, completion_tokens=10)
        tail = (
            SimpleNamespace(choices=[], usage=usage) if kind == "emptychoices"
            else _response(content="closing" if kind == "textonly" else None,
                           finish_reason="error" if kind == "finish_reasonerror" else "stop", usage=usage)
        )
        responses = iter([
            _response(tool_calls=[_tool_call("action", json.dumps({"index": i}), f"call-{i}")],
                      finish_reason="tool_calls", usage=usage)
            for i in range(9)
        ] + [copy.deepcopy(tail) for _ in range(4)])
        provider = _provider([])
        requests = []
        def create(**kwargs):
            requests.append(copy.deepcopy(kwargs))
            return next(responses)
        provider.client.chat.completions.create.side_effect = create
        action = MagicMock(return_value='{"ok":true}')
        save = MagicMock(return_value='{"status":"saved"}')
        tracker = CostTracker(model="offline", provider="ollama-umons")
        tracker.start_phase("intrusion")
        events = []
        callback = _runner(root, events.append) if observe else events.append
        result = provider.chat_with_tools(
            "sys", "go", _tools(action, save), max_turns=80,
            required_tool="save_deliverable", terminate_after_tool="save_deliverable",
            finalize_required_tool_on_stall=True, stream_callback=callback, cost_tracker=tracker,
        )
        outcomes.append((result, requests, action.call_args_list, save.call_args_list,
                         events, tracker.total_tokens(), tracker.total_cost()))
    assert outcomes[0] == outcomes[1]
    assert len(outcomes[1][1]) == 13
    assert len(outcomes[1][2]) == 9
    assert outcomes[1][5] == (1300, 130)
    records = _records(tmp_path / "True")
    assert len([r for r in records if r["event"] == "request"]) == 13
    assert len([r for r in records if r["event"] == "response"]) == 13
    assert len([r for r in records if r["event"] == "tool_executed"]) == 9
    assert [r["reason"] for r in records if r["event"] == "finalization_entered"] == [kind]
    assert [r["cause"] for r in records if r["event"] == "terminal"] == ["terminalretryexhausted"]


@pytest.mark.parametrize("reason,options,result", [
    ("data_tool_budget", {"max_data_tool_calls": 1}, '{"ok":true}'),
    ("data_tool_budget", {"max_data_tool_calls": 0}, '{"ok":true}'),
    ("phase4_conclusive", {"force_completion_on_phase4_conclusive": True}, '{"ok":true,"phase4_conclusive":true}'),
    ("recon_ready", {"force_completion_on_recon_ready": True}, '{"ok":true,"recon_progress":{"ready_to_save":true}}'),
    ("recon_completion_required", {"force_tool_on_stall": True}, '{"ok":false,"error_kind":"recon_completion_required"}'),
])
def test_finalization_reason_matches_triggering_condition(tmp_path, reason, options, result):
    action = MagicMock(return_value=result)
    provider = _provider([
        _response(tool_calls=[_tool_call("action")], finish_reason="tool_calls"),
        _response(tool_calls=[_tool_call("save_deliverable")], finish_reason="tool_calls"),
    ])
    provider.chat_with_tools(
        "sys", "go", _tools(action), max_turns=20, stream_callback=_runner(tmp_path),
        required_tool="save_deliverable", terminate_after_tool="save_deliverable",
        finalize_required_tool_on_stall=True, **options,
    )
    assert [r["reason"] for r in _records(tmp_path) if r["event"] == "finalization_entered"] == [reason]


def test_malformed_batch_logs_refusals_not_executions(tmp_path):
    action = MagicMock(return_value='{"ok":true}')
    provider = _provider([_response(tool_calls=[
        _tool_call("action", "invalid JSON"), _tool_call("action", "{}", "call-2"),
    ], finish_reason="tool_calls")])
    provider.chat_with_tools("sys", "go", _tools(action), max_turns=1, stream_callback=_runner(tmp_path))
    action.assert_not_called()
    records = _records(tmp_path)
    assert len([r for r in records if r["event"] == "tool_proposed"]) == 2
    assert [r["reason"] for r in records if r["event"] == "tool_refused"] == ["malformed_args"] * 2
    assert not any(r["event"] == "tool_executed" for r in records)


@pytest.mark.parametrize("finish_reason,expected", [("stop", "emptymessage"), ("length", "length"), ("error", "finish_reasonerror")])
def test_empty_message_and_fallback_response_categories(tmp_path, finish_reason, expected):
    provider = _provider([
        _response(finish_reason="error"), _response(finish_reason=finish_reason),
    ])
    provider.chat_with_tools("sys", "go", [], max_turns=2, stream_callback=_runner(tmp_path))
    responses = [r for r in _records(tmp_path) if r["event"] == "response"]
    assert [r["response_type"] for r in responses] == ["finish_reasonerror", expected]
    assert [r["request_num"] for r in responses] == [1, 2]


def test_budget_before_http_and_failed_observer_preserve_original_exception(tmp_path, monkeypatch, caplog):
    error = BudgetExceeded("secret-budget-canary")
    tracker = MagicMock()
    tracker.check_budget.side_effect = error
    provider = _provider([])
    monkeypatch.setattr("src.agent.core.runner.append_event", lambda *a, **kw: False)
    with pytest.raises(BudgetExceeded) as caught:
        provider.chat_with_tools("sys", "go", [], stream_callback=_runner(tmp_path), cost_tracker=tracker)
    assert caught.value is error
    provider.client.chat.completions.create.assert_not_called()
    assert "unavailable" in caplog.text
    assert "secret-budget-canary" not in caplog.text


def test_same_agent_successive_invocations_have_distinct_ids(tmp_path):
    provider = _provider([_response(content="one"), _response(content="two")])
    callback = _runner(tmp_path)
    for _ in range(2):
        provider.chat_with_tools("sys", "go", [], stream_callback=callback)
    ids = {r["invocation_id"] for r in _records(tmp_path)}
    assert len(ids) == 2
    for invocation in ids:
        rows = [r for r in _records(tmp_path) if r["invocation_id"] == invocation]
        assert [r["request_num"] for r in rows if r["event"] == "request"] == [1]
        assert sum(r["event"] == "terminal" for r in rows) == 1
