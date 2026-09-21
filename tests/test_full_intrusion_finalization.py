"""Offline full-profile integration: provider, transaction, ledger and final event."""
import json
from threading import Event, Lock
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.agent.core import runtime
from src.agent.cost_tracker import BudgetExceeded, CostTracker
from src.agent.execution_profiles import resolve_execution_profile
from src.agent.pipeline import Pipeline
from src.agent.provider import LLMProvider
from src.agent.registry import AGENTS
from src.agent.tools import deliverable
from src.benchmark.metric_contract import EVIDENCE_CONTRACT_VERSION


def response(*calls, text=None):
    tool_calls = [SimpleNamespace(
        id=f"call-{i}", type="function",
        function=SimpleNamespace(name=name, arguments=json.dumps(args)),
    ) for i, (name, args) in enumerate(calls)]
    return SimpleNamespace(
        choices=[SimpleNamespace(
            message=SimpleNamespace(content=text, tool_calls=tool_calls or None),
            finish_reason="tool_calls" if calls else "stop",
        )], usage=SimpleNamespace(prompt_tokens=100, completion_tokens=10),
    )


@pytest.fixture
def full(tmp_path, monkeypatch):
    monkeypatch.setattr("src.agent.cost_tracker.get_dynamic_pricing", lambda _: None)
    monkeypatch.setattr(runtime, "load_prompt", lambda *args: "Offline finalization test")
    instance = Pipeline.__new__(Pipeline)
    instance.run_dir = tmp_path
    instance.execution_profile = resolve_execution_profile("full")
    instance.context = {"target_subnet": "192.0.2.0/24"}
    instance.dry_run = True
    instance._stop_event = Event()
    instance._artifact_log_lock = Lock()
    instance._tool_call_count = 0
    instance.max_tool_calls = None
    instance.benchmark_split = "unassigned"
    instance.provider = LLMProvider.__new__(LLMProvider)
    instance.provider.provider = "ollama-umons"
    instance.provider.model = "offline"
    instance.provider._retry_limit = 0
    instance.provider.client = SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create=Mock()),
    ))
    instance.tracker = CostTracker(model="offline", provider="ollama-umons")
    instance._filter_skills = Mock(return_value="")
    (tmp_path / "run_meta.json").write_text(json.dumps({
        "evidence_contract_version": EVIDENCE_CONTRACT_VERSION,
        "evidence_integrity": True,
    }))
    action = Mock(return_value=json.dumps({"success": False, "authenticated": False}))
    tools = [
        {"name": "try_credential", "description": "offline action", "input_schema": {}, "function": action},
        next(tool for tool in deliverable.DELIVERABLE_TOOLS if tool["name"] == "save_deliverable"),
    ]
    instance._resolve_tools = lambda _: [instance._wrap_tool(t, phase=5, agent="intrusion") for t in tools]
    instance.offline_action = action
    return instance


ACTION = ("try_credential", {"ip": "192.0.2.1", "service": "ssh", "user": "test", "password": "test"})
SAVE = ("save_deliverable", {"filename": "05_intrusion.json", "content": json.dumps({
    "summary": {"devices_compromised": 0, "devices_attempted": 1, "total_hops": 0,
                "credentials_harvested": 0, "crown_jewels_reached": []},
    "chains": [], "compromised_devices": [], "credential_pool": [],
})})


@pytest.mark.parametrize("case", ["attempt", "access", "new_access", "missing", "corrupt", "stopped", "refused", "integrity_failed"])
def test_live_full_finish_marker_uses_ledger_not_model_claims(full, case):
    full.dry_run = False
    if case in {"access", "new_access"}:
        full.offline_action.return_value = json.dumps({"success": True, "authenticated": True, "service": "ssh", "stdout": "uid=0(root) gid=0(root)", "return_code": 0})
    if case == "access":
        (full.run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "recovered_credentials": [{"user": "test", "password": "test", "service": "ssh", "source_ip": "192.0.2.1"}],
        }))
    if case == "refused":
        full.offline_action.return_value = json.dumps({"error": "out of scope", "error_kind": "scope"})
    tools = full._resolve_tools(AGENTS["intrusion"])
    if case != "missing":
        tools[0]["function"](**ACTION[1])
    if case == "corrupt":
        with (full.run_dir / "tool_calls.jsonl").open("a") as handle:
            handle.write("invalid\n")
    if case == "stopped":
        full._stop_event.set()
    if case == "integrity_failed":
        full._evidence_integrity_failed = True
    save = full._apply_deliverable_transaction(tools, AGENTS["intrusion"])[1]["function"]
    receipt = json.loads(save(filename="05_intrusion.json", content='{"finish":true,"devices_compromised":999}'))
    if case in {"attempt", "access", "new_access"}:
        assert receipt.get("validated") is True
        data = json.loads((full.run_dir / "05_intrusion.json").read_text())
        assert data["summary"]["devices_compromised"] == (0 if case == "attempt" else 1)
        assert data["summary"]["devices_attempted"] == 1
        assert data["assessment"]["objectives_status"] == "not_certified"
        assert data["chains"] == []
    else:
        assert receipt["error_kind"] == "invalid_intrusion_evidence"
        assert not (full.run_dir / "05_intrusion.json").exists()


def run_phase(full):
    events = []
    status = full._run_agent(AGENTS["intrusion"], events.append)
    assert not [e for e in events if e["type"] == "phase_done"]
    results = {"intrusion": status}
    full._ensure_intrusion_deliverable(AGENTS["intrusion"], results, events.append)
    full._emit_intrusion_events(events.append)
    done = [e for e in events if e["type"] == "phase_done"]
    assert len(done) == 1
    assert done[0]["status"] == results["intrusion"]
    assert done[0]["cost_usd"] == round(full.tracker.total_cost(), 4)
    assert done[0]["turns"] > 0
    assert full.execution_profile.name == "full"
    return results["intrusion"], events


def test_model_text_stop_is_followed_by_validated_save(full):
    create = full.provider.client.chat.completions.create
    create.side_effect = [response(ACTION), response(text="Finished"), response(SAVE)]
    status, events = run_phase(full)
    assert status == "completed"
    assert full.offline_action.call_count == 1
    assert len(create.call_args_list) == 3
    assert [t["function"]["name"] for t in create.call_args_list[-1].kwargs["tools"]] == [
        "try_credential", "save_deliverable"
    ]
    attempts = [json.loads(s) for s in (full.run_dir / "deliverable_attempts.jsonl").read_text().splitlines()]
    assert attempts[-1]["valid"] is True
    diagnostics = [json.loads(s) for s in (full.run_dir / "provider_events.jsonl").read_text().splitlines()]
    saves = [e for e in diagnostics if e["event"] == "save_outcome"]
    assert len(saves) == 1
    assert saves[0]["outcome"] == "accepted"
    assert saves[0]["attempt_ref"] == attempts[-1]["attempt_ref"]
    assert (full.run_dir / saves[0]["attempt_ref"]).is_file()
    assert len({e["invocation_id"] for e in diagnostics}) == 1
    assert all(str(e["phase"]) == "5" and e["agent"] == "intrusion" for e in diagnostics)
    assert not any(e["type"] == "provider_diagnostic" for e in events)
    assert full.tracker.total_tokens() == (300, 30)


def test_failed_finalization_keeps_observations_but_not_success_events(full):
    create = full.provider.client.chat.completions.create
    create.side_effect = [response(ACTION)] + [response(text="Done") for _ in range(6)]
    status, events = run_phase(full)
    assert status == "failed:phase5_completion_missing"
    assert full.offline_action.call_count == 1
    assert create.call_count <= 6
    data = json.loads((full.run_dir / "05_intrusion.json").read_text())
    assert data["status"] == "incomplete"
    assert data["summary"]["devices_attempted"] == 1
    assert data["chains"] == []
    assert not [e for e in events if e["type"] in {"intrusion_done", "intrusion_hop", "intrusion_compromised"}]
    assert any(e["type"] == "warn" for e in events)
    diagnostics = [json.loads(s) for s in (full.run_dir / "provider_events.jsonl").read_text().splitlines()]
    assert len([e for e in diagnostics if e["event"] == "request"]) == create.call_count
    assert len([e for e in diagnostics if e["event"] == "terminal"]) == 1
    assert not any(e["event"] == "save_outcome" and e["outcome"] == "accepted" for e in diagnostics)


def test_invalid_save_cannot_be_promoted_to_completed(full):
    invalid = ("save_deliverable", {"filename": "05_intrusion.json", "content": "not JSON"})
    full.provider.client.chat.completions.create.side_effect = [response(ACTION), response(text="Done")] + [response(invalid) for _ in range(6)]
    status, _ = run_phase(full)
    assert status.startswith("failed:phase5_completion_")
    attempts = [json.loads(s) for s in (full.run_dir / "deliverable_attempts.jsonl").read_text().splitlines()]
    assert attempts and all(not a["valid"] for a in attempts)
    assert full.offline_action.call_count == 1
    diagnostics = [json.loads(s) for s in (full.run_dir / "provider_events.jsonl").read_text().splitlines()]
    saves = [e for e in diagnostics if e["event"] == "save_outcome"]
    attempted_refs = {a["attempt_ref"] for a in attempts}
    archived_saves = [e for e in saves if "attempt_ref" in e]
    assert archived_saves
    assert all(e["outcome"] == "rejected" for e in saves)
    assert {e["attempt_ref"] for e in archived_saves} == attempted_refs


@pytest.mark.parametrize("content", [
    "{}", "[]", "null", "true", '"finished"',
    '{"summary":{},"chains":[],"compromised_devices":[],"credential_pool":[]}',
    json.dumps({**json.loads(SAVE[1]["content"]), "status": "incomplete"}),
])
def test_structurally_incomplete_json_is_archived_not_promoted(full, content):
    invalid = ("save_deliverable", {"filename": "05_intrusion.json", "content": content})
    full.provider.client.chat.completions.create.side_effect = [response(ACTION)] + [response(invalid)] * 6
    status, events = run_phase(full)
    assert status.startswith("failed:")
    assert full._full_intrusion_saved is False
    assert full.offline_action.call_count == 1
    attempts = [json.loads(s) for s in (full.run_dir / "deliverable_attempts.jsonl").read_text().splitlines()]
    assert attempts and all(a["validator"] == "json_intrusion" and a["valid"] is False for a in attempts)
    assert all((full.run_dir / a["attempt_ref"]).read_text() == content for a in attempts)
    assert json.loads((full.run_dir / "05_intrusion.json").read_text())["status"] == "incomplete"
    assert not any(e["type"] in {"intrusion_done", "intrusion_compromised", "intrusion_hop"} for e in events)


def test_rejected_structure_can_be_repaired_without_repeating_actions(full):
    invalid = ("save_deliverable", {"filename": "05_intrusion.json", "content": "{}"})
    create = full.provider.client.chat.completions.create
    create.side_effect = [response(ACTION), response(invalid), response(SAVE)]
    status, events = run_phase(full)
    assert status == "completed"
    assert full.offline_action.call_count == 1
    assert create.call_count == 3
    attempts = [json.loads(s) for s in (full.run_dir / "deliverable_attempts.jsonl").read_text().splitlines()]
    assert [a["valid"] for a in attempts] == [False, True]
    assert len({a["attempt_ref"] for a in attempts}) == 2
    assert json.loads((full.run_dir / "05_intrusion.json").read_text()) == json.loads(SAVE[1]["content"])
    assert not any(e["type"] in {"intrusion_compromised", "intrusion_hop"} for e in events)
    done = next(e for e in events if e["type"] == "intrusion_done")
    assert done["devices_compromised"] == 0 and done["hops"] == 0


def test_rejected_submission_does_not_overwrite_existing_valid_file(full):
    original = SAVE[1]["content"]
    (full.run_dir / "05_intrusion.json").write_text(original)
    invalid = ("save_deliverable", {"filename": "05_intrusion.json", "content": "{}"})
    full.provider.client.chat.completions.create.side_effect = [response(invalid)] * 6
    status = full._run_agent(AGENTS["intrusion"])
    assert status.startswith("failed:")
    assert not full._full_intrusion_saved
    assert (full.run_dir / "05_intrusion.json").read_text() == original


def test_stop_does_not_trigger_an_extra_model_or_action_call(full):
    create = full.provider.client.chat.completions.create
    def answer(**kwargs):
        full._stop_event.set()
        return response(text="Done")
    create.side_effect = answer
    status, _ = run_phase(full)
    assert status == "stopped"
    assert create.call_count == 1
    full.offline_action.assert_not_called()


def test_budget_exception_is_not_hidden_by_finalization(full):
    create = full.provider.client.chat.completions.create
    original = BudgetExceeded("offline budget")
    create.side_effect = [response(text="Done"), original]
    with pytest.raises(BudgetExceeded) as caught:
        full._run_agent(AGENTS["intrusion"])
    assert caught.value is original
    full.offline_action.assert_not_called()


def test_existing_file_cannot_replace_a_new_accepted_submission(full):
    (full.run_dir / "05_intrusion.json").write_text(SAVE[1]["content"])
    full.provider.client.chat.completions.create.side_effect = [response(ACTION)] + [response(text="Done") for _ in range(6)]
    status, events = run_phase(full)
    assert status == "failed:phase5_completion_missing"
    assert json.loads((full.run_dir / "05_intrusion.json").read_text())["status"] == "incomplete"
    assert not any(e["type"] == "intrusion_done" for e in events)


def test_successful_save_without_stall_emits_one_final_event(full):
    full.provider.client.chat.completions.create.side_effect = [response(SAVE)]
    status, _ = run_phase(full)
    assert status == "completed"
    assert full.provider.client.chat.completions.create.call_count == 1


def test_repeated_actions_end_in_save_only_not_another_credential_burst(full):
    create = full.provider.client.chat.completions.create
    create.side_effect = [response(ACTION)] * 3 + [response(text="Final burst"), response(SAVE)]
    status, _ = run_phase(full)
    assert status == "completed"
    assert full.offline_action.call_count == 2
    assert create.call_count == 5
    for request in create.call_args_list[3:]:
        assert [t["function"]["name"] for t in request.kwargs["tools"]] == ["save_deliverable"]


def test_stop_after_accepted_save_is_not_announced_as_success(full):
    original = deliverable.save_deliverable
    def stopping_save(**kwargs):
        result = original(**kwargs, output_dir=full.run_dir)
        full._stop_event.set()
        return result
    saved_tools = full._resolve_tools(AGENTS["intrusion"])
    full._resolve_tools = lambda _: [
        {**t, "function": stopping_save} if t["name"] == "save_deliverable" else t
        for t in saved_tools
    ]
    full.provider.client.chat.completions.create.side_effect = [response(SAVE)]
    status, events = run_phase(full)
    assert status == "stopped"
    assert not any(e["type"] == "intrusion_done" for e in events)


def test_empty_completion_keeps_reported_token_usage(full):
    empty = SimpleNamespace(choices=[], usage=SimpleNamespace(prompt_tokens=100, completion_tokens=10))
    full.provider.client.chat.completions.create.side_effect = [response(ACTION), empty, response(SAVE)]
    status, events = run_phase(full)
    assert status == "completed"
    assert full.tracker.total_tokens() == (300, 30)
    assert next(e for e in events if e["type"] == "phase_done")["turns"] == 3


def test_sdk_does_not_retry_failed_closing_requests(full):
    import httpx
    import openai

    requests = []
    def respond(request):
        requests.append(json.loads(request.content))
        if len(requests) <= 2:
            return httpx.Response(200, json={
                "id": "offline", "object": "chat.completion", "created": 1, "model": "offline",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Done"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110},
            })
        return httpx.Response(500, json={"error": {"message": "offline provider failure"}})

    with httpx.Client(transport=httpx.MockTransport(respond)) as transport:
        with openai.OpenAI(api_key="offline", base_url="https://offline.invalid/v1", http_client=transport, max_retries=2) as client:
            full.provider.client = client
            full.provider._retry_limit = 2
            with pytest.raises(openai.InternalServerError):
                full._run_agent(AGENTS["intrusion"])
    assert len(requests) == 3
    assert [t["function"]["name"] for t in requests[1]["tools"]] == [
        "try_credential", "save_deliverable"
    ]
    assert [t["function"]["name"] for t in requests[-1]["tools"]] == ["save_deliverable"]
    full.offline_action.assert_not_called()
