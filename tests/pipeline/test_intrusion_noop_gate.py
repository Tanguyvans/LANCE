"""Phase 5 refuses a terminal finish while no intrusion action was attempted.

Regression test for S12 run 2026-10-07_211430 (blocked): the full-profile
intrusion agent finished after 6 turns with 12 read-only calls and zero
attempts, although entry points existed. The compact profile already has
stall guards; the full profile had no equivalent enforcement.
"""
import json
import threading
from types import SimpleNamespace

from src.agent.phases.intrusion.run import IntrusionPhase


TERMINAL = "05_intrusion.json"


def _self(tmp_path, *, stopped=False, dry_run=False):
    event = threading.Event()
    if stopped:
        event.set()
    (tmp_path / "tool_calls.jsonl").write_text("", encoding="utf-8")
    return SimpleNamespace(run_dir=tmp_path, _stop_event=event, dry_run=dry_run)


def _context(tmp_path, entry_points):
    (tmp_path / "05_intrusion_context.json").write_text(
        json.dumps({"entry_points": entry_points}), encoding="utf-8",
    )


def _ledger(tmp_path, *records):
    with (tmp_path / "tool_calls.jsonl").open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def _tools(calls, *, with_actions=True):
    def save(*, filename, content):
        calls.append((filename, content))
        return json.dumps({"ok": True, "status": "saved"})

    tools = [{"name": "save_deliverable", "function": save}]
    if with_actions:
        tools.append({"name": "ssh_login", "function": lambda **kwargs: "{}"})
    else:
        tools.append({"name": "read_deliverable", "function": lambda **kwargs: "{}"})
    return tools


def _guard(run, tools):
    return {
        tool["name"]: tool["function"]
        for tool in IntrusionPhase._apply_intrusion_noop_gate(run, tools, TERMINAL)
    }


def test_finish_refused_without_actions_when_entry_points_exist(tmp_path):
    run = _self(tmp_path)
    _context(tmp_path, [{"device_ip": "192.168.100.11"}])
    _ledger(tmp_path, {"phase": 5, "tool": "read_deliverable", "args": {}})
    calls = []
    save = _guard(run, _tools(calls))["save_deliverable"]
    result = json.loads(save(filename=TERMINAL, content="{}"))
    assert result["ok"] is False
    assert result["error_kind"] == "intrusion_no_action"
    assert calls == []


def test_other_files_save_freely(tmp_path):
    run = _self(tmp_path)
    _context(tmp_path, [{"device_ip": "192.168.100.11"}])
    calls = []
    save = _guard(run, _tools(calls))["save_deliverable"]
    assert json.loads(save(filename="notes.md", content="x"))["ok"] is True
    assert calls == [("notes.md", "x")]


def test_finish_allowed_after_action(tmp_path):
    run = _self(tmp_path)
    _context(tmp_path, [{"device_ip": "192.168.100.11"}])
    _ledger(tmp_path, {"phase": 5, "tool": "ssh_login",
                       "args": {"host": "192.168.100.11"}})
    calls = []
    save = _guard(run, _tools(calls))["save_deliverable"]
    assert json.loads(save(filename=TERMINAL, content="{}"))["ok"] is True
    assert len(calls) == 1


def test_errored_attempt_counts_as_attempt(tmp_path):
    run = _self(tmp_path)
    _context(tmp_path, [{"device_ip": "192.168.100.11"}])
    _ledger(tmp_path, {"phase": 5, "tool": "ssh_login",
                       "args": {"host": "192.168.100.11"},
                       "result": json.dumps({"error": "auth failed"})})
    calls = []
    save = _guard(run, _tools(calls))["save_deliverable"]
    assert json.loads(save(filename=TERMINAL, content="{}"))["ok"] is True


def test_finish_allowed_without_entry_points(tmp_path):
    run = _self(tmp_path)
    _context(tmp_path, [])
    calls = []
    save = _guard(run, _tools(calls))["save_deliverable"]
    assert json.loads(save(filename=TERMINAL, content="{}"))["ok"] is True


def test_finish_allowed_when_stopped_or_dry_run(tmp_path):
    for run in (_self(tmp_path, stopped=True), _self(tmp_path, dry_run=True)):
        _context(tmp_path, [{"device_ip": "192.168.100.11"}])
        calls = []
        save = _guard(run, _tools(calls))["save_deliverable"]
        assert json.loads(save(filename=TERMINAL, content="{}"))["ok"] is True


def test_gate_skipped_without_action_tools_in_surface(tmp_path):
    run = _self(tmp_path)
    _context(tmp_path, [{"device_ip": "192.168.100.11"}])
    calls = []
    save = _guard(run, _tools(calls, with_actions=False))["save_deliverable"]
    assert json.loads(save(filename=TERMINAL, content="{}"))["ok"] is True
    assert len(calls) == 1


def test_missing_context_file_allows_finish(tmp_path):
    run = _self(tmp_path)
    calls = []
    save = _guard(run, _tools(calls))["save_deliverable"]
    assert json.loads(save(filename=TERMINAL, content="{}"))["ok"] is True
