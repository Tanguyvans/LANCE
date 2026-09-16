"""Independent review: the new probe must use the common safety boundary."""
import json
from threading import Event, Lock
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.agent.core.executor import wrap_tool
from src.agent.tools.recon_tools import RECON_TOOLS


@pytest.fixture
def boundary(tmp_path):
    handler = Mock(return_value=json.dumps({"success": False, "status": "timeout"}))
    definition = next(tool for tool in RECON_TOOLS if tool["name"] == "mqtt_ws_listen")
    run = SimpleNamespace(
        run_dir=tmp_path, _artifact_log_lock=Lock(), max_tool_calls=None,
        _tool_call_count=0, context={"target_subnet": "192.0.2.0/24"},
        tracker=SimpleNamespace(check_budget=Mock()), _stop_event=Event(),
        benchmark_split="dev-public",
        _exploit_tool_context=SimpleNamespace(vulnerability={
            "vuln_id": "V1", "device_ip": "192.0.2.11", "port": 9001,
        }),
    )
    return run, {**definition, "function": handler}, handler


@pytest.mark.parametrize("profile", ["full", "compact"])
@pytest.mark.parametrize("phase", [4, 5])
def test_ws_outside_scope_is_archived_but_never_executed(boundary, profile, phase):
    run, tool, handler = boundary
    run.execution_profile = SimpleNamespace(name=profile)
    request = {"ip": "198.51.100.11", "port": 9001, "path": "/", "topic": "#"}
    result = json.loads(wrap_tool(run, tool, phase=phase)["function"](**request))
    handler.assert_not_called()
    assert result["error_kind"].startswith("intrusion_target_")
    record, = [json.loads(line) for line in (run.run_dir / "tool_calls.jsonl").read_text().splitlines()]
    assert record["args"] == request
    assert record["execution_origin"] == "runner"
    assert json.loads(record["result"]) == result
    assert "execution_attestation" not in result


def test_ws_stop_does_not_execute(boundary):
    run, tool, handler = boundary
    run._stop_event.set()
    result = json.loads(wrap_tool(run, tool, phase=4)["function"](
        ip="192.0.2.11", port=9001, path="/", topic="#",
    ))
    assert result["error_kind"] == "run_stopped"
    handler.assert_not_called()


def test_ws_budget_does_not_execute_or_invent_trace(boundary):
    run, tool, handler = boundary
    run.max_tool_calls = 0
    with pytest.raises(RuntimeError, match="Tool-call budget exhausted"):
        wrap_tool(run, tool, phase=4)["function"](
            ip="192.0.2.11", port=9001, path="/", topic="#",
        )
    handler.assert_not_called()
    assert not (run.run_dir / "tool_calls.jsonl").exists()


def test_ws_in_scope_uses_original_args_and_archives_observation(boundary):
    run, tool, handler = boundary
    request = {"ip": "192.0.2.11", "port": 9002, "path": "/mqtt", "topic": "sensors/#"}
    result = wrap_tool(run, tool, phase=4)["function"](**request)
    handler.assert_called_once_with(**request)
    record, = [json.loads(line) for line in (run.run_dir / "tool_calls.jsonl").read_text().splitlines()]
    assert record["args"] == request
    assert record["claim_context"]["port"] == 9001
    assert record["evidence_ref"].startswith("tc-")
    assert record["result"] == result
