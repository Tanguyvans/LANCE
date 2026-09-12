"""MQTT destination fidelity through the real shared executor and ledger.

Only the process launcher is mocked: no broker or lab access is performed.
"""
import json
from threading import Event, Lock
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.agent.core.executor import EvidenceWriteError, wrap_tool
from src.agent.exploit_evidence import synthesize_exploit_result
from src.agent.tools.tool_loader import load_all_tools


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    launcher = Mock(return_value={
        "stdout": "sensors/temp 22\n", "stderr": "Timed out\n", "return_code": 27,
    })
    monkeypatch.setattr("src.agent.tools.recon_tools._run", launcher)
    run = SimpleNamespace(
        run_dir=tmp_path, _artifact_log_lock=Lock(), max_tool_calls=None,
        _tool_call_count=0, context={"target_subnet": "192.0.2.0/24"},
        tracker=SimpleNamespace(check_budget=Mock()),
        _stop_event=Event(), benchmark_split="dev-public",
        _exploit_tool_context=SimpleNamespace(vulnerability={
            "vuln_id": "fixture", "device_ip": "192.0.2.11", "port": 1883,
        }),
    )
    tool = next(tool for tool in load_all_tools() if tool["name"] == "mqtt_listen")
    return run, tool, launcher


def _records(run):
    return [json.loads(line) for line in (run.run_dir / "tool_calls.jsonl").read_text().splitlines()]


@pytest.mark.parametrize("profile", ["full", "compact"])
@pytest.mark.parametrize("phase", [4, 5])
@pytest.mark.parametrize("port_args,effective_port", [({}, 1883), ({"port": "9001"}, 9001)])
def test_requested_and_effective_destination_are_both_archived(boundary, profile, phase, port_args, effective_port):
    run, tool, launcher = boundary
    run.execution_profile = SimpleNamespace(name=profile)
    requested = {"broker": "192.0.2.11", "topic": "sensors/#", **port_args}
    receipt = json.loads(wrap_tool(run, tool, phase=phase)["function"](**requested))
    argv = launcher.call_args.args[0]
    assert argv[argv.index("-p") + 1] == str(effective_port)
    assert argv[argv.index("-h") + 1] == "192.0.2.11"
    assert argv[argv.index("-t") + 1] == "sensors/#"
    assert receipt["stdout"] == "sensors/temp 22\n"
    assert receipt["stderr"] == "Timed out\n"
    assert receipt["return_code"] == 27
    assert receipt["execution_attestation"] == {
        "protocol": "TCP", "host": "192.0.2.11",
        "port": effective_port, "topic": "sensors/#",
        "output_format": "mosquitto-json-v1",
    }
    record, = _records(run)
    assert record["args"] == requested  # Do not rewrite the model's request.
    assert record["claim_context"]["port"] == 1883  # Claim != execution fact.
    assert json.loads(record["result"]) == receipt
    assert record["execution_origin"] == "runner"
    assert record["phase"] == phase
    assert record["evidence_ref"].startswith("tc-")
    assert record["sequence"] == 1


@pytest.mark.parametrize("profile", ["full", "compact"])
@pytest.mark.parametrize("broker", ["198.51.100.11", "example.invalid"])
def test_scope_refusal_still_precedes_execution(boundary, profile, broker):
    run, tool, launcher = boundary
    run.execution_profile = SimpleNamespace(name=profile)
    receipt = json.loads(wrap_tool(run, tool, phase=5)["function"](broker=broker, port=9001))
    assert receipt["ok"] is False
    assert receipt["error_kind"].startswith("intrusion_target_")
    launcher.assert_not_called()
    assert "execution_attestation" not in receipt
    assert json.loads(_records(run)[0]["result"]) == receipt


@pytest.mark.parametrize("extra", [{"prot": 9001}, {"port": 0}, {"port": True}, {"port": "9001 -h 198.51.100.11"}])
def test_invalid_request_is_archived_without_execution_or_fake_receipt(boundary, extra):
    run, tool, launcher = boundary
    receipt = json.loads(wrap_tool(run, tool, phase=4)["function"](broker="192.0.2.11", **extra))
    launcher.assert_not_called()
    assert receipt.get("ok") is False or receipt.get("error")
    assert "execution_attestation" not in receipt
    assert len(_records(run)) == 1
    assert json.loads(_records(run)[0]["result"]) == receipt


@pytest.mark.parametrize("overrides", [
    {"broker": None}, {"broker": ""}, {"topic": None}, {"port": "9" * 5000},
])
def test_malformed_destination_is_a_refusal_not_an_unhandled_exception(boundary, overrides):
    run, tool, launcher = boundary
    request = {"broker": "192.0.2.11", **overrides}
    receipt = json.loads(wrap_tool(run, tool, phase=4)["function"](**request))
    assert receipt.get("error")
    assert "execution_attestation" not in receipt
    launcher.assert_not_called()
    assert json.loads(_records(run)[0]["result"]) == receipt


@pytest.mark.parametrize("topic", ["-h", "-p", "-t"])
def test_topic_values_cannot_be_confused_with_command_flags(boundary, topic):
    run, tool, launcher = boundary
    receipt = json.loads(wrap_tool(run, tool, phase=4)["function"](
        broker="192.0.2.11", port=1884, topic=topic,
    ))
    assert receipt["execution_attestation"] == {
        "protocol": "TCP", "host": "192.0.2.11", "port": 1884, "topic": topic,
        "output_format": "mosquitto-json-v1",
    }
    argv = launcher.call_args.args[0]
    assert argv[argv.index("-t") + 1] == topic


def test_stop_refuses_mqtt_without_executing(boundary):
    run, tool, launcher = boundary
    run._stop_event.set()
    receipt = json.loads(wrap_tool(run, tool, phase=5)["function"](broker="192.0.2.11", port=1884))
    assert receipt["error_kind"] == "run_stopped"
    launcher.assert_not_called()
    assert "execution_attestation" not in receipt


def test_budget_exhaustion_does_not_launch_or_create_execution_evidence(boundary):
    run, tool, launcher = boundary
    run.max_tool_calls = 0
    with pytest.raises(RuntimeError, match="Tool-call budget exhausted"):
        wrap_tool(run, tool, phase=5)["function"](broker="192.0.2.11", port=1884)
    launcher.assert_not_called()
    assert not (run.run_dir / "tool_calls.jsonl").exists()


def test_tcp_receipt_on_9001_is_not_a_websocket_proof(boundary):
    run, tool, launcher = boundary
    args = {"broker": "192.0.2.11", "port": 9001, "topic": "#"}
    receipt = json.loads(wrap_tool(run, tool, phase=4)["function"](**args))
    proof = synthesize_exploit_result(
        {"type": "no_auth", "service": "mqtt-ws", "port": 9001, "device_ip": "192.0.2.11"},
        [{"tool": "mqtt_listen", "args": args, "result": receipt}],
    )
    assert proof["status"] != "EXPLOITED"
    assert proof["evidence_level"] < 2


def test_each_call_records_its_own_port_and_fresh_output(boundary):
    run, tool, launcher = boundary
    launcher.side_effect = [
        {"stdout": "sensors/temp 1\n", "stderr": "", "return_code": 0},
        {"stdout": "sensors/temp 999\n", "stderr": "", "return_code": 0},
    ]
    execute = wrap_tool(run, tool, phase=4)["function"]
    execute(broker="192.0.2.11", port=1883)
    execute(broker="192.0.2.11", port=1884)
    records = _records(run)
    assert len({record["evidence_ref"] for record in records}) == 2
    receipts = [json.loads(record["result"]) for record in records]
    assert [r["execution_attestation"]["port"] for r in receipts] == [1883, 1884]
    assert [r["stdout"] for r in receipts] == ["sensors/temp 1\n", "sensors/temp 999\n"]


def test_evidence_write_failure_is_not_hidden_by_successful_mqtt(boundary):
    run, tool, launcher = boundary
    (run.run_dir / "tool_calls.jsonl").mkdir()
    with pytest.raises(EvidenceWriteError):
        wrap_tool(run, tool, phase=4)["function"](broker="192.0.2.11", port=1883)
    launcher.assert_called_once()
    assert run._evidence_integrity_failed is True
