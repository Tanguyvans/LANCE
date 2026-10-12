"""Discovered hosts use the run's scope, cancellation, budget and raw ledger."""
import json
from threading import Event, Lock
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.agent.core import runtime
from src.agent.core.executor import RunStopped, wrap_tool
from src.agent.cost_tracker import BudgetExceeded, CostTracker
from src.agent.phases.recon.run import ReconPhase
from src.agent.phases.verification.run import VerificationPhase
from src.agent.registry import AGENTS


HOST = "192.0.2.10"


class Followup(ReconPhase):
    def __init__(self, run_dir):
        self.run_dir = run_dir
        self.context = {"target_subnet": "192.0.2.0/24"}
        self.provider = SimpleNamespace(chat_with_tools=Mock())
        self.tracker = CostTracker()
        self._stop_event = Event()
        self.scenario_tool_policy = None
        self.max_tool_calls = None
        self._tool_call_count = 0
        self._artifact_log_lock = Lock()
        self.benchmark_split = "unassigned"
        self.decision_policy = "llm"
        self._aggregate_device_vulns = Mock()
        self._aggregate_exploit_results = Mock()
        self.save_config = None

    def _uses_compact_local_moe(self):
        return False

    def _apply_scenario_tool_policy(self, tools, phase):
        return tools

    def _wrap_tool(self, tool, **kwargs):
        return wrap_tool(self, tool, **kwargs)

    def _apply_deliverable_transaction(self, tools, config, stream):
        self.save_config = config
        return tools

    def _model_stream_callback(self, *args, **kwargs):
        return None

    def run(self, ip=HOST):
        self._run_discovery_followup([{"ip": ip, "open_ports": [1883]}], AGENTS["exploitation"])


@pytest.fixture
def followup(tmp_path, monkeypatch):
    run = Followup(tmp_path)
    calls = Mock(return_value=json.dumps({"stdout": "1883/tcp open mqtt", "return_code": 0}))
    analysis = Mock(return_value=json.dumps({"stdout": "HTTP/1.1 200 OK", "return_code": 0}))
    tools = [{"name": "nmap_scan", "function": calls}, {"name": "http_get", "function": analysis}]
    monkeypatch.setattr(runtime, "RECON_TOOLS", tools)
    monkeypatch.setattr(runtime, "SKILL_TOOLS", [])
    monkeypatch.setattr(runtime, "DELIVERABLE_TOOLS", [])
    monkeypatch.setattr(runtime, "filter_unavailable_tools", lambda values: (values, {}))
    monkeypatch.setattr("src.agent.tools.tool_loader.filter_unavailable_tools", lambda values: (values, {}))
    monkeypatch.setattr(runtime, "load_prompt", lambda *_args: "offline")
    return run, calls, analysis


@pytest.mark.parametrize("ip", ["198.51.100.10", "bad-address", "192.0.2.0/24"])
def test_followup_ignores_unverifiable_or_out_of_scope_hosts(followup, ip):
    run, scanner, analysis = followup
    run.run(ip)
    scanner.assert_not_called()
    analysis.assert_not_called()
    run.provider.chat_with_tools.assert_not_called()
    run._aggregate_device_vulns.assert_not_called()
    assert not (run.run_dir / "tool_calls.jsonl").exists()


@pytest.mark.parametrize("restriction", ["stopped", "budget", "dry-run"])
def test_followup_honors_execution_limits_before_network_or_model(followup, restriction):
    run, scanner, _analysis = followup
    if restriction == "stopped":
        run._stop_event.set()
        with pytest.raises(RunStopped):
            run.run()
    elif restriction == "budget":
        run.max_tool_calls = 0
        with pytest.raises(BudgetExceeded):
            run.run()
    else:
        run.dry_run = True
        run.run()
    scanner.assert_not_called()
    run.provider.chat_with_tools.assert_not_called()
    run._aggregate_device_vulns.assert_not_called()


def test_followup_archives_scanner_and_analyst_observations(followup):
    run, scanner, analyst = followup

    def analyze(**kwargs):
        tool = next(tool for tool in kwargs["tools"] if tool["name"] == "http_get")
        tool["function"](url=f"http://{HOST}/config")

    run.provider.chat_with_tools.side_effect = analyze
    run.run()
    assert scanner.called and analyst.called
    records = [json.loads(line) for line in (run.run_dir / "tool_calls.jsonl").read_text().splitlines()]
    assert run._tool_call_count == len(records)
    assert all(record["phase"] == 3 and record["execution_origin"] == "runner" for record in records)
    assert any(record["agent"] == "followup_scanner" and record["decision_source"] == "rules" for record in records)
    assert any(record["agent"] == "followup_discovered-192-0-2-10" for record in records)
    raw = json.loads((run.run_dir / "03_scans/discovered-192-0-2-10.json").read_text())
    entries = [entry for values in raw.values() for entry in values]
    refs = {record["evidence_ref"] for record in records}
    assert entries and all(entry["evidence_ref"] in refs for entry in entries)
    assert run.save_config.validator == "json_device_vulns"
    assert not run.tracker._active
    run._aggregate_device_vulns.assert_called_once()
    run._aggregate_exploit_results.assert_called_once()


@pytest.mark.parametrize("failure", [RuntimeError("provider failed"), BudgetExceeded("provider budget")])
def test_followup_closes_cost_phase_on_failure(followup, failure):
    run, _scanner, _analyst = followup
    run.provider.chat_with_tools.side_effect = failure
    with pytest.raises(type(failure)):
        run.run()
    assert not run.tracker._active
    run._aggregate_device_vulns.assert_not_called()


def test_followup_stops_after_scanner_and_before_analyst(followup):
    run, scanner, _analyst = followup

    def scan(**kwargs):
        run._stop_event.set()
        return json.dumps({"stdout": "1883/tcp open mqtt", "return_code": 0})

    scanner.side_effect = scan
    with pytest.raises(RunStopped):
        run.run()
    run.provider.chat_with_tools.assert_not_called()


@pytest.mark.parametrize("ports", [None, "1883", [None, False, -1, 65536, "invalid", "1883", 1883]])
def test_followup_handles_malformed_model_ports_without_crashing(followup, ports):
    run, _scanner, _analyst = followup
    run._run_discovery_followup([{"ip": HOST, "open_ports": ports}], AGENTS["exploitation"])
    run.provider.chat_with_tools.assert_called_once()
    assert not run.tracker._active


@pytest.mark.parametrize("subnets,expected", [("192.0.2.0/24", [HOST]), ("", [])])
def test_discovery_collector_applies_scope_in_target_network_mode(tmp_path, subnets, expected):
    exploits = tmp_path / "04_exploits"
    exploits.mkdir()
    (exploits / "result.json").write_text(json.dumps({"new_hosts_discovered": [
        {"ip": HOST}, {"ip": "198.51.100.10"}, {"ip": "bad-address"},
        {"ip": "192.0.2.0/24"}, {"ip": HOST}, {"ip": None}, "malformed",
    ]}))
    run = SimpleNamespace(run_dir=tmp_path, scenario_id=None, context={"target_subnet": subnets})
    hosts = VerificationPhase._collect_new_hosts(run)
    assert [host["ip"] for host in hosts] == expected
