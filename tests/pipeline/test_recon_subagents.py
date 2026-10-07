"""Recon sub-agents: batch split, eligibility, ledger merge, batch contract."""
import json
from types import SimpleNamespace

import pytest

from src.agent.phases.recon.run import ReconPhase, expand_port_spec
from src.agent.phases.recon.subagents import (
    merge_recon_progress,
    split_recon_batches,
    subagents_eligible,
)
from src.agent.validators import validate_recon_markdown


def _plan_row(target, ports="22,80", device_id=None, role="router"):
    return {
        "target": target, "ports": ports,
        "device_id": device_id or target, "role": role,
    }


def test_split_recon_batches_preserves_order_and_sizes():
    rows = [_plan_row(f"192.0.2.{index}") for index in range(1, 8)]
    batches = split_recon_batches(rows, per_batch=3)
    assert [len(batch) for batch in batches] == [3, 3, 1]
    assert [row["target"] for batch in batches for row in batch] == [
        row["target"] for row in rows
    ]


def test_split_recon_batches_env_override(monkeypatch):
    rows = [_plan_row(f"192.0.2.{index}") for index in range(1, 5)]
    monkeypatch.setenv("LANCE_RECON_DEVICES_PER_BATCH", "2")
    assert [len(batch) for batch in split_recon_batches(rows)] == [2, 2]
    monkeypatch.setenv("LANCE_RECON_DEVICES_PER_BATCH", "0")
    assert [len(batch) for batch in split_recon_batches(rows)] == [4]


def test_expand_port_spec_matches_contract_syntax():
    assert expand_port_spec("22,80,8000-8002") == {22, 80, 8000, 8001, 8002}
    assert expand_port_spec("T:443, U:161") == {443, 161}
    assert expand_port_spec("bogus") == set()


def _eligible_pipeline(**overrides):
    base = {
        "dry_run": False,
        "_uses_compact_local_moe": lambda: False,
        "decision_policy": "llm",
        "sealed": False,
        "target_network": None,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _topology(count):
    return {
        "nodes": [
            {"id": f"d{index}", "ip": f"192.0.2.{index}", "role": "router"}
            for index in range(1, count + 1)
        ],
    }


def test_subagents_eligible_keeps_special_modes_on_single_agent(monkeypatch):
    import src.agent.tools.graph_tools as graph_tools

    monkeypatch.setattr(graph_tools, "_scenario_topology", _topology(8))
    # More than one batch of coverage: fan-out is worth the orchestration.
    assert subagents_eligible(_eligible_pipeline(), None) is True
    assert subagents_eligible(_eligible_pipeline(dry_run=True), None) is False
    assert subagents_eligible(
        _eligible_pipeline(_uses_compact_local_moe=lambda: True), None,
    ) is False
    assert subagents_eligible(_eligible_pipeline(decision_policy="rules"), None) is False
    assert subagents_eligible(_eligible_pipeline(sealed=True), None) is False
    assert subagents_eligible(_eligible_pipeline(target_network="192.0.2.0/24"), None) is False


def test_subagents_eligible_stays_single_agent_within_one_batch(monkeypatch):
    import src.agent.tools.graph_tools as graph_tools

    # A plan that fits in a single batch (default 6): the generalist keeps
    # it, since one batch agent plus orchestration buys no context benefit.
    monkeypatch.setattr(graph_tools, "_scenario_topology", _topology(2))
    assert subagents_eligible(_eligible_pipeline(), None) is False
    # Blind mode (no declared topology) cannot be split upfront either.
    monkeypatch.setattr(graph_tools, "_scenario_topology", None)
    assert subagents_eligible(_eligible_pipeline(), None) is False


def _ledger_success(tool, args, stdout=""):
    return {
        "phase": 2, "tool": tool, "args": args,
        "result": json.dumps({"stdout": stdout, "return_code": 0}),
    }


def test_merge_recon_progress_ready_when_ledger_covers_plan():
    plan = [_plan_row("192.0.2.1"), _plan_row("192.0.2.2", ports="1883")]
    ledger = [
        _ledger_success("arp_scan", {}),
        _ledger_success("nmap_discovery", {"target": "192.0.2.0/24"},
                        "Nmap scan report for 192.0.2.1"),
        _ledger_success("read_deliverable", {"filename": "01_graph_analysis.md"}),
        _ledger_success("nmap_scan", {"target": "192.0.2.1", "ports": "22,80"},
                        "22/tcp open ssh\n80/tcp open http"),
        _ledger_success("nmap_scan", {"target": "192.0.2.2", "ports": "1883"},
                        "1883/tcp open mqtt"),
    ]
    progress = merge_recon_progress(plan, ledger, ["192.0.2.0/24"])
    assert progress["ready_to_save"] is True
    assert progress["missing_requirements"] == []
    assert progress["completed"] == {
        "local_discovery": True, "subnet_discovery": True, "phase1_context": True,
    }


def test_merge_recon_progress_reports_missing_and_two_strike_failures():
    plan = [_plan_row("192.0.2.1"), _plan_row("192.0.2.9", ports="23")]
    failed = {"phase": 2, "tool": "nmap_scan",
              "args": {"target": "192.0.2.9", "ports": "23"},
              "result": json.dumps({"stdout": "", "stderr": "down", "return_code": 1})}
    ledger = [
        _ledger_success("arp_scan", {}),
        _ledger_success("nmap_scan", {"target": "192.0.2.1", "ports": "22,80"},
                        "22/tcp open ssh"),
        failed, dict(failed),
    ]
    progress = merge_recon_progress(plan, ledger, ["192.0.2.0/24"])
    assert progress["ready_to_save"] is False
    by_target = {row["target"]: row for row in progress["targets"]}
    assert by_target["192.0.2.9"]["failed_ports"] == [23]
    assert by_target["192.0.2.9"]["missing_ports"] == []
    missing_reqs = [req["requirement"] for req in progress["missing_requirements"]]
    assert "subnet_discovery" in missing_reqs
    assert "phase1_context" in missing_reqs


def _contract_self():
    return SimpleNamespace(
        context={"target_subnet": "192.0.2.0/24"},
        _uses_compact_local_moe=lambda: False,
        _recon_scan_plan=ReconPhase._recon_scan_plan,
        _stop_event=None,
    )


def _nmap_tool(calls):
    def fn(*, target, ports, **kwargs):
        calls.append((target, ports))
        if target == "192.0.2.9":
            return json.dumps({"stdout": "", "stderr": "down", "return_code": 1})
        return json.dumps({"stdout": f"22/tcp open ssh", "return_code": 0})
    return {"name": "nmap_scan", "function": fn}


def _save_tool(receipts):
    def fn(*, filename, content):
        receipts.append((filename, content))
        return json.dumps({"ok": True, "status": "saved"})
    return {"name": "save_deliverable", "function": fn}


def test_batch_contract_scopes_ledger_to_its_nodes():
    nodes = [
        {"id": "r1", "ip": "192.0.2.1", "role": "router"},
        {"id": "r2", "ip": "192.0.2.2", "role": "router"},
    ]
    calls, receipts = [], []
    tools = ReconPhase._apply_recon_tool_contract(
        _contract_self(), [_nmap_tool(calls), _save_tool(receipts)],
        nodes=nodes[:1], require_baseline=False,
    )
    by_name = {tool["name"]: tool["function"] for tool in tools}
    # The second node is outside this batch ledger: covering it is allowed
    # (wider scans are fine) but never required for this batch's save.
    by_name["nmap_scan"](
        target="192.0.2.1", ports="22,23,80,443,8080,8291", skip_discovery=True)
    save = json.loads(by_name["save_deliverable"](
        filename="02_recon_batch_01.json", content="{}"))
    assert save.get("ok") is not False
    assert receipts and receipts[0][0] == "02_recon_batch_01.json"


def test_sweep_contract_requires_baseline_trio():
    tools = ReconPhase._apply_recon_tool_contract(
        _contract_self(), [_save_tool([])], nodes=[],
    )
    by_name = {tool["name"]: tool["function"] for tool in tools}
    refused = json.loads(by_name["save_deliverable"](
        filename="02_recon_sweep.json", content="{}"))
    assert refused.get("ok") is False
    assert refused.get("error_kind") == "recon_contract_incomplete"


def test_batch_contract_blocks_save_until_batch_covered():
    nodes = [{"id": "r1", "ip": "192.0.2.1", "role": "router"}]
    tools = ReconPhase._apply_recon_tool_contract(
        _contract_self(), [_nmap_tool([]), _save_tool([])],
        nodes=nodes, require_baseline=False,
    )
    by_name = {tool["name"]: tool["function"] for tool in tools}
    by_name["nmap_scan"](target="192.0.2.1", ports="22", skip_discovery=True)
    refused = json.loads(by_name["save_deliverable"](
        filename="02_recon_batch_01.json", content="{}"))
    assert refused.get("ok") is False
    assert refused.get("error_kind") == "recon_contract_incomplete"


def test_merged_progress_renders_and_validates(tmp_path):
    from src.agent.phases.recon.rendering import render_recon

    projection = {
        "source_issues": [],
        "devices": [
            {"device": "r1", "ip": "192.0.2.1", "open_ports": [22],
             "services": [{"service": "ssh", "port": 22, "protocol": "tcp", "version": ""}],
             "failures": []},
            {"device": "r2", "ip": "192.0.2.2", "open_ports": [1883],
             "services": [{"service": "mqtt", "port": 1883, "protocol": "tcp", "version": ""}],
             "failures": []},
        ],
    }
    progress = {"ready_to_save": True, "targets": []}
    (tmp_path / "02_recon.md").write_text(
        render_recon(projection, progress), encoding="utf-8")
    ok, msg = validate_recon_markdown("02_recon.md", output_dir=tmp_path)
    assert ok, msg
