"""Recon completion must not depend on a model reproducing the inventory."""
import json
import threading

import pytest

from src.agent.pipeline import Pipeline
from src.agent.registry import AGENTS
from src.agent.cost_tracker import BudgetExceeded
from src.agent.phases.recon.rendering import render_recon


@pytest.mark.parametrize("outcome", ["length", "normal", "missing", "corrupt", "stopped", "failed_probe", "incomplete", "budget"])
def test_recorded_recon_completion(mock_provider, output_dir, monkeypatch, outcome):
    import src.agent.tools.graph_tools as graph_tools
    nodes = [{"id": "a", "ip": "192.0.2.1", "role": "router"},
             {"id": "b", "ip": "192.0.2.2", "role": "router"}]
    monkeypatch.setattr(graph_tools, "_scenario_topology", {"nodes": nodes})
    pipeline = Pipeline(provider=mock_provider, execution_profile="full")
    pipeline.context = {"target_subnet": "192.0.2.0/24"}
    pipeline._stop_event = threading.Event()
    scans = []

    def tool(name):
        def execute(**args):
            if name == "save_deliverable":
                (pipeline.run_dir / args["filename"]).write_text(args["content"])
                return json.dumps({"status": "saved"})
            if name == "arp_scan":
                result = {"hosts": [{"ip": n["ip"]} for n in nodes]}
            elif name == "nmap_discovery":
                result = {"stdout": "Nmap scan report for 192.0.2.1\nNmap scan report for 192.0.2.2"}
            elif name == "nmap_scan":
                scans.append(args["target"])
                result = {"stdout": "22/tcp open ssh test", "return_code": 0}
                if outcome == "failed_probe" and args["target"] == "192.0.2.2":
                    result = {"stdout": "", "stderr": "probe failed", "return_code": 1}
            else:
                result = {"content": "Graph"}
            with (pipeline.run_dir / "tool_calls.jsonl").open("a") as handle:
                handle.write(json.dumps({"phase": 2, "tool": name, "args": args, "result": result}) + "\n")
            return json.dumps(result)
        return {"name": name, "description": name, "input_schema": {}, "function": execute}

    monkeypatch.setattr(pipeline, "_resolve_tools", lambda _: [tool(n) for n in
        ["arp_scan", "nmap_discovery", "nmap_scan", "read_deliverable", "save_deliverable"]])

    def model(**kwargs):
        tools = {t["name"]: t["function"] for t in kwargs["tools"]}
        if outcome == "missing":
            return "truncated"
        tools["arp_scan"]()
        tools["nmap_discovery"](target="192.0.2.0/24")
        tools["read_deliverable"](filename="01_graph_analysis.md")
        for row in pipeline._recon_scan_plan(nodes):
            if outcome == "incomplete" and row["target"] == "192.0.2.2":
                continue
            tools["nmap_scan"](target=row["target"], ports=row["ports"])
            if outcome == "failed_probe" and row["target"] == "192.0.2.2":
                tools["nmap_scan"](target=row["target"], ports=row["ports"])
        if outcome == "corrupt":
            with (pipeline.run_dir / "tool_calls.jsonl").open("a") as handle:
                handle.write("invalid json\n")
        if outcome == "stopped":
            pipeline._stop_event.set()
        if outcome == "normal":
            tools["save_deliverable"](filename="02_recon.md", content="Invented model facts")
        if outcome == "budget":
            raise BudgetExceeded("test budget exhausted")
        return "truncated model text"

    mock_provider.chat_with_tools.side_effect = model
    if outcome == "budget":
        with pytest.raises(BudgetExceeded):
            pipeline._run_agent(AGENTS["recon"])
        assert not (pipeline.run_dir / "02_recon.md").exists()
        return
    status = pipeline._run_agent(AGENTS["recon"])
    path = pipeline.run_dir / "02_recon.md"
    if outcome in {"length", "normal", "failed_probe"}:
        assert status == "completed"
        text = path.read_text()
        assert "192.0.2.1" in text and "192.0.2.2" in text
        assert "Invented model facts" not in text
        assert "truncated model text" not in text
        if outcome == "failed_probe":
            assert "probe failed" in text and "Incomplete observations" in text
        assert len(scans) == (3 if outcome == "failed_probe" else 2)
    else:
        assert status == "stopped" if outcome == "stopped" else status.startswith("failed:")
        assert not path.exists()
    assert mock_provider.chat_with_tools.call_count == 1


def test_renderer_rejects_incomplete_contract():
    with pytest.raises(ValueError):
        render_recon({"devices": [{}]}, {"ready_to_save": False})
