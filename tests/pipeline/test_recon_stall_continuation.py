"""Full Recon stalls must resume actions without accepting missing coverage."""
import json
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from src.agent.pipeline import Pipeline
from src.agent.provider import LLMProvider
from src.agent.registry import AGENTS


def _response(*calls, reason="tool_calls", text="Truncated reconnaissance narrative."):
    tools = [SimpleNamespace(
        id=f"call-{index}-{name}",
        function=SimpleNamespace(name=name, arguments=json.dumps(args)),
    ) for index, (name, args) in enumerate(calls)]
    return SimpleNamespace(
        choices=[SimpleNamespace(
            finish_reason=reason,
            message=SimpleNamespace(
                content=None if tools else text,
                tool_calls=tools or None,
            ),
        )],
        usage=None,
    )


@pytest.mark.parametrize("case", ["length", "empty_length", "text", "rejected_save", "stall_limit", "stopped"])
def test_full_recon_continues_actions_after_text_without_lowering_coverage(output_dir, monkeypatch, case):
    import src.agent.tools.graph_tools as graph_tools

    nodes = [{"id": "a", "ip": "192.0.2.1", "role": "router"},
             {"id": "b", "ip": "192.0.2.2", "role": "router"}]
    monkeypatch.setattr(graph_tools, "_scenario_topology", {"nodes": nodes})
    provider = LLMProvider.__new__(LLMProvider)
    provider.provider = "ollama-umons"
    provider.model = "qwen3.8:27b"
    provider._retry_limit = 0
    provider.client = MagicMock()
    provider.client.base_url = "http://offline.invalid"
    provider.client.with_options.return_value = provider.client
    pipeline = Pipeline(provider=provider, execution_profile="full")
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
            else:
                result = {"content": "Recorded graph"}
            with (pipeline.run_dir / "tool_calls.jsonl").open("a") as ledger:
                ledger.write(json.dumps({"phase": 2, "tool": name, "args": args,
                                         "result": result}) + "\n")
            return json.dumps(result)
        return {"name": name, "description": name, "input_schema": {}, "function": execute}

    monkeypatch.setattr(pipeline, "_resolve_tools", lambda _: [tool(n) for n in
        ["arp_scan", "nmap_discovery", "nmap_scan", "read_deliverable", "save_deliverable"]])
    plan = pipeline._recon_scan_plan(nodes)
    def scan(row):
        return ("nmap_scan", {"target": row["target"], "ports": row["ports"]})
    reason = "stop" if case == "text" else "length"
    responses = [_response(
        ("arp_scan", {}), ("nmap_discovery", {"target": "192.0.2.0/24"}),
        ("read_deliverable", {"filename": "01_graph_analysis.md"}), scan(plan[0]),
    )]
    if case == "rejected_save":
        responses.append(_response(("save_deliverable", {
            "filename": "02_recon.md", "content": "Invented full coverage",
        })))
    text = None if case == "empty_length" else "Truncated reconnaissance narrative."
    responses.extend([_response(reason=reason, text=text), _response(reason=reason, text=text)])
    if case == "stall_limit":
        responses.append(_response(reason=reason))
    else:
        responses.extend([
            _response(scan(plan[1])),
            _response(("save_deliverable", {"filename": "02_recon.md", "content": "Finished"})),
        ])
    calls = []

    def complete(**kwargs):
        # Snapshot each mutable request before the provider appends its next turn.
        calls.append({**kwargs, "tools": list(kwargs.get("tools", []))})
        if case == "stopped" and len(calls) == 2:
            pipeline._stop_event.set()
        return responses.pop(0)

    provider.client.chat.completions.create.side_effect = complete
    status = pipeline._run_agent(AGENTS["recon"])
    path = pipeline.run_dir / "02_recon.md"
    if case in {"stall_limit", "stopped"}:
        assert status == "stopped" if case == "stopped" else status.startswith("failed:")
        assert not path.exists()
        assert scans == ["192.0.2.1"]
        assert len(calls) == (2 if case == "stopped" else 4)
    else:
        assert status == "completed"
        assert scans == ["192.0.2.1", "192.0.2.2"]
        assert "Invented full coverage" not in path.read_text()
        assert "192.0.2.2" in path.read_text()
        # The continuation still exposes exploration tools, not save-only mode.
        continuation = calls[-2]
        assert continuation["tool_choice"] == "required"
        assert "nmap_scan" in [t["function"]["name"] for t in continuation["tools"]]
        assert len(calls) == (6 if case == "rejected_save" else 5)
    assert all(c["max_tokens"] == 4096 for c in calls)
