"""UMONS serialization must preserve the full Phase 3 execution contract."""

import json
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from src.agent.pipeline import Pipeline
from src.agent.registry import AgentConfig


def test_umons_full_phase3_serializes_without_reducing_context_or_deadline(
    mock_provider, output_dir, monkeypatch
):
    mock_provider.provider = "ollama-umons"
    monkeypatch.setenv("LANCE_PHASE3_WORKERS", "4")
    monkeypatch.delenv("LANCE_PHASE3_DEVICE_TIMEOUT_S", raising=False)
    pipeline = Pipeline(provider=mock_provider, execution_profile="full")
    devices = [
        {"id": f"device-{index}", "ip": f"192.0.2.{index}", "services": []}
        for index in (1, 2)
    ]
    evidence = "complete-evidence-" + "A" * 12000
    scans = {
        device["id"]: {"scan_results": {"raw": evidence}, "findings": []}
        for device in devices
    }
    observed = []

    def model_call(**kwargs):
        observed.append(kwargs)
        assert 239 <= kwargs["deadline"] - time.monotonic() <= 240
        assert evidence in kwargs["system_prompt"]
        assert kwargs["required_tool"] == "save_deliverable"
        assert kwargs["terminate_after_tool"] == "save_deliverable"
        assert kwargs["max_turns"] == pipeline.execution_profile.phase3_max_turns
        assert kwargs["max_tokens"] == pipeline.execution_profile.phase3_max_tokens
        device_id = devices[len(observed) - 1]["id"]
        save = next(tool["function"] for tool in kwargs["tools"] if tool["name"] == "save_deliverable")
        receipt = json.loads(save(
            filename=f"03_device_{device_id}.json",
            content=json.dumps({"device_id": device_id, "vulnerabilities": []}),
        ))
        assert receipt["validated"] is True
        assert receipt["status"] == "saved"
        return "Done."

    mock_provider.chat_with_tools.side_effect = model_call
    config = AgentConfig(
        name="vuln_analysis", phase=3, prompt_template="vuln_analysis",
        deliverable_file="03_vuln_analysis.json", tools=[], has_device_agents=True,
    )
    with (
        patch("src.agent.core.runtime.get_attack_surface", return_value=json.dumps(devices)),
        patch("src.agent.core.runtime.get_device_info", return_value="{}"),
        patch("src.agent.core.runtime.run_scanner", return_value=scans) as scanner,
        patch("src.agent.tools.graph_tools.get_network_neighbors", return_value={
            "upstream": [], "downstream": [], "role": "unknown",
        }),
        patch("src.agent.core.runtime.load_prompt", side_effect=lambda name, variables: variables["scan_results"]),
        patch("concurrent.futures.ThreadPoolExecutor", wraps=ThreadPoolExecutor) as executor,
    ):
        pipeline._run_phase3(config)

    executor.assert_called_once_with(max_workers=1)
    assert scanner.call_args.kwargs["compact"] is False
    assert len(observed) == 2
    status = json.loads((pipeline.run_dir / "03_phase3_status.json").read_text())
    assert status["worker_count"] == 1
    assert status["devices_failed"] == []
