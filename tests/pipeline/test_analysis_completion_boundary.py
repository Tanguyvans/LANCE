"""Phase 3 completion must be backed by the current save transaction."""

import json
from unittest.mock import patch

import pytest

from src.agent.pipeline import Pipeline
from src.agent.registry import AgentConfig


DEVICE = {"id": "device-a", "ip": "192.0.2.10", "type": "router", "services": []}
CONFIG = AgentConfig(
    name="vuln_analysis", phase=3, prompt_template="vuln_analysis",
    deliverable_file="03_vuln_analysis.json", tools=[], has_device_agents=True,
    deterministic_aggregation=False,
)


def _run_case(mock_provider, output_dir, mode, devices=(DEVICE,), *, profile="full", memo=""):
    mock_provider.provider = "local-moe" if profile == "compact" else "ollama-umons"
    pipeline = Pipeline(provider=mock_provider, execution_profile=profile)
    run_dir = pipeline.run_dir
    (run_dir / "03_vuln_analysis.json").write_text('{"stale":true}', encoding="utf-8")
    if mode == "stale":
        (run_dir / "03_device_device-a.json").write_text('{"vulnerabilities":[]}', encoding="utf-8")

    surface = json.dumps(list(devices))
    scan_results = {
        device["id"]: {"scan_results": {}, "findings": []} for device in devices
    }

    def provider_call(**kwargs):
        if profile == "compact":
            assert kwargs["tools"] == []
            return memo
        save = next((tool["function"] for tool in kwargs["tools"] if tool["name"] == "save_deliverable"), None)
        device_id = next(device["id"] for device in devices if device["id"] in kwargs["user_message"])
        should_save = mode not in {"nosave", "stale"}
        should_save = should_save and not (mode == "mixed" and device_id == "device-b")
        if should_save and save is not None:
            content = '{"vulnerabilities":[]}' if mode != "invalidattempt" else '{"wrong":true}'
            save(filename=f"03_device_{device_id}.json", content=content)
            if mode == "corruptfile":
                (run_dir / f"03_device_{device_id}.json").write_text('{"corrupted":true}', encoding="utf-8")
        return "provider returned"

    mock_provider.chat_with_tools.side_effect = provider_call
    events = []
    with patch("src.agent.core.runtime.get_attack_surface", return_value=surface), \
         patch("src.agent.core.runtime.get_device_info", return_value=json.dumps(DEVICE)), \
         patch("src.agent.core.runtime.run_scanner", return_value=scan_results), \
         patch("src.agent.core.runtime.load_prompt", return_value="prompt"), \
         patch("src.agent.core.runtime.phase3_tool_names", return_value={"save_deliverable"}), \
         patch("src.agent.tools.graph_tools.get_network_neighbors", return_value={
             "upstream": [], "downstream": [], "role": "entrypoint",
         }), \
         patch("src.agent.cost_tracker.get_dynamic_pricing", return_value=None):
        pipeline._run_phase3(CONFIG, events.append)
    return pipeline, json.loads((run_dir / "03_phase3_status.json").read_text()), events


@pytest.mark.parametrize("mode", ["nosave", "stale", "invalidattempt", "corruptfile"])
def test_provider_without_current_valid_promoted_save_keeps_scanner_fallback(
    mock_provider, output_dir, mode,
):
    pipeline, status, events = _run_case(mock_provider, output_dir, mode)

    assert status["devices_analyzed"] == 0
    assert status["status"] == "completed_with_device_errors"
    assert status["devices_failed"][0]["error"].startswith("missing_validated_deliverable")
    done = [event for event in events if event.get("type") == "device_done"]
    assert done and done[0]["error"].startswith("missing_validated_deliverable")
    assert json.loads((pipeline.run_dir / "03_device_device-a.json").read_text())["vulnerabilities"] == []


def test_valid_save_receipt_and_byte_identical_promotion_counts_device_done(
    mock_provider, output_dir,
):
    _, status, events = _run_case(mock_provider, output_dir, "valid")

    assert status["devices_analyzed"] == 1
    assert status["devices_failed"] == []
    assert [event["type"] for event in events if event.get("type") == "device_done"] == ["device_done"]


def test_one_valid_and_one_invalid_device_only_counts_the_valid_one(
    mock_provider, output_dir,
):
    devices = (DEVICE, {**DEVICE, "id": "device-b", "ip": "192.0.2.11"})
    _, status, events = _run_case(mock_provider, output_dir, "mixed", devices=devices)

    # The provider saves the first device; the second has no matching save in
    # this fixture and must remain a scanner-fallback failure.
    assert status["devices_analyzed"] == 1
    assert [item["device_id"] for item in status["devices_failed"]] == ["device-b"]
    assert any(event.get("device_id") == "device-b" and "error" in event for event in events)


def test_failed_promotion_is_rejected_even_when_stale_file_equals_attempt(tmp_path, mock_provider, output_dir):
    pipeline = Pipeline(provider=mock_provider, execution_profile="full")
    attempt = pipeline.run_dir / ".attempts" / "03_device_device-a.json" / "attempt-old.json"
    attempt.parent.mkdir(parents=True)
    content = b'{"vulnerabilities":[]}'
    attempt.write_bytes(content)
    (pipeline.run_dir / "03_device_device-a.json").write_bytes(content)

    accepted, reason = pipeline._phase3_promoted_deliverable(
        "device-a",
        "03_device_device-a.json",
        {
            "validated": True,
            "status": "error",
            "ok": False,
            "attempt_ref": attempt.relative_to(pipeline.run_dir).as_posix(),
        },
    )

    assert accepted is False
    assert reason.startswith("missing_validated_deliverable")


@pytest.mark.parametrize("memo,completed", [
    ("", False),
    ("(max turns reached)", False),
    ("```json\n{", False),
    ("The scan found no direct evidence of a vulnerability; additional verification is required.", True),
])
def test_compact_analysis_requires_a_usable_fresh_memo(mock_provider, output_dir, memo, completed):
    pipeline, status, _ = _run_case(mock_provider, output_dir, "nosave", profile="compact", memo=memo)
    assert status["devices_analyzed"] == int(completed)
    assert (status["status"] == "completed") is completed
    assert (pipeline.run_dir / "03_device_device-a_analysis.md").exists() is completed
