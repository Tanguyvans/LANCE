"""Phase 3 full-mode block recovery after output-budget truncation.

A full device analysis can exhaust the provider's per-response output budget
(finish_reason=length) after exploring but before saving. These tests drive
the real ``Pipeline._run_phase3`` with a mocked provider: the full attempt
truncates, then save-only per-service blocks finalize the device.

Only new behavior is asserted here; existing completion contracts live in
test_analysis_completion_boundary.py and must keep passing unmodified.
"""

import json
import threading
from unittest.mock import patch

import pytest

from src.agent.phases.analysis import block_recovery
from src.agent.pipeline import Pipeline
from src.agent.prompt_manager import load_prompt
from src.agent.registry import AgentConfig


DEVICE = {
    "id": "s2-router",
    "ip": "192.168.100.1",
    "type": "router",
    "role": "router",
    "services": [
        {"name": "ssh", "port": 22},
        {"name": "http", "port": 80},
        {"name": "https", "port": 443},
    ],
}
CONFIG = AgentConfig(
    name="vuln_analysis", phase=3, prompt_template="vuln_analysis",
    deliverable_file="03_vuln_analysis.json", tools=[], has_device_agents=True,
    deterministic_aggregation=False,
)
AUTOMATED = [
    {
        "id": "s2-router-auto-1", "device_id": "s2-router",
        "device_ip": "192.168.100.1", "type": "missing_header",
        "severity": "LOW", "service": "http", "port": 80, "protocol": "tcp",
        "endpoint": "/", "product": "", "version": "", "details": "auto",
        "evidence": "scanner", "cve_ids": [], "exploitation_status": "suspected",
        "suggested_technique": "", "suggested_tools": [],
    }
]


def _block_finding(block_index, finding_id, service, port):
    return {
        "id": finding_id, "device_id": "s2-router",
        "device_ip": "192.168.100.1", "type": "no_auth",
        "severity": "HIGH", "service": service, "port": port,
        "protocol": "tcp", "endpoint": "/admin", "product": "",
        "version": "", "details": f"block {block_index}",
        "evidence": "scoped scan", "cve_ids": [],
        "exploitation_status": "suspected", "suggested_technique": "",
        "suggested_tools": [],
    }


def _block_payload(block_index, findings):
    return {
        "device_id": "s2-router", "device_ip": "192.168.100.1",
        "block_index": block_index + 1, "vulnerabilities": findings,
    }


class _Driver:
    """Mocked provider dispatching full attempt vs per-block finalization."""

    def __init__(self, pipeline, mock_provider, mode="recover"):
        self.pipeline = pipeline
        self.mock_provider = mock_provider
        self.mode = mode
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        metadata = kwargs.get("completion_metadata")
        if metadata is not None:
            metadata.clear()
        tools = [tool["name"] for tool in kwargs.get("tools", [])]
        if len(self.calls) == 1:
            # Full device attempt truncates after exploration, saving nothing.
            assert kwargs["max_tokens"] == 4096
            assert kwargs["max_turns"] == 10
            if metadata is not None:
                metadata.update(finish_reason="length", output_tokens=4096)
            return "truncated exploration without save"
        # Block finalization must be save-only and strictly smaller.
        assert tools == ["save_deliverable"], tools
        assert kwargs["max_tokens"] == 2048
        assert kwargs["max_turns"] == 4
        assert kwargs["cost_tracker"] is self.pipeline.tracker
        assert kwargs["stop_event"] is self.pipeline._stop_event
        assert kwargs["deadline"] is not None
        save = next(
            tool["function"] for tool in kwargs["tools"]
            if tool["name"] == "save_deliverable"
        )
        message = kwargs.get("user_message", "")
        block = 0 if "block 1" in message else 1
        if self.mode == "recover":
            if metadata is not None:
                metadata.update(finish_reason="tool_calls")
            if block == 0:
                payload = _block_payload(0, [
                    _block_finding(0, "s2-router-b0-ssh", "ssh", 22),
                    _block_finding(0, "s2-router-b0-http", "http", 80),
                ])
            else:
                payload = _block_payload(1, [
                    _block_finding(1, "s2-router-b1-https", "https", 443),
                ])
            save(filename=f"03_blocks/s2-router_part{block}.json",
                 content=json.dumps(payload))
            return "block saved"
        if self.mode == "truncate_blocks":
            if metadata is not None:
                metadata.update(finish_reason="length", output_tokens=2048)
            return "block truncated"
        if self.mode == "wrong_device":
            if metadata is not None:
                metadata.update(finish_reason="tool_calls")
            if block == 0:
                payload = _block_payload(0, [
                    _block_finding(0, "s2-router-b0-ssh", "ssh", 22),
                ])
                save(filename="03_blocks/s2-router_part0.json",
                     content=json.dumps(payload))
            else:
                bad = _block_finding(1, "intruder-1", "https", 443)
                bad["device_id"] = "intruder"
                save(filename="03_blocks/s2-router_part1.json",
                     content=json.dumps(_block_payload(1, [bad])))
            return "block saved"
        if self.mode == "malformed":
            if metadata is not None:
                metadata.update(finish_reason="tool_calls")
            save(filename=f"03_blocks/s2-router_part{block}.json",
                 content="{not valid json")
            return "block saved"
        if self.mode == "wrong_filename_first":
            if metadata is not None:
                metadata.update(finish_reason="tool_calls")
            if not getattr(self, "_scoped", False):
                self._scoped = True
                receipt = json.loads(save(
                    filename="03_device_s2-router.json",
                    content=json.dumps(_block_payload(block, [])),
                ))
                assert receipt.get("validated") is not True
                assert receipt.get("ok") is False
            payload = _block_payload(block, [
                _block_finding(block, f"s2-router-b{block}-x",
                               "ssh" if block == 0 else "https",
                               22 if block == 0 else 443),
            ])
            save(filename=f"03_blocks/s2-router_part{block}.json",
                 content=json.dumps(payload))
            return "block saved"
        raise AssertionError(f"unknown mode {self.mode}")


def _run_phase3(mock_provider, output_dir, mode="recover", finish_reason="length"):
    mock_provider.provider = "ollama-umons"
    pipeline = Pipeline(provider=mock_provider, execution_profile="full")
    driver = _Driver(pipeline, mock_provider, mode=mode)
    if finish_reason != "length":
        original = driver

        def driver_with_reason(**kwargs):
            if len(driver.calls) == 0:
                result = original(**kwargs)
                metadata = kwargs.get("completion_metadata")
                if metadata is not None:
                    metadata.update(finish_reason=finish_reason)
                return result
            return original(**kwargs)

        mock_provider.chat_with_tools.side_effect = driver_with_reason
    else:
        mock_provider.chat_with_tools.side_effect = driver
    events = []
    surface = json.dumps([DEVICE])
    scan_results = {"s2-router": {"scan_results": {}, "findings": list(AUTOMATED)}}
    real_load_prompt = load_prompt

    def load_prompt_spy(name, variables=None):
        if name == "analyze_device_block":
            return real_load_prompt(name, variables)
        return "prompt"

    with patch("src.agent.core.runtime.get_attack_surface", return_value=surface), \
         patch("src.agent.core.runtime.get_device_info", return_value=json.dumps(DEVICE)), \
         patch("src.agent.core.runtime.run_scanner", return_value=scan_results), \
         patch("src.agent.core.runtime.load_prompt", side_effect=load_prompt_spy), \
         patch("src.agent.core.runtime.phase3_tool_names", return_value={"save_deliverable"}), \
         patch("src.agent.tools.graph_tools.get_network_neighbors", return_value={
             "upstream": [], "downstream": [], "role": "entrypoint",
         }), \
         patch("src.agent.cost_tracker.get_dynamic_pricing", return_value=None):
        pipeline._run_phase3(CONFIG, events.append)
    status = json.loads((pipeline.run_dir / "03_phase3_status.json").read_text())
    return pipeline, status, events, driver


def test_truncated_full_attempt_recovers_into_valid_device(mock_provider, output_dir):
    pipeline, status, events, driver = _run_phase3(mock_provider, output_dir)

    assert status["devices_analyzed"] == 1
    assert status["devices_failed"] == []
    final = json.loads((pipeline.run_dir / "03_device_s2-router.json").read_text())
    ids = {finding["id"] for finding in final["vulnerabilities"]}
    assert {"s2-router-auto-1", "s2-router-b0-ssh", "s2-router-b0-http",
            "s2-router-b1-https"} <= ids
    assert final["summary"]["total"] == len(final["vulnerabilities"])
    assert final["device_id"] == "s2-router"
    # Automated findings stay untouched; block severities/types are preserved.
    auto = next(finding for finding in final["vulnerabilities"]
                if finding["id"] == "s2-router-auto-1")
    assert auto == AUTOMATED[0]
    # Valid sidecars are preserved and never globbed as device deliverables.
    assert (pipeline.run_dir / "03_blocks" / "s2-router_part0.json").is_file()
    assert (pipeline.run_dir / "03_blocks" / "s2-router_part1.json").is_file()
    device_files = sorted(
        path.name for path in pipeline.run_dir.glob("03_device_*.json")
    )
    assert device_files == ["03_device_s2-router.json"]
    done = [event for event in events if event.get("type") == "device_done"]
    assert done and done[0].get("recovered_from_truncation") is True
    # Recovery ran 1 full + 2 block calls, all on the shared tracker.
    assert len(driver.calls) == 3


def test_repeated_truncation_leaves_explicit_incomplete_state(mock_provider, output_dir):
    pipeline, status, events, driver = _run_phase3(
        mock_provider, output_dir, mode="truncate_blocks")

    assert status["devices_analyzed"] == 0
    assert len(status["devices_failed"]) == 1
    failure = status["devices_failed"][0]
    assert failure["error"].startswith("truncated_output:")
    assert failure["cause"] == "truncated_output"
    done = [event for event in events if event.get("type") == "device_done"]
    assert done and done[0]["cause"] == "truncated_output"
    # Scanner fallback preserved, never presented as model analysis.
    fallback = json.loads((pipeline.run_dir / "03_device_s2-router.json").read_text())
    assert [finding["id"] for finding in fallback["vulnerabilities"]] == ["s2-router-auto-1"]
    # Bounded: 1 full + 2 blocks x 2 attempts, then stop.
    assert len(driver.calls) == 1 + 2 * 2


def test_wrong_device_block_save_rejected(mock_provider, output_dir):
    pipeline, status, _, _ = _run_phase3(
        mock_provider, output_dir, mode="wrong_device")

    assert status["devices_analyzed"] == 0
    assert status["devices_failed"][0]["error"].startswith("truncated_output:")
    final = json.loads((pipeline.run_dir / "03_device_s2-router.json").read_text())
    assert all(finding["device_id"] == "s2-router"
               for finding in final["vulnerabilities"])
    assert "intruder-1" not in {finding["id"] for finding in final["vulnerabilities"]}
    # The valid block sidecar is preserved for diagnosis.
    part0 = json.loads((pipeline.run_dir / "03_blocks" / "s2-router_part0.json").read_text())
    assert part0["vulnerabilities"][0]["id"] == "s2-router-b0-ssh"


def test_malformed_block_save_rejected(mock_provider, output_dir):
    _, status, _, _ = _run_phase3(mock_provider, output_dir, mode="malformed")

    assert status["devices_analyzed"] == 0
    assert status["devices_failed"][0]["error"].startswith("truncated_output:")


def test_block_save_to_full_filename_rejected(mock_provider, output_dir):
    pipeline, status, _, _ = _run_phase3(
        mock_provider, output_dir, mode="wrong_filename_first")

    assert status["devices_analyzed"] == 1
    final = json.loads((pipeline.run_dir / "03_device_s2-router.json").read_text())
    assert final["device_id"] == "s2-router"


def test_stop_event_stops_before_more_calls(mock_provider, output_dir):
    mock_provider.provider = "ollama-umons"
    pipeline = Pipeline(provider=mock_provider, execution_profile="full")
    pipeline._stop_event = threading.Event()
    pipeline._stop_event.set()
    driver = _Driver(pipeline, mock_provider, mode="recover")
    mock_provider.chat_with_tools.side_effect = driver
    events = []
    surface = json.dumps([DEVICE])
    scan_results = {"s2-router": {"scan_results": {}, "findings": list(AUTOMATED)}}
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
    status = json.loads((pipeline.run_dir / "03_phase3_status.json").read_text())

    assert len(driver.calls) == 1
    assert status["devices_analyzed"] == 0
    assert "stopped" in status["devices_failed"][0]["error"]


def _run_phase3_with_setup(mock_provider, output_dir, setup):
    mock_provider.provider = "ollama-umons"
    pipeline = Pipeline(provider=mock_provider, execution_profile="full")
    setup(pipeline)
    driver = _Driver(pipeline, mock_provider, mode="recover")
    mock_provider.chat_with_tools.side_effect = driver
    events = []
    surface = json.dumps([DEVICE])
    scan_results = {"s2-router": {"scan_results": {}, "findings": list(AUTOMATED)}}
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
    status = json.loads((pipeline.run_dir / "03_phase3_status.json").read_text())
    return pipeline, status, events, driver


def test_deadline_stops_before_more_calls(mock_provider, output_dir, monkeypatch):
    import src.agent.phases.analysis.run as analysis_run

    def expired(deadline):
        raise TimeoutError("LLM request deadline exceeded")

    monkeypatch.setattr(analysis_run, "deadline_remaining", expired)
    _, status, _, driver = _run_phase3_with_setup(
        mock_provider, output_dir, lambda pipeline: None)

    assert len(driver.calls) == 1
    assert status["devices_failed"][0]["error"].startswith("truncated_output:")
    assert "deadline exceeded" in status["devices_failed"][0]["error"]


def test_budget_stops_before_more_calls(mock_provider, output_dir, monkeypatch):
    from src.agent.cost_tracker import BudgetExceeded, CostTracker

    def exhausted(self):
        raise BudgetExceeded("Observed cost limit reached ($0.0000)")

    monkeypatch.setattr(CostTracker, "check_budget", exhausted)
    _, status, _, driver = _run_phase3_with_setup(
        mock_provider, output_dir, lambda pipeline: None)

    assert len(driver.calls) == 1
    assert status["devices_failed"][0]["error"].startswith("truncated_output:")
    assert "budget exceeded" in status["devices_failed"][0]["error"]


def test_generic_missing_save_keeps_existing_cause(mock_provider, output_dir):
    _, status, _, driver = _run_phase3(
        mock_provider, output_dir, mode="recover", finish_reason="stop")

    assert status["devices_failed"][0]["error"].startswith("missing_validated_deliverable")
    # No recovery attempted without truncation evidence.
    assert len(driver.calls) == 1


def test_block_prompt_template_interpolates_cleanly():
    text = load_prompt("analyze_device_block", {
        "device_id": "s2-router", "device_ip": "192.168.100.1",
        "block_index": 1, "block_count": 2, "block_services": "ssh:22, http:80",
        "allowed_services": "ssh, http", "allowed_ports": "22, 80",
        "expected_block_file": "03_blocks/s2-router_part0.json",
        "scan_results": "{}", "automated_findings_summary": "none",
        "prior_observations": "none",
    })
    assert "MISSING" not in text
    assert "03_blocks/s2-router_part0.json" in text
    assert "save_deliverable" in text


# --- Pure helper contracts -------------------------------------------------


def test_is_truncation_only_on_length():
    assert block_recovery.is_truncation({"finish_reason": "length"}) is True
    assert block_recovery.is_truncation({"finish_reason": "stop"}) is False
    assert block_recovery.is_truncation({}) is False
    assert block_recovery.is_truncation(None) is False


def test_derive_blocks_groups_and_caps():
    device = {"id": "d", "services": [
        {"name": f"s{i}", "port": 1000 + i} for i in range(5)
    ]}
    specs = block_recovery.derive_blocks(device)
    assert [len(spec["services"]) for spec in specs] == [2, 2, 1]
    assert specs[0]["sidecar"] == "03_blocks/d_part0.json"

    many = {"id": "d", "services": [
        {"name": f"s{i}", "port": 1000 + i} for i in range(9)
    ]}
    capped = block_recovery.derive_blocks(many, max_blocks=2, services_per_block=2)
    assert len(capped) == 2
    assert len(capped[1]["services"]) == 7

    general = block_recovery.derive_blocks({"id": "d", "services": []})
    assert len(general) == 1
    assert general[0]["ports"] == []


def _unit_finding(finding_id, service, port, **overrides):
    finding = {
        "id": finding_id, "device_id": "d", "device_ip": "10.0.0.1",
        "type": "no_auth", "severity": "HIGH", "service": service,
        "port": port, "protocol": "tcp",
    }
    finding.update(overrides)
    return finding


def test_validate_block_payload_rejects_misattribution():
    spec = {"index": 0, "service_names": ["ssh"], "ports": [22],
            "sidecar": "03_blocks/d_part0.json"}
    base = {"device_id": "d", "device_ip": "10.0.0.1", "block_index": 1, "vulnerabilities": []}
    assert block_recovery.validate_block_payload(
        base, device_id="d", device_ip="10.0.0.1", spec=spec,
        device_ports={22, 80}, device_services={"ssh", "http"})[0] is True

    def check(payload, fragment):
        valid, error = block_recovery.validate_block_payload(
            payload, device_id="d", device_ip="10.0.0.1", spec=spec,
            device_ports={22, 80}, device_services={"ssh", "http"})
        assert valid is False
        assert fragment in error

    check(dict(base, device_id="other"), "does not match")
    check(dict(base, device_ip="10.9.9.9"), "does not match")
    check(dict(base, block_index=2), "block_index")
    check(dict(base, vulnerabilities=[_unit_finding("d-x", "ssh", 22, device_id="other")]),
          "targets")
    check(dict(base, vulnerabilities=[_unit_finding("d-x", "http", 80)]),
          "outside this block")
    check(dict(base, vulnerabilities=[_unit_finding("d-x", "ssh", 2222)]),
          "outside this block")
    check(dict(base, vulnerabilities=[_unit_finding("zzz-x", "ssh", 22)]),
          "not scoped")
    dup = _unit_finding("d-x", "ssh", 22)
    check(dict(base, vulnerabilities=[dup, dict(dup)]), "duplicate")
    check(dict(base, vulnerabilities=[dict(dup, port="eighty")]), "integer or null")


def test_assemble_merges_without_rewriting_classification():
    automated = [dict(AUTOMATED[0])]
    blocks = [_block_payload(0, [_block_finding(0, "s2-router-b0-ssh", "ssh", 22)])]
    merged = block_recovery.assemble_device_deliverable(
        DEVICE, automated, blocks)
    assert [finding["id"] for finding in merged["vulnerabilities"]] == [
        "s2-router-auto-1", "s2-router-b0-ssh"]
    assert merged["summary"] == {"total": 2, "critical": 0, "high": 1,
                                 "medium": 0, "low": 1, "info": 0}
    assert merged["vulnerabilities"][0] == AUTOMATED[0]

    # Identical duplicates collapse; conflicting duplicates fail loudly.
    again = block_recovery.assemble_device_deliverable(
        DEVICE, automated,
        [_block_payload(0, [dict(AUTOMATED[0])])])
    assert [finding["id"] for finding in again["vulnerabilities"]] == ["s2-router-auto-1"]
    conflict = dict(AUTOMATED[0], severity="CRITICAL")
    with pytest.raises(ValueError, match="conflicting duplicate"):
        block_recovery.assemble_device_deliverable(
            DEVICE, automated, [_block_payload(0, [conflict])])


def test_scope_keeps_unattributed_evidence():
    spec = {"index": 0, "service_names": ["http"], "ports": [80],
            "sidecar": "03_blocks/d_part0.json"}
    scan = {
        "scan_results": {
            "http:80": [{"tool": "http_get", "kwargs": {"ports": 80}, "result": "{}"}],
            "ssh:22": [{"tool": "tcp_send", "kwargs": {}, "result": "{}"}],
        },
        "findings": [
            {"id": "a", "service": "http", "port": 80},
            {"id": "b"},
        ],
    }
    scoped = block_recovery.scope_scan_for_block(scan, spec)
    assert set(scoped["scan_results"]) == {"http:80", "ssh:22"}
    assert {finding["id"] for finding in scoped["findings"]} == {"a", "b"}


def test_observation_log_is_bounded():
    log: list = []
    for index in range(30):
        block_recovery.record_observation(log, "cve_search", f"result-{index}")
    assert len(log) == block_recovery.MAX_OBSERVATION_ENTRIES
    assert log[-1]["result"] == "result-29"
    rendered = block_recovery.render_observations(
        log, {"service_names": [], "ports": []})
    assert len(rendered) <= block_recovery.MAX_RENDERED_OBSERVATIONS_CHARS


def test_block_config_defaults_and_env_override(monkeypatch):
    defaults = block_recovery.block_config()
    assert defaults == {"max_blocks": 4, "services_per_block": 2,
                        "max_attempts": 2, "max_tokens": 2048, "max_turns": 4}
    monkeypatch.setenv("LANCE_PHASE3_BLOCK_MAX_BLOCKS", "2")
    monkeypatch.setenv("LANCE_PHASE3_BLOCK_MAX_TOKENS", "0")
    overridden = block_recovery.block_config()
    assert overridden["max_blocks"] == 2
    assert overridden["max_tokens"] == 2048


def test_service_and_port_must_belong_to_the_same_observed_service():
    spec = block_recovery.derive_blocks(DEVICE)[0]
    payload = _block_payload(0, [_block_finding(0, "s2-router-wrong", "http", 22)])
    valid, reason = block_recovery.validate_block_payload(
        payload, device_id=DEVICE["id"], device_ip=DEVICE["ip"], spec=spec,
        device_ports={22, 80, 443}, device_services={"ssh", "http", "https"},
    )
    assert not valid
    assert "service/port pair" in reason


def test_length_with_parseable_save_is_not_accepted(mock_provider, output_dir, monkeypatch):
    original = _Driver.__call__

    def truncated_save(self, **kwargs):
        result = original(self, **kwargs)
        kwargs["completion_metadata"]["finish_reason"] = "length"
        return result

    monkeypatch.setattr(_Driver, "__call__", truncated_save)
    _, status, _, driver = _run_phase3(mock_provider, output_dir)
    assert status["devices_analyzed"] == 0
    assert len(driver.calls) == 5  # initial + two attempts for each block
    assert "finish_reason=length" in status["devices_failed"][0]["error"]


@pytest.mark.parametrize("interruption", ["stop", "deadline", "budget"])
def test_limits_checked_after_last_block_returns(mock_provider, output_dir, monkeypatch, interruption):
    import src.agent.phases.analysis.run as analysis_run
    from src.agent.cost_tracker import BudgetExceeded
    original = _Driver.__call__

    def interrupted(self, **kwargs):
        result = original(self, **kwargs)
        if len(self.calls) == 3:
            if interruption == "stop":
                self.pipeline._stop_event = threading.Event()
                self.pipeline._stop_event.set()
            elif interruption == "deadline":
                def expired(deadline):
                    raise TimeoutError("expired")
                monkeypatch.setattr(analysis_run, "deadline_remaining", expired)
            else:
                def exhausted():
                    raise BudgetExceeded("exhausted")
                monkeypatch.setattr(self.pipeline.tracker, "check_budget", exhausted)
        return result

    monkeypatch.setattr(_Driver, "__call__", interrupted)
    pipeline, status, _, driver = _run_phase3(mock_provider, output_dir)
    assert status["devices_analyzed"] == 0
    assert len(driver.calls) == 3
    assert interruption in status["devices_failed"][0]["error"]
    assert json.loads((pipeline.run_dir / "03_device_s2-router.json").read_text())["vulnerabilities"] == AUTOMATED


def test_only_truncated_block_retried_and_all_usage_counted(mock_provider, output_dir, monkeypatch):
    original = _Driver.__call__
    attempted = []

    def once(self, **kwargs):
        tracker = kwargs["cost_tracker"]
        tracker.record_turn(input_tokens=10, output_tokens=20)
        if self.calls:
            message = kwargs["user_message"]
            attempted.append(1 if "block 1" in message else 2)
            if len(self.calls) == 2:
                self.calls.append(kwargs)
                kwargs["completion_metadata"].update(finish_reason="length")
                return "truncated"
        return original(self, **kwargs)

    monkeypatch.setattr(_Driver, "__call__", once)
    pipeline, status, _, driver = _run_phase3(mock_provider, output_dir)
    assert status["devices_analyzed"] == 1
    assert attempted == [1, 2, 2]
    assert len(driver.calls) == 4
    assert pipeline.tracker.total_tokens() == (40, 80)
    assert len({call["deadline"] for call in driver.calls}) == 1


def test_observation_retains_target_arguments():
    observations = []
    block_recovery.record_observation(observations, "http_get", "HTTP 200", kwargs={"url": "http://192.0.2.1/admin"})
    rendered = block_recovery.render_observations(observations, {"service_names": ["http"], "ports": [80]})
    assert "http://192.0.2.1/admin" in rendered
