"""Phase 3: per-device workers and prompt context."""
import json
from unittest.mock import patch
from src.agent.pipeline import Pipeline
from src.agent.registry import AgentConfig


class TestDeviceAgents:
    """Tests for the per-device sub-agent flow."""

    FAKE_SURFACE = json.dumps([
        {
            "id": "mikrotik",
            "name": "MikroTik hAP ac³",
            "type": "router",
            "ip": "192.168.88.1",
            "services": [
                {"name": "ssh", "port": 22, "version": "9.8"},
                {"name": "http", "port": 80, "version": None},
            ],
        },
        {
            "id": "rpi5",
            "name": "Raspberry Pi 5",
            "type": "compute",
            "ip": "192.168.88.247",
            "services": [
                {"name": "mqtt", "port": 1883, "version": "2.0.21"},
            ],
        },
    ])

    FAKE_DEVICE_INFO = json.dumps({
        "id": "mikrotik",
        "os_version": "RouterOS 7.18.2",
        "firmware": "7.18.2",
    })

    @patch("src.agent.core.runtime.get_device_info")
    @patch("src.agent.core.runtime.get_attack_surface")
    @patch("src.agent.core.runtime.load_prompt")
    def test_run_agent_triggers_device_agents(
        self, mock_prompt, mock_surface, mock_device_info,
        mock_provider, output_dir
    ):
        mock_surface.return_value = self.FAKE_SURFACE
        mock_device_info.return_value = self.FAKE_DEVICE_INFO
        mock_prompt.return_value = "System prompt"

        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir

        # Side effect: device agents save valid files, aggregator saves the final deliverable
        call_count = {"n": 0}
        def side_effect(**kwargs):
            call_count["n"] += 1
            user_msg = kwargs.get("user_message", "")
            for dev_id in ("mikrotik", "rpi5"):
                if dev_id in user_msg:
                    (run_dir / f"03_device_{dev_id}.json").write_text(
                        json.dumps({"device_id": dev_id, "vulnerabilities": []})
                    )
                    return "Done."
            # aggregator call
            (run_dir / "03_vuln_analysis.json").write_text(
                json.dumps({
                    "vulnerabilities": [{
                        "id": "VULN-001",
                        "service": "http",
                        "port": 80,
                        "protocol": "tcp",
                        "endpoint": "/",
                        "product": "RouterOS",
                        "version": "7.18.2",
                    }],
                    "summary": {
                        "total": 1, "high": 1, "medium": 0, "low": 0, "info": 0,
                    },
                })
            )
            return "Done."
        mock_provider.chat_with_tools.side_effect = side_effect

        config = AgentConfig(
            name="vuln_analysis", phase=3, prompt_template="vuln_analysis",
            deliverable_file="03_vuln_analysis.json",
            tools=["graph", "recon", "deliverable"],
            has_device_agents=True, max_turns=10,
            validator="json_vuln_queue",
        )

        scan_results = {
            device_id: {"scan_results": {}, "findings": []}
            for device_id in ("mikrotik", "rpi5")
        }
        with patch("src.agent.core.runtime.run_scanner", return_value=scan_results):
            status = pipeline._run_agent(config)

        # 2 device agents (no reflector) + 1 aggregator = 3 total calls
        assert mock_provider.chat_with_tools.call_count == 3
        assert status == "completed"

    def test_no_device_agents_when_flag_false(self, mock_provider, output_dir):
        """When has_device_agents=False, _run_phase3 should NOT be called."""
        pipeline = Pipeline(provider=mock_provider)
        config = AgentConfig(
            name="test", phase=1, prompt_template="graph_analysis",
            deliverable_file="01_graph_analysis.md", tools=["graph"],
            has_device_agents=False,
        )
        run_dir = pipeline.run_dir

        def side_effect(**kwargs):
            (run_dir / "01_graph_analysis.md").write_text("## S1\n## S2\n")
            return "Done."
        mock_provider.chat_with_tools.side_effect = side_effect

        with patch("src.agent.core.runtime.load_prompt", return_value="prompt"):
            status = pipeline._run_agent(config)

        # Only 1 call (no device agents)
        assert mock_provider.chat_with_tools.call_count == 1
        assert status == "completed"


class TestInformationPreservingArchitecture:
    def test_phase3_prompt_projection_is_bounded_and_references_full_scan(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        scan_data = {
            "scan_results": {
                "http": [
                    {
                        "tool": "http_get",
                        "kwargs": {"url": f"http://device/{index}"},
                        "result": ("A" * 1800) + f" evidence-{index}",
                    }
                    for index in range(20)
                ]
            }
        }

        projection = pipeline._phase3_scan_results_for_prompt(scan_data, "device")

        rendered = json.dumps(projection)
        assert len(rendered) < 8000
        assert projection["_evidence_projection"]["omitted_entries"] > 0
        assert projection["_evidence_projection"]["full_scan_artifact"].startswith(
            "03_scans/"
        )

    def test_full_phase3_prompt_preserves_complete_scanner_evidence(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "future-full-local-model"
        pipeline = Pipeline(provider=mock_provider, execution_profile="full")
        scan_data = {
            "scan_results": {
                "http": [{
                    "tool": "http_get",
                    "kwargs": {"url": "http://device/large"},
                    "result": "complete-evidence-" + ("A" * 12000),
                }]
            },
            "findings": [{"type": "header", "evidence": "complete"}],
        }

        assert pipeline._phase3_scan_results_for_prompt(scan_data, "device") is scan_data
        assert "_evidence_projection" not in scan_data

    def test_local_moe_phase3_uses_one_worker(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")

        assert pipeline._phase3_worker_count(4) == 1

        full_pipeline = Pipeline(provider=mock_provider, execution_profile="full")
        assert full_pipeline._phase3_worker_count(4) == 1
        assert full_pipeline._uses_compact_local_moe() is False

        mock_provider.provider = "openrouter"
        mock_provider.model = "large-model"
        assert pipeline._phase3_worker_count(4) == 4

    @patch("src.agent.core.runtime.get_device_info")
    @patch("src.agent.core.runtime.get_attack_surface")
    @patch("src.agent.core.runtime.load_prompt")
    def test_local_phase3_preserves_memo_without_overwriting_scanner_json(
        self, mock_load_prompt, mock_surface, mock_device_info, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        mock_provider.chat_with_tools.return_value = "Local memo: reject generic CVE claims."
        mock_surface.return_value = json.dumps({"nodes": [{
            "id": "s1-router",
            "ip": "192.168.100.1",
            "type": "router",
            "role": "router",
            "services": [{"name": "ssh", "port": 22}, {"name": "http", "port": 80}],
        }]})
        mock_device_info.return_value = json.dumps({"os_version": "OpenWrt"})
        mock_load_prompt.return_value = "legacy json prompt should not control local path"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        run_dir = pipeline.run_dir
        fallback = {
            "device_id": "s1-router",
            "device_ip": "192.168.100.1",
            "vulnerabilities": [{
                "type": "missing_header",
                "severity": "LOW",
                "service": "http",
                "port": 80,
            }],
            "summary": {"total": 1},
        }

        def scanner_side_effect(run_dir_arg, devices, stream_callback=None, *, compact=False, stop_event=None):
            (run_dir / "03_device_s1-router.json").write_text(json.dumps(fallback))
            return {"s1-router": {"scan_results": {}, "findings": fallback["vulnerabilities"]}}

        config = AgentConfig(
            name="vuln_analysis",
            phase=3,
            prompt_template="vuln_analysis",
            deliverable_file="03_vuln_analysis.json",
            tools=[],
            has_device_agents=True,
        )
        with patch("src.agent.core.runtime.run_scanner", side_effect=scanner_side_effect), \
             patch("src.agent.tools.graph_tools.get_network_neighbors", return_value={
                 "upstream": [], "downstream": [], "role": "entrypoint",
             }):
            pipeline._run_phase3(config)

        kwargs = mock_provider.chat_with_tools.call_args.kwargs
        assert kwargs["tools"] == []
        assert kwargs["max_turns"] == 1
        assert "not JSON and not a tool call" in kwargs["system_prompt"]
        assert json.loads((run_dir / "03_device_s1-router.json").read_text()) == fallback
        assert (run_dir / "03_device_s1-router_analysis.md").read_text().strip() == "Local memo: reject generic CVE claims."
        assert "Local memo" in (run_dir / "model_outputs.jsonl").read_text()
        assert not (run_dir / "deliverable_attempts.jsonl").exists()
