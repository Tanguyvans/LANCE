"""Phase 4: worker scheduling, instructions, and fallback."""
import json
from unittest.mock import MagicMock
from src.agent.pipeline import Pipeline
from src.agent.registry import AGENTS


class TestInformationPreservingArchitecture:
    def test_phase4_empty_schedule_is_explicit_skip(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        finding = {
            "id": "VULN-001",
            "device_id": "device-a",
            "device_ip": "192.0.2.20",
            "type": "known_cve",
            "severity": "HIGH",
            "service": "ssh",
            "port": 22,
            "protocol": "tcp",
            "endpoint": "",
            "product": "OpenSSH",
            "version": "9.2",
            "evidence": "version evidence",
            "exploitation_status": "suspected",
            "cve_ids": ["CVE-2023-48795"],
        }
        (pipeline.run_dir / "03_vuln_analysis.json").write_text(json.dumps({
            "vulnerabilities": [finding],
        }))

        pipeline._run_exploit_agents(AGENTS["exploitation"])

        aggregate = json.loads(
            (pipeline.run_dir / "04_exploitation.json").read_text()
        )
        assert pipeline._phase4_execution_status is None
        assert aggregate["summary"]["total_tested"] == 1
        assert aggregate["summary"]["candidate_count"] == 1
        assert aggregate["summary"]["skipped_count"] == 0
        assert aggregate["summary"]["errors"] == 1
        assert aggregate["tests"][0]["status"] == "ERROR"

    def test_phase4_compact_worker_receives_local_exploit_instructions(
        self, output_dir, monkeypatch
    ):
        provider = MagicMock()
        provider.provider = "local-moe"
        provider.model = "lance-moe"
        pipeline = Pipeline(provider=provider, execution_profile="compact")
        finding = {
            "id": "VULN-001",
            "device_id": "router",
            "device_ip": "192.0.2.1",
            "type": "insecure_protocol",
            "severity": "MEDIUM",
            "service": "telnet",
            "port": 23,
            "protocol": "tcp",
            "endpoint": "",
            "details": "Telnet is exposed",
            "evidence": "23/tcp open",
            "exploitation_status": "confirmed",
            "cve_ids": [],
        }
        (pipeline.run_dir / "03_vuln_analysis.json").write_text(json.dumps({
            "vulnerabilities": [finding],
        }))

        def telnet_connect(**kwargs):
            return json.dumps({
                "stdout": "OpenWrt telnet banner",
                "stderr": "",
                "return_code": 0,
            })

        monkeypatch.setattr(pipeline, "_resolve_tools", lambda config: [{
            "name": "telnet_connect",
            "description": "telnet",
            "input_schema": {},
            "function": telnet_connect,
        }, {
            "name": "http_get",
            "description": "http",
            "input_schema": {},
            "function": telnet_connect,
        }, {
            "name": "try_credential",
            "description": "credentials",
            "input_schema": {},
            "function": telnet_connect,
        }, {
            "name": "search_knowledge",
            "description": "search",
            "input_schema": {},
            "function": telnet_connect,
        }])

        def chat_with_tools(*, system_prompt, tools, **kwargs):
            assert "telnet" in system_prompt.lower()
            assert [tool["name"] for tool in tools] == ["telnet_connect"]
            assert kwargs["force_tool_on_stall"] is True
            assert kwargs["recover_required_tool_on_stall"] is True
            result = tools[0]["function"](
                command_string="echo quit | timeout 3 nc 192.0.2.1 23"
            )
            with (pipeline.run_dir / "tool_calls.jsonl").open(
                "a", encoding="utf-8"
            ) as handle:
                handle.write(json.dumps({
                    "tool": "telnet_connect",
                    "args": {
                        "command_string": "echo quit | timeout 3 nc 192.0.2.1 23",
                    },
                    "result": result,
                    "vuln_id": "VULN-001",
                    "evidence_ref": "tc-phase4-telnet",
                }) + "\n")
            return "Telnet exposure verified."

        provider.chat_with_tools.side_effect = chat_with_tools

        pipeline._run_exploit_agents(AGENTS["exploitation"])

        aggregate = json.loads(
            (pipeline.run_dir / "04_exploitation.json").read_text()
        )
        assert provider.chat_with_tools.call_count == 1
        assert aggregate["summary"]["confirmed"] == 1
        assert aggregate["summary"]["errors"] == 0
        assert aggregate["tests"][0]["evidence_refs"] == ["tc-phase4-telnet"]

    def test_phase4_compact_fallback_runs_after_provider_timeout(
        self, output_dir
    ):
        provider = MagicMock()
        provider.provider = "local-moe"
        provider.model = "lance-moe"
        pipeline = Pipeline(provider=provider, execution_profile="compact")
        finding = {
            "id": "VULN-TIMEOUT",
            "device_id": "router",
            "device_ip": "192.0.2.1",
            "type": "insecure_protocol",
            "severity": "MEDIUM",
            "service": "telnet",
            "port": 23,
            "protocol": "tcp",
            "endpoint": "",
            "details": "Telnet is exposed",
            "evidence": "23/tcp open",
            "exploitation_status": "confirmed",
            "cve_ids": [],
        }
        (pipeline.run_dir / "03_vuln_analysis.json").write_text(json.dumps({
            "vulnerabilities": [finding],
        }))

        def telnet_connect(**kwargs):
            return json.dumps({
                "stdout": "OpenWrt telnet banner",
                "stderr": "",
                "return_code": 0,
            })

        tool = pipeline._wrap_tool({
            "name": "telnet_connect",
            "description": "telnet",
            "input_schema": {},
            "function": telnet_connect,
        }, phase=4, agent="exploitation")
        pipeline._resolve_tools = lambda config: [tool]
        provider.chat_with_tools.side_effect = TimeoutError("local provider timeout")

        pipeline._run_exploit_agents(AGENTS["exploitation"])

        aggregate = json.loads(
            (pipeline.run_dir / "04_exploitation.json").read_text()
        )
        assert provider.chat_with_tools.call_count == 1
        assert aggregate["summary"]["confirmed"] == 1
        assert aggregate["summary"]["errors"] == 0
        assert aggregate["tests"][0]["evidence_refs"]
