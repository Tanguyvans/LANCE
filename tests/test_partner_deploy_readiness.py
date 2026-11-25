"""Regression tests for partner Docker/offline readiness and real-network CIDR scope."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.agent.core.graph_context import GraphContext, bind_graph_context
from src.agent.knowledge import store as knowledge_store
from src.agent.tools import recon_tools


REPO_ROOT = Path(__file__).resolve().parents[1]


class TestArpScanScopeEnforcement:
    """arp_scan must follow the authorized discovery_mode / topology CIDR and fail closed."""

    def test_fails_closed_when_no_authorized_network_is_configured(self):
        ctx = GraphContext()
        with bind_graph_context(ctx), patch("src.agent.tools.recon_tools.subprocess.run") as mock_run:
            result = json.loads(recon_tools.arp_scan())

        assert result["hosts"] == []
        assert result["count"] == 0
        assert "No authorized target_network" in result["error"]
        mock_run.assert_not_called()

    def test_discovery_mode_single_physical_device_slash32_only_pings_and_returns_that_host(self):
        ctx = GraphContext(discovery_mode={"target_network": "10.20.30.40/32"})
        pinged_ips: list[str] = []

        def fake_run(cmd, **kwargs):
            if cmd[0] == "ping":
                pinged_ips.append(cmd[-1])
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if cmd[0] == "arp":
                raise FileNotFoundError("arp not installed")
            if cmd[:3] == ["ip", "neigh", "show"]:
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        "10.20.30.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"
                        "10.20.30.40 dev eth0 lladdr aa:bb:cc:dd:ee:40 REACHABLE\n"
                        "192.168.88.10 dev eth0 lladdr aa:bb:cc:dd:ee:99 REACHABLE\n"
                    ),
                    stderr="",
                )
            raise AssertionError(f"Unexpected command: {cmd}")

        with (
            bind_graph_context(ctx),
            patch("src.agent.tools.recon_tools.subprocess.run", side_effect=fake_run),
            patch("time.sleep"),
        ):
            result = json.loads(recon_tools.arp_scan())

        # Two passes of the single /32 host only — never 192.168.88.x or neighbouring IPs.
        assert pinged_ips == ["10.20.30.40", "10.20.30.40"]
        assert result["count"] == 1
        assert [h["ip"] for h in result["hosts"]] == ["10.20.30.40"]

    def test_discovery_mode_slash28_excludes_ips_outside_cidr(self):
        ctx = GraphContext(discovery_mode={"target_network": "10.20.0.16/28"})
        pinged_ips: set[str] = set()

        def fake_run(cmd, **kwargs):
            if cmd[0] == "ping":
                pinged_ips.add(cmd[-1])
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if cmd[0] == "arp":
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        "? (10.20.0.16) at aa:bb:cc:dd:ee:10 [ether] on eth0\n"
                        "? (10.20.0.17) at aa:bb:cc:dd:ee:11 [ether] on eth0\n"
                        "? (10.20.0.30) at aa:bb:cc:dd:ee:1e [ether] on eth0\n"
                        "? (10.20.0.31) at aa:bb:cc:dd:ee:1f [ether] on eth0\n"
                        "? (10.20.0.32) at aa:bb:cc:dd:ee:20 [ether] on eth0\n"
                    ),
                    stderr="",
                )
            raise AssertionError(f"Unexpected command: {cmd}")

        with (
            bind_graph_context(ctx),
            patch("src.agent.tools.recon_tools.subprocess.run", side_effect=fake_run),
            patch("time.sleep"),
        ):
            result = json.loads(recon_tools.arp_scan())

        # /28 has 14 usable hosts: .17 through .30 (.16 network and .31 broadcast excluded).
        assert len(pinged_ips) == 14
        assert "10.20.0.17" in pinged_ips
        assert "10.20.0.30" in pinged_ips
        assert "10.20.0.16" not in pinged_ips
        assert "10.20.0.31" not in pinged_ips
        assert "10.20.0.32" not in pinged_ips
        assert [h["ip"] for h in result["hosts"]] == ["10.20.0.17", "10.20.0.30"]

    def test_scenario_topology_legacy_subnet_without_mask_still_works(self):
        ctx = GraphContext(scenario_topology={"subnet": "192.168.100.0"})
        pinged_ips: set[str] = set()

        def fake_run(cmd, **kwargs):
            if cmd[0] == "ping":
                pinged_ips.add(cmd[-1])
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if cmd[0] == "arp":
                return SimpleNamespace(
                    returncode=0,
                    stdout="? (192.168.100.12) at 11:22:33:44:55:66 [ether] on eth0\n",
                    stderr="",
                )
            raise AssertionError(f"Unexpected command: {cmd}")

        with (
            bind_graph_context(ctx),
            patch("src.agent.tools.recon_tools.subprocess.run", side_effect=fake_run),
            patch("time.sleep"),
        ):
            result = json.loads(recon_tools.arp_scan())

        assert len(pinged_ips) == 254
        assert "192.168.100.1" in pinged_ips
        assert "192.168.100.254" in pinged_ips
        assert [h["ip"] for h in result["hosts"]] == ["192.168.100.12"]


class TestOfflinePackagingContracts:
    """Verify Dockerfile, ChromaDB settings, and bundle script offline guarantees."""

    def test_dockerfile_installs_iproute2_traceroute_and_disables_telemetry(self):
        dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert "iproute2" in dockerfile
        assert "traceroute" in dockerfile
        assert "ENV ANONYMIZED_TELEMETRY=FALSE" in dockerfile

    def test_chroma_store_disables_anonymized_telemetry(self):
        assert knowledge_store._CHROMA_SETTINGS.anonymized_telemetry is False

    def test_offline_bundle_script_hashes_basename_from_out_dir(self):
        script = (REPO_ROOT / "scripts/deployment/build-offline-bundle.sh").read_text(encoding="utf-8")
        assert '(cd "$OUT_DIR" && sha256sum "$TARBALL_NAME")' in script
        assert '(cd "$OUT_DIR" && shasum -a 256 "$TARBALL_NAME")' in script

    def test_verify_install_script_passes_bash_syntax_check(self):
        import subprocess

        script = REPO_ROOT / "scripts/deployment/verify-install.sh"
        assert script.is_file()
        result = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    def test_env_example_uses_clear_llm_names_and_no_inline_comments_on_active_lines(self):
        env_example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
        assert "AGENT_PROVIDER=ollama" in env_example
        assert "LANCE_LLM_BASE_URL=" in env_example
        assert "LANCE_LLM_MODEL=" in env_example
        for line in env_example.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # Docker Compose env_file treats trailing `# ...` on KEY=val lines as part of the value.
            assert "#" not in stripped, f"Inline comment found on active .env.example line: {line!r}"


class TestCleanEnvAliasesAndOllamaProvider:
    """Verify LANCE_LLM_* primary env vars, LANCE_MOE_* legacy fallback, and `ollama` provider parity."""

    def test_embed_base_url_prefers_embed_then_llm_then_legacy_moe(self, monkeypatch):
        from src.agent.knowledge import embedder

        monkeypatch.delenv("LANCE_EMBED_BASE_URL", raising=False)
        monkeypatch.delenv("LANCE_LLM_BASE_URL", raising=False)
        monkeypatch.delenv("LANCE_MOE_BASE_URL", raising=False)
        assert embedder._embed_base_url() == embedder.DEFAULT_OLLAMA_BASE_URL

        monkeypatch.setenv("LANCE_MOE_BASE_URL", "http://10.0.0.1:11434/v1/")
        assert embedder._embed_base_url() == "http://10.0.0.1:11434/v1"

        monkeypatch.setenv("LANCE_LLM_BASE_URL", "http://10.0.0.2:11434/v1/")
        assert embedder._embed_base_url() == "http://10.0.0.2:11434/v1"

        monkeypatch.setenv("LANCE_EMBED_BASE_URL", "http://10.0.0.3:11434/v1/")
        assert embedder._embed_base_url() == "http://10.0.0.3:11434/v1"

    def test_reconcile_provider_reads_lance_llm_vars_with_legacy_fallback(self, monkeypatch):
        from src.db import reconcile_provider

        monkeypatch.delenv("LANCE_LLM_BASE_URL", raising=False)
        monkeypatch.delenv("LANCE_LLM_MODEL", raising=False)
        monkeypatch.setenv("LANCE_MOE_BASE_URL", "http://legacy:11434/v1/")
        monkeypatch.setenv("LANCE_MOE_MODEL", "legacy-model")
        assert reconcile_provider._env_llm_base_url() == "http://legacy:11434/v1"
        assert reconcile_provider._env_llm_model() == "legacy-model"

        monkeypatch.setenv("LANCE_LLM_BASE_URL", "http://clean:11434/v1/")
        monkeypatch.setenv("LANCE_LLM_MODEL", "qwen2.5:14b")
        assert reconcile_provider._env_llm_base_url() == "http://clean:11434/v1"
        assert reconcile_provider._env_llm_model() == "qwen2.5:14b"

    def test_ollama_provider_matches_ollama_umons_timeout_and_continuation(self):
        from src.agent.provider import (
            _OLLAMA_UMONS_API_TIMEOUT,
            _TOOL_CONTINUATION_PROVIDERS,
            _request_timeout_for,
        )

        assert "ollama" in _TOOL_CONTINUATION_PROVIDERS
        assert "ollama-umons" in _TOOL_CONTINUATION_PROVIDERS
        assert _request_timeout_for("ollama") == _OLLAMA_UMONS_API_TIMEOUT
        assert _request_timeout_for("ollama-umons") == _OLLAMA_UMONS_API_TIMEOUT


class TestAuditMode:
    """Verify LANCE_MODE=audit isolates physical-network auditing from lab/Ansible deployment."""

    def test_environment_and_topology_reflect_audit_mode(self, monkeypatch):
        from src.api import main as api_main
        from src.api.routes import topology as topo_route

        monkeypatch.delenv("LANCE_MODE", raising=False)
        assert api_main.environment()["mode"] == "lab"

        monkeypatch.setenv("LANCE_MODE", "audit")
        assert api_main.environment()["mode"] == "audit"
        assert topo_route.get_topology() == {"nodes": [], "edges": [], "subnet": ""}

    def test_start_request_normalizes_bare_ipv4_to_slash32(self):
        from src.api.routes import pipeline as route

        req = route.StartRequest(
            runner_kind="lance",
            provider="ollama",
            model="qwen3.5-9b-32k:latest",
            target_network="10.107.10.42",
        )
        assert req.target_network == "10.107.10.42/32"

    def test_audit_mode_rejects_lab_deployment_batch_teardown_and_missing_target(self, monkeypatch):
        import asyncio
        import pytest
        from fastapi import HTTPException
        from src.api.routes import pipeline as route

        monkeypatch.setenv("LANCE_MODE", "audit")

        with pytest.raises(HTTPException) as exc_missing:
            asyncio.run(route.start_pipeline(route.StartRequest(
                runner_kind="lance", provider="ollama", model="qwen2.5:7b",
            )))
        assert exc_missing.value.status_code == 422

        with pytest.raises(HTTPException) as exc_scenario:
            asyncio.run(route.start_pipeline(route.StartRequest(
                runner_kind="lance", provider="ollama", model="qwen2.5:7b",
                scenario_id="1", target_network="10.107.10.42/32",
            )))
        assert exc_scenario.value.status_code == 403

        with pytest.raises(HTTPException) as exc_rules:
            asyncio.run(route.start_pipeline(route.StartRequest(
                runner_kind="rules", scenario_id="1",
            )))
        assert exc_rules.value.status_code == 403

        with pytest.raises(HTTPException) as exc_batch:
            asyncio.run(route.start_batch(route.BatchRequest(
                batch_ids=["1"], provider="ollama", model="qwen2.5:7b",
            )))
        assert exc_batch.value.status_code == 403

        with pytest.raises(HTTPException) as exc_teardown:
            asyncio.run(route.teardown_scenario(route.TeardownRequest(scenario_id="1")))
        assert exc_teardown.value.status_code == 403

    def test_validate_recon_markdown_allows_single_host_in_discovery_mode(self, tmp_path):
        from src.agent.validators import validate_recon_markdown

        content = (
            "# Phase 2: Reconnaissance\n\n"
            "## 1. Summary\n\n"
            "| Metric | Value |\n|---|---|\n| Target | 192.168.88.231/32 |\n| Live hosts | 1 |\n\n"
            "## 2. Discovered Services per Device\n\n"
            "| Device | IP | Open Ports | Key Services |\n|---|---|---|---|\n"
            "| iot-hub | 192.168.88.231 | 22, 1883 | OpenSSH 10.0, Mosquitto 2.0.21 |\n\n"
            "## 3. Key Findings\n\n"
            "- Single physical Raspberry Pi discovered on eno1 with SSH and MQTT exposed.\n"
        )
        (tmp_path / "02_recon.md").write_text(content, encoding="utf-8")

        # Without discovery mode, multi-host scenario validation still expects >= 2 devices.
        ok_scenario, msg_scenario = validate_recon_markdown("02_recon.md", output_dir=tmp_path)
        assert not ok_scenario
        assert "at least 2" in msg_scenario

        # In live discovery mode (/32 physical device), 1 discovered host is valid.
        ctx = GraphContext(discovery_mode={"target_network": "192.168.88.231/32"})
        with bind_graph_context(ctx):
            ok_live, msg_live = validate_recon_markdown("02_recon.md", output_dir=tmp_path)
        assert ok_live, msg_live


class TestExcludedIpsAndAdminScopeCeiling:
    """Verify excluded_ips and LANCE_ALLOWED_CIDR across scope, nmap, arp_scan, and API."""

    def test_scope_violation_blocks_excluded_ip_non_nmap_cidr_and_ssh_commands(self):
        from src.agent.phases.intrusion.scope import _intrusion_scope_violation

        excluded = ["192.168.88.1", "192.168.88.168"]
        # Direct IP hit refused
        refusal = _intrusion_scope_violation(
            "http_request", {"url": "http://192.168.88.1/"}, "192.168.88.0/24", excluded,
        )
        assert refusal and refusal["error_kind"] == "intrusion_target_excluded"

        # Non-nmap CIDR overlapping excluded IP refused
        refusal_cidr = _intrusion_scope_violation(
            "nuclei_scan", {"target": "192.168.88.0/24"}, "192.168.88.0/24", excluded,
        )
        assert refusal_cidr and refusal_cidr["error_kind"] == "intrusion_target_excluded"

        # nmap_discovery on CIDR allowed (tool_loader injects --exclude)
        assert _intrusion_scope_violation(
            "nmap_discovery", {"target": "192.168.88.0/24"}, "192.168.88.0/24", excluded,
        ) is None

        # Direct excluded IP still refused even for nmap_scan
        refusal_nmap_direct = _intrusion_scope_violation(
            "nmap_scan", {"target": "192.168.88.168"}, "192.168.88.0/24", excluded,
        )
        assert refusal_nmap_direct and refusal_nmap_direct["error_kind"] == "intrusion_target_excluded"

        # SSH command pivoting to excluded IP refused
        refusal_cmd = _intrusion_scope_violation(
            "ssh_exec",
            {"ip": "192.168.88.231", "command": "curl http://192.168.88.1/admin"},
            "192.168.88.0/24",
            excluded,
        )
        assert refusal_cmd and refusal_cmd["error_kind"] == "intrusion_command_excluded"

    def test_tool_loader_injects_nmap_exclude_flag_from_context(self):
        from src.agent.network_scope import excluded_ips_context
        from src.agent.tools.tool_loader import build_subprocess_function

        tool_fn = build_subprocess_function({
            "name": "nmap_discovery",
            "description": "Discover live hosts",
            "command": "nmap",
            "args": ["-sn"],
            "timeout": 30,
            "parameters": [{"name": "target", "format": "positional"}],
        })
        captured_cmds: list[list[str]] = []

        def fake_run(cmd, **_kwargs):
            captured_cmds.append(cmd)
            return {"stdout": "Nmap done", "stderr": "", "return_code": 0}

        with (
            patch("src.agent.tools.recon_tools._run", side_effect=fake_run),
            excluded_ips_context(["192.168.88.1", "192.168.88.168"]),
        ):
            tool_fn(target="192.168.88.0/24")

        assert len(captured_cmds) == 1
        assert "--exclude" in captured_cmds[0]
        excl_idx = captured_cmds[0].index("--exclude")
        assert captured_cmds[0][excl_idx + 1] == "192.168.88.1,192.168.88.168"

    def test_arp_scan_never_pings_or_returns_excluded_ips(self):
        ctx = GraphContext(discovery_mode={
            "target_network": "192.168.88.0/29",
            "excluded_ips": ["192.168.88.1"],
        })
        pinged: set[str] = set()

        def fake_run(cmd, **_kwargs):
            if cmd[0] == "ping":
                pinged.add(cmd[-1])
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if cmd[0] == "arp":
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        "? (192.168.88.1) at aa:bb:cc:dd:ee:01 [ether] on eno1\n"
                        "? (192.168.88.2) at aa:bb:cc:dd:ee:02 [ether] on eno1\n"
                    ),
                    stderr="",
                )
            raise AssertionError(f"Unexpected command: {cmd}")

        with (
            bind_graph_context(ctx),
            patch("src.agent.tools.recon_tools.subprocess.run", side_effect=fake_run),
            patch("time.sleep"),
        ):
            result = json.loads(recon_tools.arp_scan())

        assert "192.168.88.1" not in pinged
        assert "192.168.88.2" in pinged
        assert [h["ip"] for h in result["hosts"]] == ["192.168.88.2"]

    def test_env_allowed_cidr_and_excluded_ips_enforce_403(self, monkeypatch):
        import asyncio
        import pytest
        from fastapi import HTTPException
        from src.api.routes import pipeline as route

        monkeypatch.setenv("LANCE_MODE", "audit")
        monkeypatch.setenv("LANCE_ALLOWED_CIDR", "192.168.88.0/24")
        monkeypatch.setenv("LANCE_EXCLUDED_IPS", "192.168.88.1,192.168.88.168")

        with pytest.raises(HTTPException) as exc_outside:
            asyncio.run(route.start_pipeline(route.StartRequest(
                runner_kind="lance", provider="ollama", model="flint:latest",
                target_network="10.107.10.0/24",
            )))
        assert exc_outside.value.status_code == 403

        with pytest.raises(HTTPException) as exc_excluded:
            asyncio.run(route.start_pipeline(route.StartRequest(
                runner_kind="lance", provider="ollama", model="flint:latest",
                target_network="192.168.88.1/32",
            )))
        assert exc_excluded.value.status_code == 403


class TestGreyboxAuditTopology:
    """Verify strict parsing, security guards, and open-hypothesis graph_tools integration."""

    SAMPLE_YAML = (
        "subnet: 192.168.88.0/24\n"
        "excluded_ips:\n"
        "  - 192.168.88.1\n"
        "  - 192.168.88.168\n"
        "devices:\n"
        "  - id: iot_hub\n"
        "    ip: 192.168.88.231\n"
        "    type: gateway\n"
        "    role: Raspberry Pi MQTT Hub\n"
        "  - id: wisgate\n"
        "    ip: 192.168.88.238\n"
        "    type: gateway\n"
        "    role: LoRaWAN Gateway\n"
        "links:\n"
        "  - source: wisgate\n"
        "    target: iot_hub\n"
        "    type: mqtt\n"
    )

    def test_valid_yaml_parses_and_powers_graph_tools_in_discovery_mode(self):
        from src.agent.audit_topology import validate_audit_topology
        from src.agent.tools import graph_tools

        topo = validate_audit_topology(self.SAMPLE_YAML)
        assert topo["subnet"] == "192.168.88.0/24"
        assert topo["excluded_ips"] == ["192.168.88.1", "192.168.88.168"]
        assert len(topo["nodes"]) == 2
        assert len(topo["edges"]) == 1

        ctx = GraphContext()
        with bind_graph_context(ctx):
            summary = graph_tools.load_discovery_context(
                topo["subnet"], excluded_ips=topo["excluded_ips"], audit_topology=topo,
            )
            assert summary["device_count"] == 2
            topo_resp = json.loads(graph_tools.get_network_topology())
            assert topo_resp["mode"] == "greybox_audit"
            assert len(topo_resp["nodes"]) == 2
            dev_resp = json.loads(graph_tools.get_device_info("iot_hub"))
            assert dev_resp["ip"] == "192.168.88.231"
            paths_resp = json.loads(graph_tools.get_attack_paths())
            assert paths_resp["cves_pending_active_scan"] is True
            assert "iot_hub" in paths_resp["pivot_candidates"]
            neighbors = graph_tools.get_network_neighbors("iot_hub")
            assert any(n["id"] == "wisgate" for n in neighbors["upstream"])

    def test_rejects_yaml_aliases_unsafe_ids_and_excluded_device_ip(self):
        import pytest
        from src.agent.audit_topology import validate_audit_topology

        with pytest.raises(ValueError, match="anchors/aliases"):
            validate_audit_topology("subnet: 192.168.88.0/24\na: &a [1, 2]\nb: *a\n")

        with pytest.raises(ValueError, match="must match"):
            validate_audit_topology(
                "subnet: 192.168.88.0/24\ndevices:\n  - id: ../evil\n    ip: 192.168.88.231\n"
            )

        with pytest.raises(ValueError, match="excluded_ips"):
            validate_audit_topology(
                "subnet: 192.168.88.0/24\nexcluded_ips: [192.168.88.1]\ndevices:\n  - id: router\n    ip: 192.168.88.1\n"
            )

    def test_topology_preview_endpoint_returns_cytoscape_data(self):
        from src.api.routes.topology import TopologyPreviewRequest, preview_audit_topology

        resp = preview_audit_topology(TopologyPreviewRequest(raw_topology=self.SAMPLE_YAML))
        assert resp["subnet"] == "192.168.88.0/24"
        assert resp["device_count"] == 2
        assert resp["link_count"] == 1
        assert len(resp["topology"]["nodes"]) == 2


class TestDiscoveredTopologyGraph:
    """Verify honest L2/L3 discovered topology reconstruction without fabricated links."""

    def test_classify_discovered_device_uses_vendor_and_services(self):
        from src.agent.audit_topology import classify_discovered_device

        assert classify_discovered_device("192.168.88.238", vendor="RAK Wireless (WisGate)", open_ports=[22, 80, 1883])[0] == "gateway"
        assert classify_discovered_device("192.168.88.251", vendor="TP-Link", open_ports=[80, 443])[0] == "ap"
        assert classify_discovered_device("192.168.88.253", vendor="Ubiquiti", open_ports=[22, 80, 443])[0] == "camera"
        assert classify_discovered_device("192.168.88.248", vendor="NVIDIA (Jetson)", open_ports=[22, 1883])[0] == "compute"
        assert classify_discovered_device("192.168.88.231", vendor="Raspberry Pi", open_ports=[22, 1883])[0] == "gateway"
        assert classify_discovered_device("192.168.88.212", vendor="Raspberry Pi", open_ports=[22, 8080])[0] == "compute"
        assert classify_discovered_device("192.168.88.236", vendor="Maxglo / Unknown", open_ports=[22])[:2] == ("compute", "192.168.88.236")

    def test_flat_l2_subnet_builds_segment_gateway_and_shared_mac_without_fake_mqtt(self):
        from src.agent.audit_topology import build_discovered_topology_graph

        devices = [
            {"ip": "192.168.88.231", "mac": "88:a2:9e:6f:08:13", "vendor": "Raspberry Pi", "open_ports": [22, 1883],
             "services": [{"port": 22, "service": "ssh"}, {"port": 1883, "service": "mosquitto"}]},
            {"ip": "192.168.88.232", "mac": "88:a2:9e:6f:08:13", "vendor": "Raspberry Pi", "open_ports": [22, 1883],
             "services": [{"port": 22, "service": "ssh"}, {"port": 1883, "service": "mosquitto"}]},
            {"ip": "192.168.88.251", "mac": "e4:fa:c4:c7:49:60", "vendor": "TP-Link", "open_ports": [80, 443],
             "services": [{"port": 80, "service": "http"}]},
            {"ip": "192.168.88.131", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Excluded Tower", "open_ports": [22]},
        ]
        graph = build_discovered_topology_graph(
            target_network="192.168.88.0/24",
            devices=devices,
            host_hops={"192.168.88.231": [], "192.168.88.232": [], "192.168.88.251": []},
            default_gateway="192.168.88.1",
            excluded_ips=["192.168.88.1", "192.168.88.131", "192.168.88.168"],
        )

        node_ids = {n["id"] for n in graph["nodes"]}
        assert "192.168.88.131" not in node_ids
        assert "segment_192.168.88.0/24" in node_ids
        assert "gw_192.168.88.1" in node_ids
        gw_node = next(n for n in graph["nodes"] if n["id"] == "gw_192.168.88.1")
        assert gw_node["excluded"] is True and gw_node["out_of_scope"] is True

        # Zero fabricated mqtt edges between unrelated hosts
        assert not any(e["protocol"] == "mqtt" for e in graph["edges"])
        # Shared MAC alias detected between .231 and .232
        alias_edges = [e for e in graph["edges"] if e["protocol"] == "alias"]
        assert len(alias_edges) == 1
        assert {alias_edges[0]["source"], alias_edges[0]["target"]} == {"192.168.88.231", "192.168.88.232"}
        # All 3 observed hosts attached to the L2 segment
        l2_edges = [e for e in graph["edges"] if e["origin"] == "observed_l2" and e["protocol"] == "ethernet"]
        assert len(l2_edges) == 3

    def test_greybox_attaches_shadow_hosts_to_declared_switch_and_enriches_declared(self):
        from src.agent.audit_topology import build_discovered_topology_graph, validate_audit_topology

        declared = validate_audit_topology(
            "subnet: 192.168.88.0/24\n"
            "devices:\n"
            "  - id: sw1\n"
            "    type: switch\n"
            "    name: Netgear Switch\n"
            "  - id: rpi_hub\n"
            "    ip: 192.168.88.231\n"
            "    type: gateway\n"
            "links:\n"
            "  - source: sw1\n"
            "    target: rpi_hub\n"
            "    protocol: ethernet\n"
        )
        graph = build_discovered_topology_graph(
            target_network="192.168.88.0/24",
            devices=[
                {"ip": "192.168.88.231", "mac": "88:a2:9e:6f:08:13", "vendor": "Raspberry Pi", "open_ports": [22, 1883]},
                {"ip": "192.168.88.253", "mac": "6c:63:f8:e5:e5:f7", "vendor": "Ubiquiti", "open_ports": [22, 80]},
            ],
            host_hops={"192.168.88.231": [], "192.168.88.253": []},
            declared_topology=declared,
        )
        hub = next(n for n in graph["nodes"] if n["id"] == "rpi_hub")
        assert hub["declared"] is True and hub["observed"] is True and hub["mac"] == "88:a2:9e:6f:08:13"
        shadow = next(n for n in graph["nodes"] if n["id"] == "192.168.88.253")
        assert shadow["declared"] is False and shadow["type"] == "camera"
        assert any(
            e["origin"] == "inferred_l2" and {e["source"], e["target"]} == {"sw1", "192.168.88.253"}
            for e in graph["edges"]
        )

    def test_single_host_32_does_not_add_virtual_segment_and_routed_hops_link(self):
        from src.agent.audit_topology import build_discovered_topology_graph

        single = build_discovered_topology_graph(
            target_network="192.168.88.231/32",
            devices=[{"ip": "192.168.88.231", "vendor": "Raspberry Pi", "open_ports": [22, 1883]}],
            host_hops={"192.168.88.231": []},
            default_gateway="192.168.88.1",
        )
        assert len(single["nodes"]) == 1
        assert single["edges"] == []

        routed = build_discovered_topology_graph(
            target_network="10.20.0.0/24",
            devices=[{"ip": "10.20.0.15", "open_ports": [22]}],
            host_hops={"10.20.0.15": ["10.20.0.1", "10.10.0.1"]},
            excluded_ips=["10.20.0.1"],
        )
        tr_edges = [e for e in routed["edges"] if e["origin"] == "traceroute"]
        assert len(tr_edges) == 2

    def test_runs_api_exposes_target_network_for_lance_and_phase_done_tracks_cumulative_cost(self, tmp_path):
        from src.api.routes import pipeline as pipe_route
        from src.api.routes import runs as runs_route

        run_dir = tmp_path / "2026-11-25_150109"
        run_dir.mkdir()
        (run_dir / "run_meta.json").write_text(
            json.dumps({"runner_kind": "lance", "target_network": "192.168.88.0/24"}),
            encoding="utf-8",
        )
        details = runs_route._extract_runner_details(run_dir)
        assert details == {"target_network": "192.168.88.0/24"}

        orig_cost = pipe_route._state["cost"]
        orig_phases = list(pipe_route._state["phases_done"])
        try:
            pipe_route._state["cost"] = 0.0
            pipe_route._state["phases_done"] = []
            ev1 = {"type": "phase_done", "phase": 1, "name": "graph_analysis", "cost_usd": 0.12}
            ev2 = {"type": "phase_done", "phase": 2, "name": "recon", "cost_usd": 0.25}
            pipe_route._update_pipeline_progress(ev1)
            pipe_route._update_pipeline_progress(ev2)
            assert ev1["cumulative_cost_usd"] == 0.12
            assert ev2["cumulative_cost_usd"] == 0.37
        finally:
            pipe_route._state["cost"] = orig_cost
            pipe_route._state["phases_done"] = orig_phases

    def test_report_sections_bounds_oversized_phase4_test_evidence(self, tmp_path):
        from src.agent.phases.report import sections

        (tmp_path / "03_vuln_analysis.json").write_text(
            json.dumps({"vulnerabilities": [{"id": "V1", "device_ip": "192.168.88.231", "type": "no_auth", "severity": "HIGH"}]}),
            encoding="utf-8",
        )
        (tmp_path / "04_exploitation.json").write_text(
            json.dumps({
                "tests": [{
                    "vuln_id": "V1",
                    "device_ip": "192.168.88.231",
                    "status": "CONFIRMED",
                    "evidence": "mqtt-payload-" * 50_000,
                    "data_extracted": {"dump": "x" * 100_000},
                }]
            }),
            encoding="utf-8",
        )
        cards, _ = sections.build_cards(tmp_path)
        finding_card = next(c for c in cards if c["kind"] == "finding")
        linked = finding_card["facts"]["tests"][0]
        assert linked["record_excerpt_truncated"] is True
        assert len(linked["record"]["evidence"]) == sections.OBSERVATION_EXCERPT_CHARS
        assert len(sections.encoded(finding_card).encode("utf-8")) < sections.CONTEXT_MAX_BYTES

    def test_adjacent_mac_dual_nic_and_audit_mode_english_report_cards(self, tmp_path, monkeypatch):
        from src.agent.audit_topology import build_discovered_topology_graph
        from src.agent.phases.report import sections

        graph = build_discovered_topology_graph(
            target_network="192.168.88.0/24",
            devices=[
                {"ip": "192.168.88.231", "mac": "88:a2:9e:6f:08:13", "vendor": "Raspberry Pi", "open_ports": [22, 1883]},
                {"ip": "192.168.88.232", "mac": "88:a2:9e:6f:08:14", "vendor": "Raspberry Pi", "open_ports": [22, 1883]},
            ],
            host_hops={"192.168.88.231": [], "192.168.88.232": []},
        )
        alias_edges = [e for e in graph["edges"] if e["protocol"] == "alias"]
        assert len(alias_edges) == 1
        assert alias_edges[0]["label"] == "same host (eth/wifi)"

        (tmp_path / "03_vuln_analysis.json").write_text(
            json.dumps({"vulnerabilities": [{"id": "V1", "device_ip": "192.168.88.231", "type": "no_auth", "severity": "HIGH"}]}),
            encoding="utf-8",
        )
        (tmp_path / "04_exploitation.json").write_text(json.dumps({"tests": []}), encoding="utf-8")

        monkeypatch.setenv("LANCE_MODE", "audit")
        cards_en, summary_en = sections.build_cards(tmp_path)
        assert cards_en[0]["title"] == "Finding V1"
        assert "Analysis:" in sections.render_summary(summary_en)

        monkeypatch.setenv("LANCE_MODE", "lab")
        cards_fr, summary_fr = sections.build_cards(tmp_path)
        assert cards_fr[0]["title"] == "Hypothèse V1"
        assert "Analyse :" in sections.render_summary(summary_fr)
