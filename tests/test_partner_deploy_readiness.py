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
