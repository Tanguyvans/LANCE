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
