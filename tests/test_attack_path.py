"""Tests for attack_path module."""

from pathlib import Path

import pytest

from src.cve_lookup import CVEResult, DeviceCVEReport
from src.loader import build_graph
from src.attack_path import (
    PROTOCOL_FACTORS,
    EdgeWeight,
    AttackPath,
    AttackPathReport,
    compute_exploitability,
    compute_edge_weights,
    build_weighted_graph,
    find_attack_paths,
    find_pivot_nodes,
    analyze_attack_paths,
)

YAML_PATH = Path(__file__).resolve().parent.parent / "infrastructure" / "nato_lab.yaml"


@pytest.fixture(scope="module")
def backend():
    return build_graph(YAML_PATH)


def _make_report(device_id, cves=None):
    return DeviceCVEReport(
        device_id=device_id,
        device_name=device_id,
        cves=cves or [],
    )


# Realistic mock CVE data
MOCK_CVE_REPORTS = [
    _make_report("mikrotik", [
        CVEResult("CVE-2023-32154", "RouterOS RADVD buffer overflow",
                  cvss_score=9.1, severity="CRITICAL", attack_vector="NETWORK"),
        CVEResult("CVE-2023-30799", "RouterOS privilege escalation",
                  cvss_score=7.2, severity="HIGH", attack_vector="NETWORK"),
    ]),
    _make_report("wisgate", [
        CVEResult("CVE-2021-23017", "nginx DNS resolver vuln",
                  cvss_score=7.7, severity="HIGH", attack_vector="NETWORK"),
        CVEResult("CVE-2021-36369", "Dropbear SSH trivial auth",
                  cvss_score=7.5, severity="HIGH", attack_vector="NETWORK"),
    ]),
    _make_report("rpi5", [
        CVEResult("CVE-2023-51385", "OpenSSH command injection",
                  cvss_score=5.9, severity="MEDIUM", attack_vector="NETWORK"),
    ]),
    _make_report("eap613", [
        CVEResult("CVE-2023-27359", "TP-Link RCE",
                  cvss_score=8.8, severity="HIGH", attack_vector="ADJACENT_NETWORK"),
    ]),
]


# ------------------------------------------------------------------
# Exploitability
# ------------------------------------------------------------------


class TestExploitability:
    def test_device_with_cves(self):
        score = compute_exploitability(MOCK_CVE_REPORTS, "mikrotik")
        assert score > 0.7  # 0.85 * 9.1/10 = 0.7735

    def test_device_without_cves(self):
        score = compute_exploitability(MOCK_CVE_REPORTS, "netgear")
        assert score == 0.0

    def test_uses_highest_cvss(self):
        """Should pick the CVE with the highest CVSS, not the first one."""
        reports = [_make_report("test", [
            CVEResult("CVE-LOW", "low", cvss_score=3.0, attack_vector="LOCAL"),
            CVEResult("CVE-HIGH", "high", cvss_score=9.5, attack_vector="NETWORK"),
        ])]
        score = compute_exploitability(reports, "test")
        # Should use 9.5: 0.85 * 9.5/10 = 0.8075
        assert score > 0.8

    def test_adjacent_network_vector(self):
        score = compute_exploitability(MOCK_CVE_REPORTS, "eap613")
        # 0.62 * 8.8/10 = 0.5456
        assert 0.5 < score < 0.6


# ------------------------------------------------------------------
# Edge weights
# ------------------------------------------------------------------


class TestEdgeWeights:
    def test_all_edges_weighted(self, backend):
        weights = compute_edge_weights(backend, MOCK_CVE_REPORTS)
        graph_edges = backend.graph.number_of_edges()
        assert len(weights) == graph_edges

    def test_vulnerable_target_higher_weight(self, backend):
        weights = compute_edge_weights(backend, MOCK_CVE_REPORTS)
        weight_map = {(ew.source, ew.target): ew for ew in weights}

        # internet -> mikrotik (vulnerable, wan)
        w_mikrotik = weight_map[("internet", "mikrotik")]
        # netgear -> jetson (no CVE, ethernet)
        w_jetson = weight_map[("netgear", "jetson")]

        assert w_mikrotik.weight > w_jetson.weight

    def test_relay_higher_than_non_relay(self, backend):
        """A switch (relay) without CVE should be easier to traverse than a compute node without CVE."""
        weights = compute_edge_weights(backend, MOCK_CVE_REPORTS)
        weight_map = {(ew.source, ew.target): ew for ew in weights}

        # mikrotik -> netgear (switch = relay, no CVE)
        w_relay = weight_map[("mikrotik", "netgear")]
        # netgear -> jetson (compute = not relay, no CVE)
        w_compute = weight_map[("netgear", "jetson")]

        assert w_relay.weight > w_compute.weight

    def test_protocol_factor_applied(self, backend):
        weights = compute_edge_weights(backend, MOCK_CVE_REPORTS)
        weight_map = {(ew.source, ew.target): ew for ew in weights}

        # lorawan link should have lower protocol factor
        w_lorawan = weight_map[("em310", "wisgate")]
        assert w_lorawan.protocol_factor == PROTOCOL_FACTORS["lorawan"]

        # ethernet link
        w_eth = weight_map[("netgear", "wisgate")]
        assert w_eth.protocol_factor == PROTOCOL_FACTORS["ethernet"]


# ------------------------------------------------------------------
# Weighted graph
# ------------------------------------------------------------------


class TestWeightedGraph:
    def test_same_node_edge_count(self, backend):
        weights = compute_edge_weights(backend, MOCK_CVE_REPORTS)
        wg = build_weighted_graph(backend, weights)
        assert wg.number_of_nodes() == backend.graph.number_of_nodes()
        assert wg.number_of_edges() == backend.graph.number_of_edges()

    def test_attack_cost_present(self, backend):
        weights = compute_edge_weights(backend, MOCK_CVE_REPORTS)
        wg = build_weighted_graph(backend, weights)
        for src, tgt, data in wg.edges(data=True):
            assert "attack_cost" in data
            assert "attack_weight" in data
            assert data["attack_cost"] > 0


# ------------------------------------------------------------------
# Attack paths
# ------------------------------------------------------------------


class TestAttackPaths:
    @pytest.fixture(scope="class")
    def attack_data(self, backend):
        weights = compute_edge_weights(backend, MOCK_CVE_REPORTS)
        wg = build_weighted_graph(backend, weights)
        paths = find_attack_paths(wg, MOCK_CVE_REPORTS)
        return paths

    def test_path_to_mikrotik_one_hop(self, attack_data):
        mk_paths = [p for p in attack_data if p.target_device == "mikrotik"]
        assert len(mk_paths) == 1
        assert mk_paths[0].path == ["internet", "mikrotik"]
        assert len(mk_paths[0].hops) == 1

    def test_path_to_wisgate_multi_hop(self, attack_data):
        wg_paths = [p for p in attack_data if p.target_device == "wisgate"]
        assert len(wg_paths) == 1
        assert len(wg_paths[0].hops) >= 3  # internet -> mikrotik -> netgear -> wisgate

    def test_no_path_to_sensors(self, attack_data):
        """Sensors have no services, so no attack path should target them."""
        sensor_ids = {"em310", "sensecap", "elsys", "dragino", "aqara_vib", "aqara_door"}
        targeted = {p.target_device for p in attack_data}
        assert targeted.isdisjoint(sensor_ids)

    def test_sorted_by_score(self, attack_data):
        for i in range(len(attack_data) - 1):
            assert attack_data[i].total_score >= attack_data[i + 1].total_score

    def test_path_score_is_product_of_hops(self, attack_data):
        for ap in attack_data:
            expected = 1.0
            for hop in ap.hops:
                expected *= hop.weight
            assert abs(ap.path_score - round(expected, 6)) < 1e-4


# ------------------------------------------------------------------
# Pivot nodes
# ------------------------------------------------------------------


class TestPivotNodes:
    @pytest.fixture(scope="class")
    def pivots(self, backend):
        weights = compute_edge_weights(backend, MOCK_CVE_REPORTS)
        wg = build_weighted_graph(backend, weights)
        paths = find_attack_paths(wg, MOCK_CVE_REPORTS)
        return find_pivot_nodes(backend, paths)

    def test_netgear_is_pivot(self, pivots):
        pivot_ids = {p["node_id"] for p in pivots}
        assert "netgear" in pivot_ids

    def test_internet_not_pivot(self, pivots):
        """Internet is always source, never an intermediary."""
        pivot_ids = {p["node_id"] for p in pivots}
        assert "internet" not in pivot_ids

    def test_pivot_has_betweenness(self, pivots):
        netgear = next(p for p in pivots if p["node_id"] == "netgear")
        assert netgear["betweenness"] > 0


# ------------------------------------------------------------------
# Integration: full report
# ------------------------------------------------------------------


class TestAnalyzeAttackPaths:
    def test_report_has_paths_and_pivots(self, backend):
        report = analyze_attack_paths(backend, MOCK_CVE_REPORTS)
        assert isinstance(report, AttackPathReport)
        assert len(report.critical_paths) > 0
        assert len(report.pivot_nodes) > 0

    def test_summary_populated(self, backend):
        report = analyze_attack_paths(backend, MOCK_CVE_REPORTS)
        assert "total_paths" in report.summary
        assert "total_pivots" in report.summary
        assert report.summary["top_target"] is not None
        assert report.summary["top_score"] > 0
