"""Tests for risk_scorer module."""

from pathlib import Path

import pytest

from src.cve_lookup import CVEResult, DeviceCVEReport
from src.loader import build_graph
from src.risk_scorer import (
    DeviceRiskScore,
    compute_centrality,
    compute_hops_from_internet,
    score_all_devices,
    score_device,
)

YAML_PATH = Path(__file__).resolve().parent.parent / "infrastructure" / "nato_lab.yaml"


@pytest.fixture(scope="module")
def backend():
    return build_graph(YAML_PATH)


def _make_report(device_id, cves=None):
    """Helper to build a DeviceCVEReport with optional CVEs."""
    return DeviceCVEReport(
        device_id=device_id,
        device_name=device_id,
        cves=cves or [],
    )


# ------------------------------------------------------------------
# Hops from internet
# ------------------------------------------------------------------


class TestHopsFromInternet:
    def test_mikrotik_is_closest(self, backend):
        hops = compute_hops_from_internet(backend, "mikrotik")
        assert hops == 1

    def test_netgear_two_hops(self, backend):
        hops = compute_hops_from_internet(backend, "netgear")
        assert hops == 2

    def test_jetson_three_hops(self, backend):
        hops = compute_hops_from_internet(backend, "jetson")
        assert hops == 3

    def test_sensor_further_than_gateway(self, backend):
        sensor_hops = compute_hops_from_internet(backend, "em310")
        gateway_hops = compute_hops_from_internet(backend, "wisgate")
        assert sensor_hops > gateway_hops


# ------------------------------------------------------------------
# Centrality
# ------------------------------------------------------------------


class TestCentrality:
    def test_netgear_has_high_centrality(self, backend):
        centrality = compute_centrality(backend)
        netgear = centrality["netgear"]
        # Netgear is the switch connecting everything
        assert netgear > 0.1

    def test_sensor_has_low_centrality(self, backend):
        centrality = compute_centrality(backend)
        sensor = centrality["em310"]
        assert sensor < 0.05


# ------------------------------------------------------------------
# Device scoring
# ------------------------------------------------------------------


class TestScoreDevice:
    def test_device_with_cves_has_positive_score(self, backend):
        report = _make_report("wisgate", [
            CVEResult("CVE-2021-23017", "nginx", cvss_score=7.7, severity="HIGH", attack_vector="NETWORK"),
            CVEResult("CVE-2021-36369", "dropbear", cvss_score=7.5, severity="HIGH", attack_vector="NETWORK"),
        ])
        centrality = compute_centrality(backend)
        result = score_device(backend, "wisgate", report, centrality)
        assert result.risk_score > 0
        assert result.max_cvss == 7.7
        assert result.cve_count == 2

    def test_device_no_cves_lower_score(self, backend):
        report_with = _make_report("wisgate", [
            CVEResult("CVE-2021-23017", "nginx", cvss_score=7.7, severity="HIGH", attack_vector="NETWORK"),
        ])
        report_without = _make_report("wisgate")
        centrality = compute_centrality(backend)
        score_with = score_device(backend, "wisgate", report_with, centrality)
        score_without = score_device(backend, "wisgate", report_without, centrality)
        assert score_with.risk_score > score_without.risk_score

    def test_score_capped_at_10(self, backend):
        report = _make_report("mikrotik", [
            CVEResult("CVE-FAKE", "fake", cvss_score=10.0, severity="CRITICAL", attack_vector="NETWORK"),
        ])
        centrality = compute_centrality(backend)
        result = score_device(backend, "mikrotik", report, centrality)
        assert result.risk_score <= 10.0


# ------------------------------------------------------------------
# Full scoring
# ------------------------------------------------------------------


class TestScoreAllDevices:
    def test_sorted_descending(self, backend):
        reports = [
            _make_report("mikrotik", [
                CVEResult("CVE-2018-5951", "dos", cvss_score=7.5, severity="HIGH", attack_vector="NETWORK"),
            ]),
            _make_report("wisgate", [
                CVEResult("CVE-2021-23017", "nginx", cvss_score=7.7, severity="HIGH", attack_vector="NETWORK"),
            ]),
        ]
        scores = score_all_devices(backend, reports)
        for i in range(len(scores) - 1):
            assert scores[i].risk_score >= scores[i + 1].risk_score

    def test_mikrotik_higher_than_sensor(self, backend):
        reports = [
            _make_report("mikrotik", [
                CVEResult("CVE-2018-5951", "dos", cvss_score=7.5, severity="HIGH", attack_vector="NETWORK"),
            ]),
        ]
        scores = score_all_devices(backend, reports)
        score_map = {s.device_id: s for s in scores}
        assert score_map["mikrotik"].risk_score > score_map["em310"].risk_score

    def test_all_nodes_scored(self, backend):
        scores = score_all_devices(backend, [])
        node_count = backend.get_graph_stats()["nodes"]
        assert len(scores) == node_count
