"""Risk scoring module.

Computes a risk score (0-10) per device by combining:
- Vulnerability score (max CVSS from known CVEs)
- Exposure score (number of services / distance from internet)
- Centrality score (betweenness centrality in the network graph)
"""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from .cve_lookup import DeviceCVEReport
from .graph_backend import NetworkXBackend


@dataclass
class DeviceRiskScore:
    device_id: str
    device_name: str
    risk_score: float = 0.0
    max_cvss: float = 0.0
    avg_cvss: float = 0.0
    cve_count: int = 0
    num_services: int = 0
    hops_from_internet: int = -1
    betweenness: float = 0.0
    details: dict = field(default_factory=dict)


# ---- Weights ----
W_VULN = 0.4
W_EXPOSURE = 0.3
W_CENTRALITY = 0.3


def compute_hops_from_internet(backend: NetworkXBackend, device_id: str) -> int:
    """Shortest-path length from 'internet' to *device_id* (undirected).

    Returns -1 if no path exists.
    """
    undirected = backend.graph.to_undirected()
    try:
        return nx.shortest_path_length(undirected, "internet", device_id)
    except (nx.NetworkXError, nx.NodeNotFound):
        return -1


def compute_centrality(backend: NetworkXBackend) -> dict[str, float]:
    """Betweenness centrality on the undirected view of the graph."""
    undirected = backend.graph.to_undirected()
    return nx.betweenness_centrality(undirected)


def _exposure_score(num_services: int, hops: int) -> float:
    """Exposure score (0-10).

    More services + fewer hops from internet = higher score.
    """
    if hops <= 0:
        hops = 1
    raw = num_services * (1.0 / hops)
    return min(raw * 10.0 / 6.0, 10.0)


def _centrality_score(betweenness: float, max_betweenness: float) -> float:
    """Centrality score (0-10), normalized to the graph's max betweenness."""
    if max_betweenness <= 0:
        return 0.0
    return (betweenness / max_betweenness) * 10.0


def score_device(
    backend: NetworkXBackend,
    device_id: str,
    cve_report: DeviceCVEReport | None,
    centrality_map: dict[str, float],
) -> DeviceRiskScore:
    """Compute a risk score for a single device."""
    dev = backend.get_device(device_id)
    services = dev.get("services", [])
    hops = compute_hops_from_internet(backend, device_id)

    # Vulnerability metrics
    scores = [c.cvss_score for c in (cve_report.cves if cve_report else []) if c.cvss_score]
    max_cvss = max(scores) if scores else 0.0
    avg_cvss = sum(scores) / len(scores) if scores else 0.0
    cve_count = len(cve_report.cves) if cve_report else 0

    # Component scores
    vuln = max_cvss
    exposure = _exposure_score(len(services), hops)
    max_betweenness = max(centrality_map.values()) if centrality_map else 0.0
    betweenness = centrality_map.get(device_id, 0.0)
    centrality = _centrality_score(betweenness, max_betweenness)

    risk = W_VULN * vuln + W_EXPOSURE * exposure + W_CENTRALITY * centrality
    risk = min(risk, 10.0)

    return DeviceRiskScore(
        device_id=device_id,
        device_name=dev.get("name", device_id),
        risk_score=round(risk, 1),
        max_cvss=round(max_cvss, 1),
        avg_cvss=round(avg_cvss, 1),
        cve_count=cve_count,
        num_services=len(services),
        hops_from_internet=hops,
        betweenness=round(betweenness, 4),
        details={
            "vuln_score": round(vuln, 2),
            "exposure_score": round(exposure, 2),
            "centrality_score": round(centrality, 2),
        },
    )


def score_all_devices(
    backend: NetworkXBackend,
    cve_reports: list[DeviceCVEReport],
) -> list[DeviceRiskScore]:
    """Score every node in the graph and return sorted by risk (desc)."""
    report_map = {r.device_id: r for r in cve_reports}
    centrality_map = compute_centrality(backend)

    results = []
    for node_id in backend.graph.nodes:
        results.append(
            score_device(backend, node_id, report_map.get(node_id), centrality_map)
        )

    results.sort(key=lambda s: s.risk_score, reverse=True)
    return results


def print_risk_report(scores: list[DeviceRiskScore]) -> None:
    """Print a formatted risk report to stdout."""
    print()
    print("=" * 78)
    print("RISK SCORE REPORT")
    print("=" * 78)
    print(
        f"{'#':>3}  {'Device':<25} {'Risk':>5}  {'MaxCVSS':>7}  "
        f"{'Svc':>3}  {'Hops':>4}  {'CVEs':>4}  {'Betw':>6}"
    )
    print("-" * 78)

    for i, s in enumerate(scores, 1):
        hops_str = str(s.hops_from_internet) if s.hops_from_internet >= 0 else "N/A"
        print(
            f"{i:>3}  {s.device_name:<25} {s.risk_score:>5.1f}  {s.max_cvss:>7.1f}  "
            f"{s.num_services:>3}  {hops_str:>4}  {s.cve_count:>4}  {s.betweenness:>6.4f}"
        )

    print("=" * 78)
