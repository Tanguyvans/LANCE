"""Attack path analysis module.

Weights graph edges by exploitation difficulty and detects
critical multi-hop attack paths from the internet to vulnerable devices.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from .cve_lookup import DeviceCVEReport
from .graph_backend import NetworkXBackend


# -- Constants ---------------------------------------------------------------

PROTOCOL_FACTORS: dict[str, float] = {
    "ethernet": 0.8,
    "wan": 0.7,
    "mqtt": 0.6,
    "zigbee": 0.3,
    "lorawan": 0.2,
}

ATTACK_VECTOR_SCORES: dict[str, float] = {
    "NETWORK": 0.85,
    "ADJACENT_NETWORK": 0.62,
    "LOCAL": 0.55,
    "PHYSICAL": 0.20,
}

HOP_AMPLIFICATION = 1.1

# Network infrastructure types that act as passive relays (not exploitation targets)
NETWORK_RELAY_TYPES = {"switch", "router", "ap"}
RELAY_PASSTHROUGH_FACTOR = 0.5
DEFAULT_NO_CVE_FACTOR = 0.1


# -- Dataclasses -------------------------------------------------------------

@dataclass
class EdgeWeight:
    source: str
    target: str
    weight: float
    link_type: str
    protocol_factor: float
    exploit_factor: float


@dataclass
class AttackHop:
    source: str
    target: str
    weight: float
    link_type: str
    target_cves: list[str] = field(default_factory=list)


@dataclass
class AttackPath:
    path: list[str]
    hops: list[AttackHop]
    path_score: float
    impact_score: float
    total_score: float
    target_device: str


@dataclass
class AttackPathReport:
    critical_paths: list[AttackPath]
    pivot_nodes: list[dict]
    summary: dict = field(default_factory=dict)


# -- Exploitability ----------------------------------------------------------

def compute_exploitability(
    cve_reports: list[DeviceCVEReport], device_id: str
) -> float:
    """Exploitability score (0-1) based on the highest-CVSS CVE of a device.

    Returns 0.0 if the device has no CVEs.
    """
    report = next((r for r in cve_reports if r.device_id == device_id), None)
    if not report or not report.cves:
        return 0.0

    best = max(
        report.cves,
        key=lambda c: c.cvss_score if c.cvss_score else 0.0,
    )
    if not best.cvss_score:
        return 0.0

    av_score = ATTACK_VECTOR_SCORES.get(best.attack_vector or "", 0.55)
    return av_score * (best.cvss_score / 10.0)


# -- Edge weights ------------------------------------------------------------

def compute_edge_weights(
    backend: NetworkXBackend, cve_reports: list[DeviceCVEReport]
) -> list[EdgeWeight]:
    """Compute an exploitation weight for every directed edge in the graph."""
    weights: list[EdgeWeight] = []

    for src, tgt, data in backend.graph.edges(data=True):
        link_type = data.get("type", "ethernet")
        protocol_factor = PROTOCOL_FACTORS.get(link_type, 0.5)
        exploit_factor = compute_exploitability(cve_reports, tgt)

        if exploit_factor > 0:
            weight = protocol_factor * exploit_factor
        else:
            # Network relays (switch, router, ap) are passive — easy to traverse.
            # Other devices without CVEs are harder to use as pivot.
            target_type = backend.graph.nodes[tgt].get("type", "")
            if target_type in NETWORK_RELAY_TYPES:
                weight = protocol_factor * RELAY_PASSTHROUGH_FACTOR
            else:
                weight = protocol_factor * DEFAULT_NO_CVE_FACTOR

        weights.append(EdgeWeight(
            source=src,
            target=tgt,
            weight=round(weight, 4),
            link_type=link_type,
            protocol_factor=protocol_factor,
            exploit_factor=round(exploit_factor, 4),
        ))

    return weights


# -- Weighted graph ----------------------------------------------------------

def build_weighted_graph(
    backend: NetworkXBackend, edge_weights: list[EdgeWeight]
) -> nx.DiGraph:
    """Return a copy of the directed graph with attack weights on edges."""
    wg = backend.graph.copy()

    weight_map = {(ew.source, ew.target): ew for ew in edge_weights}

    for src, tgt in wg.edges():
        ew = weight_map.get((src, tgt))
        if ew:
            wg[src][tgt]["attack_weight"] = ew.weight
            wg[src][tgt]["attack_cost"] = 1.0 / ew.weight if ew.weight > 0 else 1000.0
        else:
            wg[src][tgt]["attack_weight"] = 0.01
            wg[src][tgt]["attack_cost"] = 100.0

    return wg


# -- Attack paths ------------------------------------------------------------

def find_attack_paths(
    weighted_graph: nx.DiGraph,
    cve_reports: list[DeviceCVEReport],
    source: str = "internet",
) -> list[AttackPath]:
    """Find shortest attack paths from *source* to every device with services.

    Uses Dijkstra on the directed graph with ``attack_cost`` as weight.
    """
    report_map = {r.device_id: r for r in cve_reports}
    paths: list[AttackPath] = []

    targets = [
        n for n, d in weighted_graph.nodes(data=True)
        if d.get("services") and n != source
    ]

    for target in targets:
        try:
            node_path = nx.shortest_path(
                weighted_graph, source, target, weight="attack_cost"
            )
        except nx.NetworkXNoPath:
            continue

        hops: list[AttackHop] = []
        path_score = 1.0

        for i in range(len(node_path) - 1):
            s, t = node_path[i], node_path[i + 1]
            edge_data = weighted_graph[s][t]
            w = edge_data.get("attack_weight", 0.01)
            link_type = edge_data.get("type", "ethernet")

            cve_ids = []
            if t in report_map:
                cve_ids = [c.cve_id for c in report_map[t].cves]

            hops.append(AttackHop(
                source=s, target=t, weight=w,
                link_type=link_type, target_cves=cve_ids,
            ))
            path_score *= w

        # Impact = max CVSS of target device / 10
        target_report = report_map.get(target)
        if target_report and target_report.cves:
            scores = [c.cvss_score for c in target_report.cves if c.cvss_score]
            impact_score = max(scores) / 10.0 if scores else 0.1
        else:
            impact_score = 0.1

        n_hops = len(hops)
        amplification = HOP_AMPLIFICATION ** (n_hops - 1) if n_hops > 1 else 1.0
        total_score = path_score * impact_score * amplification

        paths.append(AttackPath(
            path=node_path,
            hops=hops,
            path_score=round(path_score, 6),
            impact_score=round(impact_score, 4),
            total_score=round(total_score, 6),
            target_device=target,
        ))

    paths.sort(key=lambda p: p.total_score, reverse=True)
    return paths


# -- Pivot nodes -------------------------------------------------------------

def find_pivot_nodes(
    backend: NetworkXBackend, attack_paths: list[AttackPath]
) -> list[dict]:
    """Identify nodes that appear as intermediaries in multiple attack paths."""
    path_count: dict[str, int] = {}
    for ap in attack_paths:
        intermediaries = ap.path[1:-1]  # exclude source and target
        for node in intermediaries:
            path_count[node] = path_count.get(node, 0) + 1

    undirected = backend.graph.to_undirected()
    centrality = nx.betweenness_centrality(undirected)

    pivots: list[dict] = []
    for node_id, count in path_count.items():
        data = backend.graph.nodes[node_id]
        pivots.append({
            "node_id": node_id,
            "name": data.get("name", node_id),
            "betweenness": round(centrality.get(node_id, 0.0), 4),
            "paths_through": count,
            "type": data.get("type", "unknown"),
        })

    pivots.sort(key=lambda p: p["paths_through"], reverse=True)
    return pivots


# -- Main entry point --------------------------------------------------------

def analyze_attack_paths(
    backend: NetworkXBackend, cve_reports: list[DeviceCVEReport]
) -> AttackPathReport:
    """Full attack-path analysis: weights, paths, pivots, summary."""
    edge_weights = compute_edge_weights(backend, cve_reports)
    weighted_graph = build_weighted_graph(backend, edge_weights)
    attack_paths = find_attack_paths(weighted_graph, cve_reports)
    pivot_nodes = find_pivot_nodes(backend, attack_paths)

    summary = {
        "total_paths": len(attack_paths),
        "total_pivots": len(pivot_nodes),
        "top_target": attack_paths[0].target_device if attack_paths else None,
        "top_score": attack_paths[0].total_score if attack_paths else 0.0,
    }

    return AttackPathReport(
        critical_paths=attack_paths,
        pivot_nodes=pivot_nodes,
        summary=summary,
    )


# -- Report printing ---------------------------------------------------------

def print_attack_report(report: AttackPathReport) -> None:
    """Print a formatted attack-path report to stdout."""
    print()
    print("=" * 80)
    print("ATTACK PATH REPORT")
    print("=" * 80)

    print(f"\nPaths found: {report.summary.get('total_paths', 0)}")
    print(f"Pivot nodes: {report.summary.get('total_pivots', 0)}")

    print("\n--- Critical Attack Paths ---\n")
    for i, ap in enumerate(report.critical_paths, 1):
        chain = " -> ".join(ap.path)
        print(f"  #{i}  {chain}")
        print(f"       Score: {ap.total_score:.4f}  "
              f"(path={ap.path_score:.4f} x impact={ap.impact_score:.2f})")
        for hop in ap.hops:
            cve_str = f"  CVEs: {', '.join(hop.target_cves[:3])}" if hop.target_cves else ""
            print(f"         {hop.source} --[{hop.link_type} w={hop.weight:.3f}]--> {hop.target}{cve_str}")
        print()

    if report.pivot_nodes:
        print("--- Pivot Nodes ---\n")
        print(f"  {'Node':<25} {'Type':<10} {'Paths':>5}  {'Betweenness':>11}")
        print(f"  {'-'*25} {'-'*10} {'-'*5}  {'-'*11}")
        for p in report.pivot_nodes:
            print(f"  {p['name']:<25} {p['type']:<10} {p['paths_through']:>5}  {p['betweenness']:>11.4f}")

    print("\n" + "=" * 80)
