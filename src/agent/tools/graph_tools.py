"""Graph query tools exposing existing Phase 1-3 modules to the LLM agent."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import yaml as _yaml

from src.loader import build_graph, load_yaml
from src.cve_lookup import load_cpe_mapping, scan_all_devices
from src.risk_scorer import score_all_devices
from src.attack_path import analyze_attack_paths

INFRA_YAML = Path("infrastructure/nato_lab.yaml")
CPE_YAML = Path("infrastructure/cpe_mapping.yaml")

# Cached state (populated by load_lab_context)
_backend = None
_infra = None
_cve_reports = None
_risk_scores = None
_attack_report = None

# Scenario override — set by load_scenario_topology() when a benchmark is active
_scenario_topology: dict | None = None


def load_lab_context() -> dict:
    """Load the full lab context (graph + CVEs + risk + attack paths).

    Returns a summary dict suitable for injection into the system prompt.
    """
    global _backend, _infra, _cve_reports, _risk_scores, _attack_report

    _infra = load_yaml(INFRA_YAML)
    _backend = build_graph(INFRA_YAML)
    _cve_reports = scan_all_devices(_infra, load_cpe_mapping(CPE_YAML))
    _risk_scores = score_all_devices(_backend, _cve_reports)
    _attack_report = analyze_attack_paths(_backend, _cve_reports)

    return {
        "stats": _backend.get_graph_stats(),
        "device_count": len(_infra.devices),
        "link_count": len(_infra.links),
        "cve_count": sum(len(r.cves) for r in _cve_reports),
        "top_risk": _risk_scores[0].device_id if _risk_scores else None,
    }


def load_scenario_topology(scenario_id: int) -> dict:
    """Override graph tools with the benchmark scenario topology.

    When active, get_network_topology / get_attack_surface / get_device_info
    return the scenario VMs (192.168.100.x) instead of the physical lab.
    Returns a summary dict (device_count, link_count, cve_count, top_risk).
    """
    global _scenario_topology

    gt_path = Path("benchmarks/ground_truth") / f"scenario_{scenario_id}.yaml"
    if not gt_path.exists():
        return load_lab_context()

    data = _yaml.safe_load(gt_path.read_text())
    topology = data.get("topology", {})
    router = topology.get("router", {})
    services = topology.get("services", [])

    nodes = []
    if router:
        nodes.append({
            "id": router.get("name", "router"),
            "name": router.get("name", "router"),
            "type": "router",
            "role": "router",
            "ip": router.get("ip"),
            "os": "OpenWrt",
            "services": [
                {"name": "ssh", "port": 22, "protocol": "tcp"},
                {"name": "http", "port": 80, "protocol": "tcp"},
            ],
        })
    for svc in services:
        nodes.append({
            "id": svc["name"],
            "name": svc["name"],
            "type": "server",
            "role": svc.get("role", ""),
            "ip": svc.get("ip"),
            "os": "Debian",
            "services": [],
        })

    _scenario_topology = {
        "scenario_id": scenario_id,
        "scenario_name": data.get("scenario_name", f"S{scenario_id}"),
        "subnet": "192.168.100.0/24",
        "nodes": nodes,
        "node_index": {n["id"]: n for n in nodes},
    }

    return {
        "device_count": len(nodes),
        "link_count": len(services),
        "cve_count": 0,
        "top_risk": router.get("name") if router else None,
    }


def _ensure_loaded():
    if _scenario_topology is None and _backend is None:
        load_lab_context()


# ── Tool functions ───────────────────────────────────────────────

def get_network_topology() -> str:
    """Return the full network topology as JSON (nodes + edges)."""
    _ensure_loaded()
    if _scenario_topology is not None:
        return json.dumps({
            "scenario": _scenario_topology["scenario_name"],
            "subnet": _scenario_topology["subnet"],
            "nodes": _scenario_topology["nodes"],
        }, ensure_ascii=False)
    return json.dumps(_backend.to_dict(), ensure_ascii=False, default=str)


def get_device_info(device_id: str) -> str:
    """Return detailed info for a specific device."""
    _ensure_loaded()
    if _scenario_topology is not None:
        node = _scenario_topology["node_index"].get(device_id)
        if node:
            return json.dumps(node, ensure_ascii=False)
        return json.dumps({"error": f"Device '{device_id}' not found in scenario"})
    try:
        device = _backend.get_device(device_id)
        neighbors = _backend.get_neighbors(device_id)
        device["neighbors"] = neighbors
        return json.dumps(device, ensure_ascii=False, default=str)
    except KeyError:
        return json.dumps({"error": f"Device '{device_id}' not found"})


def get_attack_surface() -> str:
    """Return devices that expose services (have open ports)."""
    _ensure_loaded()
    if _scenario_topology is not None:
        return json.dumps(_scenario_topology["nodes"], ensure_ascii=False)
    return json.dumps(_backend.get_attack_surface(), ensure_ascii=False, default=str)


def get_attack_paths() -> str:
    """Return the attack path analysis report."""
    _ensure_loaded()
    if _scenario_topology is not None:
        return json.dumps({
            "note": "Attack paths not pre-computed for benchmark scenarios — discover via active recon.",
            "subnet": _scenario_topology["subnet"],
            "nodes": [n["id"] for n in _scenario_topology["nodes"]],
        }, ensure_ascii=False)
    report = {
        "summary": _attack_report.summary,
        "critical_paths": [asdict(p) for p in _attack_report.critical_paths],
        "pivot_nodes": _attack_report.pivot_nodes,
    }
    return json.dumps(report, ensure_ascii=False, default=str)


def get_risk_scores() -> str:
    """Return risk scores for all devices, sorted by risk (descending)."""
    _ensure_loaded()
    if _scenario_topology is not None:
        return json.dumps({
            "note": "Risk scores not pre-computed for benchmark scenarios — discover vulnerabilities via active recon.",
            "devices": [{"id": n["id"], "ip": n["ip"], "role": n["role"]} for n in _scenario_topology["nodes"]],
        }, ensure_ascii=False)
    scores = [asdict(s) for s in _risk_scores]
    return json.dumps(scores, ensure_ascii=False, default=str)


# ── Tool definitions (for the provider) ──────────────────────────

GRAPH_TOOLS = [
    {
        "name": "get_network_topology",
        "description": "Get the full network topology (all devices and links) as a JSON graph with nodes and edges.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "function": get_network_topology,
    },
    {
        "name": "get_device_info",
        "description": "Get detailed information about a specific device by its ID, including services, OS, firmware, and neighbors.",
        "input_schema": {
            "type": "object",
            "properties": {
                "device_id": {
                    "type": "string",
                    "description": "The device ID (e.g. 'mikrotik', 'rpi5', 'wisgate')",
                }
            },
            "required": ["device_id"],
        },
        "function": get_device_info,
    },
    {
        "name": "get_attack_surface",
        "description": "Get the list of devices that expose network services (open ports). Sensors without services are excluded.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "function": get_attack_surface,
    },
    {
        "name": "get_attack_paths",
        "description": "Get the attack path analysis: critical multi-hop paths from the internet, pivot nodes, and risk summary.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "function": get_attack_paths,
    },
    {
        "name": "get_risk_scores",
        "description": "Get risk scores for all devices, combining CVSS vulnerability scores, network exposure, and betweenness centrality.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "function": get_risk_scores,
    },
]
