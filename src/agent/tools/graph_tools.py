"""Graph query tools exposing existing Phase 1-3 modules to the LLM agent."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

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


def _ensure_loaded():
    if _backend is None:
        load_lab_context()


# ── Tool functions ───────────────────────────────────────────────

def get_network_topology() -> str:
    """Return the full network topology as JSON (nodes + edges)."""
    _ensure_loaded()
    return json.dumps(_backend.to_dict(), ensure_ascii=False, default=str)


def get_device_info(device_id: str) -> str:
    """Return detailed info for a specific device."""
    _ensure_loaded()
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
    return json.dumps(_backend.get_attack_surface(), ensure_ascii=False, default=str)


def get_attack_paths() -> str:
    """Return the attack path analysis report."""
    _ensure_loaded()
    report = {
        "summary": _attack_report.summary,
        "critical_paths": [asdict(p) for p in _attack_report.critical_paths],
        "pivot_nodes": _attack_report.pivot_nodes,
    }
    return json.dumps(report, ensure_ascii=False, default=str)


def get_risk_scores() -> str:
    """Return risk scores for all devices, sorted by risk (descending)."""
    _ensure_loaded()
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
