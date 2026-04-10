"""Graph query tools exposing existing Phase 1-3 modules to the LLM agent."""

from __future__ import annotations

import json
import re
import threading
from dataclasses import asdict
from pathlib import Path

import yaml as _yaml

from src.loader import build_graph, load_yaml
from src.cve_lookup import load_cpe_mapping, scan_all_devices
from src.risk_scorer import score_all_devices
from src.attack_path import analyze_attack_paths

INFRA_YAML = Path("infrastructure/nato_lab.yaml")
CPE_YAML = Path("infrastructure/cpe_mapping.yaml")

# Thread-local state — each run gets its own scenario topology
_tls = threading.local()

# Shared lab context (read-only once loaded, safe across threads)
_backend = None
_infra = None
_cve_reports = None
_risk_scores = None
_attack_report = None
_lab_lock = threading.Lock()


def _get_scenario_topology() -> dict | None:
    """Get the scenario topology for the current thread."""
    return getattr(_tls, "scenario_topology", None)


def _set_scenario_topology(topo: dict | None) -> None:
    """Set the scenario topology for the current thread."""
    _tls.scenario_topology = topo


def load_lab_context() -> dict:
    """Load the full lab context (graph + CVEs + risk + attack paths).

    Returns a summary dict suitable for injection into the system prompt.
    Thread-safe: uses a lock for first-time loading.
    """
    global _backend, _infra, _cve_reports, _risk_scores, _attack_report

    with _lab_lock:
        if _backend is not None:
            return {
                "stats": _backend.get_graph_stats(),
                "device_count": len(_infra.devices),
                "link_count": len(_infra.links),
                "cve_count": sum(len(r.cves) for r in _cve_reports),
                "top_risk": _risk_scores[0].device_id if _risk_scores else None,
            }

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


_ROLE_SERVICES: dict[str, list[dict]] = {
    "router":       [{"name": "ssh", "port": 22, "protocol": "tcp"}, {"name": "http", "port": 80, "protocol": "tcp"}],
    "mqtt_broker":  [{"name": "mqtt", "port": 1883, "protocol": "tcp"}],
    "web_server":   [{"name": "http", "port": 80, "protocol": "tcp"}],
    "ssh_server":   [{"name": "ssh", "port": 22, "protocol": "tcp"}],
    "db_server":    [{"name": "mysql", "port": 3306, "protocol": "tcp"}],
    "iot_gateway":  [{"name": "ssh", "port": 22, "protocol": "tcp"}, {"name": "http", "port": 80, "protocol": "tcp"}],
    "ldap_server":  [{"name": "ldap", "port": 389, "protocol": "tcp"}],
    "nfs_server":   [{"name": "nfs", "port": 2049, "protocol": "tcp"}],
    "ftp_server":   [{"name": "ftp", "port": 21, "protocol": "tcp"}],
}

_PORT_NAME: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http",
    389: "ldap", 443: "https", 1883: "mqtt", 2049: "nfs",
    3306: "mysql", 5432: "postgres", 8080: "http-alt", 8883: "mqtt-tls",
}

_PORT_RE = re.compile(r'[Pp]ort (\d+)/(tcp|udp)')


def _enrich_node_services(node: dict, vulnerabilities: list[dict]) -> None:
    """Add services discovered from vulnerability indicators (port mentions)."""
    existing = {s["port"] for s in node["services"]}
    for vuln in vulnerabilities:
        if vuln.get("device") != node["id"]:
            continue
        for indicator in vuln.get("indicators", []):
            for m in _PORT_RE.finditer(indicator):
                port, proto = int(m.group(1)), m.group(2)
                if port not in existing:
                    node["services"].append({"name": _PORT_NAME.get(port, f"port-{port}"), "port": port, "protocol": proto})
                    existing.add(port)


def _build_edges_from_attack_paths(attack_paths_data: list[dict], node_index: dict, ip_to_id: dict, subnet_prefix: str) -> list[dict]:
    """Derive network edges from attack_path chains (consecutive hops)."""
    # Build regex pattern to extract host suffix from chain device strings
    # Matches patterns like (10.0.11) or (100.11) in chain device names
    escaped_prefix = re.escape(subnet_prefix.rsplit(".", 1)[0])  # e.g. "10.10" from "10.10.0"
    ip_re = re.compile(r'\((?:' + escaped_prefix + r'\.0\.)?(\d+)\)')

    def _resolve(chain_device: str) -> str | None:
        if chain_device.lower() in ("internet", "wan"):
            return "internet"
        name = chain_device.split(" (")[0].strip()
        if name in node_index:
            return name
        m = ip_re.search(chain_device)
        if m:
            return ip_to_id.get(f"{subnet_prefix}.{m.group(1)}")
        return None

    edges: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for path in attack_paths_data:
        chain = path.get("chain", [])
        for i in range(len(chain) - 1):
            src = _resolve(chain[i]["device"])
            dst = _resolve(chain[i + 1]["device"])
            if src and dst and src != dst and (src, dst) not in seen:
                seen.add((src, dst))
                edges.append({"source": src, "target": dst})
    return edges


def _get_scenario_subnet(scenario_id: int) -> str:
    """Look up the subnet prefix for a scenario from scenario_vlans config."""
    vlans_path = Path("benchmarks/ansible/group_vars/all/main.yml")
    if vlans_path.exists():
        data = _yaml.safe_load(vlans_path.read_text())
        vlans = data.get("scenario_vlans", {})
        entry = vlans.get(str(scenario_id))
        if entry:
            return entry["subnet_prefix"]
    # Fallback: compute from VLAN formula
    vlan_id = scenario_id * 10
    return f"10.{vlan_id}.0"


def load_scenario_topology(scenario_id: int) -> dict:
    """Override graph tools with the benchmark scenario topology.

    When active, get_network_topology / get_attack_surface / get_device_info
    return the scenario VMs instead of the physical lab.
    Returns a summary dict (device_count, link_count, cve_count, top_risk).

    Thread-safe: stores topology in thread-local storage.
    """
    gt_path = Path("benchmarks/ground_truth") / f"scenario_{scenario_id}.yaml"
    if not gt_path.exists():
        return load_lab_context()

    subnet_prefix = _get_scenario_subnet(scenario_id)

    data = _yaml.safe_load(gt_path.read_text())
    topology = data.get("topology", {})
    router = topology.get("router", {})
    services = topology.get("services", [])
    vulnerabilities = data.get("vulnerabilities", [])
    attack_paths_data = data.get("attack_paths", [])

    # Build nodes with role-based services
    nodes: list[dict] = []
    if router:
        nodes.append({
            "id": router.get("name", "router"),
            "name": router.get("name", "router"),
            "type": "router",
            "role": "router",
            "ip": router.get("ip"),
            "os": "OpenWrt",
            "services": list(_ROLE_SERVICES["router"]),
        })
    for svc in services:
        role = svc.get("role", "")
        nodes.append({
            "id": svc["name"],
            "name": svc["name"],
            "type": "server",
            "role": role,
            "ip": svc.get("ip"),
            "os": "Debian",
            "services": list(_ROLE_SERVICES.get(role, [])),
        })

    node_index = {n["id"]: n for n in nodes}
    ip_to_id = {n["ip"]: n["id"] for n in nodes if n.get("ip")}

    # Enrich services from vulnerability indicators (port mentions)
    for node in nodes:
        _enrich_node_services(node, vulnerabilities)

    # Build edges from attack_path chains
    edges = _build_edges_from_attack_paths(attack_paths_data, node_index, ip_to_id, subnet_prefix)

    # Count CVEs (vulns with a real CVE ID)
    cve_count = sum(1 for v in vulnerabilities if v.get("cve"))

    # Top risk = device with highest severity vulnerability
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    top_risk = max(vulnerabilities, key=lambda v: sev_order.get(v.get("severity", ""), 0), default={}).get("device")

    _set_scenario_topology({
        "scenario_id": scenario_id,
        "scenario_name": data.get("scenario_name", f"S{scenario_id}"),
        "subnet": f"{subnet_prefix}.0/24",
        "nodes": nodes,
        "node_index": node_index,
        "edges": edges,
    })

    return {
        "device_count": len(nodes),
        "link_count": len(edges),
        "cve_count": cve_count,
        "top_risk": top_risk,
    }


def _ensure_loaded():
    if _get_scenario_topology() is None and _backend is None:
        load_lab_context()


# ── Tool functions ───────────────────────────────────────────────

def get_network_topology() -> str:
    """Return the full network topology as JSON (nodes + edges)."""
    _ensure_loaded()
    topo = _get_scenario_topology()
    if topo is not None:
        return json.dumps({
            "scenario": topo["scenario_name"],
            "subnet": topo["subnet"],
            "nodes": topo["nodes"],
            "edges": topo["edges"],
        }, ensure_ascii=False)
    return json.dumps(_backend.to_dict(), ensure_ascii=False, default=str)


def get_device_info(device_id: str) -> str:
    """Return detailed info for a specific device."""
    _ensure_loaded()
    topo = _get_scenario_topology()
    if topo is not None:
        node = topo["node_index"].get(device_id)
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
    topo = _get_scenario_topology()
    if topo is not None:
        exposed = [n for n in topo["nodes"] if n.get("services")]
        return json.dumps(exposed, ensure_ascii=False)
    return json.dumps(_backend.get_attack_surface(), ensure_ascii=False, default=str)


def get_attack_paths() -> str:
    """Return the attack path analysis report."""
    _ensure_loaded()
    topo = _get_scenario_topology()
    if topo is not None:
        return json.dumps({
            "note": "Attack paths not pre-computed for benchmark scenarios — discover via active recon.",
            "subnet": topo["subnet"],
            "nodes": [n["id"] for n in topo["nodes"]],
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
    topo = _get_scenario_topology()
    if topo is not None:
        return json.dumps({
            "note": "Risk scores not pre-computed for benchmark scenarios — discover vulnerabilities via active recon.",
            "devices": [{"id": n["id"], "ip": n["ip"], "role": n["role"]} for n in topo["nodes"]],
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
