"""Topology route — expose lab graph nodes/edges for Cytoscape.js."""
from __future__ import annotations

from pathlib import Path

import yaml
from fastapi import APIRouter, HTTPException

router = APIRouter()

ROOT = Path(__file__).resolve().parents[3]

DEVICE_TYPE_COLORS = {
    "router":   "#e74c3c",
    "switch":   "#95a5a6",
    "gateway":  "#e67e22",
    "sensor":   "#2ecc71",
    "compute":  "#3498db",
    "camera":   "#9b59b6",
    "ap":       "#1abc9c",
    "external": "#7f8c8d",
}

PROTOCOL_COLORS = {
    "ethernet": "#bdc3c7",
    "lorawan":  "#f39c12",
    "zigbee":   "#27ae60",
    "mqtt":     "#8e44ad",
    "wan":      "#c0392b",
}


def _load_physical_lab() -> dict:
    lab_yaml = ROOT / "infrastructure" / "nato_lab.yaml"
    data = yaml.safe_load(lab_yaml.read_text())

    nodes = []
    for dev in data.get("devices", []):
        services = [s.get("name", "") for s in dev.get("services", [])]
        nodes.append({
            "id": dev["id"],
            "label": dev["id"],
            "ip": dev.get("ip", ""),
            "type": dev.get("type", "compute"),
            "services": services,
            "color": DEVICE_TYPE_COLORS.get(dev.get("type", "compute"), "#3498db"),
        })

    for ext in data.get("external", []):
        nodes.append({
            "id": ext["id"],
            "label": ext["id"],
            "ip": "",
            "type": "external",
            "services": [],
            "color": DEVICE_TYPE_COLORS["external"],
        })

    edges = []
    for link in data.get("links", []):
        edges.append({
            "id": f"{link['source']}-{link['target']}",
            "source": link["source"],
            "target": link["target"],
            "protocol": link.get("protocol", "ethernet"),
            "color": PROTOCOL_COLORS.get(link.get("protocol", "ethernet"), "#bdc3c7"),
        })

    return {"nodes": nodes, "edges": edges, "subnet": "192.168.88.0/24"}


# Map service roles to visual device types for Cytoscape rendering
ROLE_TO_TYPE = {
    "mqtt_broker":    "gateway",
    "mqtt_broker_v2": "gateway",
    "iot_gateway":    "gateway",
    "web_server":     "compute",
    "web_server_v2":  "compute",
    "web_upload":     "compute",
    "ssh_server":     "compute",
    "ssh_server_v2":  "compute",
    "db_server":      "compute",
    "db_server_v2":   "compute",
    "camera_server":  "camera",
    "nvr_server":     "camera",
    "modbus_server":  "sensor",
    "coap_server":    "sensor",
    "snmp_server":    "sensor",
    "ftp_server":     "compute",
    "nodered_server": "gateway",
}


def _load_scenario(scenario_id: int) -> dict:
    gt_file = ROOT / "benchmarks" / "ground_truth" / f"scenario_{scenario_id}.yaml"
    if not gt_file.exists():
        raise HTTPException(status_code=404, detail=f"Scenario {scenario_id} not found")

    data = yaml.safe_load(gt_file.read_text())
    topo = data.get("topology", {})

    nodes = []
    router = topo.get("router", {})
    if router:
        nodes.append({
            "id": router.get("name", f"s{scenario_id}-router"),
            "label": router.get("name", f"s{scenario_id}-router"),
            "ip": router.get("ip", ""),
            "type": "router",
            "services": [],
            "color": DEVICE_TYPE_COLORS["router"],
        })

    for svc in topo.get("services", []):
        role = svc.get("role", "")
        dev_type = ROLE_TO_TYPE.get(role, "compute")
        nodes.append({
            "id": svc["name"],
            "label": svc["name"],
            "ip": svc.get("ip", ""),
            "type": dev_type,
            "services": [role],
            "color": DEVICE_TYPE_COLORS.get(dev_type, "#3498db"),
        })

    # Build edges: router ↔ each service (default star topology)
    edges = []
    router_id = router.get("name", f"s{scenario_id}-router") if router else None
    for svc in topo.get("services", []):
        if router_id:
            edges.append({
                "id": f"{router_id}-{svc['name']}",
                "source": router_id,
                "target": svc["name"],
                "protocol": "ethernet",
                "color": PROTOCOL_COLORS["ethernet"],
            })

    # Additional links defined in the topology (mesh, multi-zone, etc.)
    for link in topo.get("links", []):
        edge_id = f"{link['source']}-{link['target']}"
        # Avoid duplicating router→service edges
        if not any(e["id"] == edge_id for e in edges):
            edges.append({
                "id": edge_id,
                "source": link["source"],
                "target": link["target"],
                "protocol": link.get("protocol", "mqtt"),
                "color": PROTOCOL_COLORS.get(link.get("protocol", "mqtt"), "#8e44ad"),
            })

    return {"nodes": nodes, "edges": edges, "subnet": "192.168.100.0/24"}


@router.get("")
def get_topology(scenario: int | None = None):
    """Return Cytoscape-ready nodes and edges for the lab or a benchmark scenario."""
    if scenario is not None:
        return _load_scenario(scenario)
    return _load_physical_lab()
