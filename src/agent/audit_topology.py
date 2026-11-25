"""Strict parser and validator for optional grey-box audit topologies (YAML/JSON).

Used exclusively in live/partner audit runs (`LANCE_MODE=audit` or discovery runs)
without touching benchmark `scenario_topology` or UMONS `nato_lab.yaml`.

Security guarantees:
- Size cap (64 KB raw text), no YAML anchors/aliases (prevents billion-laughs bombs).
- Strict allowlisted fields and bounded counts (<= 128 devices, <= 256 links).
- Safe device IDs (`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`) so IDs are safe in artifact filenames.
- Declared device IPs must be valid IPv4 addresses inside `target_network` and not excluded.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

import yaml

from src.agent.network_scope import (
    is_ip_excluded,
    parse_excluded_ips,
    parse_ipv4_network_or_host,
)


MAX_TOPOLOGY_BYTES = 64 * 1024
MAX_DEVICES = 128
MAX_LINKS = 256
_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_YAML_ALIAS_RE = re.compile(r"(^|[\s:\[,{])[&*][A-Za-z0-9_-]+")

DEVICE_TYPE_COLORS = {
    "router": "#e74c3c",
    "switch": "#95a5a6",
    "gateway": "#e67e22",
    "sensor": "#2ecc71",
    "compute": "#3498db",
    "camera": "#9b59b6",
    "ap": "#1abc9c",
    "host": "#3498db",
    "external": "#7f8c8d",
}

PROTOCOL_COLORS = {
    "ethernet": "#bdc3c7",
    "wifi": "#1abc9c",
    "lorawan": "#f39c12",
    "zigbee": "#27ae60",
    "mqtt": "#8e44ad",
    "wan": "#c0392b",
}

_ALLOWED_TOP_KEYS = frozenset({"name", "subnet", "excluded_ips", "devices", "links", "metadata", "networks"})
_ALLOWED_DEVICE_KEYS = frozenset({"id", "name", "ip", "type", "role", "os", "os_version", "firmware", "services", "protocols", "network"})
_ALLOWED_LINK_KEYS = frozenset({"source", "target", "type", "protocol", "description"})


def parse_raw_topology_text(raw: str) -> dict[str, Any]:
    """Safely parse YAML or JSON topology text without allowing YAML anchors/aliases."""
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("Topology payload is empty.")
    encoded = raw.encode("utf-8")
    if len(encoded) > MAX_TOPOLOGY_BYTES:
        raise ValueError(f"Topology exceeds maximum size ({MAX_TOPOLOGY_BYTES // 1024} KB).")
    stripped = raw.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON topology: {exc}") from exc
    else:
        for line in raw.splitlines():
            clean = line.split("#", 1)[0]
            if _YAML_ALIAS_RE.search(clean):
                raise ValueError("YAML anchors/aliases (& / *) are not permitted in audit topologies.")
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML topology: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Topology root must be a YAML/JSON object.")
    return data


def _extract_subnet(data: dict[str, Any]) -> str | None:
    if data.get("subnet"):
        return str(parse_ipv4_network_or_host(str(data["subnet"]).strip()))
    networks = data.get("networks")
    if isinstance(networks, list) and networks:
        first = networks[0]
        if isinstance(first, dict) and first.get("subnet"):
            return str(parse_ipv4_network_or_host(str(first["subnet"]).strip()))
    return None


def validate_audit_topology(
    raw_or_dict: str | dict[str, Any],
    *,
    target_network: str | None = None,
    excluded_ips: list[str] | None = None,
) -> dict[str, Any]:
    """Validate and normalize an operator-supplied grey-box network topology."""
    data = parse_raw_topology_text(raw_or_dict) if isinstance(raw_or_dict, str) else raw_or_dict
    if not isinstance(data, dict):
        raise ValueError("Topology must be a YAML/JSON object.")

    unknown_top = set(data) - _ALLOWED_TOP_KEYS
    if unknown_top:
        raise ValueError(f"Unsupported top-level topology fields: {sorted(unknown_top)}")

    declared_subnet = _extract_subnet(data)
    effective_subnet_str = target_network or declared_subnet
    if not effective_subnet_str:
        raise ValueError("Topology must declare `subnet` or be paired with an authorized target_network.")
    effective_net = parse_ipv4_network_or_host(effective_subnet_str)

    if declared_subnet and target_network:
        decl_net = parse_ipv4_network_or_host(declared_subnet)
        if not effective_net.subnet_of(decl_net) and not decl_net.subnet_of(effective_net):
            raise ValueError(
                f"Topology subnet ({decl_net}) does not match target_network ({effective_net})."
            )

    merged_excluded = parse_excluded_ips([*(excluded_ips or []), *parse_excluded_ips(data.get("excluded_ips"))])

    raw_devices = data.get("devices") or []
    if not isinstance(raw_devices, list):
        raise ValueError("`devices` must be a list.")
    if len(raw_devices) > MAX_DEVICES:
        raise ValueError(f"Too many declared devices ({len(raw_devices)} > {MAX_DEVICES}).")

    nodes: list[dict[str, Any]] = []
    node_index: dict[str, dict[str, Any]] = {}
    ip_index: dict[str, dict[str, Any]] = {}
    for idx, entry in enumerate(raw_devices):
        if not isinstance(entry, dict):
            raise ValueError(f"devices[{idx}] must be an object.")
        unknown_dev = set(entry) - _ALLOWED_DEVICE_KEYS
        if unknown_dev:
            raise ValueError(f"devices[{idx}] has unsupported fields: {sorted(unknown_dev)}")
        dev_id = str(entry.get("id") or "").strip()
        if not _DEVICE_ID_RE.fullmatch(dev_id):
            raise ValueError(
                f"devices[{idx}].id ({dev_id!r}) must match [A-Za-z0-9][A-Za-z0-9_-]{{0,63}}."
            )
        if dev_id in node_index:
            raise ValueError(f"Duplicate device id: {dev_id!r}")

        ip_str = str(entry.get("ip") or "").strip()
        if ip_str:
            try:
                addr = ipaddress.ip_address(ip_str)
            except ValueError as exc:
                raise ValueError(f"devices[{idx}].ip is not a valid IPv4 address: {ip_str!r}") from exc
            if not isinstance(addr, ipaddress.IPv4Address):
                raise ValueError(f"devices[{idx}].ip must be IPv4: {ip_str!r}")
            if addr not in effective_net:
                raise ValueError(
                    f"Declared device {dev_id!r} IP {addr} is outside authorized network {effective_net}."
                )
            if is_ip_excluded(str(addr), merged_excluded):
                raise ValueError(
                    f"Declared device {dev_id!r} IP {addr} is in excluded_ips; remove it from devices or exclusions."
                )
            ip_str = str(addr)

        dev_type = str(entry.get("type") or "host").strip().lower()[:32]
        services_raw = entry.get("services") or []
        if not isinstance(services_raw, list):
            raise ValueError(f"devices[{idx}].services must be a list.")
        services: list[dict[str, Any]] = []
        for svc in services_raw[:64]:
            if isinstance(svc, str) and svc.strip():
                services.append({"name": svc.strip()[:64]})
            elif isinstance(svc, dict):
                svc_item: dict[str, Any] = {"name": str(svc.get("name") or "").strip()[:64]}
                if svc.get("port") is not None:
                    port = int(svc["port"])
                    if not 1 <= port <= 65535:
                        raise ValueError(f"devices[{idx}] invalid service port: {port}")
                    svc_item["port"] = port
                if svc.get("protocol"):
                    svc_item["protocol"] = str(svc["protocol"]).strip().lower()[:16]
                services.append(svc_item)

        node = {
            "id": dev_id,
            "name": str(entry.get("name") or dev_id).strip()[:128],
            "ip": ip_str,
            "type": dev_type,
            "role": str(entry.get("role") or dev_type).strip()[:128],
            "os": str(entry.get("os") or "").strip()[:64],
            "services": services,
            "declared": True,
        }
        nodes.append(node)
        node_index[dev_id] = node
        if ip_str:
            ip_index[ip_str] = node

    raw_links = data.get("links") or []
    if not isinstance(raw_links, list):
        raise ValueError("`links` must be a list.")
    if len(raw_links) > MAX_LINKS:
        raise ValueError(f"Too many declared links ({len(raw_links)} > {MAX_LINKS}).")

    edges: list[dict[str, Any]] = []
    for idx, link in enumerate(raw_links):
        if not isinstance(link, dict):
            raise ValueError(f"links[{idx}] must be an object.")
        unknown_link = set(link) - _ALLOWED_LINK_KEYS
        if unknown_link:
            raise ValueError(f"links[{idx}] has unsupported fields: {sorted(unknown_link)}")
        src = str(link.get("source") or "").strip()
        dst = str(link.get("target") or "").strip()
        if src not in node_index or dst not in node_index:
            raise ValueError(f"links[{idx}] references unknown device(s): {src!r} -> {dst!r}")
        proto = str(link.get("type") or link.get("protocol") or "ethernet").strip().lower()[:32]
        edges.append({
            "id": f"{src}-{dst}",
            "source": src,
            "target": dst,
            "protocol": proto,
            "color": PROTOCOL_COLORS.get(proto, "#bdc3c7"),
            "description": str(link.get("description") or "").strip()[:160],
        })

    cytoscape_nodes = [
        {
            "id": n["id"],
            "label": n["name"],
            "ip": n["ip"],
            "type": n["type"],
            "role": n["role"],
            "services": [s.get("name", "") for s in n["services"] if s.get("name")],
            "color": DEVICE_TYPE_COLORS.get(n["type"], "#3498db"),
        }
        for n in nodes
    ]

    return {
        "name": str(data.get("name") or "Operator Network Topology").strip()[:128],
        "subnet": str(effective_net),
        "excluded_ips": merged_excluded,
        "nodes": nodes,
        "edges": edges,
        "node_index": node_index,
        "ip_index": ip_index,
        "cytoscape": {
            "nodes": cytoscape_nodes,
            "edges": edges,
            "subnet": str(effective_net),
        },
    }


def compute_topological_summary(topology: dict[str, Any]) -> dict[str, Any]:
    """Compute purely structural graph metrics (degree, potential pivots) without inventing CVEs."""
    nodes = topology.get("nodes") or []
    edges = topology.get("edges") or []
    adjacency: dict[str, set[str]] = {n["id"]: set() for n in nodes}
    for edge in edges:
        src, dst = edge.get("source"), edge.get("target")
        if src in adjacency and dst in adjacency:
            adjacency[src].add(dst)
            adjacency[dst].add(src)

    ranked = sorted(
        (
            {
                "id": n["id"],
                "ip": n.get("ip", ""),
                "type": n.get("type", "host"),
                "role": n.get("role", ""),
                "degree": len(adjacency.get(n["id"], ())),
                "neighbors": sorted(adjacency.get(n["id"], ())),
                "cves_pending_active_scan": True,
            }
            for n in nodes
        ),
        key=lambda item: (-item["degree"], item["id"]),
    )
    pivots = [item["id"] for item in ranked if item["degree"] >= 2 or item["type"] in {"gateway", "router"}]
    return {
        "mode": "greybox_audit",
        "subnet": topology.get("subnet", ""),
        "excluded_ips": topology.get("excluded_ips", []),
        "cves_pending_active_scan": True,
        "pivot_candidates": pivots,
        "devices": ranked,
        "note": (
            "Structural topology provided by the operator as an open hypothesis. "
            "No CVEs are pre-computed; active recon must verify declared hosts and discover undocumented devices."
        ),
    }
