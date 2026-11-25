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
    "l2_segment": "#7f8c8d",
    "alias": "#f39c12",
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


def _short_ip_suffix(ip: str) -> str:
    parts = ip.split(".")
    return f".{parts[-1]}" if len(parts) == 4 else ip


def _format_service_tags(services: list[Any] | None, open_ports: list[int] | None = None) -> list[str]:
    """Return deterministic, human-readable Cytoscape service tags like `ssh:22`."""
    tags: list[tuple[int, str]] = []
    seen: set[str] = set()
    for item in services or []:
        if isinstance(item, str) and item.strip():
            tag = item.strip()[:64]
            if tag not in seen:
                seen.add(tag)
                tags.append((99999, tag))
        elif isinstance(item, dict):
            name = str(item.get("service") or item.get("name") or "").strip().lower()
            port = item.get("port")
            try:
                port_int = int(port) if port is not None else 0
            except (TypeError, ValueError):
                port_int = 0
            if name and port_int > 0:
                tag = f"{name}:{port_int}"
            elif name:
                tag = name
            elif port_int > 0:
                tag = f"tcp:{port_int}"
            else:
                continue
            if tag not in seen:
                seen.add(tag)
                tags.append((port_int or 99999, tag))
    for port in open_ports or []:
        try:
            port_int = int(port)
        except (TypeError, ValueError):
            continue
        if not any(p == port_int for p, _ in tags):
            tag = f"port:{port_int}"
            if tag not in seen:
                seen.add(tag)
                tags.append((port_int, tag))
    tags.sort(key=lambda pair: (pair[0], pair[1]))
    return [tag for _, tag in tags]


def classify_discovered_device(
    ip: str,
    *,
    vendor: str = "",
    hostname: str = "",
    services: list[Any] | None = None,
    open_ports: list[int] | None = None,
) -> tuple[str, str, str]:
    """Infer `(device_type, label, role)` honestly from observed MAC vendor & open services."""
    vendor_clean = (vendor or "").strip()
    vendor_low = vendor_clean.lower()
    host_clean = (hostname or "").strip()
    ports: set[int] = set()
    service_blob_parts: list[str] = []

    for p in open_ports or []:
        try:
            ports.add(int(p))
        except (TypeError, ValueError):
            continue
    for svc in services or []:
        if isinstance(svc, dict):
            try:
                if svc.get("port") is not None:
                    ports.add(int(svc["port"]))
            except (TypeError, ValueError):
                pass
            for key in ("service", "name", "version"):
                val = str(svc.get(key) or "").strip()
                if val:
                    service_blob_parts.append(val.lower())
        elif isinstance(svc, str):
            service_blob_parts.append(svc.lower())

    svc_blob = " ".join(service_blob_parts)
    suffix = _short_ip_suffix(ip)
    has_mqtt = 1883 in ports or 8883 in ports or "mosquitto" in svc_blob or "mqtt" in svc_blob
    has_rtsp = 554 in ports or "rtsp" in svc_blob
    has_ot_sensor = bool(ports & {502, 4840, 5683, 47808}) or any(
        kw in svc_blob for kw in ("modbus", "opcua", "coap", "bacnet")
    )

    if any(kw in vendor_low for kw in ("rak", "wisgate", "lorawan", "dragino", "kerlink")):
        return ("gateway", f"RAK WisGate ({suffix})" if "rak" in vendor_low else f"{vendor_clean} ({suffix})", "LoRaWAN Gateway")
    if any(kw in vendor_low or kw in svc_blob for kw in ("tp-link", "aruba", "ruckus", "meraki", "access point")):
        short_vendor = "TP-Link AP" if ("tp-link" in vendor_low or "tp-link" in svc_blob) else vendor_clean or "Wi-Fi AP"
        return ("ap", f"{short_vendor} ({suffix})", "Wireless Access Point")
    if any(kw in vendor_low for kw in ("ubiquiti", "hikvision", "dahua", "axis", "reolink", "foscam")) or has_rtsp:
        short_vendor = "Ubiquiti" if "ubiquiti" in vendor_low else (vendor_clean or "Camera/NVR")
        return ("camera", f"{short_vendor} ({suffix})", "NVR / Camera Device")
    if any(kw in vendor_low for kw in ("mikrotik", "cisco", "fortinet", "juniper", "pfsense", "opnsense", "openwrt")):
        return ("router", f"{vendor_clean} ({suffix})", "Router / Firewall")
    if any(kw in vendor_low for kw in ("netgear", "procurve", "switch")):
        return ("switch", f"{vendor_clean} ({suffix})", "Network Switch")
    if has_ot_sensor or any(kw in vendor_low for kw in ("espressif", "arduino", "stmicro", "microchip")):
        lbl = f"{vendor_clean} ({suffix})" if vendor_clean and "unknown" not in vendor_low else f"IoT/OT Node ({suffix})"
        return ("sensor", lbl, "IoT / OT Sensor or PLC")
    if "nvidia" in vendor_low or "jetson" in vendor_low:
        role = "NVIDIA Jetson · MQTT" if has_mqtt else "NVIDIA Jetson Compute"
        return ("compute", f"NVIDIA Jetson ({suffix})", role)
    if "raspberry" in vendor_low:
        if has_mqtt:
            return ("gateway", f"Raspberry Pi MQTT ({suffix})", "Raspberry Pi · MQTT Broker")
        return ("compute", f"Raspberry Pi ({suffix})", "Raspberry Pi Node")
    if has_mqtt:
        return ("gateway", f"MQTT Broker ({suffix})", "MQTT Broker / IoT Hub")

    meaningful_vendor = (
        vendor_clean
        and "unknown" not in vendor_low
        and vendor_low not in {"realtek", "intel", "generic"}
    )
    if host_clean and host_clean != ip:
        label = f"{host_clean} ({suffix})"
    elif meaningful_vendor:
        label = f"{vendor_clean} ({suffix})"
    else:
        label = ip
    role = f"{vendor_clean} Host" if vendor_clean and "unknown" not in vendor_low else "Discovered Host"
    return ("compute", label, role)


def detect_default_gateway() -> str | None:
    """Passively read the local default IPv4 gateway from `ip route` (sends zero packets)."""
    import subprocess

    try:
        proc = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if proc.returncode == 0:
            match = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)\b", proc.stdout)
            if match:
                ipaddress.IPv4Address(match.group(1))
                return match.group(1)
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None


def build_discovered_topology_graph(
    *,
    target_network: str,
    devices: list[dict[str, Any]],
    host_hops: dict[str, list[str]] | None = None,
    default_gateway: str | None = None,
    excluded_ips: list[str] | None = None,
    declared_topology: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an honest, Cytoscape-ready discovered topology graph without inventing app links.

    Combines:
    - Declared grey-box nodes & edges (if operator provided a base topology),
    - Observed devices from Phase 2 evidence (typed via MAC vendor + open ports),
    - Observed L3 traceroute hops (multi-VLAN / routed paths),
    - Observed L2 broadcast segment hub (`LAN <cidr>`) + optional default gateway,
    - Observed shared-MAC multi-IP alias links (`same MAC`).
    """
    effective_net = parse_ipv4_network_or_host(target_network)
    merged_excluded = parse_excluded_ips(
        [*(excluded_ips or []), *((declared_topology or {}).get("excluded_ips") or [])]
    )
    hops_map = host_hops or {}

    nodes_by_id: dict[str, dict[str, Any]] = {}
    node_id_by_ip: dict[str, str] = {}
    edges_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    linked_node_ids: set[str] = set()

    def _add_edge(
        src: str,
        dst: str,
        *,
        protocol: str = "ethernet",
        origin: str = "observed_l2",
        label: str = "",
        description: str = "",
    ) -> None:
        if not src or not dst or src == dst:
            return
        if src not in nodes_by_id or dst not in nodes_by_id:
            return
        pair = (min(src, dst), max(src, dst), protocol)
        if pair in edges_by_key:
            return
        edges_by_key[pair] = {
            "id": f"{src}-{dst}-{protocol}",
            "source": src,
            "target": dst,
            "protocol": protocol,
            "origin": origin,
            "label": label,
            "description": description,
            "color": PROTOCOL_COLORS.get(protocol, "#bdc3c7"),
        }
        linked_node_ids.add(src)
        linked_node_ids.add(dst)

    # 1. Seed with declared grey-box topology if present
    if declared_topology:
        for node in declared_topology.get("nodes") or []:
            nid = str(node.get("id") or "").strip()
            if not nid:
                continue
            ip = str(node.get("ip") or "").strip()
            ntype = str(node.get("type") or "compute").strip().lower()
            entry = {
                "id": nid,
                "label": str(node.get("name") or node.get("label") or nid),
                "ip": ip,
                "type": ntype,
                "role": str(node.get("role") or ntype),
                "mac": "",
                "vendor": "",
                "services": _format_service_tags(node.get("services")),
                "color": DEVICE_TYPE_COLORS.get(ntype, "#3498db"),
                "declared": True,
                "observed": False,
                "out_of_scope": False,
                "excluded": False,
            }
            nodes_by_id[nid] = entry
            if ip:
                node_id_by_ip[ip] = nid

        for edge in declared_topology.get("edges") or []:
            src = str(edge.get("source") or "").strip()
            dst = str(edge.get("target") or "").strip()
            proto = str(edge.get("protocol") or edge.get("type") or "ethernet").strip().lower()
            _add_edge(
                src,
                dst,
                protocol=proto,
                origin="declared",
                description=str(edge.get("description") or ""),
            )

    # 2. Merge observed devices from Phase 2 evidence (strictly inside scope & not excluded)
    observed_device_ids: list[str] = []
    mac_to_node_ids: dict[str, list[str]] = {}
    for dev in devices or []:
        if not isinstance(dev, dict):
            continue
        ip = str(dev.get("ip") or "").strip()
        if not ip:
            continue
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if addr not in effective_net:
            continue
        if effective_net.prefixlen <= 30 and addr in (effective_net.network_address, effective_net.broadcast_address):
            continue
        if is_ip_excluded(ip, merged_excluded):
            continue

        mac = str(dev.get("mac") or "").strip().lower()
        vendor = str(dev.get("vendor") or "").strip()
        hostname = str(dev.get("hostname") or "").strip()
        svc_tags = _format_service_tags(dev.get("services"), dev.get("open_ports"))

        if ip in node_id_by_ip:
            nid = node_id_by_ip[ip]
            existing = nodes_by_id[nid]
            existing["observed"] = True
            if mac:
                existing["mac"] = mac
            if vendor:
                existing["vendor"] = vendor
            merged_tags = list(dict.fromkeys([*(existing.get("services") or []), *svc_tags]))
            existing["services"] = merged_tags
        else:
            nid = ip
            dev_type, label, role = classify_discovered_device(
                ip,
                vendor=vendor,
                hostname=hostname,
                services=dev.get("services"),
                open_ports=dev.get("open_ports"),
            )
            nodes_by_id[nid] = {
                "id": nid,
                "label": label,
                "ip": ip,
                "type": dev_type,
                "role": role,
                "mac": mac,
                "vendor": vendor,
                "services": svc_tags,
                "color": DEVICE_TYPE_COLORS.get(dev_type, "#3498db"),
                "declared": False,
                "observed": True,
                "out_of_scope": False,
                "excluded": False,
            }
            node_id_by_ip[ip] = nid

        if nid not in observed_device_ids:
            observed_device_ids.append(nid)
        if mac and mac not in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
            mac_to_node_ids.setdefault(mac, [])
            if nid not in mac_to_node_ids[mac]:
                mac_to_node_ids[mac].append(nid)

    # 3. Shared-MAC multi-IP alias & adjacent-MAC dual-NIC (eth0/wlan0) detection
    for mac, nids in mac_to_node_ids.items():
        if len(nids) >= 2:
            anchor = nids[0]
            for peer in nids[1:]:
                _add_edge(
                    anchor,
                    peer,
                    protocol="alias",
                    origin="observed_l2",
                    label="same MAC",
                    description=f"Shared NIC MAC {mac}",
                )

    parsed_macs: list[tuple[str, int, str, str]] = []
    for mac, nids in mac_to_node_ids.items():
        parts = mac.split(":")
        if len(parts) == 6:
            try:
                prefix = ":".join(parts[:5])
                last_byte = int(parts[5], 16)
                parsed_macs.append((prefix, last_byte, mac, nids[0]))
            except ValueError:
                pass
    parsed_macs.sort()
    for idx in range(len(parsed_macs)):
        p1, b1, m1, n1 = parsed_macs[idx]
        for jdx in range(idx + 1, len(parsed_macs)):
            p2, b2, m2, n2 = parsed_macs[jdx]
            if p1 != p2:
                break
            if abs(b2 - b1) == 1 and n1 != n2:
                _add_edge(
                    n1,
                    n2,
                    protocol="alias",
                    origin="observed_l2",
                    label="same host (eth/wifi)",
                    description=f"Adjacent NIC MACs {m1} / {m2}",
                )

    # 4. Observed L3 traceroute hops (multi-VLAN / routed targets)
    def _ensure_hop_node(hop_ip: str) -> str:
        if hop_ip in node_id_by_ip:
            return node_id_by_ip[hop_ip]
        excluded = is_ip_excluded(hop_ip, merged_excluded)
        try:
            in_net = ipaddress.IPv4Address(hop_ip) in effective_net
        except ValueError:
            in_net = False
        nid = f"hop_{hop_ip}"
        if nid not in nodes_by_id:
            suffix = " (excluded)" if excluded else (" (router)" if not in_net else "")
            nodes_by_id[nid] = {
                "id": nid,
                "label": f"{hop_ip}{suffix}",
                "ip": hop_ip,
                "type": "router",
                "role": "Intermediate L3 router (out of scan scope)" if (excluded or not in_net) else "Intermediate L3 router",
                "mac": "",
                "vendor": "",
                "services": [],
                "color": DEVICE_TYPE_COLORS["router"],
                "declared": False,
                "observed": True,
                "out_of_scope": excluded or not in_net,
                "excluded": excluded,
            }
            node_id_by_ip[hop_ip] = nid
        return nid

    direct_host_ids: list[str] = []
    for nid in observed_device_ids:
        ip = nodes_by_id[nid]["ip"]
        hops = [h for h in (hops_map.get(ip) or []) if h and h != ip]
        if hops:
            first_hop_id = _ensure_hop_node(hops[0])
            _add_edge(nid, first_hop_id, protocol="ethernet", origin="traceroute")
            for idx in range(len(hops) - 1):
                src_hop = _ensure_hop_node(hops[idx])
                dst_hop = _ensure_hop_node(hops[idx + 1])
                _add_edge(src_hop, dst_hop, protocol="ethernet", origin="traceroute")
        else:
            direct_host_ids.append(nid)

    # 5. Connect direct L2 hosts (0 intermediate hops) to their L2 broadcast segment or declared switch
    unlinked_direct = [nid for nid in direct_host_ids if nid not in linked_node_ids or not declared_topology]
    declared_hub_id: str | None = None
    if declared_topology:
        for candidate_type in ("switch", "router"):
            for nid, node in nodes_by_id.items():
                if node.get("declared") and node.get("type") == candidate_type:
                    declared_hub_id = nid
                    break
            if declared_hub_id:
                break

    if declared_hub_id:
        for nid in direct_host_ids:
            if nid != declared_hub_id and nid not in linked_node_ids:
                _add_edge(
                    declared_hub_id,
                    nid,
                    protocol="l2_segment",
                    origin="inferred_l2",
                    description="Discovered on same L2 subnet",
                )
    elif unlinked_direct and (effective_net.prefixlen < 32 or len(direct_host_ids) >= 2):
        seg_id = f"segment_{effective_net}"
        nodes_by_id[seg_id] = {
            "id": seg_id,
            "label": f"LAN {effective_net}",
            "ip": "",
            "type": "switch",
            "role": "Observed L2 broadcast segment",
            "mac": "",
            "vendor": "",
            "services": [],
            "color": DEVICE_TYPE_COLORS["switch"],
            "declared": False,
            "observed": True,
            "virtual": True,
            "out_of_scope": True,
            "excluded": False,
        }
        for nid in direct_host_ids:
            _add_edge(
                seg_id,
                nid,
                protocol="ethernet",
                origin="observed_l2",
                description="Direct L2 reachability on authorized subnet",
            )
        # Optionally link the local default gateway if it sits in this subnet
        if default_gateway:
            try:
                gw_addr = ipaddress.IPv4Address(default_gateway)
            except ValueError:
                gw_addr = None
            if gw_addr and gw_addr in effective_net:
                gw_excluded = is_ip_excluded(default_gateway, merged_excluded)
                if default_gateway in node_id_by_ip:
                    gw_id = node_id_by_ip[default_gateway]
                else:
                    gw_id = f"gw_{default_gateway}"
                    nodes_by_id[gw_id] = {
                        "id": gw_id,
                        "label": f"Gateway {default_gateway}" + (" (excluded)" if gw_excluded else ""),
                        "ip": default_gateway,
                        "type": "router",
                        "role": "Default gateway (excluded from scan)" if gw_excluded else "Default gateway",
                        "mac": "",
                        "vendor": "",
                        "services": [],
                        "color": DEVICE_TYPE_COLORS["router"],
                        "declared": False,
                        "observed": True,
                        "out_of_scope": gw_excluded,
                        "excluded": gw_excluded,
                    }
                    node_id_by_ip[default_gateway] = gw_id
                _add_edge(
                    gw_id,
                    seg_id,
                    protocol="wan" if gw_excluded else "ethernet",
                    origin="observed_l3",
                    description="Default gateway from local routing table",
                )

    nodes_list = list(nodes_by_id.values())
    edges_list = list(edges_by_key.values())
    return {
        "schema_version": 1,
        "subnet": str(effective_net),
        "excluded_ips": merged_excluded,
        "default_gateway": default_gateway,
        "nodes": nodes_list,
        "edges": edges_list,
        "host_hops": hops_map,
        "summary": {
            "node_count": len(nodes_list),
            "edge_count": len(edges_list),
            "observed_hosts": len(observed_device_ids),
            "declared_nodes": sum(1 for n in nodes_list if n.get("declared")),
            "shadow_hosts": sum(1 for n in nodes_list if n.get("observed") and not n.get("declared") and not n.get("out_of_scope") and not n.get("virtual")),
        },
    }
