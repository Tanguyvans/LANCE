"""Load a YAML infrastructure file into the graph backend."""

from __future__ import annotations

from pathlib import Path

import yaml

from .graph_backend import GraphBackend, NetworkXBackend
from .models import (
    Device,
    ExternalEntity,
    Infrastructure,
    Link,
    Network,
    Service,
)

DEFAULT_YAML = Path(__file__).resolve().parent.parent / "infrastructure" / "nato_lab.yaml"


def _parse_services(raw: list[dict] | None) -> list[Service]:
    if not raw:
        return []
    return [
        Service(
            name=s["name"],
            port=s["port"],
            protocol=s.get("protocol", "tcp"),
            version=s.get("version"),
        )
        for s in raw
    ]


def load_yaml(path: Path = DEFAULT_YAML) -> Infrastructure:
    """Parse a YAML file and return an :class:`Infrastructure` instance."""
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    networks = [
        Network(
            id=n["id"],
            name=n["name"],
            subnet=n.get("subnet"),
            vlan=n.get("vlan"),
        )
        for n in data.get("networks", [])
    ]

    devices = [
        Device(
            id=d["id"],
            name=d["name"],
            type=d["type"],
            role=d.get("role", ""),
            ip=d.get("ip"),
            network=d.get("network"),
            os=d.get("os"),
            os_version=d.get("os_version"),
            firmware=d.get("firmware"),
            services=_parse_services(d.get("services")),
            protocols=d.get("protocols", []),
        )
        for d in data.get("devices", [])
    ]

    links = [
        Link(
            source=l["source"],
            target=l["target"],
            type=l.get("type", "ethernet"),
            description=l.get("description", ""),
        )
        for l in data.get("links", [])
    ]

    external = [
        ExternalEntity(
            id=e["id"],
            name=e["name"],
            type=e.get("type", "external"),
        )
        for e in data.get("external", [])
    ]

    return Infrastructure(
        metadata=data.get("metadata", {}),
        networks=networks,
        devices=devices,
        links=links,
        external=external,
    )


def build_graph(
    path: Path = DEFAULT_YAML,
    backend: GraphBackend | None = None,
) -> GraphBackend:
    """Load YAML and populate a graph backend (default: NetworkX)."""
    if backend is None:
        backend = NetworkXBackend()
    infra = load_yaml(path)
    backend.load_infrastructure(infra)
    return backend
