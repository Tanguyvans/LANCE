"""Dataclasses for the NATO Smart City IoT infrastructure model."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Service:
    name: str
    port: int
    protocol: str = "tcp"


@dataclass
class Device:
    id: str
    name: str
    type: str  # router | switch | gateway | sensor | compute | camera | ap
    role: str = ""
    ip: str | None = None
    network: str | None = None
    os: str | None = None
    services: list[Service] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)


@dataclass
class Network:
    id: str
    name: str
    subnet: str | None = None
    vlan: int | None = None


@dataclass
class Link:
    source: str
    target: str
    type: str = "ethernet"  # ethernet | lorawan | zigbee | mqtt | wan
    description: str = ""


@dataclass
class ExternalEntity:
    id: str
    name: str
    type: str = "external"


@dataclass
class Infrastructure:
    metadata: dict = field(default_factory=dict)
    networks: list[Network] = field(default_factory=list)
    devices: list[Device] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    external: list[ExternalEntity] = field(default_factory=list)
