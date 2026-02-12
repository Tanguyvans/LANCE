"""Abstract graph backend and NetworkX implementation."""

from __future__ import annotations

from abc import ABC, abstractmethod

import networkx as nx

from .models import Infrastructure


class GraphBackend(ABC):
    """Abstract interface for graph operations on the infrastructure."""

    @abstractmethod
    def load_infrastructure(self, infra: Infrastructure) -> None:
        """Populate the graph from an Infrastructure model."""

    @abstractmethod
    def get_device(self, device_id: str) -> dict:
        """Return device attributes as a dict."""

    @abstractmethod
    def get_neighbors(self, device_id: str) -> list[str]:
        """Return IDs of directly connected devices."""

    @abstractmethod
    def find_all_paths(
        self, source: str, target: str, max_depth: int = 10
    ) -> list[list[str]]:
        """Return all simple paths between two nodes up to *max_depth*."""

    @abstractmethod
    def get_attack_surface(self) -> list[dict]:
        """Return devices that expose services (open ports)."""

    @abstractmethod
    def get_graph_stats(self) -> dict:
        """Return basic graph statistics."""

    @abstractmethod
    def to_dict(self) -> dict:
        """Export the graph as a serialisable dict (for LLM agents)."""


class NetworkXBackend(GraphBackend):
    """Graph backend powered by :pymod:`networkx`."""

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_infrastructure(self, infra: Infrastructure) -> None:
        self.graph.clear()

        # Add external entities as nodes
        for ext in infra.external:
            self.graph.add_node(
                ext.id,
                name=ext.name,
                type=ext.type,
                role="",
                ip=None,
                os=None,
                services=[],
                protocols=[],
            )

        # Add devices as nodes
        for dev in infra.devices:
            self.graph.add_node(
                dev.id,
                name=dev.name,
                type=dev.type,
                role=dev.role,
                ip=dev.ip,
                os=dev.os,
                services=[
                    {"name": s.name, "port": s.port, "protocol": s.protocol}
                    for s in dev.services
                ],
                protocols=dev.protocols,
            )

        # Add links as edges
        for link in infra.links:
            self.graph.add_edge(
                link.source,
                link.target,
                type=link.type,
                description=link.description,
            )

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_device(self, device_id: str) -> dict:
        data = dict(self.graph.nodes[device_id])
        data["id"] = device_id
        return data

    def get_neighbors(self, device_id: str) -> list[str]:
        successors = set(self.graph.successors(device_id))
        predecessors = set(self.graph.predecessors(device_id))
        return sorted(successors | predecessors)

    def find_all_paths(
        self, source: str, target: str, max_depth: int = 10
    ) -> list[list[str]]:
        # Work on undirected view so paths go both ways
        undirected = self.graph.to_undirected()
        return list(
            nx.all_simple_paths(undirected, source, target, cutoff=max_depth)
        )

    def get_attack_surface(self) -> list[dict]:
        surface: list[dict] = []
        for node_id, data in self.graph.nodes(data=True):
            services = data.get("services", [])
            if services:
                surface.append(
                    {
                        "id": node_id,
                        "name": data.get("name"),
                        "type": data.get("type"),
                        "ip": data.get("ip"),
                        "services": services,
                    }
                )
        return surface

    def get_graph_stats(self) -> dict:
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "density": nx.density(self.graph),
            "is_connected": nx.is_weakly_connected(self.graph),
        }

    def to_dict(self) -> dict:
        nodes = []
        for node_id, data in self.graph.nodes(data=True):
            entry = dict(data)
            entry["id"] = node_id
            nodes.append(entry)

        edges = []
        for src, tgt, data in self.graph.edges(data=True):
            entry = dict(data)
            entry["source"] = src
            entry["target"] = tgt
            edges.append(entry)

        return {"nodes": nodes, "edges": edges}
