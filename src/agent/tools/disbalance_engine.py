"""Disbalance Engine — Weighted attack graph with local disbalance computation.

Models the network as a directed weighted graph G = (V, E, W) where:
- V is the set of devices (nodes)
- E is the set of network accesses (edges)
- W(u, v) represents the exploitation difficulty weight for edge (u → v)

Provides Dijkstra-based shortest-distance computation and a T-1 / T distance
cache to compute local disbalance Δ(v) = D_{T-1}(v, Target) - D_T(v, Target).
"""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx

log = logging.getLogger(__name__)

# Weight constants (aligned with attack_path.py conventions)
WEIGHT_INFINITE = float("inf")

# Protocol difficulty factors (mirrored from attack_path.py)
PROTOCOL_FACTORS: dict[str, float] = {
    "ethernet": 0.8,
    "wan": 0.7,
    "mqtt": 0.6,
    "zigbee": 0.3,
    "lorawan": 0.2,
}

# Default exploitation weight when no CVE data is available
DEFAULT_EXPLOIT_WEIGHT = 0.1


class WeightedAttackGraph:
    """Encapsulates a directed weighted graph for attack-cost distance computation.

    Edge weight semantics:
    - ``attack_weight`` (float): exploitation ease (0 = impossible, 1 = trivial).
      Higher values mean the link is *easier* to exploit.
    - ``attack_cost`` (float): 1 / attack_weight.  Used as Dijkstra weight so
      that *easier* edges yield *shorter* paths.

    The class maintains a snapshot of distances at step T-1 so that the local
    disbalance Δ(v) can be computed after a graph mutation at step T.
    """

    def __init__(self, target_node: str) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        self.target_node: str = target_node
        # Cache of distances computed at step T-1: {node_id: distance}
        self._previous_distances: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Graph construction helpers
    # ------------------------------------------------------------------

    def add_node(self, node_id: str, **attrs: Any) -> None:
        """Add or update a node with arbitrary attributes."""
        self.graph.add_node(node_id, **attrs)

    def set_edge_weight(self, u: str, v: str, weight: float, **attrs: Any) -> None:
        """Set the exploitation weight for edge (u → v).

        ``attack_cost`` is derived automatically as ``1 / weight`` (clamped to
        avoid division by zero).
        """
        cost = 1.0 / weight if weight > 0 else 1e6
        self.graph.add_edge(u, v, attack_weight=weight, attack_cost=cost, **attrs)

    def get_edge_weight(self, u: str, v: str) -> float:
        """Return the current attack_weight for edge (u → v), or inf if absent."""
        if self.graph.has_edge(u, v):
            return self.graph[u][v].get("attack_weight", DEFAULT_EXPLOIT_WEIGHT)
        return WEIGHT_INFINITE

    # ------------------------------------------------------------------
    # Distance computation
    # ------------------------------------------------------------------

    def calculate_current_distance(self, node: str, target: str | None = None) -> float:
        """Dijkstra shortest-path cost from *node* to *target* on the current graph.

        Uses ``attack_cost`` as edge weight.  Returns ``float('inf')`` when no
        path exists.
        """
        target = target or self.target_node
        if node == target:
            return 0.0
        if node not in self.graph or target not in self.graph:
            return WEIGHT_INFINITE
        try:
            return nx.shortest_path_length(
                self.graph, node, target, weight="attack_cost"
            )
        except nx.NetworkXNoPath:
            return WEIGHT_INFINITE

    def calculate_all_distances(self, target: str | None = None) -> dict[str, float]:
        """Compute distances from every node to *target*."""
        target = target or self.target_node
        distances: dict[str, float] = {}
        for node in self.graph.nodes:
            distances[node] = self.calculate_current_distance(node, target)
        return distances

    def get_previous_distance(self, node: str, target: str | None = None) -> float:
        """Return the cached T-1 distance for *node*.

        Returns ``float('inf')`` if no snapshot was taken yet.
        """
        return self._previous_distances.get(node, WEIGHT_INFINITE)

    # ------------------------------------------------------------------
    # Snapshot management
    # ------------------------------------------------------------------

    def snapshot_distances(self) -> None:
        """Save all current distances as the T-1 reference."""
        self._previous_distances = self.calculate_all_distances()
        log.info(
            "Distance snapshot saved: %d nodes, target=%s",
            len(self._previous_distances),
            self.target_node,
        )

    # ------------------------------------------------------------------
    # Disbalance
    # ------------------------------------------------------------------

    def compute_disbalance(self, node: str, target: str | None = None) -> float:
        """Compute local disbalance Δ(v) = D_{T-1}(v, Target) - D_T(v, Target).

        A positive value means the node is now *closer* to the target (the attack
        surface improved for the attacker).
        """
        d_old = self.get_previous_distance(node, target)
        d_new = self.calculate_current_distance(node, target)
        # Handle inf - inf = nan → treat as 0
        if d_old == WEIGHT_INFINITE and d_new == WEIGHT_INFINITE:
            return 0.0
        if d_old == WEIGHT_INFINITE:
            # Was unreachable, now reachable → large positive Δ
            return d_new * 10  # scaled indicator
        return d_old - d_new

    def predecessors(self, node: str) -> list[str]:
        """Return IDs of nodes that have an edge pointing *to* this node."""
        if node not in self.graph:
            return []
        return list(self.graph.predecessors(node))


# ------------------------------------------------------------------
# Factory functions
# ------------------------------------------------------------------

def _detect_target_node(nodes: list[dict]) -> str:
    """Auto-detect the OT target node from topology.

    Priority: modbus_server > scada_server > any node with role containing 'ot'
    or 'plc' > last node in the list.
    """
    priority_roles = ["modbus_server", "scada_server"]
    for role in priority_roles:
        for n in nodes:
            if n.get("role") == role:
                return n["id"]
    # Fallback: look for OT-ish roles
    for n in nodes:
        r = (n.get("role") or "").lower()
        if "ot" in r or "plc" in r or "hmi" in r:
            return n["id"]
    # Ultimate fallback: last node (typically deepest in topology)
    if nodes:
        return nodes[-1]["id"]
    return "unknown"


def build_weighted_attack_graph(
    nodes: list[dict],
    edges: list[dict],
    target_node: str | None = None,
) -> WeightedAttackGraph:
    """Construct a WeightedAttackGraph from topology data.

    Parameters
    ----------
    nodes : list[dict]
        Topology nodes (must have ``id``, optionally ``role``, ``services``, ``status``).
    edges : list[dict]
        Topology edges (must have ``source``, ``target``; optionally ``type``).
    target_node : str | None
        Explicit OT target node.  Auto-detected if None.

    Returns
    -------
    WeightedAttackGraph
        Ready-to-use weighted graph with initial distance snapshot.
    """
    if target_node is None:
        target_node = _detect_target_node(nodes)

    wag = WeightedAttackGraph(target_node=target_node)

    # Add nodes
    for n in nodes:
        wag.add_node(
            n["id"],
            role=n.get("role", ""),
            ip=n.get("ip", ""),
            status=n.get("status", "unknown"),
        )

    # Add edges with weights derived from link type + target exploitability
    for e in edges:
        src, tgt = e.get("source", ""), e.get("target", "")
        if not src or not tgt:
            continue
        link_type = e.get("type", "ethernet")
        protocol_factor = PROTOCOL_FACTORS.get(link_type, 0.5)

        # Target node status determines exploit factor
        tgt_data = next((n for n in nodes if n["id"] == tgt), None)
        if tgt_data:
            status = (tgt_data.get("status") or "").lower()
            if status == "compromised":
                exploit_factor = 1.0  # traversal is trivial
            elif status == "exploited":
                exploit_factor = 0.9
            else:
                # Rough estimate from number of services (more services = more attack surface)
                n_services = len(tgt_data.get("services", []))
                exploit_factor = min(0.1 + n_services * 0.1, 0.8)
        else:
            exploit_factor = DEFAULT_EXPLOIT_WEIGHT

        weight = protocol_factor * exploit_factor
        wag.set_edge_weight(src, tgt, weight, type=link_type)

    # Take initial snapshot (T-1 = T₀)
    wag.snapshot_distances()
    log.info(
        "WeightedAttackGraph built: %d nodes, %d edges, target=%s",
        wag.graph.number_of_nodes(),
        wag.graph.number_of_edges(),
        target_node,
    )
    return wag


def compute_node_disbalance(
    graph: WeightedAttackGraph,
    node: str,
    target: str | None = None,
) -> dict:
    """Compute disbalance for a single node and return a structured dict.

    Returns
    -------
    dict
        ``{"node": str, "delta": float, "d_old": float, "d_new": float}``
    """
    target = target or graph.target_node
    d_old = graph.get_previous_distance(node, target)
    d_new = graph.calculate_current_distance(node, target)
    delta = graph.compute_disbalance(node, target)
    return {
        "node": node,
        "delta": round(delta, 4),
        "d_old": round(d_old, 4) if d_old != WEIGHT_INFINITE else "infinite",
        "d_new": round(d_new, 4) if d_new != WEIGHT_INFINITE else "infinite",
    }
