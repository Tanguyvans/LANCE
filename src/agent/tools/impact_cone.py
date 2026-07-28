"""Impact Cone — Epicenter identification and local propagation algorithm.

Implements two core functions:
1. **Epicenter identification**: Pinpoint the mutated node (v_m) from either
   a discovery event or an exploitation event.
2. **Cone of Impact**: BFS-based local propagation that only recalculates
   distances for nodes affected by the mutation, using the predecessors
   of nodes with positive disbalance to control the propagation boundary.

This avoids the O(n²) full-graph JSON diff by restricting computation to
the O(k·log n) cone of impacted nodes.
"""

from __future__ import annotations

import logging

from src.agent.tools.disbalance_engine import WeightedAttackGraph, WEIGHT_INFINITE

log = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Epicenter identification
# ------------------------------------------------------------------

def identify_epicenter(
    mutation_source: str,
    mutation_data: dict,
) -> str | None:
    """Identify the epicenter node v_m from a mutation event.

    Parameters
    ----------
    mutation_source : str
        ``"discovery"`` — triggered by ``update_discovery_hosts()``
        ``"exploitation"`` — triggered by a successful exploit tool call
    mutation_data : dict
        Context-dependent payload:
        - For discovery: ``{"new_hosts": [{"id": ..., "ip": ..., "services": [...]}],
                           "changed_hosts": [{"id": ..., "new_ports": [...]}]}``
        - For exploitation: ``{"device_id": str, "device_ip": str,
                              "exploit_status": str, "vuln_type": str}``

    Returns
    -------
    str | None
        Device ID of the epicenter node, or None if no valid epicenter found.
    """
    if mutation_source == "discovery":
        # Priority 1: newly added hosts
        new_hosts = mutation_data.get("new_hosts", [])
        if new_hosts:
            epicenter = new_hosts[0].get("id") or new_hosts[0].get("ip")
            log.info("Epicenter identified (discovery/new_host): %s", epicenter)
            return epicenter

        # Priority 2: hosts with new ports (service discovery)
        changed_hosts = mutation_data.get("changed_hosts", [])
        if changed_hosts:
            epicenter = changed_hosts[0].get("id") or changed_hosts[0].get("ip")
            log.info("Epicenter identified (discovery/changed_host): %s", epicenter)
            return epicenter

    elif mutation_source == "exploitation":
        device_id = mutation_data.get("device_id")
        status = (mutation_data.get("exploit_status") or "").lower()
        if device_id and status in ("compromised", "exploited", "confirmed"):
            log.info("Epicenter identified (exploitation): %s (status=%s)", device_id, status)
            return device_id

    log.warning("Could not identify epicenter from %s: %s", mutation_source, mutation_data)
    return None


# ------------------------------------------------------------------
# Cone of Impact algorithm
# ------------------------------------------------------------------

def compute_graph_disbalance(
    graph: WeightedAttackGraph,
    mutated_node: str,
    target_node: str | None = None,
) -> list[dict]:
    """Compute the cone of impact starting from the mutated node.

    Implements the BFS-based local propagation algorithm:

    1. Initialize a queue with the epicenter v_m.
    2. For each node in the queue, compute Δ = D_{T-1} - D_T.
    3. If Δ > 0 (the node is now closer to the target):
       - Record the node as affected.
       - Add its **predecessors** (parent nodes) to the queue for evaluation.
    4. Continue until the queue is empty (no more propagation).

    Parameters
    ----------
    graph : WeightedAttackGraph
        The weighted attack graph with T-1 snapshot already taken.
    mutated_node : str
        Device ID of the epicenter node.
    target_node : str | None
        Override for the OT target node.  Uses graph's default if None.

    Returns
    -------
    list[dict]
        List of affected nodes: ``[{"node": str, "delta": float,
        "d_old": float|str, "d_new": float|str}]``
    """
    target = target_node or graph.target_node
    if mutated_node not in graph.graph:
        log.warning("Mutated node '%s' not in graph — no impact computed", mutated_node)
        return []

    nodes_to_evaluate: list[str] = [mutated_node]
    visited: set[str] = set()
    affected_nodes: list[dict] = []

    while nodes_to_evaluate:
        current_node = nodes_to_evaluate.pop(0)

        # Avoid re-evaluating the same node
        if current_node in visited:
            continue
        visited.add(current_node)

        # Compute distances T-1 and T for the current node towards the OT target
        d_old = graph.get_previous_distance(current_node, target)
        d_new = graph.calculate_current_distance(current_node, target)

        # Compute disbalance
        if d_old == WEIGHT_INFINITE and d_new == WEIGHT_INFINITE:
            disbalance = 0.0
        elif d_old == WEIGHT_INFINITE:
            # Was unreachable, now reachable → significant positive change
            disbalance = d_new * 10  # scaled indicator of major change
        else:
            disbalance = d_old - d_new

        # Pinpoint: is there a real disbalance?
        if disbalance > 0:
            affected_nodes.append({
                "node": current_node,
                "delta": round(disbalance, 4),
                "d_old": round(d_old, 4) if d_old != WEIGHT_INFINITE else "infinite",
                "d_new": round(d_new, 4) if d_new != WEIGHT_INFINITE else "infinite",
            })

            # Controlled propagation: add ONLY predecessors (nodes pointing to current)
            for parent in graph.predecessors(current_node):
                if parent not in visited and parent not in nodes_to_evaluate:
                    nodes_to_evaluate.append(parent)

    log.info(
        "Cone of impact: %d affected node(s) from epicenter '%s' (visited %d total)",
        len(affected_nodes),
        mutated_node,
        len(visited),
    )
    return affected_nodes


# ------------------------------------------------------------------
# Report builder
# ------------------------------------------------------------------

def build_graph_delta_report(
    affected_nodes: list[dict],
    edges_modified: list[dict],
    source_trigger: str,
    iteration: str = "T",
) -> dict:
    """Build the structured graph_delta JSON report.

    Parameters
    ----------
    affected_nodes : list[dict]
        Output from ``compute_graph_disbalance()``.
    edges_modified : list[dict]
        List of edges that were modified: ``[{"from": str, "to": str,
        "previous_weight": str|float, "current_weight": str|float,
        "status": str}]``
    source_trigger : str
        What triggered the mutation (e.g., ``"update_discovery_hosts"``,
        ``"ssh_login"``, ``"mysql_query"``).
    iteration : str
        Iteration label (default ``"T"``).

    Returns
    -------
    dict
        Complete graph_delta report matching the specified JSON schema.
    """
    nodes_report = []
    for node_info in affected_nodes:
        delta = node_info["delta"]
        nodes_report.append({
            "device_id": node_info["node"],
            "hostname": node_info.get("hostname", node_info["node"]),
            "local_disbalance_score": f"+{delta}" if delta > 0 else str(delta),
            "reason": _infer_reason(delta, node_info),
        })

    report = {
        "status": "success",
        "iteration": iteration,
        "mutation_detected": len(affected_nodes) > 0,
        "graph_delta": {
            "source_trigger": source_trigger,
            "nodes_affected": nodes_report,
            "edges_modified": edges_modified,
        },
    }

    log.info(
        "Graph delta report: %d affected nodes, %d edges modified, trigger=%s",
        len(nodes_report),
        len(edges_modified),
        source_trigger,
    )
    return report


def _infer_reason(delta: float, node_info: dict) -> str:
    """Generate a human-readable reason for the disbalance."""
    d_old = node_info.get("d_old")
    d_new = node_info.get("d_new")

    if d_old == "infinite" and d_new != "infinite":
        return "New logical path opened towards OT Zone"
    if delta > 5.0:
        return "Major path improvement — node is now significantly closer to OT target"
    if delta > 1.0:
        return "Path cost reduced — new exploitation route discovered"
    if delta > 0:
        return "Minor path improvement via upstream mutation"
    return "No significant change"
