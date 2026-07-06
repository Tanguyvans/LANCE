"""Tests for the disbalance engine and impact cone modules.

Covers:
- WeightedAttackGraph construction and Dijkstra distance computation
- T-1 snapshot and disbalance Δ calculation
- Epicenter identification (discovery + exploitation modes)
- Cone of impact BFS propagation algorithm
- Graph delta report JSON structure conformity
- End-to-end integration with graph_tools triggers
"""

from __future__ import annotations

import math
import pytest

from src.agent.tools.disbalance_engine import (
    WeightedAttackGraph,
    build_weighted_attack_graph,
    compute_node_disbalance,
    WEIGHT_INFINITE,
)
from src.agent.tools.impact_cone import (
    identify_epicenter,
    compute_graph_disbalance,
    build_graph_delta_report,
)


# ── Fixtures ─────────────────────────────────────────────────────


def _build_linear_graph() -> WeightedAttackGraph:
    """Build a simple linear graph:

        Internet → Router → Gateway → OT_Target

    Weights: Internet→Router=0.8, Router→Gateway=0.5, Gateway→OT=0.3
    """
    wag = WeightedAttackGraph(target_node="OT_Target")
    for node_id in ["Internet", "Router", "Gateway", "OT_Target"]:
        wag.add_node(node_id, role=node_id.lower())
    wag.set_edge_weight("Internet", "Router", 0.8)
    wag.set_edge_weight("Router", "Gateway", 0.5)
    wag.set_edge_weight("Gateway", "OT_Target", 0.3)
    wag.snapshot_distances()
    return wag


def _build_diamond_graph() -> WeightedAttackGraph:
    """Build a diamond graph:

        Internet → Router → WebServer → OT_Target
                       ↘ MQTT_Broker ↗

    Two paths to OT_Target with different costs.
    """
    wag = WeightedAttackGraph(target_node="OT_Target")
    for node_id in ["Internet", "Router", "WebServer", "MQTT_Broker", "OT_Target"]:
        wag.add_node(node_id, role=node_id.lower())

    wag.set_edge_weight("Internet", "Router", 0.8)
    wag.set_edge_weight("Router", "WebServer", 0.4)
    wag.set_edge_weight("Router", "MQTT_Broker", 0.6)
    wag.set_edge_weight("WebServer", "OT_Target", 0.3)
    wag.set_edge_weight("MQTT_Broker", "OT_Target", 0.2)
    wag.snapshot_distances()
    return wag


# ══════════════════════════════════════════════════════════════════
# Test Suite 1: WeightedAttackGraph basics
# ══════════════════════════════════════════════════════════════════


class TestWeightedAttackGraph:
    """Unit tests for the WeightedAttackGraph class."""

    def test_node_and_edge_creation(self):
        wag = WeightedAttackGraph(target_node="target")
        wag.add_node("A")
        wag.add_node("B")
        wag.set_edge_weight("A", "B", 0.5)

        assert "A" in wag.graph
        assert "B" in wag.graph
        assert wag.graph.has_edge("A", "B")
        assert wag.graph["A"]["B"]["attack_weight"] == 0.5
        assert wag.graph["A"]["B"]["attack_cost"] == pytest.approx(2.0)

    def test_edge_weight_zero_gives_high_cost(self):
        """Weight=0 should produce a very high cost (not inf or error)."""
        wag = WeightedAttackGraph(target_node="B")
        wag.add_node("A")
        wag.add_node("B")
        wag.set_edge_weight("A", "B", 0.0)
        assert wag.graph["A"]["B"]["attack_cost"] == 1e6

    def test_get_edge_weight_nonexistent(self):
        wag = WeightedAttackGraph(target_node="B")
        wag.add_node("A")
        wag.add_node("B")
        assert wag.get_edge_weight("A", "B") == WEIGHT_INFINITE

    def test_dijkstra_distance_linear(self):
        """Verify Dijkstra on a linear chain."""
        wag = _build_linear_graph()
        # Gateway → OT_Target: cost = 1/0.3 ≈ 3.33
        d = wag.calculate_current_distance("Gateway", "OT_Target")
        assert d == pytest.approx(1.0 / 0.3, rel=1e-3)

        # Router → OT_Target: cost = 1/0.5 + 1/0.3 = 2 + 3.33 = 5.33
        d = wag.calculate_current_distance("Router", "OT_Target")
        assert d == pytest.approx(1.0 / 0.5 + 1.0 / 0.3, rel=1e-3)

    def test_distance_to_self_is_zero(self):
        wag = _build_linear_graph()
        assert wag.calculate_current_distance("OT_Target", "OT_Target") == 0.0

    def test_no_path_returns_infinite(self):
        """Disconnected nodes should return infinite distance."""
        wag = WeightedAttackGraph(target_node="B")
        wag.add_node("A")
        wag.add_node("B")
        assert wag.calculate_current_distance("A", "B") == WEIGHT_INFINITE

    def test_predecessors(self):
        wag = _build_linear_graph()
        assert wag.predecessors("Router") == ["Internet"]
        assert wag.predecessors("OT_Target") == ["Gateway"]
        assert wag.predecessors("Internet") == []


# ══════════════════════════════════════════════════════════════════
# Test Suite 2: Disbalance Δ computation
# ══════════════════════════════════════════════════════════════════


class TestDisbalance:
    """Tests for the disbalance computation Δ(v) = D_{T-1} - D_T."""

    def test_no_change_zero_disbalance(self):
        """When nothing changes, Δ should be 0 for all nodes."""
        wag = _build_linear_graph()
        for node in ["Internet", "Router", "Gateway", "OT_Target"]:
            delta = wag.compute_disbalance(node)
            assert delta == 0.0, f"Node {node} should have Δ=0 but got {delta}"

    def test_weight_improvement_positive_disbalance(self):
        """When an edge weight improves (higher), Δ should be positive."""
        wag = _build_linear_graph()

        # Mutate: Gateway→OT weight improves from 0.3 to 1.0
        # Old cost: 1/0.3 ≈ 3.33,  New cost: 1/1.0 = 1.0
        wag.set_edge_weight("Gateway", "OT_Target", 1.0)

        delta_gateway = wag.compute_disbalance("Gateway")
        # Δ = old_distance - new_distance = 3.33 - 1.0 = 2.33
        assert delta_gateway > 0
        assert delta_gateway == pytest.approx(1.0 / 0.3 - 1.0, rel=1e-2)

    def test_weight_degradation_negative_disbalance(self):
        """When an edge weight degrades (lower), Δ should be negative."""
        wag = _build_linear_graph()

        # Mutate: Gateway→OT weight degrades from 0.3 to 0.1
        wag.set_edge_weight("Gateway", "OT_Target", 0.1)

        delta_gateway = wag.compute_disbalance("Gateway")
        # Δ = old_distance - new_distance = 3.33 - 10.0 < 0
        assert delta_gateway < 0

    def test_unreachable_becomes_reachable(self):
        """When a node goes from unreachable to reachable, Δ should be large positive."""
        wag = WeightedAttackGraph(target_node="OT_Target")
        wag.add_node("A")
        wag.add_node("OT_Target")
        # No edge → unreachable
        wag.snapshot_distances()

        # Add edge → now reachable
        wag.set_edge_weight("A", "OT_Target", 0.5)
        delta = wag.compute_disbalance("A")
        assert delta > 0  # was infinite, now finite

    def test_compute_node_disbalance_dict(self):
        """Test that compute_node_disbalance returns correct dict structure."""
        wag = _build_linear_graph()
        wag.set_edge_weight("Gateway", "OT_Target", 1.0)

        result = compute_node_disbalance(wag, "Gateway")
        assert "node" in result
        assert result["node"] == "Gateway"
        assert "delta" in result
        assert "d_old" in result
        assert "d_new" in result
        assert result["delta"] > 0


# ══════════════════════════════════════════════════════════════════
# Test Suite 3: Epicenter identification
# ══════════════════════════════════════════════════════════════════


class TestEpicenter:
    """Tests for epicenter identification from mutation events."""

    def test_discovery_new_host(self):
        """Discovery of a new host → epicenter = new host."""
        epicenter = identify_epicenter("discovery", {
            "new_hosts": [{"id": "192.168.88.25", "ip": "192.168.88.25"}],
        })
        assert epicenter == "192.168.88.25"

    def test_discovery_changed_host(self):
        """Discovery of new ports on existing host → epicenter = that host."""
        epicenter = identify_epicenter("discovery", {
            "changed_hosts": [{"id": "Router", "new_ports": [8080]}],
        })
        assert epicenter == "Router"

    def test_discovery_prefers_new_over_changed(self):
        """New hosts take priority over changed hosts."""
        epicenter = identify_epicenter("discovery", {
            "new_hosts": [{"id": "NewHost"}],
            "changed_hosts": [{"id": "Router"}],
        })
        assert epicenter == "NewHost"

    def test_exploitation_confirmed(self):
        """Successful exploitation → epicenter = compromised device."""
        epicenter = identify_epicenter("exploitation", {
            "device_id": "Gateway",
            "exploit_status": "CONFIRMED",
            "vuln_type": "ssh_login",
        })
        assert epicenter == "Gateway"

    def test_exploitation_exploited_status(self):
        """'exploited' status also triggers epicenter identification."""
        epicenter = identify_epicenter("exploitation", {
            "device_id": "WebServer",
            "exploit_status": "exploited",
        })
        assert epicenter == "WebServer"

    def test_exploitation_failed_no_epicenter(self):
        """Failed exploit → no epicenter."""
        epicenter = identify_epicenter("exploitation", {
            "device_id": "WebServer",
            "exploit_status": "FAILED",
        })
        assert epicenter is None

    def test_unknown_source_no_epicenter(self):
        """Unknown mutation source → no epicenter."""
        epicenter = identify_epicenter("unknown", {"some": "data"})
        assert epicenter is None

    def test_empty_data_no_epicenter(self):
        """Empty mutation data → no epicenter."""
        epicenter = identify_epicenter("discovery", {})
        assert epicenter is None


# ══════════════════════════════════════════════════════════════════
# Test Suite 4: Cone of Impact algorithm
# ══════════════════════════════════════════════════════════════════


class TestConeOfImpact:
    """Tests for the BFS cone-of-impact propagation."""

    def test_linear_graph_mutation_at_gateway(self):
        """Mutation at Gateway: cone should include Gateway and Router
        (propagated via predecessor), but NOT Internet (its Δ may be 0
        unless the mutation propagates that far)."""
        wag = _build_linear_graph()

        # Mutate: Gateway→OT_Target weight goes from 0.3 to 1.0
        wag.set_edge_weight("Gateway", "OT_Target", 1.0)

        affected = compute_graph_disbalance(wag, "Gateway")
        affected_ids = {n["node"] for n in affected}

        # Gateway should definitely be affected (direct mutation)
        assert "Gateway" in affected_ids
        # Router is a predecessor of Gateway — its distance to OT also improved
        assert "Router" in affected_ids

    def test_no_disbalance_no_propagation(self):
        """If Δ=0 at the epicenter, nothing should propagate."""
        wag = _build_linear_graph()
        # No mutation → Δ=0 everywhere
        affected = compute_graph_disbalance(wag, "Gateway")
        assert len(affected) == 0

    def test_diamond_graph_propagation(self):
        """In a diamond graph, improving one path should only affect
        nodes on that path, not the alternative path."""
        wag = _build_diamond_graph()

        # Improve WebServer→OT_Target from 0.3 to 1.0
        wag.set_edge_weight("WebServer", "OT_Target", 1.0)

        affected = compute_graph_disbalance(wag, "WebServer")
        affected_ids = {n["node"] for n in affected}

        assert "WebServer" in affected_ids
        # Router is predecessor to WebServer, its best path to OT may improve
        assert "Router" in affected_ids
        # MQTT_Broker should NOT be in cone (not a predecessor of WebServer)
        assert "MQTT_Broker" not in affected_ids

    def test_nonexistent_epicenter(self):
        """Non-existent epicenter → empty result."""
        wag = _build_linear_graph()
        affected = compute_graph_disbalance(wag, "NonExistent")
        assert len(affected) == 0

    def test_all_deltas_positive(self):
        """Every node in the cone should have Δ > 0."""
        wag = _build_linear_graph()
        wag.set_edge_weight("Gateway", "OT_Target", 1.0)
        affected = compute_graph_disbalance(wag, "Gateway")

        for node_info in affected:
            assert node_info["delta"] > 0, (
                f"Node {node_info['node']} in cone but has Δ={node_info['delta']}"
            )


# ══════════════════════════════════════════════════════════════════
# Test Suite 5: Graph Delta Report
# ══════════════════════════════════════════════════════════════════


class TestGraphDeltaReport:
    """Tests for the JSON report structure."""

    def test_report_structure(self):
        """Verify the report matches the expected JSON schema."""
        affected = [
            {"node": "Gateway", "delta": 2.33, "d_old": 3.33, "d_new": 1.0},
        ]
        edges = [
            {
                "from": "Router",
                "to": "Gateway",
                "previous_weight": "infinite",
                "current_weight": "0.1",
                "status": "EXPLOITED",
            }
        ]
        report = build_graph_delta_report(
            affected, edges, "ssh_login", iteration="T",
        )

        assert report["status"] == "success"
        assert report["iteration"] == "T"
        assert report["mutation_detected"] is True
        assert "graph_delta" in report
        delta = report["graph_delta"]
        assert delta["source_trigger"] == "ssh_login"
        assert len(delta["nodes_affected"]) == 1
        assert len(delta["edges_modified"]) == 1

        node = delta["nodes_affected"][0]
        assert "device_id" in node
        assert "local_disbalance_score" in node
        assert "reason" in node

    def test_no_mutation_report(self):
        """Empty affected list → mutation_detected = False."""
        report = build_graph_delta_report([], [], "test")
        assert report["mutation_detected"] is False
        assert len(report["graph_delta"]["nodes_affected"]) == 0

    def test_positive_delta_shows_plus_sign(self):
        """Positive deltas should be formatted with a '+' prefix."""
        affected = [{"node": "A", "delta": 5.0}]
        report = build_graph_delta_report(affected, [], "test")
        score = report["graph_delta"]["nodes_affected"][0]["local_disbalance_score"]
        assert score.startswith("+")


# ══════════════════════════════════════════════════════════════════
# Test Suite 6: build_weighted_attack_graph factory
# ══════════════════════════════════════════════════════════════════


class TestBuildWeightedAttackGraph:
    """Tests for the factory function."""

    def test_builds_from_topology(self):
        nodes = [
            {"id": "router", "role": "router", "services": [{"name": "ssh", "port": 22}]},
            {"id": "web", "role": "web_server", "services": [{"name": "http", "port": 80}]},
            {"id": "ot", "role": "modbus_server", "services": [{"name": "modbus", "port": 502}]},
        ]
        edges = [
            {"source": "router", "target": "web"},
            {"source": "web", "target": "ot"},
        ]
        wag = build_weighted_attack_graph(nodes, edges)

        assert wag.graph.number_of_nodes() == 3
        assert wag.graph.number_of_edges() == 2
        assert wag.target_node == "ot"  # auto-detected as modbus_server

    def test_auto_detect_target_modbus(self):
        """modbus_server role should be auto-detected as target."""
        nodes = [
            {"id": "A", "role": "router"},
            {"id": "B", "role": "modbus_server"},
        ]
        wag = build_weighted_attack_graph(nodes, [])
        assert wag.target_node == "B"

    def test_explicit_target_override(self):
        """Explicit target_node should override auto-detection."""
        nodes = [
            {"id": "A", "role": "router"},
            {"id": "B", "role": "modbus_server"},
        ]
        wag = build_weighted_attack_graph(nodes, [], target_node="A")
        assert wag.target_node == "A"

    def test_initial_snapshot_exists(self):
        """After build, T-1 distances should be populated."""
        nodes = [
            {"id": "A", "role": "router", "services": []},
            {"id": "B", "role": "modbus_server", "services": []},
        ]
        edges = [{"source": "A", "target": "B"}]
        wag = build_weighted_attack_graph(nodes, edges)

        # Previous distance should be finite (snapshot was taken)
        d = wag.get_previous_distance("A")
        assert d != WEIGHT_INFINITE


# ══════════════════════════════════════════════════════════════════
# Test Suite 7: Integration test — end-to-end disbalance cycle
# ══════════════════════════════════════════════════════════════════


class TestEndToEnd:
    """Integration test simulating a full discovery → mutation → disbalance cycle."""

    def test_discovery_then_exploit_cycle(self):
        """Simulate:
        1. Build initial graph (3 nodes)
        2. Discovery adds a new node (Gateway)
        3. Exploitation compromises Gateway
        4. Verify cone of impact at each step
        """
        # Step 1: Initial topology
        nodes = [
            {"id": "Internet", "role": "external", "services": []},
            {"id": "Router", "role": "router", "services": [{"name": "ssh", "port": 22}]},
            {"id": "OT_PLC", "role": "modbus_server", "services": [{"name": "modbus", "port": 502}]},
        ]
        edges = [
            {"source": "Internet", "target": "Router"},
            {"source": "Router", "target": "OT_PLC"},
        ]
        wag = build_weighted_attack_graph(nodes, edges)
        assert wag.target_node == "OT_PLC"

        # Step 2: Discovery — add Gateway between Router and OT_PLC
        wag.add_node("Gateway", role="iot_gateway")
        wag.set_edge_weight("Router", "Gateway", 0.5)
        wag.set_edge_weight("Gateway", "OT_PLC", 0.4)

        affected_discovery = compute_graph_disbalance(wag, "Gateway")
        # Gateway should be affected (new path to OT)
        discovery_ids = {n["node"] for n in affected_discovery}

        # At minimum, Gateway should show up (it was unreachable in T-1, now reachable)
        # But it depends on whether there's a disbalance
        # Since Gateway was not in the original snapshot, its T-1 distance = inf
        # And now it has a path → Δ should be positive
        assert "Gateway" in discovery_ids

        # Update snapshot for next iteration
        wag.snapshot_distances()

        # Step 3: Exploitation — compromise Gateway
        # When a node is compromised, edges FROM it become cheaper
        # (attacker can use the compromised node freely as a pivot)
        wag.set_edge_weight("Gateway", "OT_PLC", 1.0)  # was 0.4, now 1.0 (trivial)

        affected_exploit = compute_graph_disbalance(wag, "Gateway")
        exploit_ids = {n["node"] for n in affected_exploit}

        # Gateway should be affected (its distance to OT dropped)
        assert "Gateway" in exploit_ids

        # Step 4: All deltas should be positive
        for node_info in affected_exploit:
            assert node_info["delta"] > 0

        # Step 5: Build report
        report = build_graph_delta_report(
            affected_exploit,
            [{"from": "Router", "to": "Gateway", "previous_weight": "0.5",
              "current_weight": "1.0", "status": "EXPLOITED"}],
            "ssh_login",
        )
        assert report["status"] == "success"
        assert report["mutation_detected"] is True
        assert len(report["graph_delta"]["nodes_affected"]) > 0
