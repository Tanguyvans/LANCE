"""Selection and disclosure tests for the public topology endpoint."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from src.api.routes.topology import _load_scenario, get_topology


@pytest.mark.parametrize(
    ("selector", "prefix", "expected_nodes"),
    [
        ("S1h", "s1h-", 4),
        ("4H", "s4h-", 8),
    ],
)
def test_public_hardened_variants_load_topology(selector, prefix, expected_nodes):
    topology = _load_scenario(selector)

    node_ids = {node["id"] for node in topology["nodes"]}
    assert len(node_ids) == expected_nodes
    assert all(node_id.startswith(prefix) for node_id in node_ids)
    assert topology["subnet"] == "192.168.100.0/24"
    assert set(topology) == {"nodes", "edges", "subnet", "subnets"}
    assert all(
        edge["source"] in node_ids and edge["target"] in node_ids
        for edge in topology["edges"]
    )


def test_public_test_topology_is_visible():
    topology = _load_scenario("20")

    node_ids = {node["id"] for node in topology["nodes"]}
    assert "s20-entry" in node_ids
    assert "s20-vault" in node_ids


def test_unknown_topology_returns_not_found():
    with pytest.raises(HTTPException) as exc:
        _load_scenario("does-not-exist")

    assert exc.value.status_code == 404


def test_empty_topology_mode_does_not_resolve_a_scenario():
    assert get_topology(scenario="20", empty=True) == {
        "nodes": [],
        "edges": [],
        "subnet": "",
    }
