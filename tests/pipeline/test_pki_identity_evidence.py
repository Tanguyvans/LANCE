"""Cross-device PKI evidence from synthetic scan files; no network calls."""
from dataclasses import replace
import json

import pytest

from src.agent.phases.analysis.aggregation import aggregate
from src.agent.phases.analysis.aggregation_context import AggregationContext


def observation(ip, fingerprint="a" * 64, **result_changes):
    url = f"http://{ip}:8080/identity/fingerprint"
    result = {
        "status_code": 200, "final_url": url,
        "body": json.dumps({"public_key_fingerprint": fingerprint}),
    }
    result.update(result_changes)
    return {"tool": "http_request", "kwargs": {"url": url}, "result": json.dumps(result)}


@pytest.fixture
def context(tmp_path):
    nodes = [
        {"id": "device-a", "ip": "192.0.2.15", "role": "pki_device"},
        {"id": "device-b", "ip": "192.0.2.16", "role": "pki_device"},
    ]
    (tmp_path / "03_scans").mkdir()
    return AggregationContext(run_dir=tmp_path, surface_nodes=nodes)


def write_scan(context, device_id, entries):
    (context.run_dir / "03_scans" / f"{device_id}.json").write_text(
        json.dumps({"http": entries}), encoding="utf-8",
    )


def pki_candidates(context):
    return [
        row["raw_finding"] for row in aggregate(context).raw["candidates"]
        if row["source_file"] == "03_scans/cross_device_pki.json"
    ]


@pytest.mark.parametrize("duplicate", ["requests", "node", "alias"])
def test_one_device_cannot_prove_shared_keys(context, duplicate):
    node = context.surface_nodes[0]
    entry = observation(node["ip"])
    write_scan(context, node["id"], [entry, entry] if duplicate == "requests" else [entry])
    nodes = [node]
    if duplicate == "node":
        nodes.append(dict(node))
    elif duplicate == "alias":
        alias = {**node, "id": "device-alias"}
        nodes.append(alias)
        write_scan(context, alias["id"], [entry])
    assert pki_candidates(replace(context, surface_nodes=nodes)) == []


def test_matching_keys_on_distinct_devices_count_devices_not_requests(context):
    for node in context.surface_nodes:
        entry = observation(node["ip"], "A" * 64)
        write_scan(context, node["id"], [entry, entry])
    candidates = pki_candidates(context)
    assert len(candidates) == 1
    assert candidates[0]["device_id"] == "device-b"
    assert "for 2 devices" in candidates[0]["evidence"]


@pytest.mark.parametrize("changes", [
    {"status_code": 403}, {"status_code": 500}, {"status_code": None},
    {"body": "[]"}, {"body": "null"}, {"body": "invalid"},
    {"final_url": "http://192.0.2.15:8080/identity/fingerprint"},
    {"error": "request failed"},
], ids=["denied", "server-error", "missing-status", "list", "null", "invalid-json", "other-device", "error"])
def test_invalid_second_observation_never_confirms_shared_keys(context, changes):
    write_scan(context, "device-a", [observation("192.0.2.15")])
    write_scan(context, "device-b", [observation("192.0.2.16", **changes)])
    assert pki_candidates(context) == []


def test_scan_filename_does_not_attest_a_different_requested_host(context):
    for node in context.surface_nodes:
        write_scan(context, node["id"], [observation("192.0.2.15")])
    assert pki_candidates(context) == []


@pytest.mark.parametrize("malformed", [None, 42, [], {"tool": "http_request", "kwargs": []}])
def test_malformed_entry_does_not_discard_valid_neighbor(context, malformed):
    for node in context.surface_nodes:
        write_scan(context, node["id"], [malformed, observation(node["ip"])])
    assert len(pki_candidates(context)) == 1


def test_different_public_keys_are_a_negative_control(context):
    write_scan(context, "device-a", [observation("192.0.2.15")])
    write_scan(context, "device-b", [observation("192.0.2.16", "b" * 64)])
    assert pki_candidates(context) == []
