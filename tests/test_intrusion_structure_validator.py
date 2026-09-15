"""Tests for the structural Phase 5 intrusion deliverable validator."""
import json

import pytest

from src.agent.validators import VALIDATORS, validate_json_intrusion


@pytest.fixture(autouse=True)
def clean_output(tmp_path):
    return tmp_path


def write_json(output_dir, payload, filename="intrusion.json"):
    path = output_dir / filename
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        path.write_text(json.dumps(payload), encoding="utf-8")
    return validate_json_intrusion(filename, output_dir=output_dir)


def zero_access():
    return {
        "summary": {
            "devices_compromised": 0,
            "devices_attempted": 0,
            "credentials_harvested": 0,
            "total_hops": 0,
            "crown_jewels_reached": [],
        },
        "credential_pool": [],
        "compromised_devices": [],
        "chains": [],
    }


def direct_single_hop():
    return {
        "summary": {
            "devices_compromised": 1,
            "devices_attempted": 1,
            "credentials_harvested": 0,
            "total_hops": 0,
            "crown_jewels_reached": ["device-a"],
        },
        "credential_pool": [{
            "user": "",
            "password": "",
            "service": "ssh",
            "source_ip": "",
            "source_device": "",
        }],
        "compromised_devices": [{
            "device_id": "device-a",
            "device_ip": "192.0.2.10",
            "access_method": "try_credential:ssh:anonymous",
            "access_via": "entry_point",
            "data_exfiltrated": "",
            "credentials_found": [],
        }],
        "chains": [{
            "id": "chain-1",
            "hops": [{
                "hop_index": 1,
                "device_id": "device-a",
                "device_ip": "192.0.2.10",
                "access_method": "try_credential:ssh:anonymous",
                "commands_run": [],
                "output_summary": "direct access",
                "pivot_to": None,
            }],
            "crown_jewel_reached": "device-a",
        }],
    }


def test_registry_contains_intrusion_validator():
    assert VALIDATORS["json_intrusion"] is validate_json_intrusion


def test_accepts_zero_access_and_direct_single_hop(clean_output):
    assert write_json(clean_output, zero_access()) == (True, "OK")
    assert write_json(clean_output, direct_single_hop()) == (True, "OK")


def test_counts_independent_chains_as_transitions_not_connections(clean_output):
    data = direct_single_hop()
    data["summary"]["devices_compromised"] = 2
    data["summary"]["devices_attempted"] = 2
    data["summary"]["crown_jewels_reached"] = []
    data["compromised_devices"].append({
        "device_id": "device-b",
        "device_ip": "192.0.2.11",
        "access_method": "ssh_exec:pivot",
        "access_via": "192.0.2.10",
        "data_exfiltrated": "",
        "credentials_found": [],
    })
    data["chains"].append({
        "id": "chain-2",
        "hops": [{
            "hop_index": 1,
            "device_id": "device-b",
            "device_ip": "192.0.2.11",
            "access_method": "ssh_exec:pivot",
            "commands_run": ["id"],
            "output_summary": "",
            "pivot_to": None,
        }],
        "crown_jewel_reached": None,
    })
    assert write_json(clean_output, data) == (True, "OK")


@pytest.mark.parametrize("raw", ["not json", "{}", "[]", "null", "true", "7", '"text"'])
def test_rejects_malformed_or_non_object_roots(clean_output, raw):
    ok, message = write_json(clean_output, raw)
    assert not ok
    assert "structure" in message or "JSON" in message


@pytest.mark.parametrize(
    "field,value",
    [
        ("devices_compromised", True),
        ("devices_attempted", 1.0),
        ("credentials_harvested", -1),
        ("total_hops", float("nan")),
    ],
)
def test_rejects_invalid_summary_counters(clean_output, field, value):
    data = zero_access()
    data["summary"][field] = value
    ok, message = write_json(clean_output, data)
    assert not ok
    assert f"summary.{field}" in message or "valid JSON" in message


@pytest.mark.parametrize("status", ["incomplete", "failed", "blocked", "stopped", "draft", None])
def test_rejects_incomplete_nested_completion(clean_output, status):
    data = zero_access()
    data["status"] = "completed"
    data["completion"] = {"status": status}
    ok, message = write_json(clean_output, data)
    assert not ok
    assert "completion.status" in message


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_rejects_nonstandard_json_in_extra_fields(clean_output, constant):
    raw = json.dumps(zero_access())[:-1] + ', "extra": ' + constant + '}'
    assert write_json(clean_output, raw)[0] is False


def test_rejects_missing_keys_and_invalid_summary_list(clean_output):
    data = zero_access()
    del data["credential_pool"]
    ok, message = write_json(clean_output, data)
    assert not ok
    assert "structure" in message

    data = zero_access()
    data["summary"]["crown_jewels_reached"] = ["", 4]
    ok, message = write_json(clean_output, data)
    assert not ok
    assert "crown_jewels_reached" in message


def test_rejects_invalid_device_items_and_duplicate_device_ids(clean_output):
    data = direct_single_hop()
    data["compromised_devices"][0]["credentials_found"] = ["not an object"]
    ok, message = write_json(clean_output, data)
    assert not ok
    assert "credentials_found" in message

    data = direct_single_hop()
    data["summary"]["devices_compromised"] = 2
    data["summary"]["devices_attempted"] = 2
    data["compromised_devices"].append(dict(data["compromised_devices"][0]))
    ok, message = write_json(clean_output, data)
    assert not ok
    assert "device_id" in message


def test_rejects_invalid_credential_pool_items(clean_output):
    data = zero_access()
    data["credential_pool"] = [{
        "user": "anonymous",
        "password": "",
        "service": "",
        "source_ip": 10,
        "source_device": "device-a",
    }]
    ok, message = write_json(clean_output, data)
    assert not ok
    assert "credential_pool[0]" in message


@pytest.mark.parametrize(
    "mutate",
    [
        lambda data: data["chains"][0]["id"].__class__,
        lambda data: data["chains"][0]["hops"].append({}),
    ],
)
def test_rejects_invalid_chain_items(clean_output, mutate):
    data = direct_single_hop()
    if mutate(data) is str:
        data["chains"][0]["id"] = ""
    ok, _ = write_json(clean_output, data)
    assert not ok


@pytest.mark.parametrize(
    "field,value",
    [
        ("hop_index", 0),
        ("hop_index", 2),
        ("device_id", ""),
        ("commands_run", ["id", 3]),
        ("output_summary", None),
        ("pivot_to", ""),
        ("pivot_to", 4),
        ("crown_jewel_reached", 4),
    ],
)
def test_rejects_invalid_hop_and_chain_fields(clean_output, field, value):
    data = direct_single_hop()
    if field == "crown_jewel_reached":
        data["chains"][0][field] = value
    else:
        data["chains"][0]["hops"][0][field] = value
    ok, message = write_json(clean_output, data)
    assert not ok
    assert field in message


def test_rejects_count_mismatches(clean_output):
    data = direct_single_hop()
    data["summary"]["devices_compromised"] = 0
    ok, message = write_json(clean_output, data)
    assert not ok
    assert "devices_compromised" in message

    data = direct_single_hop()
    data["summary"]["devices_attempted"] = 0
    ok, message = write_json(clean_output, data)
    assert not ok
    assert "devices_attempted" in message

    data = direct_single_hop()
    data["chains"][0]["hops"].append({
        "hop_index": 2,
        "device_id": "device-b",
        "device_ip": "192.0.2.11",
        "access_method": "ssh",
        "commands_run": [],
        "output_summary": "",
        "pivot_to": None,
    })
    ok, message = write_json(clean_output, data)
    assert not ok
    assert "total_hops" in message


@pytest.mark.parametrize("status", ["incomplete", "partial", "failed", "error", "draft", "raw_non_validated"])
def test_rejects_non_promotable_statuses(clean_output, status):
    data = zero_access()
    data["status"] = status
    ok, message = write_json(clean_output, data)
    assert not ok
    assert "status" in message


def test_errors_do_not_echo_payload_identifiers(clean_output):
    data = direct_single_hop()
    data["chains"][0]["id"] = "SUPER-SECRET-CHAIN-ID"
    data["chains"].append(dict(data["chains"][0]))
    ok, message = write_json(clean_output, data)
    assert not ok
    assert "SUPER-SECRET-CHAIN-ID" not in message
