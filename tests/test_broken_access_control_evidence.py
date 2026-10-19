"""Proof contract for broken access control claims (IDOR, scope, mass assignment)."""
import json

import pytest

from src.agent.exploit_evidence import synthesize_exploit_result
from src.benchmark.evaluator import (
    _semantic_output_supports_finding,
    _semantic_records_support_finding,
)


def finding(endpoint, vuln_type="broken_access_control", **overrides):
    value = {
        "id": "VULN-1", "device_id": "api", "device_ip": "192.0.2.10",
        "type": vuln_type, "severity": "HIGH", "service": "http",
        "port": 8080, "protocol": "tcp", "endpoint": endpoint,
        "details": "Authorization bypass",
    }
    value.update(overrides)
    return value


def http_call(url, *, method=None, body=None, credential="Bearer tenant-a-read",
              status=200, response=None, tool="http_request"):
    args = {"url": url, "headers": {"Authorization": credential}}
    if method:
        args["method"] = method
    if body is not None:
        args["body"] = json.dumps(body)
    return {
        "tool": tool,
        "args": args,
        "result": {
            "status_code": status,
            "method": method or "GET",
            "final_url": url,
            "body": json.dumps(response if response is not None else {}),
            "redirect_chain": [],
        },
    }


def serialize(record):
    """Match the archived tool_calls.jsonl shape (JSON result string)."""
    return {**record, "result": json.dumps(record["result"])}


def test_idor_requires_a_foreign_owner_bound_to_the_requested_object():
    vuln = finding("/v1/devices/device-b")
    record = http_call(
        "http://192.0.2.10:8080/v1/devices/device-b",
        response={"id": "device-b", "owner_id": "tenant-b", "role": "sensor"},
    )
    proof = synthesize_exploit_result(vuln, [record])
    assert proof["status"] == "EXPLOITED"
    assert proof["evidence_level"] == 3
    assert "tenant-b" in proof["evidence"]


@pytest.mark.parametrize("response,credential,url", [
    # The returned owner is the caller's own principal.
    ({"id": "device-a", "owner_id": "tenant-a"}, "Bearer tenant-a-read", "http://192.0.2.10:8080/v1/devices/device-a"),
    # Opaque credential shares no namespace with the returned owner.
    ({"id": "device-b", "owner_id": "tenant-b"}, "Bearer 9f2c81", "http://192.0.2.10:8080/v1/devices/device-b"),
    # The body does not identify the object named in the request path.
    ({"id": "device-c", "owner_id": "tenant-b"}, "Bearer tenant-a-read", "http://192.0.2.10:8080/v1/devices/device-b"),
    # No owner identity is returned.
    ({"id": "device-b", "role": "sensor"}, "Bearer tenant-a-read", "http://192.0.2.10:8080/v1/devices/device-b"),
])
def test_idor_rejects_same_principal_unbound_or_opaque_cases(response, credential, url):
    object_id = url.rstrip("/").rsplit("/", 1)[-1]
    record = http_call(url, credential=credential, response=response)
    proof = synthesize_exploit_result(finding(f"/v1/devices/{object_id}"), [record])
    assert proof["status"] == "FAILED"


def test_idor_is_not_credited_on_a_non_primary_endpoint():
    vuln = finding("/v1/devices/device-b")
    record = http_call(
        "http://192.0.2.10:8080/v1/devices/device-c",
        response={"id": "device-c", "owner_id": "tenant-b"},
    )
    proof = synthesize_exploit_result(vuln, [record])
    assert proof["status"] != "EXPLOITED"


def test_scope_bypass_requires_a_read_only_credential_on_an_admin_route():
    vuln = finding("/v1/admin/export")
    record = http_call(
        "http://192.0.2.10:8080/v1/admin/export",
        response={"devices": ["device-a", "device-b"], "tenants": ["tenant-a", "tenant-b"]},
    )
    proof = synthesize_exploit_result(vuln, [record])
    assert proof["status"] == "EXPLOITED"
    assert proof["evidence_level"] == 3


@pytest.mark.parametrize("credential,url,response", [
    # A write-scoped credential is not a scope bypass.
    ("Bearer tenant-a-write", "http://192.0.2.10:8080/v1/admin/export", {"tenants": ["tenant-a", "tenant-b"]}),
    # No administrative route.
    ("Bearer tenant-a-read", "http://192.0.2.10:8080/v1/devices/device-a", {"tenants": ["tenant-a", "tenant-b"]}),
    # No multi-principal collection in the response.
    ("Bearer tenant-a-read", "http://192.0.2.10:8080/v1/admin/export", {"devices": ["device-a"]}),
])
def test_scope_bypass_rejects_non_read_only_non_admin_and_single_principal(
    credential, url, response,
):
    endpoint = url.split("8080", 1)[1]
    record = http_call(url, credential=credential, response=response)
    proof = synthesize_exploit_result(finding(endpoint), [record])
    assert proof["status"] == "FAILED"


def test_mass_assignment_acknowledged_in_the_write_response():
    vuln = finding("/v1/devices/device-a")
    record = http_call(
        "http://192.0.2.10:8080/v1/devices/device-a", method="PATCH",
        body={"role": "admin"},
        response={"id": "device-a", "role": "admin", "updated": ["role"]},
    )
    proof = synthesize_exploit_result(vuln, [record])
    assert proof["status"] == "EXPLOITED"
    assert proof["evidence_level"] == 2
    assert "role" in proof["evidence"]


def test_mass_assignment_persisted_through_a_later_read_back():
    vuln = finding("/v1/devices/device-a")
    patch = http_call(
        "http://192.0.2.10:8080/v1/devices/device-a", method="PATCH",
        body={"role": "admin"},
        response={"id": "device-a", "updated": ["role"]},
    )
    read_back = http_call(
        "http://192.0.2.10:8080/v1/devices/device-a",
        response={"id": "device-a", "owner_id": "tenant-a", "role": "admin"},
    )
    proof = synthesize_exploit_result(vuln, [patch, read_back])
    assert proof["status"] == "EXPLOITED"
    assert proof["evidence_level"] == 3
    assert "subsequent authenticated GET" in proof["evidence"]


@pytest.mark.parametrize("record", [
    # The credential is not explicitly read-only.
    http_call(
        "http://192.0.2.10:8080/v1/devices/device-a", method="PATCH",
        body={"role": "admin"}, credential="Bearer tenant-a-write",
        response={"id": "device-a", "role": "admin", "updated": ["role"]},
    ),
    # The submitted field is not server-controlled.
    http_call(
        "http://192.0.2.10:8080/v1/devices/device-a", method="PATCH",
        body={"label": "room-1"},
        response={"id": "device-a", "label": "room-1", "updated": ["label"]},
    ),
    # A read alone does not prove a write.
    http_call(
        "http://192.0.2.10:8080/v1/devices/device-a",
        response={"id": "device-a", "owner_id": "tenant-a", "role": "admin"},
    ),
])
def test_mass_assignment_rejects_unprivileged_or_unproven_writes(record):
    proof = synthesize_exploit_result(finding("/v1/devices/device-a"), [record])
    assert proof["status"] == "FAILED"


def test_mass_assignment_does_not_borrow_a_read_back_from_another_credential():
    vuln = finding("/v1/devices/device-a")
    patch = http_call(
        "http://192.0.2.10:8080/v1/devices/device-a", method="PATCH",
        body={"role": "admin"},
        response={"id": "device-a", "updated": ["role"]},
    )
    read_back = http_call(
        "http://192.0.2.10:8080/v1/devices/device-a",
        credential="Bearer tenant-a-write",
        response={"id": "device-a", "role": "admin"},
    )
    assert _persistence_proof(vuln, [patch, read_back]) is None


def _persistence_proof(vuln, records):
    from src.agent.exploit_evidence import _persisted_mass_assignment_confirmation
    return _persisted_mass_assignment_confirmation(vuln, records)


def test_evaluator_correlates_write_and_read_back_for_one_finding():
    vuln = finding("/v1/devices/device-a")
    patch = serialize(http_call(
        "http://192.0.2.10:8080/v1/devices/device-a", method="PATCH",
        body={"role": "admin"},
        response={"id": "device-a"},
    ))
    read_back = serialize(http_call(
        "http://192.0.2.10:8080/v1/devices/device-a",
        response={"id": "device-a", "owner_id": "tenant-a", "role": "admin"},
    ))
    assert not _semantic_output_supports_finding(
        "http_request", json.loads(patch["result"]), vuln, args=patch["args"],
    )
    assert not _semantic_output_supports_finding(
        "http_request", json.loads(read_back["result"]), vuln, args=read_back["args"],
    )
    assert _semantic_records_support_finding(vuln, [patch, read_back])


def test_evaluator_grouped_proof_requires_the_write_and_the_read_back():
    vuln = finding("/v1/devices/device-a")
    patch = serialize(http_call(
        "http://192.0.2.10:8080/v1/devices/device-a", method="PATCH",
        body={"role": "admin"},
        response={"id": "device-a"},
    ))
    assert not _semantic_records_support_finding(vuln, [patch])
    assert not _semantic_records_support_finding(vuln, [])
