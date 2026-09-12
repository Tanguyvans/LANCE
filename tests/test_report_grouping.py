"""Unit tests for conservative, report-only finding grouping."""

from copy import deepcopy

from src.agent.phases.report.grouping import group_findings_for_report


def _finding(identifier="V1", **changes):
    finding = {
        "id": identifier,
        "device_ip": "192.0.2.10",
        "device_id": "broker-1",
        "type": "no_auth",
        "service": "mqtt",
        "port": 1883,
        "protocol": "tcp",
        "endpoint": "sensors/temperature/#",
        "product": "mosquitto",
        "version": "2.0",
        "details": "original detail",
        "severity": "HIGH",
        "evidence_refs": ["evidence-a"],
    }
    finding.update(changes)
    return finding


def _groups(findings):
    return [group["member_indices"] for group in group_findings_for_report(findings)]


def test_mqtt_aliases_group_and_ignore_narrative_fields():
    findings = [
        _finding("V1", product="mosquitto", details="first claim"),
        _finding(
            "V2",
            service="mqtt",
            product="",
            version="",
            details="completely different prose",
            severity="CRITICAL",
            evidence_refs=["other-ref"],
        ),
    ]

    assert _groups(findings) == [[0, 1]]
    assert group_findings_for_report(findings)[0]["possible_duplicate"] is True


def test_mqtt_ws_known_aliases_and_root_empty_slash_are_narrowly_equal():
    findings = [
        _finding("V1", type="network_exposure", service="websocket", port=9001, endpoint=""),
        _finding("V2", type="network_exposure", service="mqtt-websocket", port=9001, endpoint="/"),
    ]

    assert _groups(findings) == [[0, 1]]


def test_http_colon_variant_is_dropped_only_when_exact_resource_exists():
    findings = [
        _finding("V1", service="http", port=80, endpoint=["/admin", "/health", "/admin:"]),
        _finding("V2", service="http", port=80, endpoint=["/health", "/admin"]),
        _finding("V3", service="http", port=80, endpoint="/admin:"),
        _finding("V4", service="http", port=80, endpoint="/admin"),
    ]

    assert _groups(findings) == [[0, 1], [2], [3]]


def test_primary_and_plural_endpoint_fields_are_unioned():
    findings = [
        _finding("V1", service="http", port=80, endpoint="/primary", endpoints=["/secondary"]),
        _finding("V2", service="http", port=80, endpoint="/secondary"),
    ]
    assert _groups(findings) == [[0], [1]]


def test_valid_port_rejects_fractional_bool_and_nonfinite_float():
    findings = [
        _finding("V1", port=80),
        _finding("V2", port=80.5),
        _finding("V3", port=True),
        _finding("V4", port=float("nan")),
        _finding("V5", port=80.0),
    ]
    assert _groups(findings) == [[0, 4], [1], [2], [3]]


def test_endpoint_case_query_mqtt_topic_and_resources_are_preserved():
    base = _finding("V1", service="http", port=80, endpoint="/Admin?A=1")
    same = _finding("V2", service="http", port=80, endpoint="/Admin?A=1")
    different_query = _finding("V3", service="http", port=80, endpoint="/Admin?a=1")
    different_resource = _finding("V4", service="http", port=80, endpoint="/other")
    assert _groups([base, same, different_query, different_resource]) == [[0, 1], [2], [3]]

    mqtt_a = _finding("M1", endpoint="sensors/Temperature/#")
    mqtt_b = _finding("M2", endpoint="sensors/temperature/#")
    assert _groups([mqtt_a, mqtt_b]) == [[0], [1]]


def test_structural_mismatches_and_explicit_properties_stay_separate():
    base = _finding("V1")
    cases = [
        _finding("V2", port=1884),
        _finding("V3", device_ip="192.0.2.11"),
        _finding("V4", type="data_exposure"),
        _finding("V5", condition="authenticated"),
        _finding("V6", parameter="username"),
        _finding("V7", vector="network"),
        _finding("V8", claim="claim-b"),
        _finding("V9", cve_ids=["CVE-2024-0001"]),
        _finding("V10", endpoint="sensors/temperature/#", service="mqtt-ws"),
    ]
    assert _groups([base, *cases]) == [[0], [1], [2], [3], [4], [5], [6], [7], [8], [9]]


def test_explicit_conditions_parameters_vectors_and_claims_are_case_sensitive():
    base = _finding("V1", conditions="Authenticated", parameters="User", vector="Network", claim="Claim-A")
    assert _groups([
        base,
        _finding("V2", conditions="authenticated", parameters="User", vector="Network", claim="Claim-A"),
        _finding("V3", conditions="Authenticated", parameters="user", vector="Network", claim="Claim-A"),
        _finding("V4", conditions="Authenticated", parameters="User", vector="network", claim="Claim-A"),
        _finding("V5", conditions="Authenticated", parameters="User", vector="Network", claim="claim-a"),
    ]) == [[0], [1], [2], [3], [4]]


def test_only_cve_metadata_is_casefolded():
    findings = [
        _finding("V1", cve_ids=["CVE-2024-0001"]),
        _finding("V2", cves=["cve-2024-0001"]),
    ]
    assert _groups(findings) == [[0, 1]]


def test_conflicting_specific_product_or_version_does_not_merge():
    findings = [
        _finding("V1", product="mosquitto", version="2.0"),
        _finding("V2", product="mosquitto", version="2.1"),
        _finding("V3", product="other-broker", version="2.0"),
    ]
    assert _groups(findings) == [[0], [1], [2]]


def test_missing_metadata_is_not_a_transitive_bridge():
    findings = [
        _finding("A", product="broker-a", version="1"),
        _finding("U", product="", version=""),
        _finding("B", product="broker-b", version="1"),
    ]
    assert _groups(findings) == [[0], [1], [2]]

    unambiguous = [
        _finding("A", product="broker-a", version="1"),
        _finding("U", product="", version=""),
    ]
    assert _groups(unambiguous) == [[0, 1]]

    partial_unique = [
        _finding("A", product="nginx", version=""),
        _finding("U", product="", version=""),
    ]
    assert _groups(partial_unique) == [[0, 1]]

    partial_ambiguous = [
        _finding("A", product="nginx", version=""),
        _finding("U", product="", version=""),
        _finding("B", product="nginx", version="2"),
    ]
    assert _groups(partial_ambiguous) == [[0, 2], [1]]


def test_missing_structure_unknowns_and_ids_remain_traceable():
    findings = [
        _finding("V1", device_ip="", device_id=""),
        _finding(None, type=""),
        _finding("", port=0),
        _finding("V4", service=""),
        _finding("V5", endpoint="/same"),
        _finding("V6", endpoint="/same"),
    ]
    result = group_findings_for_report(findings)
    assert sorted(index for group in result for index in group["member_indices"]) == list(range(6))
    assert result[-1]["member_indices"] == [4, 5]
    assert result[0]["member_ids"] == ["V1"]
    assert result[1]["member_ids"] == []
    assert result[2]["member_ids"] == []
    assert result[3]["member_ids"] == ["V4"]


def test_literal_unknown_structural_values_are_not_grouped():
    findings = [
        _finding("V1", device_ip="unknown", device_id="unknown"),
        _finding("V2", type="unknown"),
        _finding("V3", service="unknown"),
    ]
    assert _groups(findings) == [[0], [1], [2]]


def test_group_ids_are_stable_and_input_is_immutable():
    findings = [_finding("V1"), _finding("V2", details="changed")]
    before = deepcopy(findings)
    first = group_findings_for_report(findings)
    second = group_findings_for_report(findings)
    assert first == second
    assert first[0]["group_id"] == "RG-0001"
    assert findings == before
