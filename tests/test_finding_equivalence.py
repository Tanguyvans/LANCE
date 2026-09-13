from src.agent.finding_identity import (
    finding_identity_key,
    group_equivalent_findings,
)


def finding(name, **overrides):
    result = {
        "id": name,
        "type": "weak_cipher",
        "device_ip": "192.0.2.10",
        "service": "ssh",
        "port": 22,
        "protocol": "tcp",
        "endpoint": "/ssh",
        "product": "Acme",
        "version": "1.0",
        "condition": "cipher negotiation",
        "cve_ids": ["CVE-2024-0001"],
        "evidence_ref": f"ref-{name}",
    }
    result.update(overrides)
    return result


def ids(groups):
    return {frozenset(item["id"] for item in group) for group in groups}


def test_exact_duplicates_group_and_metadata_missing_joins_unique_anchor():
    a = finding("a", product="Acme", version="1.0")
    duplicate = finding("a2", product="Acme", version="1.0")
    missing = finding("missing", product="", version="")

    assert ids(group_equivalent_findings([missing, duplicate, a])) == {
        frozenset({"a", "a2", "missing"}),
    }


def test_missing_bucket_does_not_bridge_conflicting_maxima():
    a = finding("a", product="x", version="1")
    b = finding("b", product="", version="")
    c = finding("c", product="y", version="1")

    assert ids(group_equivalent_findings([a, b, c])) == {
        frozenset({"a"}), frozenset({"b"}), frozenset({"c"}),
    }


def test_partial_metadata_does_not_infer_a_product_version_combination():
    a = finding("a", product="x", version="")
    b = finding("b", product="", version="1")

    assert ids(group_equivalent_findings([a, b])) == {
        frozenset({"a"}), frozenset({"b"}),
    }


def test_more_specific_bucket_dominates_less_specific_bucket():
    specific = finding("specific", product="x", version="1")
    product_only = finding("product-only", product="x", version="")
    empty = finding("empty", product="", version="")

    assert ids(group_equivalent_findings([empty, product_only, specific])) == {
        frozenset({"empty", "product-only", "specific"}),
    }


def test_strict_identity_fields_prevent_grouping():
    base = finding("base")
    variants = [
        finding("endpoint", endpoint="/other"),
        finding("cve", cve_ids=["CVE-2024-0002"]),
        finding("condition", condition="different"),
        finding("service", service="https"),
        finding("port", port=2222),
        finding("protocol", protocol="udp"),
    ]

    assert all(len(group) == 1 for group in group_equivalent_findings([base, *variants]))


def test_product_version_conflicts_do_not_group_when_both_are_specific():
    left = finding("left", product="x", version="1")
    right = finding("right", product="y", version="2")

    assert ids(group_equivalent_findings([right, left])) == {
        frozenset({"left"}), frozenset({"right"}),
    }


def test_unidentifiable_findings_are_never_deduplicated():
    missing_target_1 = finding("target-1", device_ip="")
    missing_target_2 = finding("target-2", device_ip="")
    missing_type_1 = finding("type-1", type="")
    missing_type_2 = finding("type-2", type="")

    result = group_equivalent_findings([
        missing_type_2, missing_target_1, missing_type_1, missing_target_2,
    ])
    assert len(result) == 4
    assert all(len(group) == 1 for group in result)


def test_order_is_deterministic_and_inputs_are_not_mutated():
    findings = [
        finding("z", product="x", version="1", evidence_ref="z-ref"),
        finding("a", product="", version="", evidence_ref="a-ref"),
        finding("b", product="x", version="1", evidence_ref="b-ref"),
    ]
    before = [dict(item) for item in findings]

    first = group_equivalent_findings(findings)
    second = group_equivalent_findings(list(reversed(findings)))

    assert ids(first) == ids(second) == {frozenset({"a", "b", "z"})}
    assert [item["id"] for item in first[0]] == ["a", "b", "z"]
    assert findings == before
    assert all(item["evidence_ref"] in {"a-ref", "b-ref", "z-ref"} for item in first[0])


def test_finding_identity_key_is_unchanged_and_metadata_only_is_ignored_in_base():
    left = finding("left", product="x", version="1")
    right = finding("right", product="y", version="2")

    assert finding_identity_key(left)[0:6] == finding_identity_key(right)[0:6]
    assert finding_identity_key(left)[8:] == finding_identity_key(right)[8:]
