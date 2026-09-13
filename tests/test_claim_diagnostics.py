from copy import deepcopy

from src.benchmark.claim_diagnostics import build_claim_diagnostics


def finding(identifier, **overrides):
    result = {
        "id": identifier,
        "device_ip": "192.0.2.10",
        "service": "ssh",
        "port": 22,
        "type": "weak_cipher",
        "evidence_refs": [f"ref-{identifier}"],
    }
    result.update(overrides)
    return result


def matcher(ground_truth_by_type):
    def match(items):
        return {
            index: ground_truth_by_type[item.get("type")]
            for index, item in enumerate(items)
            if item.get("type") in ground_truth_by_type
        }
    return match


def test_counts_insufficient_outside_redundant_and_no_contradicted():
    credited = finding("credited", _evidence_supported=True, type="a")
    insufficient = finding("insufficient", _evidence_supported=False, type="missing")
    outside = finding("outside", _evidence_supported=True, type="b")
    redundant = finding("redundant", _evidence_supported=True, type="a")
    result = build_claim_diagnostics(
        [credited, insufficient, outside, redundant],
        {0: 10},
        matcher({"a": 10}),
    )

    assert result["available"] is True
    assert result["false_positive_count"] == 3
    assert result["counts"] == {
        "insufficient_evidence": 1,
        "supported_outside_reference": 1,
        "redundant_reference_claim": 1,
        "reference_assignment_conflict": 0,
        "contradicted": 0,
    }
    assert [(claim["id"], claim["category"]) for claim in result["claims"]] == [
        ("insufficient", "insufficient_evidence"),
        ("outside", "supported_outside_reference"),
        ("redundant", "redundant_reference_claim"),
    ]


def test_supported_claim_matching_already_credited_gt_is_redundant():
    result = build_claim_diagnostics(
        [
            finding("credited", _evidence_supported=True, type="known"),
            finding("copy", _evidence_supported=True, type="known"),
        ],
        {0: 3},
        matcher({"known": 3}),
    )

    assert result["claims"][0]["category"] == "redundant_reference_claim"
    assert result["counts"]["redundant_reference_claim"] == 1


def test_singleton_match_to_uncredited_gt_is_assignment_conflict():
    result = build_claim_diagnostics(
        [
            finding("credited", _evidence_supported=True, type="known"),
            finding("conflict", _evidence_supported=True, type="conflict"),
        ],
        {0: 3},
        matcher({"known": 3, "conflict": 8}),
    )

    assert result["claims"][0]["category"] == "reference_assignment_conflict"
    assert result["false_positive_count"] == 1
    assert result["counts"]["reference_assignment_conflict"] == 1
    assert result["counts"]["supported_outside_reference"] == 0


def test_model_confirmed_without_trusted_boolean_is_insufficient():
    result = build_claim_diagnostics(
        [finding("model", status="CONFIRMED", type="not-matched")],
        {},
        matcher({}),
    )

    assert result["false_positive_count"] == 1
    assert result["claims"][0]["category"] == "insufficient_evidence"
    assert result["counts"]["contradicted"] == 0


def test_failed_or_unmatched_checks_never_create_contradicted():
    calls = []

    def failed_match(items):
        calls.append(items)
        return {}

    result = build_claim_diagnostics(
        [finding("failed", _evidence_supported=True)],
        {},
        failed_match,
    )

    assert calls
    assert result["claims"][0]["category"] == "supported_outside_reference"
    assert result["counts"]["contradicted"] == 0


def test_duplicate_sources_are_separate_from_false_positive_count():
    first = finding("canonical", _evidence_supported=True, type="outside")
    first["_dedup_members"] = [
        finding("source-1", evidence_ref="tool-1", evidence_refs=[]),
        finding("source-2", evidence_refs=["tool-2", "tool-1"]),
    ]
    result = build_claim_diagnostics(
        [first],
        {},
        matcher({}),
    )

    assert result["false_positive_count"] == 1
    assert result["counts"]["supported_outside_reference"] == 1
    assert result["duplicate_sources"] == [{
        "source_ids": ["source-1", "source-2"],
        "evidence_refs": ["tool-1", "tool-2"],
    }]


def test_no_text_from_tools_is_leaked_and_refs_are_normalized():
    claim = finding(
        "claim",
        _evidence_supported=True,
        evidence_ref=" ref-a ",
        evidence_refs=["ref-a", " ref-b ", ""],
        output="secret tool output must not appear",
    )
    result = build_claim_diagnostics([claim], {}, matcher({}))

    assert result["claims"][0]["evidence_refs"] == ["ref-a", "ref-b"]
    assert "secret tool output must not appear" not in repr(result)


def test_non_string_refs_and_source_ids_are_ignored():
    claim = finding("claim", evidence_refs=[{"secret": "tool output"}, 42, " ref-a "])
    claim["_dedup_members"] = [
        {"id": {"not": "a source"}, "evidence_refs": [{"secret": "output"}, "ref-1"]},
        {"id": "source-2", "evidence_refs": [None, "ref-2"]},
    ]

    result = build_claim_diagnostics([claim], {}, matcher({}))

    assert result["claims"][0]["evidence_refs"] == ["ref-a"]
    assert result["duplicate_sources"] == [{
        "source_ids": ["source-2"],
        "evidence_refs": ["ref-1", "ref-2"],
    }]


def test_final_matches_are_one_to_one_credit_and_do_not_add_true_positives():
    credited = finding("credited", _evidence_supported=True, type="known")
    outside = finding("outside", _evidence_supported=True, type="other")
    result = build_claim_diagnostics(
        [credited, outside],
        {0: 7},
        matcher({"known": 7, "other": 8}),
    )

    assert [claim["id"] for claim in result["claims"]] == ["outside"]
    assert result["false_positive_count"] == 1
    assert 7 not in [claim.get("true_positive") for claim in result["claims"]]


def test_pure_deterministic_and_non_mutating():
    items = [
        finding("b", _evidence_supported=True, type="b"),
        finding("a", _evidence_supported=False, type="a"),
    ]
    snapshot = deepcopy(items)
    calls = []

    def match(values):
        calls.append([item["id"] for item in values])
        return {}

    first = build_claim_diagnostics(items, {}, match)
    second = build_claim_diagnostics(items, {}, match)

    assert first == second
    assert items == snapshot
    assert calls == [["b"], ["b"]]


def test_preverification_deduplication_provenance_remains_visible():
    item = finding("canonical", _evidence_supported=True, _provenance={
        "candidate_ids": ["C1", "C2"], "evidence_refs": ["r1", "r2"],
    })
    result = build_claim_diagnostics([item], {0: 0}, matcher({"weak_cipher": 0}))
    assert result["false_positive_count"] == 0
    assert result["duplicate_sources"] == [{"source_ids": ["C1", "C2"], "evidence_refs": ["r1", "r2"]}]
