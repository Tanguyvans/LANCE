import json

from src.benchmark.evaluator import evaluate
from src.benchmark.funnel import unique_predictions
from tests.test_evaluation_funnel import finding, write_run, confirmation, proof


def test_missing_metadata_duplicate_counts_once_without_borrowing_proof(tmp_path):
    a = finding("a", "192.0.2.1")
    b = {**a, "id": "b", "product": "nginx", "version": "1.22"}
    run, gt = write_run(tmp_path, [a, b], [a, b], [confirmation(a), confirmation(b)], records=[proof(b)])
    original = {p.name: p.read_bytes() for p in run.iterdir() if p.is_file()}
    evaluation = evaluate(run, gt, policy="strict-v3")
    for stage in evaluation.funnel["stages"].values():
        assert stage["predictions"] == 1
    assert evaluation.funnel["stages"]["confirmed"]["true_positives"] == 1
    d = evaluation.funnel["diagnostics"]
    assert d["verification_population"] == 2  # actual queue, not statistical groups
    assert d["deduplication"]["confirmed"]["removed"] == 1
    assert set(d["deduplication"]["confirmed"]["groups"][0]["source_ids"]) == {"a", "b"}
    assert d["claims"]["false_positive_count"] == 0
    assert set(d["claims"]["duplicate_sources"][0]["source_ids"]) == {"a", "b"}
    assert all((run / name).read_bytes() == content for name, content in original.items())


def test_equivalent_claims_cannot_collect_invalid_proofs_into_a_valid_one(tmp_path):
    a = finding("a", "192.0.2.1")
    b = {**a, "id": "b", "product": "nginx"}
    run, gt = write_run(tmp_path, [a, b], [a, b], [confirmation(a), confirmation(b)], records=[
        proof(a, result={"status_code": 200, "body": "Welcome"}),
        proof(b, args={"url": "http://192.0.2.99/backup.sql"}),
    ])
    stage = evaluate(run, gt, policy="strict-v3").funnel["stages"]["confirmed"]
    assert stage["predictions"] == stage["false_positives"] == 1
    assert stage["true_positives"] == 0


def test_partial_metadata_does_not_bridge_conflicting_versions():
    a = finding("a", "192.0.2.1")
    values = [a, {**a, "id": "b", "product": "nginx", "version": "1"},
              {**a, "id": "c", "product": "nginx", "version": "2"}]
    assert len(unique_predictions(values)) == 3


def test_integrated_diagnostics_distinguish_outside_reference_and_bad_proof(tmp_path):
    a = finding("a", "192.0.2.1")
    outside = finding("outside", "192.0.2.2")
    bad = finding("bad", "192.0.2.3")
    run, gt = write_run(tmp_path, [a, outside, bad], [a, outside, bad],
        [confirmation(f) for f in (a, outside, bad)], truth=[a], records=[
            proof(a), proof(outside), proof(bad, result={"status_code": 200, "body": "Welcome"}),
        ])
    result = evaluate(run, gt, policy="strict-v3")
    stage = result.funnel["stages"]["confirmed"]
    diagnostic = result.funnel["diagnostics"]["claims"]
    assert diagnostic["false_positive_count"] == stage["false_positives"] == 2
    assert diagnostic["counts"]["supported_outside_reference"] == 1
    assert diagnostic["counts"]["insufficient_evidence"] == 1
    assert diagnostic["counts"]["contradicted"] == 0
    assert stage["true_positives"] == 1
