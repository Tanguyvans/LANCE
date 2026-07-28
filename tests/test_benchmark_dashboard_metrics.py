from dataclasses import asdict
from pathlib import Path

from src.benchmark.evaluator import EvaluationResult


ROOT = Path(__file__).resolve().parents[1]


def test_evaluation_contract_contains_dashboard_quality_metrics():
    payload = asdict(
        EvaluationResult(
            scenario_id="15",
            run_dir="/tmp/run",
            ground_truth_file="/tmp/gt.yaml",
        )
    )

    expected = {
        "quality_adjusted_f1",
        "verified_f1",
        "exploitation_coverage",
        "phase4_completion_rate",
        "evidence_f1",
        "traceable_evidence_coverage",
        "evidence_faithfulness",
        "evidence_contradiction_rate",
        "quality_path_coverage",
        "verified_path_coverage",
        "mhr_1_credited",
        "mhr_1_verified",
        "cost_per_tp",
        "cost_per_expected_vulnerability",
        "turns_per_tp",
        "metric_contract_version",
        "run_metric_contract_version",
        "run_evidence_contract_version",
        "evidence_contract_compatible",
        "metrics_compatibility_reason",
    }

    assert expected <= payload.keys()


def test_benchmark_dashboard_renders_strict_v3_metric_groups():
    html = (ROOT / "src" / "static" / "index.html").read_text(encoding="utf-8")
    javascript = (ROOT / "src" / "static" / "app.js").read_text(encoding="utf-8")

    for heading in ("Q-F1/Spec", "Preuves", "Exploit.", "Chemins", "Effic."):
        assert heading in html

    for metric in (
        "quality_adjusted_f1",
        "evidence_f1",
        "traceable_evidence_coverage",
        "evidence_faithfulness",
        "exploitation_coverage",
        "phase4_completion_rate",
        "quality_path_coverage",
        "verified_path_coverage",
        "mhr_${depth}_credited",
        "cost_per_tp",
        "cost_per_expected_vulnerability",
        "turns_per_tp",
    ):
        assert metric in javascript

    assert "evidence_metrics_available" in javascript
    assert "evidence_contract_compatible" in javascript
    assert "metrics_compatibility_reason" in javascript
    assert "score_error" in javascript
    assert "Legacy" in javascript
    assert "Non comparable" in javascript
    assert "Score officiel" in javascript
    assert "m?.score_pct != null" in javascript
    assert "agg.avg_score_pct != null" in javascript
    assert "const totalPaths" in javascript
    assert "s?.is_zero_gt === true" in javascript
    assert "if (v == null) return null" in javascript
    assert "barMetric != null ? pct(barMetric)" in javascript


def test_benchmark_api_recomputes_public_scores_with_strict_v3():
    source = (ROOT / "src" / "api" / "routes" / "runs.py").read_text(
        encoding="utf-8"
    )

    benchmark_route = source[source.index('def get_benchmark():') : source.index(
        '@router.get("/{run_id}")'
    )]
    assert 'evaluate(d, gt_path, policy="strict-v3")' in benchmark_route
