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
        "funnel",
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
        "phase5_metrics_available",
        "phase5_target_coverage",
        "phase5_target_attempt_coverage",
        "phase5_compromise_rate",
        "phase5_hop_coverage",
        "phase5_pivot_success_rate",
        "phase5_chain_faithfulness",
        "phase5_target_coverage_by_depth",
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


def test_benchmark_dashboard_renders_one_funnel_without_legacy_score_duplicates():
    html = (ROOT / "src/static/index.html").read_text(encoding="utf-8")
    javascript = (ROOT / "src/static/app.js").read_text(encoding="utf-8")
    table = html[html.index('<table id="bm-table"'):html.index('</table>', html.index('<table id="bm-table"'))]
    renderer = javascript[javascript.index("function bmNumber("):javascript.index("// ── Modal")]
    for heading in ("1. Candidats", "2. Après filtrage", "3. Rapport final", "Coût et efficacité", "Diagnostic"):
        assert heading in table
    assert table.count("<th>") + table.count('<th scope="col">') == 9
    for legacy in ("quality_adjusted_f1", "evidence_f1", "weighted_score", "turns_per_tp", "cost_per_expected_vulnerability"):
        assert legacy not in renderer
    for metric in ("cost_per_valid_confirmation", "turns_per_valid_confirmation", "d.proofs",
                   "phase5_target_attempt_coverage", "phase5_pivot_success_rate", "phase5_hop_coverage"):
        assert metric in renderer
    for text in ("Acceptées", "Rejetées", "Manquantes ou non attribuables", "F1 final", "Spécificité",
                 "Avis LLM — diagnostic", "ni preuve d’exécution ni score officiel"):
        assert text in renderer
    assert "evidence_contract_compatible" in renderer
    assert "metrics_compatibility_reason" in renderer
    assert "renderFunnelDiagnostics(compatible ? s.funnel : null, s)" in renderer
    assert "score_error" in renderer
    assert '<details class="bm-funnel-diagnostics"><summary>' in renderer
    assert 'data-bm-run=' in renderer
    assert "button.dataset.bmRun" in renderer
    assert "barMetric" not in renderer
    assert "score(agg.avg_score_pct)" in javascript
    assert "metrics.macro_scenario_score_pct" in javascript


def test_benchmark_dashboard_requests_compact_paginated_results():
    html = (ROOT / "src" / "static" / "index.html").read_text(encoding="utf-8")
    javascript = (ROOT / "src" / "static" / "app.js").read_text(encoding="utf-8")

    assert 'id="bm-prev"' in html
    assert 'id="bm-next"' in html
    assert 'id="bm-page-info"' in html
    assert "const BM_PAGE_SIZE = 50" in javascript
    assert "compact: 'true'" in javascript
    assert "offset: String(_bmOffset)" in javascript
    assert "Array.isArray(page.items)" in javascript


def test_benchmark_api_evaluates_cache_misses_with_strict_v3():
    source = (ROOT / "src" / "api" / "routes" / "runs.py").read_text(
        encoding="utf-8"
    )

    cached_evaluator = source[
        source.index("def _evaluate_cached(") : source.index("def _compact_score(")
    ]
    assert 'evaluate(run_dir, ground_truth, policy="strict-v3")' in cached_evaluator
    assert "_benchmark_fingerprint" in cached_evaluator
