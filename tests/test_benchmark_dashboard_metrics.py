from dataclasses import asdict
import json
import shutil
import subprocess
from pathlib import Path

import pytest

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
    for heading in ("1. Pistes détectées", "2. Pistes retenues", "3. Confirmations finales", "Consommation", "Vérification"):
        assert heading in table
    assert "Pistes = prédictions" in table
    assert "Pred = prédictions" not in table
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


def test_benchmark_dashboard_behavioral_rendering_via_node_vm():
    """Exercise the real table renderer with representative API payloads."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js unavailable; dashboard VM test skipped")
    javascript = (ROOT / "src/static/app.js").read_text(encoding="utf-8")
    start = javascript.index("function bmFiniteNumber(")
    end = javascript.index("// ── Modal", start)
    script = r'''
const vm = require('vm');
const assert = require('assert');
const source = __BENCHMARK_RENDERER_SOURCE__;
const elements = {};
for (const id of ['bm-filter-scenario', 'bm-filter-model', 'bm-tbody']) {
  elements[id] = {value: '', innerHTML: '', querySelectorAll: () => []};
}
const context = {
  console,
  escapeHtml: value => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;'),
  isSealedRun: run => run.sealed === true,
  document: {
    getElementById: id => elements[id],
  },
};
vm.createContext(context);
vm.runInContext(source, context);
const stage = {available: true, predictions: 2, true_positives: 1,
  false_positives: 1, false_negatives: 0, precision: .5, recall: .5, f1: .5};
const unavailable = {available: false, reason: 'Ancien contrat'};
const funnel = {stages: {candidates: stage, filtered: {...stage, predictions: 4}, confirmed: stage}, diagnostics: {
  verification: {confirmed: 2, inconclusive: 1, error: 0, not_tested: 1},
  verification_attempt_rate: .75,
  true_candidates_lost_in_filter: 1,
}};
const score = {funnel, evidence_contract_compatible: true, is_zero_gt: false,
  scenario_score_pct: 50, specificity: null, total_tokens: 0, total_cost_usd: 0,
  cost_is_estimate: false, process_metrics_available: false};
const row = {id: 'run_<safe>', scenario: 'S1', model: '<model>', status: 'done',
  cost: 0, score};
context._bmData = [row];
context.renderBenchmarkTable();
let html = elements['bm-tbody'].innerHTML;
assert(html.includes('Pistes <strong>2</strong>'));
assert(html.includes('VP 1 · FP 1 · FN 0'));
assert(html.includes('3/4 pistes testées'));
assert(html.includes('indéterminées 1'));
assert(html.includes('Vraies pistes perdues au filtrage : 1'));
assert(html.includes('Coût $0'));
assert(html.includes('Tokens 0'));
assert(html.includes('&lt;model&gt;'));
assert(!html.includes('<model>'));
assert((html.match(/bm-final-metrics/g) || []).length === 1);
assert(html.includes('<strong>F1 final 50 %</strong>'));

elements['bm-tbody'].innerHTML = '';
context._bmData = [{...row, id: 'legacy', score: {
  ...score, evidence_contract_compatible: false, metrics_compatibility_reason: 'legacy',
  funnel: {diagnostics: {verification: {confirmed: 0, inconclusive: 0, error: 0, not_tested: 0}},
    stages: {candidates: unavailable, filtered: unavailable, confirmed: unavailable}},
  total_tokens: 12, total_cost_usd: null,
}, cost: undefined}];
context.renderBenchmarkTable();
html = elements['bm-tbody'].innerHTML;
assert(html.includes('Indisponible'));
assert(html.includes('Données de vérification indisponibles'));
assert(html.includes('Tokens 12'));
assert(!html.includes('Coût $0'));

elements['bm-tbody'].innerHTML = '';
context._bmData = [{...row, id: 'zero-gt', cost: null, score: {
  ...score, is_zero_gt: true, specificity: 1, total_cost_usd: null, total_tokens: null,
  funnel: {stages: {
    candidates: {...stage, predictions: 0, true_positives: 0, false_positives: 0,
      false_negatives: 0, precision: null, recall: null, f1: null},
    filtered: {...stage, predictions: 0, true_positives: 0, false_positives: 0,
      false_negatives: 0, precision: null, recall: null, f1: null},
    confirmed: {...stage, predictions: 0, true_positives: 0, false_positives: 0,
      false_negatives: 0, precision: null, recall: null, f1: null},
  }, diagnostics: {verification: {confirmed: 0, inconclusive: 0, error: 0, not_tested: 0}},},
}}];
context.renderBenchmarkTable();
html = elements['bm-tbody'].innerHTML;
assert(html.includes('Spécificité 100 %'));
assert(html.includes('0/0 pistes testées'));
assert(html.includes('Tokens —'));

for (const invalidTokens of [null, false, '']) {
  elements['bm-tbody'].innerHTML = '';
  context._bmData = [{...row, id: `invalid-${String(invalidTokens)}`, cost: null,
    score: {...score, total_tokens: invalidTokens, total_cost_usd: null}}];
  context.renderBenchmarkTable();
  html = elements['bm-tbody'].innerHTML;
  assert(html.includes('Tokens —'));
  assert(!html.includes('Tokens 0'));
}

const invalidVerification = {...funnel,
  diagnostics: {...funnel.diagnostics,
    verification: {confirmed: null, inconclusive: 1, error: 0, not_tested: 0}}};
const mismatchedPopulation = {...funnel,
  stages: {...funnel.stages, filtered: {...funnel.stages.filtered, predictions: 9}}};
for (const badFunnel of [invalidVerification, mismatchedPopulation]) {
  elements['bm-tbody'].innerHTML = '';
  context._bmData = [{...row, id: 'bad-coverage', score: {...score, funnel: badFunnel}}];
  context.renderBenchmarkTable();
  html = elements['bm-tbody'].innerHTML;
  assert(html.includes('Couverture de vérification indisponible'));
  assert(!html.includes('0/0 pistes testées'));
}

elements['bm-tbody'].innerHTML = '';
context._bmData = [{...row, id: 'missing-rate', score: {...score,
  funnel: {...funnel, diagnostics: {...funnel.diagnostics, verification_attempt_rate: null}}}}];
context.renderBenchmarkTable();
html = elements['bm-tbody'].innerHTML;
assert(html.includes('3/4 pistes testées'));
assert(!html.includes('0,0 %'));
const missingRateCoverage = context.renderVerificationCoverage(
  context._bmData[0].score.funnel);
assert(missingRateCoverage.includes('3/4 pistes testées'));
assert(!missingRateCoverage.includes('%'));

elements['bm-tbody'].innerHTML = '';
context._bmData = [{...row, id: 'sealed', sealed: true,
  score: {metrics: {overall_score: .5, cost_usd: 0}, total_tokens: 999}}];
context.renderBenchmarkTable();
html = elements['bm-tbody'].innerHTML;
assert(html.includes('Coût $0'));
assert(html.includes('Tokens —'));
assert(!html.includes('Tokens 999'));
console.log('BENCHMARK_DASHBOARD_VM_OK');
'''
    completed = subprocess.run(
        [node, "-"],
        input=script.replace("__BENCHMARK_RENDERER_SOURCE__", json.dumps(javascript[start:end])),
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert "BENCHMARK_DASHBOARD_VM_OK" in completed.stdout


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
