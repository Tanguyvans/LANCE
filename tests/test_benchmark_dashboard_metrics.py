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
    for heading in ("1. Failles potentielles", "2. Failles retenues", "3. Confirmations déclarées", "Consommation", "Vérification"):
        assert heading in table
    assert "Une faille potentielle est une hypothèse à vérifier" in table
    assert table.count('class="bm-stage-help"') == 3
    for explanation in ("Toutes les hypothèses proposées par l’agent",
                        "Hypothèses sélectionnées pour vérification après filtrage",
                        "L’agent les dit confirmées ; l’évaluation contrôle les preuves",
                        "Après vérification, un VP exige aussi une preuve acceptée"):
        assert explanation in table
    assert "3. Confirmations finales" not in table
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
const funnel = {schema_version: 'funnel-v1', stages: {candidates: stage, filtered: {...stage, predictions: 4}, confirmed: stage}, diagnostics: {
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
assert(html.includes('Failles potentielles <strong>2</strong>'));
assert(html.includes('Failles retenues <strong>4</strong>'));
assert(html.includes('Déclarations <strong>2</strong>'));
assert((html.match(/class="bm-stage-count">Failles /g) || []).length === 2);
assert((html.match(/class="bm-stage-count">Déclarations /g) || []).length === 1);
assert(html.includes('VP 1 · FP 1 · FN 0'));
assert(html.includes('3/4 hypothèses testées'));
assert(html.includes('Non concluantes 1'));
assert(html.includes('Failles réelles écartées au filtrage : 1'));
assert(html.includes('Coût $0'));
assert(html.includes('Tokens 0'));
assert(html.includes('&lt;model&gt;'));
assert(!html.includes('<model>'));
assert((html.match(/bm-final-metrics/g) || []).length === 1);
assert(html.includes('<strong>F1 final 50 %</strong>'));
assert(html.includes('>Terminé</span>'));
assert(!html.includes('Vérification incomplète'));
assert(html.includes('Non testées 1'));

const queueCoverage = context.renderVerificationCoverage({...funnel,
  stages: {...funnel.stages, filtered: {...funnel.stages.filtered, predictions: 2}},
  diagnostics: {...funnel.diagnostics, verification_population: 4}});
assert(queueCoverage.includes('3/4 hypothèses testées'));
assert(!queueCoverage.includes('incohérente'));
const claimsHtml = context.renderClaimDiagnostics({available: true, false_positive_count: 2,
  claims: [{id: '<V1>', device_ip: '192.0.2.1', service: 'ssh', port: 22,
    category: 'supported_outside_reference', evidence_refs: ['<ref>']},
    {id: 'V2', category: 'insufficient_evidence', evidence_refs: []}],
  duplicate_sources: [{source_ids: ['a', 'b'], evidence_refs: ['trace-a']}]});
assert(claimsHtml.includes('Étayée, hors référentiel'));
assert(claimsHtml.includes('Preuve insuffisante'));
assert(claimsHtml.includes('192.0.2.1 · ssh · 22'));
assert(claimsHtml.includes('&lt;V1&gt;') && !claimsHtml.includes('<V1>'));
assert(claimsHtml.includes('&lt;ref&gt;') && !claimsHtml.includes('<ref>'));
assert(claimsHtml.includes('a, b') && claimsHtml.includes('trace-a'));
assert(context.renderClaimDiagnostics(null).includes('indisponible'));

const completeFunnel = {...funnel, diagnostics: {verification: {
  confirmed: 4, inconclusive: 0, error: 0, not_tested: 0}}};
context._bmData = [{...row, score: {...score, funnel: completeFunnel,
  phase3_metrics_available: true, phase3_devices_total: 4,
  phase3_devices_analyzed: 3, phase3_devices_failed: 1,
  run_evidence_contract_version: 'evidence-v8', evidence_contract_version: 'evidence-v10',
  run_metric_contract_version: 'metric-v1', metric_contract_version: 'metric-v1',
}}];
context.renderBenchmarkTable();
html = elements['bm-tbody'].innerHTML;
assert(html.includes('Analyse partielle (3/4 analysés, 1 en échec)'));
assert(html.includes('Terminé avec incidents techniques'));
assert(html.includes('evidence-v8'));
assert(html.includes('evidence-v10'));
assert(row.status === 'done');

context._bmData = [{...row, score: {...score, funnel: completeFunnel}}];
context.renderBenchmarkTable();
assert(!elements['bm-tbody'].innerHTML.includes('Terminé avec incidents techniques'));
assert(elements['bm-tbody'].innerHTML.includes('run-badge done'));

context._bmData = [{...row, completion: {phase6_status: 'partial:memo_truncated', phase6_cause: 'memo_truncated'},
  score: {...score, funnel: completeFunnel}}];
context.renderBenchmarkTable();
assert(elements['bm-tbody'].innerHTML.includes('Rapport partiel — note tronquée'));

for (const status of ['failed', 'running', 'stopped', 'partial']) {
  context._bmData = [{...row, status}];
  context.renderBenchmarkTable();
  assert(!elements['bm-tbody'].innerHTML.includes('Terminé avec incidents techniques'));
  assert(elements['bm-tbody'].innerHTML.includes(`run-badge ${status}`));
}

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
assert(html.includes('Contrat historique — non comparable'));
assert(html.includes('Audit final indisponible'));

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
assert(html.includes('0/0 hypothèses testées'));
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
  assert(!html.includes('0/0 hypothèses testées'));
}

elements['bm-tbody'].innerHTML = '';
context._bmData = [{...row, id: 'missing-rate', score: {...score,
  funnel: {...funnel, diagnostics: {...funnel.diagnostics, verification_attempt_rate: null}}}}];
context.renderBenchmarkTable();
html = elements['bm-tbody'].innerHTML;
assert(html.includes('3/4 hypothèses testées'));
assert(!html.includes('0,0 %'));
const missingRateCoverage = context.renderVerificationCoverage(
  context._bmData[0].score.funnel);
assert(missingRateCoverage.includes('3/4 hypothèses testées'));
assert(!missingRateCoverage.includes('%'));

elements['bm-tbody'].innerHTML = '';
context._bmData = [{...row, id: 'sealed', sealed: true,
  score: {metrics: {overall_score: .5, cost_usd: 0}, total_tokens: 999}}];
context.renderBenchmarkTable();
html = elements['bm-tbody'].innerHTML;
assert(html.includes('Coût $0'));
assert(html.includes('Tokens —'));
assert(!html.includes('Tokens 999'));
assert(!html.includes('Déclarations <strong>'));
console.log('BENCHMARK_DASHBOARD_VM_OK');
'''
    completed = subprocess.run(
        [node, "-"],
        input=script.replace("__BENCHMARK_RENDERER_SOURCE__", json.dumps(
            javascript[start:end] + javascript[javascript.index("function _summaryFinite("):javascript.index("\nfunction addLog")]
        )),
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert "BENCHMARK_DASHBOARD_VM_OK" in completed.stdout


def test_compact_score_keeps_completion_and_contract_diagnostics():
    from src.api.routes.runs import _compact_score

    diagnostics = {
        "phase3_metrics_available": True, "phase3_status": "completed_with_device_errors",
        "phase3_devices_total": 4, "phase3_devices_analyzed": 3, "phase3_devices_failed": 1,
        "metric_contract_version": "metric-v1", "run_metric_contract_version": "metric-v1",
        "evidence_contract_version": "evidence-v10", "run_evidence_contract_version": "evidence-v8",
        "evidence_contract_compatible": False,
    }
    assert _compact_score({**diagnostics, "private_observation": "not exported"}) == diagnostics


@pytest.mark.parametrize("sealed", [False, True])
def test_benchmark_completion_metadata_is_allowlisted_and_never_exposes_sealed_details(tmp_path, monkeypatch, sealed):
    from src.api.routes import runs

    (tmp_path / "run_meta.json").write_text(json.dumps({
        "status": "completed", "phase6_status": "partial", "phase6_cause": "memo_truncated",
        "phase6_error": "private model text", "phase6_analysis": "private observation",
    }))
    monkeypatch.setattr(runs, "_load_sealed_summary", lambda *_: {"status": "done"})
    entry = runs._benchmark_entry({"run_dir": tmp_path, "scenario": "S1", "sealed": sealed, "model": "test"}, compact=True)
    if sealed:
        assert "completion" not in entry
    else:
        assert entry["completion"] == {"phase6_status": "partial", "phase6_cause": "memo_truncated"}
        assert entry["status"] == "done"
    assert "private" not in json.dumps(entry)


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
