"""Details-toggle behavior for the compact benchmark comparison table.

The comparison row stays compact (8 columns, one Details control per run);
Investigation happens in one tabbed row immediately after the selected run.
"""
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "src" / "static" / "index.html"
JS = ROOT / "src" / "static" / "app.js"


def _table_html():
    html = HTML.read_text(encoding="utf-8")
    start = html.index('<table id="bm-table"')
    return html[start:html.index("</table>", start)]


def test_benchmark_table_is_compact_with_explicit_details_control():
    table = _table_html()
    th_count = table.count("<th>") + table.count('<th scope="col">')
    assert th_count == 8, f"expected 8 columns, found {th_count}"
    for heading in ("Run", "Modèle", "Audit final", "Précision", "Rappel", "Statut", "Coût"):
        assert heading in table
    assert "Détails" in table
    # Identity cells are combined: no standalone scenario column anymore.
    assert "<th>Scénario</th>" not in table
    assert "<th>Consommation</th>" not in table


def test_benchmark_metrics_help_disclosure_exists_once():
    html = HTML.read_text(encoding="utf-8")
    assert 'id="bm-metrics-help"' in html
    assert "Comprendre les métriques" in html
    # Main view stays free of explanatory paragraphs: definitions live in the disclosure.
    help_block = html[html.index('id="bm-metrics-help"'):html.index("</details>", html.index('id="bm-metrics-help"'))]
    assert "VP = failles attendues" in help_block


def test_benchmark_details_rendering_contracts():
    javascript = JS.read_text(encoding="utf-8")
    renderer = javascript[javascript.index("function bmNumber("):javascript.index("// ── Modal")]
    # Explicit keyboard-accessible control wired to a full-width panel.
    assert "data-bm-details=" in renderer
    assert "aria-expanded=" in renderer
    assert "aria-controls=" in renderer
    assert '<tr class="bm-details-row"><td colspan="8">' in renderer
    assert "return mainRow + (open ?" in renderer
    assert 'role="tablist"' in renderer
    assert 'role="tabpanel"' in renderer
    # Exactly one open panel at a time, retained across benign refresh.
    assert "_bmOpenRunId" in renderer
    assert "BM_OPEN_RUN_STORAGE_KEY" in renderer
    assert "toggleBenchmarkDetails" in renderer
    # Investigation groups in the expanded panel.
    for group in ("Entonnoir de détection", "Vérification et preuves", "Intrusion", "Consommation"):
        assert group in renderer
    # No data loss: every diagnostic field stays reachable in the panel.
    for metric in ("cost_per_valid_confirmation", "turns_per_valid_confirmation", "d.proofs",
                   "phase5_target_attempt_coverage", "phase5_pivot_success_rate",
                   "phase5_hop_coverage", "cost_is_estimate", "score_unavailable_reason",
                   "metrics_compatibility_reason", "score_error"):
        assert metric in renderer
    # Authoritative contracts preserved.
    assert "Non concluantes" in renderer
    assert "Spécificité" in renderer
    assert "F1 final" in renderer
    assert "Détails scellés" in renderer


def _run_node_vm():
    node = shutil.which("node")
    if node is None:
        import pytest
        pytest.skip("Node.js unavailable; dashboard VM test skipped")
    javascript = JS.read_text(encoding="utf-8")
    start = javascript.index("function bmFiniteNumber(")
    end = javascript.index("// ── Modal", start)
    script = r'''
const vm = require('vm');
const assert = require('assert');
const source = __BENCHMARK_RENDERER_SOURCE__;
const elements = {};
for (const id of ['bm-filter-scenario', 'bm-filter-model', 'bm-tbody', 'bm-selected-run']) {
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
const funnel = {schema_version: 'funnel-v1', stages: {candidates: stage, filtered: {...stage, predictions: 4}, confirmed: stage}, diagnostics: {
  verification: {confirmed: 2, inconclusive: 1, error: 0, not_tested: 1},
  verification_attempt_rate: .75,
  true_candidates_lost_in_filter: 1,
  verification_population: 4,
  proofs: {available: true, accepted: 1, rejected: 0, missing: 0},
}};
const score = {funnel, evidence_contract_compatible: true, is_zero_gt: false,
  scenario_score_pct: 50, specificity: null, total_tokens: 7, total_cost_usd: 0.5,
  cost_is_estimate: false, process_metrics_available: false,
  cost_per_valid_confirmation: null, turns_per_valid_confirmation: null};
const rowA = {id: 'run_a', scenario: 'S1', model: 'm', status: 'done', cost: 0.5, score};
const rowB = {id: 'run_b', scenario: 'S1', model: 'm', status: 'done', cost: 0.5, score};
context._bmData = [rowA, rowB];

// Closed by default: compact rows only, one Details control each, stable panel ids.
context.renderBenchmarkTable();
let html = elements['bm-tbody'].innerHTML + elements['bm-selected-run'].innerHTML;
assert(!html.includes('bm-details-row'), 'no panel open initially');
assert((html.match(/data-bm-details=/g) || []).length === 2);
assert((html.match(/aria-expanded="false"/g) || []).length === 2);
assert(html.includes('aria-controls="bm-selected-run"'));
assert(!html.includes('bm-details-row'));
assert.notEqual(context.bmDetailsPanelId('a/b'), context.bmDetailsPanelId('a-b'));
assert(html.includes('<strong>F1 final 50 %</strong>'));
assert(!html.includes('hypothèses testées'), 'verification lives in the selected panel');
const firstRender = html;
context.renderBenchmarkTable();
assert.strictEqual(elements['bm-tbody'].innerHTML + elements['bm-selected-run'].innerHTML, firstRender, 'stable identity across renders');

// Opening one run shows a single full-width panel with the funnel + groups.
context.toggleBenchmarkDetails('run_a');
html = elements['bm-tbody'].innerHTML + elements['bm-selected-run'].innerHTML;
assert(!elements['bm-selected-run'].hidden);
assert((html.match(/role="tablist"/g) || []).length === 1);
assert(html.includes(`id="${context.bmDetailsPanelId('run_a')}-audit"`));
assert(html.includes('aria-expanded="true"'));
assert((html.match(/aria-expanded="true"/g) || []).length === 1);
assert(html.includes('Entonnoir de détection'));
assert(html.includes('Failles potentielles</th><td>2</td>'));
assert(html.includes('Failles retenues</th><td>4</td>'));
assert(html.includes('Confirmations déclarées</th><td>2</td>'));
assert(html.includes('Vérification et preuves'));
assert(html.includes('Consommation'));
assert((elements['bm-tbody'].innerHTML.match(/class="bm-details-row"/g) || []).length === 1);
assert(elements['bm-tbody'].innerHTML.indexOf('data-bm-details="run_a"') < elements['bm-tbody'].innerHTML.indexOf('class="bm-details-row"'));
assert(elements['bm-tbody'].innerHTML.indexOf('class="bm-details-row"') < elements['bm-tbody'].innerHTML.indexOf('data-bm-details="run_b"'), 'details directly precede the next run');
assert((elements['bm-selected-run'].innerHTML.match(/role="tabpanel"/g) || []).length === 4);
assert((elements['bm-selected-run'].innerHTML.match(/tabindex="0" hidden/g) || []).length === 3);
context.selectBenchmarkTab('proofs');
context.renderBenchmarkTable();
assert(elements['bm-selected-run'].innerHTML.includes('data-bm-tab="proofs" aria-selected="true"'));
context.selectBenchmarkTab('invalid');
context.renderBenchmarkTable();
assert(elements['bm-selected-run'].innerHTML.includes('data-bm-tab="proofs" aria-selected="true"'));

// Switching runs moves the single panel; toggling again closes it.
context.toggleBenchmarkDetails('run_b');
html = elements['bm-tbody'].innerHTML + elements['bm-selected-run'].innerHTML;
assert(elements['bm-selected-run'].innerHTML.includes('data-bm-tab="audit" aria-selected="true"'));
assert(elements['bm-tbody'].innerHTML.indexOf('data-bm-details="run_b"') < elements['bm-tbody'].innerHTML.indexOf('class="bm-details-row"'));
assert((html.match(/role="tablist"/g) || []).length === 1);
assert(html.includes(`id="${context.bmDetailsPanelId('run_b')}-audit"`));
assert(!elements['bm-selected-run'].innerHTML.includes(context.bmDetailsPanelId('run_a')));
context.toggleBenchmarkDetails('run_b');
assert(elements['bm-selected-run'].hidden);
assert(!elements['bm-tbody'].innerHTML.includes('bm-details-row'));
assert((elements['bm-tbody'].innerHTML.match(/aria-expanded="false"/g) || []).length === 2);
assert(context.renderVerificationCompact({...funnel, diagnostics:{...funnel.diagnostics, verification_population:99}}).includes('incohérente'));

// Sealed runs stay aggregate-only even when expanded.
context._bmData = [{id: 'sealed', sealed: true, scenario: 'S9', model: 'm',
  status: 'done', score: {metrics: {overall_score: .5, cost_usd: 0}, total_tokens: 999}}];
context.toggleBenchmarkDetails('sealed');
html = elements['bm-tbody'].innerHTML + elements['bm-selected-run'].innerHTML;
assert(!elements['bm-selected-run'].hidden);
assert(!html.includes('Failles potentielles'), 'no funnel detail leaks for sealed runs');
assert(html.includes('Détails scellés'));

// Untrusted run content is escaped in rows and panels.
context._bmData = [{id: 'run_<evil>', scenario: 'S1', model: '<model>',
  status: 'done', cost: 0, score}];
context.toggleBenchmarkDetails('run_<evil>');
html = elements['bm-tbody'].innerHTML + elements['bm-selected-run'].innerHTML;
assert(!html.includes('<evil>') && !html.includes('<model>'));
assert(html.includes('&lt;evil&gt;') && html.includes('&lt;model&gt;'));
console.log('BENCHMARK_DETAILS_TOGGLE_VM_OK');
'''
    completed = subprocess.run(
        [node, "-"],
        input=script.replace("__BENCHMARK_RENDERER_SOURCE__", json.dumps(
            javascript[start:end] + javascript[javascript.index("function _summaryFinite("):javascript.index("\nfunction addLog")]
        )),
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert "BENCHMARK_DETAILS_TOGGLE_VM_OK" in completed.stdout


def test_benchmark_details_toggle_behavioral_rendering_via_node_vm():
    _run_node_vm()
