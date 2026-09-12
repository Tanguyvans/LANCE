"""Pure Node-driven tests for the live pipeline summary formatters."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _run_node(cases):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to exercise the UI formatters")
    source = (ROOT / "src/static/app.js").read_text(encoding="utf-8")
    start = source.index("function _summaryFinite(")
    end = source.index("\nfunction addLog", start)
    formatter_source = source[start:end]
    # Keep the formatter execution inside a VM context so this test does not
    # depend on browser globals or accidentally exercise unrelated UI setup.
    script = f"""
const vm = require('vm');
const assert = require('assert');
const context = {{}};
vm.createContext(context);
vm.runInContext({json.dumps(formatter_source)}, context);
const cases = {json.dumps(cases)};
const output = cases.map(item => ({{
  audit: context.formatAuditFinalSummary(item.event),
  intrusion: context.formatIntrusionDiagnostics(item.event.metrics),
  pipeline: context.formatPipelineCompletionSummary(item.event),
}}));
console.log(JSON.stringify(output));
"""
    result = subprocess.run([node, "-e", script], check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def test_confirmed_funnel_wins_over_legacy_metrics_and_intrusion_is_separate():
    metrics = {
        "precision": 0.625, "recall": 0.833, "f1": 0.714,
        "tp": 10, "fp": 6, "fn": 2, "scenario_score_pct": 76.9,
        "evidence_contract_compatible": True,
        "funnel": {"schema_version": "funnel-v1", "stages": {"confirmed": {
            "available": True, "predictions": 14, "true_positives": 10,
            "false_positives": 4, "false_negatives": 2,
            "precision": 0.714, "recall": 0.833, "f1": 0.769,
        }}},
        "phase5_metrics_available": True, "phase5_evidence_available": True,
        "intrusion_paths_available": True,
        "phase5_targets_compromised": 2, "phase5_targets_total": 4,
        "verified_attack_paths": 1, "total_attack_paths": 4,
        "phase5_verified_hops": 0,
    }
    result = _run_node([{"event": {"metrics": metrics, "evaluation_status": "completed", "status": "completed"}}])[0]
    assert "Audit final" in result["audit"]
    assert "VP=10 FP=4 FN=2" in result["audit"]
    assert "Précision=71.4%" in result["audit"]
    assert "Rappel=83.3%" in result["audit"]
    assert "F1=76.9%" in result["audit"]
    assert "0.625" not in result["audit"]
    assert "0.714" not in result["audit"].split("F1=", 1)[-1]
    assert "Score" not in result["audit"]
    assert result["intrusion"] == (
        "Intrusion vérifiée — Cibles compromises=2/4 · Chemins vérifiés=1/4 · "
        "Transitions vérifiées=0"
    )
    assert result["pipeline"] == "Exécution terminée"


@pytest.mark.parametrize("metrics", [
    {},
    {"funnel": {"schema_version": "funnel-v1", "stages": {"confirmed": {"available": False}}}},
    {"funnel": {"schema_version": "funnel-v0", "stages": {"confirmed": {"available": True, "f1": 1}}}},
    {"evidence_contract_compatible": False, "funnel": {"schema_version": "funnel-v1", "stages": {"confirmed": {"available": True, "f1": 1}}}},
])
def test_absent_or_incompatible_confirmed_contract_never_falls_back(metrics):
    result = _run_node([{"event": {"metrics": metrics, "evaluation_status": "completed", "status": "completed"}}])[0]
    assert result["audit"] == "Audit final — indisponible"
    assert "Exécution terminée avec réserves" in result["pipeline"]
    assert "Audit final indisponible" in result["pipeline"]


def test_zero_and_null_values_remain_distinct_from_unavailable():
    metrics = {
        "evidence_contract_compatible": True,
        "funnel": {"schema_version": "funnel-v1", "stages": {"confirmed": {
            "available": True, "true_positives": 0, "false_positives": 0,
            "false_negatives": 0, "precision": None, "recall": None, "f1": None,
        }}},
        "phase5_metrics_available": True, "phase5_evidence_available": True,
        "intrusion_paths_available": True,
        "phase5_targets_compromised": 0, "phase5_targets_total": 0,
        "verified_attack_paths": 0, "total_attack_paths": 0,
        "phase5_verified_hops": 0,
    }
    result = _run_node([{"event": {"metrics": metrics, "evaluation_status": "completed", "status": "completed"}}])[0]
    assert "VP=0 FP=0 FN=0" in result["audit"]
    assert "Précision=indisponible" in result["audit"]
    assert "Rappel=indisponible" in result["audit"]
    assert "F1=indisponible" in result["audit"]
    assert "Cibles compromises=0/0" in result["intrusion"]
    assert "Transitions vérifiées=0" in result["intrusion"]
    assert result["pipeline"] == "Exécution terminée"


def test_missing_intrusion_evidence_does_not_fabricate_zeroes_or_rates():
    metrics = {
        "phase5_metrics_available": True, "phase5_evidence_available": False,
        "intrusion_paths_available": False,
        "phase5_targets_compromised": 0, "phase5_targets_total": 4,
        "verified_attack_paths": 0, "total_attack_paths": 4,
        "phase5_verified_hops": 0, "path_coverage": 0, "phase5_pivot_success_rate": 0,
    }
    result = _run_node([{"event": {"metrics": metrics, "status": "completed"}}])[0]
    assert result["intrusion"].count("indisponible") == 3
    assert "0/4" not in result["intrusion"]
    assert "0" not in result["intrusion"].replace("indisponible", "")
    assert "path_coverage" not in result["intrusion"]
    assert "pivot" not in result["intrusion"].lower()


def test_incompatible_evidence_contract_suppresses_stale_intrusion_counters():
    metrics = {
        "evidence_contract_compatible": False,
        "phase5_metrics_available": True, "phase5_evidence_available": True,
        "intrusion_paths_available": True,
        "phase5_targets_compromised": 2, "phase5_targets_total": 4,
        "verified_attack_paths": 1, "total_attack_paths": 4,
        "phase5_verified_hops": 0,
    }
    result = _run_node([{"event": {"metrics": metrics, "status": "completed"}}])[0]
    assert result["intrusion"] == (
        "Intrusion vérifiée — Cibles compromises=indisponible · "
        "Chemins vérifiés=indisponible · Transitions vérifiées=indisponible"
    )


def test_completion_reservations_are_concise_and_do_not_change_lifecycle():
    metrics = {
        "phase3_metrics_available": True, "phase3_status": "partial",
        "phase3_devices_total": 4, "phase3_devices_analyzed": 3,
        "phase3_devices_failed": 1,
        "funnel": {"schema_version": "funnel-v1", "stages": {"confirmed": {"available": True}},
                   "diagnostics": {"verification": {"confirmed": 10, "inconclusive": 2, "error": 1, "not_tested": 1}}},
    }
    result = _run_node([{"event": {"status": "completed", "evaluation_status": "completed", "metrics": metrics}}])[0]
    assert "Exécution terminée avec réserves" in result["pipeline"]
    assert "3/4 analysés" in result["pipeline"]
    assert "1 en échec" in result["pipeline"]
    assert "2 indéterminées" in result["pipeline"]
    assert "1 erreur" in result["pipeline"]
    assert "1 non testée" in result["pipeline"]
    assert "Pipeline en échec" not in result["pipeline"]


def test_completed_warnings_are_reservations_and_complete_counts_need_no_status_field():
    funnel = {"schema_version": "funnel-v1", "stages": {"confirmed": {"available": True}}}
    complete_metrics = {
        "evidence_contract_compatible": True,
        "phase3_metrics_available": True,
        "phase3_devices_total": 4, "phase3_devices_analyzed": 4,
        "phase3_devices_failed": 0,
        "funnel": funnel,
    }
    results = _run_node([
        {"event": {"status": "completed", "evaluation_status": "completed", "metrics": complete_metrics,
                    "cleanup_status": "failed", "usage_status": "incomplete", "metadata_status": "failed"}},
        {"event": {"status": "completed", "evaluation_status": "completed", "metrics": complete_metrics}},
    ])
    assert "Exécution terminée avec réserves" in results[0]["pipeline"]
    assert "Nettoyage en échec" in results[0]["pipeline"]
    assert "Consommation incomplète" in results[0]["pipeline"]
    assert "Métadonnées en échec" in results[0]["pipeline"]
    assert "Analyse partielle" not in results[0]["pipeline"]
    assert results[1]["pipeline"] == "Exécution terminée"


@pytest.mark.parametrize("status,expected", [
    ("failed", "Pipeline en échec"), ("stopped", "Pipeline arrêté"),
    ("blocked", "Pipeline bloqué"), ("budget_exceeded", "budget atteint"),
])
def test_terminal_status_precedence_and_warnings_are_preserved(status, expected):
    result = _run_node([{"event": {
        "status": status, "cleanup_status": "failed", "usage_status": "incomplete",
        "evaluation_status": "failed", "evaluation_error": "should not reclassify",
    }}])[0]
    assert expected in result["pipeline"]
    assert "Nettoyage en échec" in result["pipeline"]
    assert "Consommation incomplète" in result["pipeline"]
    assert "Exécution terminée" not in result["pipeline"]


def test_clean_and_deployment_only_completion_has_no_evaluation_reservation():
    results = _run_node([
        {"event": {"status": "completed", "metrics": None}},
        {"event": {"status": "completed", "metrics": None, "deploy_only": True}},
    ])
    assert results[0]["pipeline"] == "Exécution terminée"
    assert results[1]["pipeline"] == "Exécution terminée"
