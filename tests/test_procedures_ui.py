"""Exercise guided requests, evidence rendering and historical failure states."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from src.agent.procedures import get_procedure, procedure_catalogue

ROOT = Path(__file__).resolve().parents[1]


def ui(program, *, responses=None, hash=""):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for procedure UI checks")
    script = r"""
const fs = require('node:fs'), vm = require('node:vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const elements = new Map();
const el = id => {
  if (!elements.has(id)) elements.set(id, {id, value:'', hidden:false, disabled:false,
    textContent:'', innerHTML:'', dataset:{}, checked:true, classList:{toggle(){}}, listeners:{},
    querySelectorAll:()=>[], setAttribute(){}, scrollIntoView(){}, focus(){},
    addEventListener(type, handler){this.listeners[type]=handler;}});
  return elements.get(id);
};
const document = {getElementById:el, querySelectorAll:()=>[], addEventListener(type, handler){if(type==='DOMContentLoaded') handler();}};
const escapeHtml = value => String(value).replace(/&/g,'&amp;').replace(/</g,'&lt;')
  .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
const window = {location:{hash:input.hash,pathname:'/',search:''},history:{replaceState(_a,_b,url){window.location.hash=url.startsWith('#')?url:'';}}};
const context = vm.createContext({document, window, console, escapeHtml, input, setInterval(){},
  isSealedScenario:s=>s.sealed===true, _formatErrDetail:v=>String(v),
  fetchJSON:async url => url==='/api/procedures' ? input.catalogue
    : url==='/api/runs' ? [] : url==='/api/scenarios' ? {scenarios:[]}
    : url==='/api/pipeline/status' ? input.status || {running:false}
    : input.responses?.[url] || (url.startsWith('/api/procedures/runs?') ? {items:[],total:0,offset:0,limit:10,procedures:[],targets:[]} : null),
  fetch:async url=>({ok:true,json:async()=>input.responses?.[url] || {available:false}})});
context.adminFetch=async()=>({ok:true,json:async()=>({})});
vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
(async()=>{
  const result = await vm.runInContext('(async()=>{'+input.program+'})()',context);
  console.log(JSON.stringify({result, status:el('procedure-status').textContent,
    description:el(el('procedure-form').hidden ? 'procedure-record-description' : 'procedure-description').innerHTML, results:el('procedure-results').innerHTML,
    steps:el('procedure-steps').innerHTML, formHidden:el('procedure-form').hidden,
    activity:el('procedure-activity').textContent, durationLabel:el('procedure-duration-label').textContent,
    durationHelp:el('procedure-duration-help').textContent, overview:el('procedure-run-rows').innerHTML,
    summary:el('procedure-run-summary').innerHTML, launcherHidden:el('procedure-launcher').hidden,
    overviewHidden:el('procedure-overview').hidden, detailHidden:el('procedure-detail').hidden,
    overviewError:el('procedure-overview-error').textContent, progressOpen:el('procedure-progress-details').open,
    hash:window.location.hash}));
})().catch(error=>{console.error(error);process.exitCode=1;});
"""
    payload = {"program": program, "catalogue": procedure_catalogue(), "responses": responses or {}, "hash": hash}
    result = subprocess.run([node, "-e", script, str(ROOT / "src/static/procedures.js")],
                            input=json.dumps(payload), text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def test_direct_execution_link_opens_results_and_new_launch_clears_it():
    result = ui("await ProcedureUI.open();", hash="#automation/saved")
    assert result["detailHidden"] is False
    assert result["formHidden"] is True
    assert result["hash"] == "#automation/saved"

    result = ui("await ProcedureUI.open(); ProcedureUI.setSection('launch');", hash="#automation/saved")
    assert result["launcherHidden"] is False
    assert result["formHidden"] is False
    assert result["detailHidden"] is True
    assert result["hash"] == ""


def test_closing_results_clears_direct_link_and_invalid_routes_stay_closed():
    result = ui("await ProcedureUI.open(); document.getElementById('procedure-close-detail').listeners.click();",
                hash="#automation/saved")
    assert result["hash"] == "" and result["detailHidden"] is True
    result = ui("await ProcedureUI.open(); document.getElementById('procedure-close-detail').listeners.click(); ProcedureUI.setSection('launch');",
                hash="#automation/saved")
    assert result["formHidden"] is False
    result = ui("await ProcedureUI.open();", hash="#automation/../../sealed")
    assert result["detailHidden"] is True


@pytest.mark.parametrize("identifier,values,expected", [
    ("smoke-v1", {"duration": 120}, {"runner_kind": "scripted", "script_id": "smoke-v1", "max_duration_s": 120}),
    ("service-inventory-v1", {"network": "192.0.2.0/24", "duration": 600, "calls": 17},
     {"runner_kind": "scripted", "script_id": "service-inventory-v1", "target_network": "192.0.2.0/24", "max_duration_s": 600, "max_tool_calls": 17}),
    ("rules-audit-v1", {"scenario": "1", "cleanup": True, "duration": 600, "calls": 200},
     {"runner_kind": "rules", "scenario_id": "1", "auto_teardown": True, "max_duration_s": 600, "max_tool_calls": 200}),
    ("rules-audit-v1", {"scenario": "1", "cleanup": True, "duration": "", "calls": ""},
     {"runner_kind": "rules", "scenario_id": "1", "auto_teardown": True}),
])
def test_guided_launch_sends_only_the_existing_runner_contract(identifier, values, expected):
    program = f"return ProcedureUI.buildRequest({json.dumps(get_procedure(identifier))}, {json.dumps(values)});"
    assert ui(program)["result"] == expected


@pytest.mark.parametrize("values", [
    {"network": "", "duration": 600, "calls": 17},
    {"network": "192.0.2.0/24", "duration": 0, "calls": 17},
    {"network": "192.0.2.0/24", "duration": 600, "calls": 101},
])
def test_guided_launch_rejects_missing_target_and_invalid_limits(values):
    program = f"try {{ ProcedureUI.buildRequest({json.dumps(get_procedure('service-inventory-v1'))}, {json.dumps(values)}); return false; }} catch (_) {{ return true; }}"
    assert ui(program)["result"] is True


def test_inventory_preserves_versions_partial_coverage_and_escapes_observations():
    data = {"script_id": "service-inventory-v1", "status": "partial",
            "coverage": {"partial": True, "incomplete_reasons": ["host_limit"]},
            "hosts": [{"ip": "192.0.2.1", "status": "up", "services": [
                {"port": 80, "protocol": "tcp", "name": "http", "detail": "<script>unsafe</script> nginx/1.2"}]}]}
    result = ui(f"return ProcedureUI.renderInventory({json.dumps(data)});")["result"]
    assert "nginx/1.2" in result and "80/tcp" in result
    assert "Couverture partielle" in result and "16 équipements" in result
    assert "<script>" not in result and "&lt;script&gt;" in result


def test_discovery_does_not_describe_uninspected_services_as_a_clean_scan():
    data = {"script_id": "discovery-v1", "status": "completed", "coverage": {},
            "hosts": [{"ip": "192.0.2.1", "status": "up", "services": []}]}
    assert "Services non inspectés" in ui(f"return ProcedureUI.renderInventory({json.dumps(data)});")["result"]


@pytest.mark.parametrize("step_status,expected,absent", [
    ("partial", "Inspection non effectuée", "Aucun port ouvert observé"),
    ("completed", "Aucun port ouvert observé", "Inspection non effectuée"),
])
def test_empty_service_observation_distinguishes_incomplete_and_completed_inspection(step_status, expected, absent):
    data = {"script_id": "service-inventory-v1", "status": step_status,
            "coverage": {"partial": step_status == "partial"},
            "steps": [{"id": "host-192.0.2.1", "status": step_status}],
            "hosts": [{"ip": "192.0.2.1", "status": "up", "services": []}]}
    result = ui(f"return ProcedureUI.renderInventory({json.dumps(data)});")["result"]
    assert expected in result
    assert absent not in result


def test_confirmed_finding_does_not_hide_incomplete_device_coverage():
    data = {"devices": [{"device_id": "web", "device_ip": "192.0.2.1",
                         "analysis_status": "incomplete", "verification_status": "incomplete",
                         "scanner_error_count": 2, "verification_error_count": 1,
                         "findings": [{"type": "data_exposure", "verification": "confirmed",
                                       "evidence": "<img src=x onerror=unsafe>"}]}]}
    result = ui(f"return ProcedureUI.renderAudit({json.dumps(data)});")["result"]
    assert "Confirmé par les preuves" in result
    assert "Analyse : Incomplet" in result and "2 erreur(s) de scan" in result
    assert "1 erreur(s) de vérification" in result
    assert "<img" not in result and "&lt;img" in result


def test_historical_preparation_failure_keeps_steps_without_topology():
    response = {"available": False, "kind": "audit", "reason": "no topology",
                "procedure": {"id": "rules-audit-v1", "title": "Audit automatique", "version": "0.9"},
                "progress": {"status": "failed", "steps": [{"id": "deployment", "label": "Préparer le scénario", "status": "failed"}]}}
    result = ui("await ProcedureUI.open(); await ProcedureUI.showRun('failed');",
                responses={"/api/runs/failed/procedure-results": response})
    assert result["status"] == "Échec"
    assert 'data-status="failed"' in result["steps"]
    assert "Audit automatique" in result["description"] and "0.9" in result["description"]
    assert result["formHidden"] is True


@pytest.mark.parametrize("reason,status,expected", [
    ("predeployment_cleanup", "running", "Suppression des scénarios précédents avant le déploiement."),
    ("predeployment_cleanup_failed", "failed", "Le nettoyage préalable a échoué"),
])
def test_predeployment_cleanup_reason_is_explained_in_the_timeline(reason, status, expected):
    response = {"available": True, "kind": "audit", "audit": {"devices": []},
                "progress": {"status": status, "steps": [{"id": "deployment", "label": "Préparer le scénario",
                                                        "status": status, "reason": reason}]}}
    result = ui("await ProcedureUI.open(); await ProcedureUI.showRun('preparation');",
                responses={"/api/runs/preparation/procedure-results": response})
    assert expected in result["steps"]
    assert reason not in result["steps"]


def test_archived_rules_status_is_used_when_no_progress_was_recorded():
    response = {"available": True, "kind": "audit", "procedure": {"id": "rules-audit-v1", "title": "Audit historique", "version": None},
                "audit": {"run_status": "partial", "devices": []}}
    result = ui("await ProcedureUI.open(); await ProcedureUI.showRun('old');",
                responses={"/api/runs/old/procedure-results": response})
    assert result["status"] == "Partiel"
    assert "Version non enregistrée" in result["description"]


def test_new_live_run_restores_form_after_history_of_the_same_procedure():
    procedure = {"id": "discovery-v1", "title": "Ancienne découverte", "version": "0.9"}
    responses = {
        "/api/runs/old/procedure-results": {"available": True, "kind": "inventory", "procedure": procedure,
            "results": {"status": "completed", "hosts": [], "steps": [], "coverage": {}}},
        "/api/runs/live": {"script_id": "discovery-v1"},
        "/api/runs/live/procedure-results": {"available": True, "kind": "inventory",
            "results": {"status": "running", "hosts": [], "steps": [], "coverage": {}}},
    }
    result = ui("""
await ProcedureUI.open(); await ProcedureUI.showRun('old');
input.status={running:true,runner_kind:'scripted',run_dir:'/runs/live'};
await ProcedureUI.open();
""", responses=responses)
    assert result["formHidden"] is False
    assert "Exécution enregistrée" not in result["description"]
    assert "Découvrir les équipements" in result["description"]
    assert result["status"] == "En cours"


def test_history_entry_for_active_run_keeps_the_live_configuration_and_identity():
    responses = {
        "/api/runs/live": {"script_id": "discovery-v1"},
        "/api/runs/live/procedure-results": {"available": True, "kind": "inventory",
            "procedure": {"id": "discovery-v1", "title": "Découvrir les équipements", "version": "1.0.0"},
            "results": {"status": "running", "hosts": [], "steps": [], "coverage": {}}},
    }
    result = ui("""
await ProcedureUI.open();
input.status={running:true,runner_kind:'scripted',run_dir:'/runs/live'};
await ProcedureUI.open(); await ProcedureUI.showRun('live'); await ProcedureUI.open();
""", responses=responses)
    assert result["formHidden"] is False
    assert "Exécution enregistrée" not in result["description"]
    assert "Préparer une nouvelle exécution" not in result["description"]
    assert "Découvrir les équipements" in result["description"]
    assert result["status"] == "En cours"


@pytest.mark.parametrize("control,expected", [("stopping", "Arrêt demandé"), ("lab_waiting", "Attente du laboratoire")])
def test_live_control_status_takes_priority_over_running_result_artifacts(control, expected):
    responses = {
        "/api/runs/live": {"script_id": "discovery-v1"},
        "/api/runs/live/procedure-results": {"available": True, "kind": "inventory",
            "results": {"status": "running", "hosts": [], "steps": [], "coverage": {}}},
    }
    result = ui(f"""
await ProcedureUI.open();
input.status={{running:true,runner_kind:'scripted',run_dir:'/runs/live',{control}:true}};
await ProcedureUI.open();
""", responses=responses)
    assert result["status"] == expected
    assert ("Arrêt demandé" if control == "stopping" else "En attente") in result["activity"]


def test_running_events_do_not_erase_an_accepted_stop_request():
    responses = {
        "/api/runs/live/procedure-results": {"available": True, "kind": "audit",
            "progress": {"status": "running", "steps": []}, "audit": {"devices": []}},
    }
    result = ui("""
await ProcedureUI.open();
input.status={running:true,runner_kind:'rules',run_dir:'/runs/live'};
await ProcedureUI.open();
await document.getElementById('procedure-stop').listeners.click();
ProcedureUI.onEvent({type:'procedure_progress',runner_kind:'rules',run_dir:'/runs/live',progress:{status:'running',steps:[]}});
ProcedureUI.onEvent({type:'procedure_step',runner_kind:'rules',run_dir:'/runs/live',step_id:'analysis',label:'Analyse',status:'running'});
""", responses=responses)
    assert result["status"] == "Arrêt demandé"
    assert "Arrêt demandé" in result["activity"]


def test_rules_time_limit_explains_which_operations_it_covers():
    responses = {
        "/api/runs/live/procedure-results": {"available": True, "kind": "audit",
            "progress": {"status": "running", "steps": []}, "audit": {"devices": []}},
    }
    result = ui("""
await ProcedureUI.open();
input.status={running:true,runner_kind:'rules',run_dir:'/runs/live'};
await ProcedureUI.open();
""", responses=responses)
    assert result["durationLabel"] == "Temps maximal des contrôles (secondes)"
    assert "l’analyse et la vérification" in result["durationHelp"]
    assert "le déploiement et le nettoyage" in result["durationHelp"]


def _overview_item():
    return {"id": "inventory", "procedure": {"id": "service-inventory-v1", "title": "Inventorier les services", "version": "1.0.1"},
            "target": "192.0.2.0/28", "scenario": None, "diagnostic": False, "available": True,
            "started_at": "2026-10-15T12:38:29+02:00", "status": "done", "coverage": "collected",
            "observations": {"hosts": 4, "services": 10}, "duration_s": 166, "duration_scope": "total",
            "tool_calls": 5, "tool_errors": 0,
            "evaluation": {"status": "not_evaluated", "reason": "scenario_not_recorded"}}


def test_results_are_the_entry_view_and_launch_is_a_separate_section():
    result = ui("await ProcedureUI.open();")
    assert result["launcherHidden"] is True
    assert result["overviewHidden"] is False
    assert result["detailHidden"] is True
    result = ui("await ProcedureUI.open(); ProcedureUI.setSection('launch');")
    assert result["launcherHidden"] is False
    assert result["overviewHidden"] is True


def test_execution_table_distinguishes_measurements_from_unavailable_quality_score():
    item = _overview_item()
    page = {"items": [item], "total": 1, "offset": 0, "limit": 10, "procedures": [], "targets": []}
    result = ui(f"ProcedureUI.renderOverview({json.dumps(page)});")
    assert "4 hôtes · 10 services TCP" in result["overview"]
    assert "2 min 46 s" in result["overview"]
    assert "0 erreur" in result["overview"]
    assert "Scénario non enregistré" in result["overview"]
    assert "Non évaluée" in result["overview"] and "F1" not in result["overview"]


def test_summary_preserves_unknown_metrics_and_does_not_assign_a_scenario():
    item = _overview_item()
    item.update(duration_s=None, tool_calls=None, tool_errors=None)
    result = ui(f"ProcedureUI.renderSummary({json.dumps(item)});")
    assert "—" in result["summary"]
    assert "Aucun scénario" in result["summary"]
    assert "10" in result["summary"] and "non évaluée" in result["summary"]


def test_archived_result_opens_the_result_section_with_steps_collapsed():
    result = ui("await ProcedureUI.open(); await ProcedureUI.showRun('inventory');",
        responses={"/api/procedures/runs/inventory": _overview_item(),
            "/api/runs/inventory/procedure-results": {"available": True, "kind": "inventory",
                "procedure": _overview_item()["procedure"], "results": {"status": "completed", "hosts": [], "steps": []}}})
    assert result["launcherHidden"] is True and result["overviewHidden"] is False
    assert result["detailHidden"] is False and result["progressOpen"] is False
    assert "Inventorier les services" in result["description"]
    assert "2 min 46 s" in result["summary"]


def test_overview_error_is_not_an_empty_or_successful_result_list():
    url = "/api/procedures/runs?offset=0&limit=10&include_diagnostics=false&procedure_id=&target="
    result = ui("await ProcedureUI.open();", responses={url: {"detail": "unavailable"}})
    assert "Impossible de charger" in result["overviewError"]


def test_execution_table_escapes_archived_metadata():
    item = _overview_item()
    item["procedure"]["title"] = "<img src=x onerror=bad>"
    item["target"] = "<script>bad</script>"
    page = {"items": [item], "total": 1, "offset": 0, "limit": 10}
    result = ui(f"ProcedureUI.renderOverview({json.dumps(page)});")["overview"]
    assert "<script>" not in result and "<img" not in result
    assert "&lt;img" in result and "&lt;script&gt;" in result
