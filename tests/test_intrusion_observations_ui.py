"""Offline real-dashboard checks for declarative vs corroborated intrusion."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest


APP = Path(__file__).resolve().parents[1] / "src/static/app.js"
VIEW = {
    "schema_version": "intrusion-observations-v1", "available": True,
    "accesses": [{"device_ip": "192.0.2.1", "evidence_refs": ["tc-a"]}],
    "transitions": [], "transition_evidence_available": False,
    "declarations": {"accesses": 2, "chains": 1, "transitions": 1},
}


def render(program, **data):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for real dashboard checks")
    script = r"""
const vm = require('node:vm'), fs = require('node:fs');
class Element {
  constructor() { this.children=[]; this.style={}; this.textContent=''; }
  appendChild(c) { this.children.push(c); }
  removeChild(c) { this.children.splice(this.children.indexOf(c), 1); }
  setAttribute() {}
}
class Node {
  constructor(ip) {
    this.values={ip, label:ip, color:'original'};
    this.styles={'background-color':'original', 'border-color':'gray', 'border-width':'2px'};
  }
  id() { return this.values.ip; }
  data(k,v) { if(arguments.length===1) return this.values[k]; this.values[k]=v; }
  removeData(keys) { keys.split(' ').forEach(k=>delete this.values[k]); }
  style(k,v) {
    if (typeof k==='object') return Object.assign(this.styles,k);
    if(arguments.length===1) return this.styles[k]; this.styles[k]=v;
  }
}
const elements=new Map(), nodes=[new Node('192.0.2.1'),new Node('192.0.2.2')];
let edges=0;
const document={documentElement:new Element(),
  getElementById(id) { if(!elements.has(id)) elements.set(id,new Element()); return elements.get(id); },
  createElement:()=>new Element(),querySelectorAll:()=>[],addEventListener(){}};
const context=vm.createContext({document,console,
  getComputedStyle:()=>({getPropertyValue:()=>''}),
  mockCy:{nodes:()=>nodes,remove:()=>{},add:()=>{edges++;}},
  input:JSON.parse(fs.readFileSync(0,'utf8')),urls:[],
});
vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
vm.runInContext('cy=mockCy; fetchJSON=async url=>{urls.push(url);return input.response;};',context);
(async()=>{
  await vm.runInContext('(async()=>{'+context.input.program+'})()',context);
  console.log(JSON.stringify({nodes:nodes.map(n=>({values:n.values,styles:n.styles})),edges,
    urls:context.urls,logs:document.getElementById('log').children.map(l=>l.children[0].textContent)}));
})().catch(e=>{console.error(e);process.exitCode=1;});
"""
    result = subprocess.run(
        [node, "-e", script, str(APP)], input=json.dumps({"program": program, **data}),
        text=True, capture_output=True, check=True,
    )
    return json.loads(result.stdout)


def test_live_projection_marks_only_corroborated_ip_and_adds_text_label():
    result = render("handleEvent({...input.view,type:'intrusion_observations'});", view=VIEW)
    assert "accès corroboré" in result["nodes"][0]["values"]["label"]
    assert result["nodes"][1]["styles"]["background-color"] == "original"
    assert result["edges"] == 0
    assert "Accès corroborés : 1" in result["logs"][0]
    assert "2 accès déclaré(s)" in result["logs"][0]


@pytest.mark.parametrize("event", [
    {"type": "intrusion_hop", "from_ip": "192.0.2.1", "to_ip": "192.0.2.2", "verified": True},
    {"type": "intrusion_compromised", "device_ip": "192.0.2.1", "evidence_status": "verified"},
    {"type": "intrusion_done", "chains_successful": 9, "chains": 9, "hops": 9},
])
def test_legacy_events_cannot_color_nodes_or_create_pivots(event):
    result = render("handleEvent(input.event);", event=event)
    assert result["edges"] == 0
    assert all(n["styles"]["background-color"] == "original" for n in result["nodes"])
    assert "9" not in " ".join(result["logs"])


@pytest.mark.parametrize("response", [
    None,
    {**VIEW, "schema_version": "legacy"},
    {**VIEW, "available": False},
    {**VIEW, "accesses": [{"device_ip": "192.0.2.1", "evidence_refs": []}]},
    {"content": {"compromised_devices": [{"device_ip": "192.0.2.1", "verified": True}]}},
])
def test_historical_overlay_uses_projection_endpoint_and_fails_closed(response):
    result = render("activeRunId='run'; await loadIntrusionOverlay('run');", response=response)
    assert result["urls"] == ["/api/runs/run/intrusion-observations"]
    assert all(n["styles"]["background-color"] == "original" for n in result["nodes"])
    assert "indisponibles" in result["logs"][0]


def test_two_accesses_and_declared_transitions_never_produce_network_edges():
    view = {**VIEW, "accesses": VIEW["accesses"] + [
        {"device_ip": "192.0.2.2", "evidence_refs": ["tc-b"]},
    ], "transitions": [{"from_ip": "192.0.2.1", "to_ip": "192.0.2.2"}]}
    result = render("activeRunId='run'; await loadIntrusionOverlay('run');", response=view)
    assert all("accès corroboré" in n["values"]["label"] for n in result["nodes"])
    assert result["edges"] == 0


def test_unavailable_new_projection_clears_previous_access_qualification():
    result = render("applyIntrusionObservations(input.view); applyIntrusionObservations(null);", view=VIEW)
    assert result["nodes"][0]["values"]["label"] == "192.0.2.1"
    assert result["nodes"][0]["styles"]["background-color"] == "original"


def test_overlay_response_for_a_different_selected_run_is_ignored():
    result = render("activeRunId='new'; await loadIntrusionOverlay('old');", response=VIEW)
    assert all(n["styles"]["background-color"] == "original" for n in result["nodes"])
    assert result["logs"] == []


def test_no_access_is_distinct_from_an_unavailable_projection():
    result = render("applyIntrusionObservations(input.view);", view={**VIEW, "accesses": []})
    assert "Accès corroborés : 0" in result["logs"][0]
    assert "indisponibles" not in result["logs"][0]


def test_pending_historical_response_cannot_overwrite_new_live_observations():
    result = render("""
      activeRunId='run';
      let complete;
      fetchJSON=()=>new Promise(resolve=>{complete=resolve;});
      const pending=loadIntrusionOverlay('run');
      applyIntrusionObservations(input.view);
      complete(null);
      await pending;
    """, view=VIEW)
    assert "accès corroboré" in result["nodes"][0]["values"]["label"]
    assert len(result["logs"]) == 1


@pytest.mark.parametrize("model_present", [False, True])
def test_view_run_reloads_ledger_accesses_independently_of_model_file(model_present):
    files = ["run_meta.json", "tool_calls.jsonl"]
    if model_present:
        files.append("05_intrusion.json")
    result = render("""
      applyIntrusionObservations(input.view);
      loadTopology=async()=>{};
      fetchJSON=async url=>{
        urls.push(url);
        return url.endsWith('/intrusion-observations') ? input.view : input.run;
      };
      await viewRun('run');
    """, view=VIEW, run={"files": files, "status": "partial"})
    assert result["urls"] == ["/api/runs/run", "/api/runs/run/intrusion-observations"]
    assert "accès corroboré" in result["nodes"][0]["values"]["label"]
    assert result["nodes"][1]["values"]["label"] == "192.0.2.2"
    assert result["edges"] == 0


def test_view_run_does_not_request_observations_for_sealed_run():
    result = render("""
      applyIntrusionObservations(input.view);
      showSealedTopologyPlaceholder=()=>clearIntrusionObservations();
      fetchJSON=async url=>{
        urls.push(url);
        return url.endsWith('/score') ? null : input.run;
      };
      await viewRun('run');
    """, view=VIEW, run={"files": [], "status": "done", "sealed": True})
    assert result["urls"] == ["/api/runs/run", "/api/runs/run/score"]
    assert all("accès corroboré" not in n["values"]["label"] for n in result["nodes"])


def test_real_server_projection_reaches_dashboard_without_model_claim_promotion(tmp_path):
    from src.agent.phases.intrusion.observations import project_intrusion_observations
    from src.benchmark.metric_contract import EVIDENCE_CONTRACT_VERSION

    (tmp_path / "run_meta.json").write_text(json.dumps({
        "evidence_contract_version": EVIDENCE_CONTRACT_VERSION,
        "evidence_integrity": True,
    }))
    (tmp_path / "05_intrusion.json").write_text(json.dumps({
        "compromised_devices": [{"device_ip": "192.0.2.2"}],
        "chains": [{"hops": [{"device_ip": "192.0.2.1"}, {"device_ip": "192.0.2.2"}]}],
    }))
    (tmp_path / "tool_calls.jsonl").write_text(json.dumps({
        "tool": "ssh_exec", "phase": 5, "execution_origin": "runner",
        "evidence_ref": "tc-" + "a" * 32,
        "args": {"ip": "192.0.2.1", "command": "id"},
        "result": {"return_code": 0, "stdout": "uid=1000(test)"},
    }) + "\n")
    projection = project_intrusion_observations(tmp_path)
    result = render("activeRunId='run'; await loadIntrusionOverlay('run');", response=projection)
    assert "accès corroboré" in result["nodes"][0]["values"]["label"]
    assert result["nodes"][1]["values"]["label"] == "192.0.2.2"
    assert result["edges"] == 0
