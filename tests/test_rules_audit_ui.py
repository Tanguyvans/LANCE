"""Exercise production dashboard functions with synthetic results and no HTTP I/O."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

APP = Path(__file__).resolve().parents[1] / "src/static/app.js"


def dashboard(program, response=None):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for dashboard behavior checks")
    script = r"""
const fs = require('node:fs'), vm = require('node:vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id, {id,value:'',hidden:false,style:{},dataset:{},textContent:'',innerHTML:'',
    classList:{add(){},remove(){},toggle(){}},checkValidity:()=>true, focus(){}});
  return elements.get(id);
}
const document = {documentElement:element('root'),body:element('body'),getElementById:element,
  querySelector(selector){return selector.includes('run-mode') ? {value:'preset',checked:true} : element('query');},
  querySelectorAll:()=>[],addEventListener(){},createElement:()=>element('new')};
const nodes = ['web','other'].map(id=>({values:{id,ip:id==='web'?'192.0.2.10':'192.0.2.11'},
  id(){return this.values.id;},data(key,value){if(arguments.length===0)return this.values;if(arguments.length===1)return this.values[key];this.values[key]=value;}}));
const context=vm.createContext({document,console,input,payloads:[],urls:[],getComputedStyle:()=>({getPropertyValue:()=>''}),
  fakeCy:{nodes:()=>nodes},setTimeout,clearTimeout});
vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
vm.runInContext(`fetchJSON=async url=>{urls.push(url);return input.response;};
  adminFetch=async(url,request)=>{payloads.push(JSON.parse(request.body));return {ok:true};};
  loadTopology=async()=>{nodeAuditResults={};nodeVulns={};};activateSecurityMode=()=>{};
  colorNodeBySeverity=()=>{};resetNodeColors=()=>{};clearPhasePills=()=>{};clearLog=()=>{};
  setCost=()=>{};startSSE=()=>{};cy=fakeCy;`,context);
(async()=>{
  await vm.runInContext('(async()=>{'+input.program+'})()',context);
  console.log(JSON.stringify({payloads:context.payloads,urls:context.urls,nodes:nodes.map(node=>node.values),
    modelHidden:element('model-config').hidden,graphHidden:element('simple-run-stage').hidden,
    rulesHidden:element('rules-config').hidden,title:element('btn-start').textContent,
    detail:element('detail-node-view').innerHTML,table:element('topology-tbody').innerHTML}));
})().catch(error=>{console.error(error);process.exitCode=1;});
"""
    result = subprocess.run([node, "-e", script, str(APP)], input=json.dumps({"program": program, "response": response}),
                            capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def test_rules_choice_keeps_graph_and_architecture_without_model_controls():
    view = dashboard("setRunnerView('rules');")
    assert view["modelHidden"] and view["graphHidden"] and not view["rulesHidden"]
    assert view["title"] == "Lancer l'audit par règles"


def test_rules_launch_uses_scenario_without_model_and_with_explicit_limits():
    view = dashboard("""
setRunnerView('rules');document.getElementById('sel-scenario').value='1';
document.getElementById('inp-rules-max-calls').value='200';
document.getElementById('inp-rules-duration').value='600';
document.getElementById('cb-teardown').checked=true;
await startRulesAudit();
""")
    assert view["payloads"] == [{"runner_kind": "rules", "scenario_id": "1", "auto_teardown": True,
                                 "max_tool_calls": 200, "max_duration_s": 600}]


def test_device_projection_labels_confirmations_and_does_not_mark_unchecked_nodes_healthy():
    projection = {"schema_version": 1, "available": True, "topology": {"nodes": [], "edges": []},
                  "devices": [
                      {"device_id": "web", "analysis_status": "completed", "verification_status": "completed", "confirmed_count": 1,
                       "scanner_error_count": 0, "findings": [{"id": "V1", "type": "data_exposure", "severity": "HIGH", "verification": "confirmed"}]},
                      {"device_id": "other", "analysis_status": "incomplete", "verification_status": "pending", "confirmed_count": 0,
                       "scanner_error_count": 1, "findings": []},
                  ]}
    view = dashboard("await loadRulesAuditResults('run');showNodeDetail({id:'web',ip:'192.0.2.10',services:[]});", projection)
    assert view["urls"] == ["/api/runs/run/audit-results"]
    assert "1 confirmée" in view["nodes"][0]["label"]
    assert "Contrôles incomplets" in view["nodes"][1]["label"]
    assert "Confirmée par les preuves" in view["detail"]
    assert "Contrôles incomplets" in view["table"]
    assert "OK" not in view["table"]


def test_rules_launch_passes_custom_architecture_and_posture_without_model():
    view = dashboard("""
setRunnerView('rules');document.querySelector=()=>({value:'custom'});
getCustomConfig=()=>({architecture:'a1',posture:'hardened',packs:['f0_hardened']});
document.getElementById('inp-rules-max-calls').value='200';
document.getElementById('inp-rules-duration').value='600';
document.getElementById('cb-teardown').checked=true;
await startRulesAudit();
""")
    assert view["payloads"] == [{"runner_kind": "rules", "architecture": "a1", "posture": "hardened",
                                 "selected_packs": ["f0_hardened"], "auto_teardown": True,
                                 "max_tool_calls": 200, "max_duration_s": 600}]


def test_late_projection_is_discarded_after_switching_execution_kind():
    view = dashboard("""
let release;fetchJSON=()=>new Promise(resolve=>{release=resolve;});
const waiting=loadRulesAuditResults('old');setRunnerView('lance');
release({schema_version:1,available:true,topology:{nodes:[],edges:[]},devices:[]});
await waiting;
""")
    assert all("auditStatus" not in node for node in view["nodes"])
    assert view["title"] == "Lancer le pentest"
