"""User-visible comparison semantics, missing measures and escaped identities."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


def render(data):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for comparison UI verification")
    script = r"""
const fs=require('node:fs'), vm=require('node:vm');
const input=JSON.parse(fs.readFileSync(0,'utf8')), elements=new Map();
function el(id){if(!elements.has(id)) elements.set(id,{innerHTML:'',textContent:'',hidden:false,
  querySelectorAll:()=>[],addEventListener(){},value:''});return elements.get(id);}
const document={getElementById:el,addEventListener(){}};
const context=vm.createContext({document,console,input,escapeHtml:v=>String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')});
vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
vm.runInContext('ComparisonUI.render(input)',context);
console.log(JSON.stringify({html:el('comparison-results').innerHTML,outcome:el('comparison-outcome').textContent,
 context:el('comparison-context').textContent,steps:el('comparison-steps').innerHTML,
 resultsHidden:el('comparison-results').hidden,stepsOpen:el('comparison-steps-panel').open,
 number:vm.runInContext("ComparisonUI.number(-65,'duration')",context)}));
"""
    result = subprocess.run([node, "-e", script, str(ROOT / "src/static/comparisons.js")],
                            input=json.dumps(data), text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def pair(comparable=True):
    metrics = {"confirmed.true_positives": 2, "confirmed.false_positives": 0,
               "confirmed.false_negatives": 1, "confirmed.f1": 0.8, "total_cost_usd": 0,
               "wall_clock_duration_s": 90}
    return {"id": "saved", "status": "completed", "started_at": "2026-10-15T12:00:00Z",
        "scenario": {"id": "1", "name": "Public"}, "config": {"model": "test", "max_tool_calls": 200, "max_duration_s": 600},
        "order": ["rules", "llm"], "steps": [], "preflights": {}, "arms": {"rules": "rules", "llm": "llm"},
        "environment_scope": "Partial preflight", "comparison": {"comparable": comparable,
            "arms": {"rules": {"metrics": metrics}, "llm": {"metrics": metrics}},
            "delta_llm_minus_rules": {"confirmed.true_positives": 999, "confirmed.f1": 0.1} if comparable else None,
            "incomparability_reasons": [] if comparable else ["llm: incomplete analysis"]}}


def test_comparable_pair_displays_confirmed_scores_and_delta_with_correct_scope():
    output = render(pair())
    assert "Paire comparable" in output["outcome"]
    assert "+999" in output["html"] and "+10.0 points" in output["html"]
    assert "80.0 %" in output["html"] and "$0.0000" in output["html"]
    assert "hors préparation et nettoyage" in output["html"]
    assert "supériorité générale" in output["html"]
    assert output["number"] == "-1 min 5 s"


def test_incomplete_pair_never_displays_deltas_even_if_artifact_contains_them():
    data = pair(False)
    data["comparison"]["delta_llm_minus_rules"] = {"confirmed.true_positives": 999}
    output = render(data)
    assert "non comparable" in output["outcome"] and "+999" not in output["html"]
    assert "Agent LLM : analyse incomplète" in output["html"]


def test_missing_and_undefined_measures_remain_unknown_including_healthy_control_f1():
    data = pair()
    for arm in data["comparison"]["arms"].values():
        arm["metrics"] = {"specificity": 1, "confirmed.f1": None}
    data["comparison"]["delta_llm_minus_rules"] = {}
    output = render(data)
    assert "100.0 %" in output["html"] and "$0.0000" not in output["html"]
    assert "<td>—</td>" in output["html"] and "F1 reste non défini" in output["html"]


def test_server_identities_errors_and_reasons_are_escaped():
    data = pair(False)
    data["error"] = '<img src=x onerror=bad>'
    data["arms"]["rules"] = '" onclick="bad'
    data["comparison"]["incomparability_reasons"] = ['pair: <script>bad</script>']
    output = render(data)
    assert "<script>" not in output["html"] and "<img" not in output["html"]
    assert "&lt;script&gt;" in output["html"] and "&quot; onclick=&quot;" in output["html"]


def test_live_pair_prioritizes_steps_and_shows_measures_only_after_completion():
    data = pair()
    data.update(status="running", comparison=None)
    output = render(data)
    assert output["resultsHidden"] is True and output["stepsOpen"] is True
    output = render(pair())
    assert output["resultsHidden"] is False and output["stepsOpen"] is False


def test_unlimited_pair_and_historical_limits_are_distinguished():
    data = pair()
    data["config"].update(max_duration_s=None, max_cost_usd=None)
    output = render(data)
    assert "sans plafond de durée" in output["context"]
    assert "sans plafond de coût" in output["context"]
    assert "null secondes" not in output["context"]
    data["config"].update(max_duration_s=1200, max_cost_usd=2)
    output = render(data)
    assert "1200 secondes maximum" in output["context"]
    assert "$2.0000 maximum" in output["context"]
