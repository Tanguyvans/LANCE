"""Exercise the dashboard device/architecture/weakness filters without a browser."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

APP = Path(__file__).resolve().parents[1] / "src/static/app.js"

SCENARIOS = {
    "taxonomy": {
        "device": {"broker": "-", "camera": "-", "host": "-"},
        "architecture": {"flat": "-", "multi_hop": "-"},
        "weakness": {"authentication": "-", "injection": "-"},
    },
    "architectures": [],
    "packs": [],
    "scenarios": [
        {"id": "1", "name": "Flat", "posture": "vulnerable", "axes": {
            "devices": ["broker", "host"], "architecture_measured": "flat",
            "weaknesses": ["authentication"]}},
        {"id": "4", "name": "Injection", "posture": "vulnerable", "axes": {
            "devices": ["camera"], "architecture_measured": "flat",
            "weaknesses": ["authentication", "injection"]}},
        {"id": "20", "name": "Pivot", "posture": "vulnerable", "axes": {
            "devices": ["host"], "architecture_measured": "multi_hop",
            "weaknesses": ["authentication"]}},
        {"id": "gen-custom-1", "name": "Export", "exported": True, "posture": "mixed"},
    ],
}


def run_filters(selected: dict) -> dict:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for dashboard behavior checks")
    script = r"""
const fs = require('node:fs'), vm = require('node:vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const elements = new Map();
function make(tag, id) {
  return {tag, id, value: '', hidden: false, style: {}, dataset: {}, textContent: '', children: [],
    classList: {add(){}, remove(){}, toggle(){}},
    get options() { const out = []; const walk = n => { for (const c of n.children) {
      if (c.tag === 'option') out.push(c); walk(c); } }; walk(this); return out; },
    set innerHTML(html) { const m = /<option[^>]*>([^<]*)</.exec(html);
      this.children = m ? [Object.assign(make('option'), {value: '', textContent: m[1]})] : []; },
    appendChild(child) { this.children.push(child); return child; },
    addEventListener() {}, dispatchEvent() {}, focus() {}};
}
function element(id) { if (!elements.has(id)) elements.set(id, make('div', id)); return elements.get(id); }
const document = {documentElement: element('root'), body: element('body'), getElementById: element,
  querySelector: () => element('query'), querySelectorAll: () => [], addEventListener() {},
  createElement: tag => make(tag), createTextNode: text => ({tag: '#text', text})};
const context = vm.createContext({document, console, input, Event: class { constructor(t) { this.type = t; } },
  getComputedStyle: () => ({getPropertyValue: () => ''}), setTimeout, clearTimeout});
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
vm.runInContext(`
  _scenariosData = input.data;
  populateAxisFilters();
  for (const [id, value] of Object.entries(input.selected)) document.getElementById(id).value = value;
  renderScenarioChoices();
  result = {
    scenarios: document.getElementById('sel-scenario').options.map(o => o.value).filter(Boolean),
    batch: document.getElementById('batch-checkboxes').children.map(l => l.children[0].value),
    weaknessOptions: document.getElementById('sel-filter-weakness').options.map(o => o.textContent),
    count: document.getElementById('axis-filter-count').textContent,
  };`, context);
console.log(JSON.stringify(context.result));
"""
    completed = subprocess.run(
        [node, "-e", script, str(APP)],
        input=json.dumps({"data": SCENARIOS, "selected": selected}),
        capture_output=True, text=True, check=True,
    )
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_without_filters_every_scenario_is_listed():
    result = run_filters({})
    assert result["scenarios"] == ["gen-custom-1", "1", "4", "20"]
    assert result["batch"] == ["1", "4", "20", "gen-custom-1"]
    assert result["count"] == ""


def test_filter_options_show_how_many_scenarios_match():
    assert run_filters({})["weaknessOptions"] == ["Tous", "authentication (3)", "injection (1)"]


def test_filters_combine_and_drop_unlabelled_scenarios():
    result = run_filters({"sel-filter-device": "host", "sel-filter-architecture": "multi_hop"})
    assert result["scenarios"] == ["20"]
    assert result["batch"] == ["20"]
    assert result["count"] == "1 scénario(s) correspondant(s)"
    assert run_filters({"sel-filter-weakness": "injection"})["scenarios"] == ["4"]
