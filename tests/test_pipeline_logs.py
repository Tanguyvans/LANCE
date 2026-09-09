"""Offline diagnostics tests: no scenario, SSH connection or model is started."""
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.agent.core import lifecycle


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def scenario(tmp_path):
    instance = lifecycle.ScenarioLifecycle()
    instance.scenario_id = "1"
    instance.run_dir = tmp_path
    instance._generated_deployment = None
    instance._scenario_owned = True
    return instance


@pytest.mark.parametrize("returncode", [0, 4])
def test_playbook_reports_result_and_saves_both_streams(scenario, monkeypatch, returncode):
    run = Mock(return_value=SimpleNamespace(returncode=returncode, stdout="TASK owner check\n", stderr="SSH diagnostic\n"))
    monkeypatch.setattr(lifecycle.subprocess, "run", run)
    events = []
    assert scenario._run_playbook("03_deploy_scenario.yml", events.append, "deploy_start", "deploy_done") is (returncode == 0)
    start, done = events
    assert start["playbook"] == done["playbook"] == "03_deploy_scenario.yml"
    assert start["attempt"] == done["attempt"] == 1
    assert start["timestamp"].endswith("+00:00")
    assert done["returncode"] == returncode
    assert done["duration_s"] >= 0
    assert done["success"] is (returncode == 0)
    assert done["timed_out"] is False
    assert done["log_saved"] is True
    assert done["output_truncated"] is False
    saved = (scenario.run_dir / done["log_file"]).read_text()
    assert "TASK owner check\nSSH diagnostic" in saved
    assert "tentative 1" in saved
    assert "--vault-password-file" not in saved
    assert run.call_args.kwargs["capture_output"] is True


@pytest.mark.parametrize("partial", [b"TASK before timeout\n", "TASK before timeout\n"])
def test_timeout_keeps_partial_output(scenario, monkeypatch, partial):
    monkeypatch.setenv("ANSIBLE_PLAYBOOK_TIMEOUT", "9")
    error = subprocess.TimeoutExpired("ansible-playbook", 9, output=partial, stderr=b"SSH timed out")
    monkeypatch.setattr(lifecycle.subprocess, "run", Mock(side_effect=error))
    events = []
    assert not scenario._run_playbook("03_deploy_scenario.yml", events.append, "deploy_start", "deploy_done")
    done = events[-1]
    assert done["returncode"] is None
    assert done["timed_out"] is True
    assert "TASK before timeout" in done["output"]
    assert "SSH timed out" in done["output"]
    assert "timeout (9s)" in done["output"]
    assert done["output"] in (scenario.run_dir / done["log_file"]).read_text()


def test_missing_ansible_is_not_reported_as_skipped_success(scenario, monkeypatch):
    monkeypatch.setattr(lifecycle.subprocess, "run", Mock(side_effect=FileNotFoundError))
    events = []
    assert not scenario._run_playbook("03_deploy_scenario.yml", events.append, "deploy_start", "deploy_done")
    assert "not found" in events[-1]["output"]
    assert events[-1]["success"] is False
    assert events[-1]["returncode"] is None


def test_cleanup_retries_keep_separate_attempts_and_release_only_on_success(scenario, monkeypatch):
    deployment = SimpleNamespace(overlay_path=Path("overlay.yml"), source_scenario_id="1", release=Mock())
    scenario._generated_deployment = deployment
    results = [SimpleNamespace(returncode=rc, stdout=out, stderr="") for rc, out in [(4, "first failure"), (4, "second failure"), (0, "cleaned")]]
    monkeypatch.setattr(lifecycle.subprocess, "run", Mock(side_effect=results))
    events = []
    for _ in range(2):
        assert not scenario._run_teardown(events.append)
        assert scenario._scenario_owned is True
        deployment.release.assert_not_called()
    assert scenario._run_teardown(events.append)
    assert scenario._scenario_owned is False
    deployment.release.assert_called_once()
    done = [e for e in events if e["type"] == "teardown_done"]
    assert [e["attempt"] for e in done] == [1, 2, 3]
    saved = (scenario.run_dir / "ansible_99_teardown.log").read_text()
    assert all(value in saved for value in ("first failure", "second failure", "cleaned"))


def test_large_output_is_bounded_in_event_but_complete_in_file(scenario, monkeypatch):
    output = "beginning\n" + "x" * 15000 + "\nend"
    monkeypatch.setattr(lifecycle.subprocess, "run", Mock(return_value=SimpleNamespace(returncode=4, stdout=output, stderr="")))
    events = []
    scenario._run_playbook("03_deploy_scenario.yml", events.append, "deploy_start", "deploy_done")
    done = events[-1]
    assert len(done["output"]) == 10000
    assert done["output_truncated"] is True
    assert output in (scenario.run_dir / done["log_file"]).read_text()


def test_log_write_failure_is_visible_without_hiding_ansible_error(scenario, monkeypatch):
    scenario.run_dir /= "missing-directory"
    monkeypatch.setattr(lifecycle.subprocess, "run", Mock(return_value=SimpleNamespace(returncode=4, stdout="", stderr="SSH error")))
    events = []
    assert not scenario._run_playbook("03_deploy_scenario.yml", events.append, "deploy_start", "deploy_done")
    assert events[-1]["log_saved"] is False
    assert events[-1]["log_file"] is None
    assert events[-1]["output"] == "SSH error"


@pytest.mark.parametrize("success", [False, True])
def test_deploy_only_emits_explicit_terminal_status(scenario, monkeypatch, success):
    scenario.execution_profile = SimpleNamespace(name="full")
    monkeypatch.setattr(scenario, "_run_scenario_deploy", Mock(return_value=success))
    events = []
    scenario.run_deploy_only(events.append)
    assert events[-1]["type"] == "pipeline_done"
    assert events[-1]["status"] == ("completed" if success else "failed")


def test_preparation_warns_once_when_ssh_checks_fail(scenario, monkeypatch, tmp_path):
    ansible = tmp_path / "benchmarks/ansible"
    variables = ansible / "group_vars/all"
    variables.mkdir(parents=True)
    (variables / "main.yml").write_text('scenario_vmid_ranges: {"2": 200, "3": 300}\n')
    (variables / "scenarios_v2.yml").write_text('{}\n')
    (ansible / "inventory.yml").write_text('all: {hosts: {proxmox: {ansible_host: 192.0.2.10}}}\n')
    monkeypatch.setattr(lifecycle.runtime, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(lifecycle.runtime.GeneratedScenarioDeployment, "active_leases", lambda: [])
    run = Mock(return_value=SimpleNamespace(returncode=255, stdout="", stderr="Connection timed out"))
    monkeypatch.setattr(lifecycle.subprocess, "run", run)
    events = []
    scenario._teardown_all_running_scenarios(events.append)
    assert run.call_count == 2
    assert [event["type"] for event in events] == ["info", "warn"]
    assert "192.0.2.10" in events[0]["message"]
    assert events[1]["output"] == "Connection timed out"


def test_event_log_displays_failures_and_keyboard_disclosures():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to exercise the dashboard renderer")
    source = (ROOT / "src/static/app.js").read_text()
    renderer = source[source.index("const MAX_LOG ="):source.index("// ── Sidebar Collapsible")]
    script = r'''
const vm = require('vm');
const assert = require('assert');
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.textContent = ''; }
  appendChild(child) { this.children.push(child); }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
  get firstChild() { return this.children[0]; }
  setAttribute(key, value) { this.attrs[key] = value; }
  set innerHTML(value) { throw new Error('Log output must never use innerHTML'); }
}
const log = new Element('div');
const context = {document: {getElementById: () => log, createElement: tag => new Element(tag)},
  PHASE_NAMES: {}, _truncate: (text, length) => text.slice(0, length), batchSummaryText: () => 'batch'};
vm.createContext(context);
vm.runInContext(__SOURCE__, context);
function render(event) { context.addLog(event); return log.children[log.children.length - 1]; }
const output = 'PLAY S1\n[ERROR]: SSH connect to 192.168.88.165 port 22: Connection timed out\n<img src=x onerror=alert(1)>';
let line = render({type:'deploy_done', scenario_id:'1', playbook:'03_deploy_scenario.yml',
  success:false, output, returncode:4, duration_s:5, attempt:1, timestamp:'2026-09-09T08:00:00Z',
  log_file:'ansible_03_deploy_scenario.log'});
assert(line.children[0].textContent.includes('ÉCHEC'));
assert(line.children[0].textContent.includes('Connection timed out'));
assert(line.children[0].textContent.includes('code retour 4'));
assert(line.children[0].textContent.includes('5.0 s'));
assert(line.children[0].attrs.role === 'alert');
assert(line.children[1].tag === 'details' && line.children[1].open === true);
assert(line.children[1].children[0].tag === 'summary');
assert(line.children[1].children[1].textContent === output);

line = render({type:'teardown_done', scenario_id:'1', success:false, output:'short', attempt:2});
assert(line.children[0].textContent.includes('Nettoyage S1 — ÉCHEC'));
assert(line.children[0].textContent.includes('tentative 2'));
assert(line.children[1].children[1].textContent === 'short');
line = render({type:'teardown_done', scenario_id:'1', success:true, output:'ok'});
assert(line.children[0].textContent.includes('réussi'));
assert(line.children[1].open === false);
line = render({type:'teardown_done', scenario_id:'1'});
assert(line.children[0].textContent.includes('résultat inconnu'));

for (const status of ['failed','completed','partial','blocked','stopped','skipped','budget_exceeded']) {
  line = render({type:'pipeline_done', status, total_cost_usd:0});
  assert(line.children[0].textContent.includes('$0.0000'));
  assert(line.children[0].textContent.includes('réussi') === (status === 'completed'));
}
line = render({type:'pipeline_done', status:'failed', cleanup_status:'failed', total_cost_usd:null});
assert(line.children[0].textContent.includes('Pipeline en échec'));
assert(line.children[0].textContent.includes('Nettoyage en échec'));
assert(!line.children[0].textContent.includes('$0.0000'));
line = render({type:'pipeline_done'});
assert(line.children[0].textContent.includes('statut indisponible'));
for (const type of ['info','warn']) {
  line = render({type, message:'Préparation SSH', output:'timeout'});
  assert(line.children[0].textContent.includes('Préparation SSH'));
}
for (const type of ['verify_start','verify_done']) {
  line = render({type, scenario_id:'1', success:false});
  assert(line.children[0].textContent.includes('Vérification du scénario'));
}
line = render({type:'deploy_done', scenario_id:'1', success:false, log_saved:false, output_truncated:true});
assert(line.children[0].textContent.includes('journal non sauvegardé'));
assert(line.children[0].textContent.includes('Extrait de sortie limité'));
assert(!line.children[0].textContent.includes('est dans le journal du run'));
for (let i=0; i<310; i++) render({type:'info',message:'bounded'});
assert(log.children.length === 300);
'''
    result = subprocess.run([node, "-"], input=script.replace("__SOURCE__", json.dumps(renderer)), text=True, capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr


def test_reload_replays_scenario_diagnostics():
    source = (ROOT / "src/static/app.js").read_text()
    replay = source[source.index("const replayTypes"):source.index("// — Sync scenario")]
    for kind in ("info", "warn", "verify_start", "verify_done", "teardown_start", "teardown_done"):
        assert f"'{kind}'" in replay
