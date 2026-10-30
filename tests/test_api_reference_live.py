"""Live API harness: parametric fixture identity, preflight and archive duties, offline."""
import hashlib
import importlib.util
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from benchmarks.experiments import api_reference_live as live
from benchmarks.experiments.api_reference import CONTRACT, bind_http_tool, run_rules, validate_briefing
from src.agent.audit_experiment import digest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "benchmarks/experiments/api-reference/fixture/start.py"
GUEST_PATH = ROOT / "benchmarks/ansible/files/api_reference_proxmox.py"


def _module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def args(**overrides):
    values = {"max_tool_calls": 16, "max_duration_s": None, "max_cost_usd": None,
              "max_turns": 16, "provider": live.PROVIDER, "model": live.MODEL}
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.fixture
def server():
    fixtures = []

    def start(flaws):
        _, config, identity = live.case_configuration(flaws)
        config = {**config, "listen_address": "127.0.0.1", "port": 0}
        httpd = _module(FIXTURE_PATH, "api_fixture_live").make_server(config, address="127.0.0.1", port=0)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        fixtures.append((httpd, thread))
        return config, identity, httpd.server_address[1]

    yield start
    for httpd, thread in fixtures:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_case_configuration_is_parametric_and_accepted_by_both_validators():
    control, config, identity = live.case_configuration(1)
    _, other, _ = live.case_configuration(1)
    fixture = _module(FIXTURE_PATH, "api_fixture_check")
    guest = _module(GUEST_PATH, "api_guest_check")
    fixture._checked({**config, "listen_address": "127.0.0.1"})
    guest.validate_fixture({**config, "port": 8080})
    assert config["control_user"] == control["username"]
    assert config["control_password"] == control["password"]
    # No identifier may repeat between trials: the solution is never a name.
    assert {item["id"] for item in config["objects"]}.isdisjoint(
        {item["id"] for item in other["objects"]})
    assert identity["control_object_id"] != identity["private_object_id"]
    assert identity["control_object_id"] in config["collections"][0]["members"]


@pytest.mark.parametrize("flaws", [0, 1], ids=["protected", "vulnerable"])
def test_preflight_attests_each_posture(tmp_path, server, flaws):
    config, identity, port = server(flaws)
    public = validate_briefing(live.build_briefing(
        "api-trial", "127.0.0.1", {"username": config["control_user"],
                                   "password": config["control_password"]},
        network="127.0.0.0/8"))
    public["target"]["port"] = port
    oracle = live.oracle_for(public, flaws, config, identity)
    live.preflight(public, oracle, identity, tmp_path, args())
    attestation = json.loads((tmp_path / "attestation.json").read_text())
    assert attestation["status"] == "valid"
    assert attestation["post_probe_control_proven"] is True
    checks = {item["check"]: item for item in attestation["checks"]}
    assert checks["control_own_object"]["proven"] is True
    assert checks["foreign_object_denied"]["proven"] is True
    assert checks["collection_membership"]["disclosed"] is (flaws == 1)


def test_preflight_refuses_a_posture_that_disagrees_with_the_oracle(tmp_path, server):
    config, identity, port = server(1)
    public = validate_briefing(live.build_briefing(
        "api-trial", "127.0.0.1", {"username": config["control_user"],
                                   "password": config["control_password"]},
        network="127.0.0.0/8"))
    public["target"]["port"] = port
    # Declare the protected posture against a vulnerable fixture.
    oracle = live.oracle_for(public, 0, config, identity)
    with pytest.raises(RuntimeError, match="disagrees with the private posture"):
        live.preflight(public, oracle, identity, tmp_path, args())
    assert json.loads((tmp_path / "attestation.json").read_text())["status"] == "invalid"


def test_oracle_binds_the_briefing_and_distinct_canaries():
    config = {
        "intentional_flaws": 1,
        "users": [{"username": "a", "password": "x", "organization": "n", "role": "reader"}],
        "objects": [{"id": "o1", "organization": "n", "canary": "c1", "payload": {}},
                    {"id": "o2", "organization": "s", "canary": "c2", "payload": {}}],
    }
    public = live.build_briefing("t", "192.168.100.221", {"username": "a", "password": "x"})
    oracle = live.oracle_for(public, 1, config, {"control_object_id": "o1", "private_object_id": "o2"})
    assert oracle["briefing_sha256"] == digest(public)
    assert oracle["control_canary_sha256"] == hashlib.sha256(b"c1").hexdigest()
    assert oracle["private_canary_sha256"] == hashlib.sha256(b"c2").hexdigest()
    assert CONTRACT in json.dumps({"contract": CONTRACT})


def test_briefing_never_carries_the_peer_identity():
    control, config, identity = live.case_configuration(0)
    public = live.build_briefing("t", "192.168.100.221", control)
    text = json.dumps(public)
    peer = next(item for item in config["users"] if item["username"] != control["username"])
    assert peer["username"] not in text and peer["password"] not in text
    for item in config["objects"]:
        assert item["canary"] not in text
    assert "intentional_flaws" not in public


def test_require_nato_refuses_a_foreign_runner(monkeypatch):
    monkeypatch.setenv("RUNNER_NAME", "somewhere-else")
    with pytest.raises(RuntimeError, match="nato-master"):
        live.require_nato()
    monkeypatch.setenv("RUNNER_NAME", "nato-master")
    monkeypatch.delenv("LANCE_API_LOCK_HELD", raising=False)
    # The runner identity is the presence of a Tailscale address, not one
    # memorised value: a rebuilt container receives a new one.
    import src.agent.core.runtime as runtime
    monkeypatch.setattr(runtime, "tailscale_identity_present", lambda: True)
    with pytest.raises(RuntimeError, match="laboratory lock"):
        live.require_nato()


def test_workflow_is_manual_dev2_only_and_never_uploads_evidence(tmp_path):
    import subprocess
    import yaml

    path = ROOT / ".github/workflows/api-reference.yml"
    workflow = yaml.safe_load(path.read_text())
    assert set(workflow[True]) == {"workflow_dispatch"}
    job = workflow["jobs"]["api-trial"]
    assert job["runs-on"] == ["self-hosted", "nato-master"]
    assert workflow["concurrency"] == {"group": "lance-lab-dev2", "cancel-in-progress": False}
    text = path.read_text()
    assert 'test "$GITHUB_REF" = refs/heads/dev/2' in text
    assert 'test "$RUNNER_NAME" = nato-master' in text
    assert "LANCE_API_LOCK_HELD" in text
    assert "--max-tool-calls 16" in text and "--max-duration-s" not in text
    assert "actions/upload-artifact" not in text
    assert "api_reference_live recover" in text and "api_reference_live seal" in text
    for step in job["steps"]:
        script = tmp_path / "step.sh"
        script.write_text(step["run"])
        assert subprocess.run(["bash", "-n", str(script)]).returncode == 0


def test_rules_arm_reuses_the_same_binding_as_the_offline_increment(tmp_path, server):
    config, identity, port = server(0)
    public = validate_briefing(live.build_briefing(
        "api-trial", "127.0.0.1", {"username": config["control_user"],
                                   "password": config["control_password"]},
        network="127.0.0.0/8"))
    public["target"]["port"] = port
    run = SimpleNamespace(
        run_dir=tmp_path, max_tool_calls=16, max_duration_s=None,
        _artifact_log_lock=threading.Lock(), _tool_call_count=0,
        _run_started=0.0, _execution_limit_reason=None,
        experiment_scope="api-reference-calibration", context={"target_subnet": "127.0.0.0/8"},
        decision_policy="rules",
        tracker=SimpleNamespace(max_cost_usd=None, check_budget=lambda: None),
    )
    decision = run_rules(public, bind_http_tool(run))
    assert decision["status"] == "completed" and decision["finding"] is False
    assert len(decision["evidence_refs"]) == 4  # policy, inventory, two object reads
