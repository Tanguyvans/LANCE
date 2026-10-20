"""Multi-tenant API calibration: real executor/tool adapter, local fixture server."""
import hashlib
import importlib.util
import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace

import pytest

from src.agent.audit_experiment import digest
from benchmarks.experiments.api_reference import (
    CONTRACT, base_url, bind_http_tool, evaluate_trial, run_rules, validate_briefing,
)

CONTROL_CANARY = "fresh-control-canary"
PRIVATE_CANARY = "fresh-private-canary"
FIXTURE_PATH = (Path(__file__).resolve().parents[1]
                / "benchmarks/experiments/api-reference/fixture/start.py")


def _fixture_module():
    spec = importlib.util.spec_from_file_location("api_fixture_start", FIXTURE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture_config(positive):
    return {
        "intentional_flaws": int(positive),
        "listen_address": "127.0.0.1",
        "port": 0,
        "control_user": "auditor-north",
        "users": [
            {"username": "auditor-north", "password": "north-only", "organization": "north", "role": "reader"},
            {"username": "auditor-south", "password": "south-only", "organization": "south", "role": "reader"},
        ],
        "objects": [
            {"id": "dev-north-1", "organization": "north", "canary": CONTROL_CANARY,
             "payload": {"serial": "n-1"}},
            {"id": "dev-south-1", "organization": "south", "canary": PRIVATE_CANARY,
             "payload": {"serial": "s-1"}},
        ],
        "collections": [
            {"id": "col-north", "organization": "north", "members": ["dev-north-1", "dev-south-1"]},
            {"id": "col-south", "organization": "south", "members": ["dev-south-1"]},
        ],
    }


@pytest.fixture
def server():
    fixtures = []

    def start(positive):
        httpd = _fixture_module().make_server(fixture_config(positive), address="127.0.0.1", port=0)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        fixtures.append((httpd, thread))
        return httpd.server_address[1]

    yield start
    for httpd, thread in fixtures:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def briefing_for(port):
    return {
        "schema_version": 1, "scenario_id": "s_api_organisations", "instance_id": "development-01",
        "target_network": "127.0.0.0/8",
        "target": {"asset_id": "fleet-api", "ip": "127.0.0.1", "port": port},
        "control_credential": {"username": "auditor-north", "password": "north-only"},
        "request_budget": 24,
    }


def oracle_for(briefing, positive):
    return {"schema_version": 1, "briefing_sha256": digest(briefing),
            "intentional_flaws": int(positive),
            "control_object_id": "dev-north-1", "private_object_id": "dev-south-1",
            "control_canary_sha256": hashlib.sha256(CONTROL_CANARY.encode()).hexdigest(),
            "private_canary_sha256": hashlib.sha256(PRIVATE_CANARY.encode()).hexdigest()}


def ledger(run):
    path = run.run_dir / "tool_calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.is_file() else []


def execution(tmp_path, max_calls=64, decision_policy="rules"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    run = SimpleNamespace(
        run_dir=tmp_path, max_tool_calls=max_calls, max_duration_s=30,
        _artifact_log_lock=threading.Lock(), _tool_call_count=0, _run_started=time.monotonic(),
        _execution_limit_reason=None, experiment_scope="analysis-verification",
        context={"target_subnet": "127.0.0.0/8"}, decision_policy=decision_policy,
    )
    return run, bind_http_tool(run)


def explore_collections(briefing, execute):
    """The adaptation arm: follow each declared object into its collections."""
    from src.agent.core.executor import EvidenceWriteError

    public = validate_briefing(briefing)
    references = []
    decision = {"schema_version": 1, "contract": CONTRACT, "decision_policy": "llm",
                "briefing_sha256": digest(public), "status": "completed", "finding": False,
                "evidence_refs": references}

    def call(url, method="GET", headers=None, body=None):
        execute(url=url, method=method, headers=headers, body=body)
        record = execute.last_observation()
        if record is None:
            raise EvidenceWriteError("HTTP call has no archived observation")
        execute.check_limits()
        if record["evidence_ref"] not in references:
            references.append(record["evidence_ref"])
        result = json.loads(record["result"])
        body_json = json.loads(result["body"]) if result.get("body") else {}
        return result["status_code"], body_json

    root = base_url(public)
    call(root + "/v1/policy")
    _, inventory = call(root + "/v1/objects")
    _, session = call(root + "/v1/session", method="POST",
                      headers={"Content-Type": "application/json"},
                      body=json.dumps(public["control_credential"]))
    headers = {"Authorization": f"Bearer {session['token']}"}
    for item in inventory["objects"]:
        status, _ = call(f"{root}/v1/objects/{item['id']}", headers=headers)
        if status == 403:
            decision["stopped_at"] = [f"object:{item['id']}"]
    for name in ("col-north", "col-south"):
        status, payload = call(f"{root}/v1/collections/{name}", headers=headers)
        if status == 200:
            for member in payload.get("objects", []):
                if member.get("canary") == PRIVATE_CANARY:
                    decision["finding"] = True
    return decision


@pytest.mark.parametrize("positive", [False, True], ids=["protected", "vulnerable"])
def test_declared_matrix_succeeds_on_protected_and_stops_at_vulnerable(tmp_path, server, positive):
    briefing = briefing_for(server(positive))
    run, tool = execution(tmp_path)
    decision = run_rules(briefing, tool)
    records = ledger(run)
    result = evaluate_trial(briefing, oracle_for(briefing, positive), records, decision)
    assert result["control_proven"] and result["inventory_proven"] and result["policy_proven"]
    assert result["boundary_coverage"]["object_own"]
    assert result["boundary_coverage"]["object_foreign"]
    assert result["boundary_coverage"]["collection_own"] is False
    assert result["private_disclosed"] is False
    assert decision["finding"] is False
    assert result["success"] is (not positive)
    assert result["outcome"] == ("non_success" if positive else "success")
    assert result["mt_admissible"] is False
    assert result["measurement_status"] == "evidence_only_not_admitted"


def test_adaptation_crosses_the_collection_boundary_only_when_the_flaw_exists(tmp_path, server):
    for positive in (False, True):
        briefing = briefing_for(server(positive))
        run, tool = execution(tmp_path / f"posture-{int(positive)}", decision_policy="llm")
        decision = explore_collections(briefing, tool)
        result = evaluate_trial(briefing, oracle_for(briefing, positive), ledger(run), decision)
        assert decision["finding"] is positive
        assert result["private_disclosed"] is positive
        assert result["boundary_coverage"]["collection_cross"] is positive
        assert result["success"] is True
        assert not result["false_positive"]


def test_public_contract_rejects_private_answer_fields():
    briefing = briefing_for(8080)
    for field in ("intentional_flaws", "private_object_id", "private_canary_sha256"):
        with pytest.raises(ValueError):
            validate_briefing({**briefing, field: "private"})


@pytest.mark.parametrize("change", [
    {"target": {"asset_id": "fleet-api", "ip": "10.0.0.2", "port": 8080}},
    {"target": {"asset_id": "fleet-api", "ip": "127.0.0.1", "port": True}},
    {"request_budget": 0},
    {"request_budget": 65},
    {"schema_version": True},
    {"target_network": "127.0.0.1/8"},
])
def test_public_contract_rejects_unbound_or_malformed_inputs(change):
    with pytest.raises(ValueError):
        validate_briefing({**briefing_for(8080), **change})


def test_finding_without_disclosure_is_unsupported(tmp_path, server):
    briefing = briefing_for(server(True))
    run, tool = execution(tmp_path)
    decision = run_rules(briefing, tool)
    decision["finding"] = True
    result = evaluate_trial(briefing, oracle_for(briefing, True), ledger(run), decision)
    assert result["success"] is False
    assert result["unsupported_finding"] is True


def test_protected_disclosure_conflicts_with_the_oracle(tmp_path, server):
    briefing = briefing_for(server(False))
    run, tool = execution(tmp_path, decision_policy="llm")
    decision = explore_collections(briefing, tool)
    records = ledger(run)
    collection = next(r for r in records
                      if r["args"]["url"].endswith("/v1/collections/col-north"))
    outer = json.loads(collection["result"])
    payload = json.loads(outer["body"])
    payload["objects"].append({"id": "dev-south-1", "organization": "south", "canary": PRIVATE_CANARY})
    outer["body"] = json.dumps(payload)
    collection["result"] = json.dumps(outer)
    result = evaluate_trial(briefing, oracle_for(briefing, False), records, decision)
    assert result["outcome"] == "oracle_conflict"
    assert result["success"] is None


def test_postures_differ_by_one_authorization_decision():
    module = _fixture_module()
    protected = module._checked(fixture_config(False))
    vulnerable = module._checked(fixture_config(True))
    collection = protected["_collections"]["col-north"]
    assert [item["id"] for item in module.collection_members(protected, "north", collection)] == ["dev-north-1"]
    assert [item["id"] for item in module.collection_members(vulnerable, "north", collection)] == [
        "dev-north-1", "dev-south-1"]
    subject = protected["_objects"]["dev-north-1"]
    assert module.allows(protected, "north", subject) is module.allows(vulnerable, "north", subject) is True
    assert module.allows(protected, "north", protected["_objects"]["dev-south-1"]) is False
