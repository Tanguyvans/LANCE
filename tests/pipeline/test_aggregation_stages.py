"""Independent aggregation boundaries using synthetic offline artifacts only."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path

import pytest

from src.agent.core import runtime
from src.agent.phases.analysis.aggregation import (
    aggregate,
    capture_context,
    render_projection,
)
from src.agent.phases.analysis.aggregation_context import AggregationContext, AggregationInputs
from src.agent.phases.analysis.aggregation_loading import CandidateRegistry, load_inputs
from src.agent.phases.analysis.aggregation_normalization import normalize_candidates
from src.agent.phases.analysis.aggregation_projection import project_candidates
from src.agent.phases.analysis.mqtt_grouping import load_authoritative_mqtt_observations
from src.agent.tools import graph_tools
import src.agent.phases.analysis.mqtt_grouping as mqtt_grouping


HOST = "192.0.2.10"
MQTT_TOPIC = "review/admin/credentials"
MQTT_PAYLOAD = '{"password":"offline-fixture-secret"}'


def finding(**changes):
    value = {
        "id": "model-original", "device_id": "review-web", "device_ip": HOST,
        "type": "data_exposure", "severity": "MEDIUM", "service": "http",
        "port": 80, "protocol": "tcp", "endpoint": "/config",
        "details": "A sensitive configuration file may be exposed at this path",
        "evidence": "", "product": "", "version": "",
    }
    value.update(changes)
    return value


@pytest.fixture
def context(tmp_path):
    return AggregationContext(
        run_dir=tmp_path,
        surface_nodes=[{"id": "review-web", "ip": HOST, "role": "web_server"}],
        surface_roles={"review-web": "web_server"},
        ip_to_device_id={HOST: "review-web"},
        tool_names=frozenset({"http_request", "mqtt_listen", "ssh_audit"}),
    )


def write_candidates(run_dir, findings):
    path = run_dir / "03_device_review-web.json"
    path.write_text(json.dumps({"vulnerabilities": findings}), encoding="utf-8")
    return path


def forbid_ambient(*_args, **_kwargs):
    raise AssertionError("Aggregation stage used an ambient service or filesystem")


def mqtt_observations(run_dir):
    args = {"broker": HOST, "port": 1883, "topic": "#"}
    entry = {
        "tool": "mqtt_listen", "phase": 3, "args": args,
        "result": {
            "stdout": json.dumps({
                "tst": "offline", "topic": MQTT_TOPIC, "qos": 0,
                "retain": 1, "payload": MQTT_PAYLOAD,
            }) + "\n",
            "stderr": "", "return_code": 0,
            "execution_attestation": {
                "protocol": "TCP", "host": HOST, "port": 1883,
                "topic": "#", "output_format": "mosquitto-json-v1",
            },
        },
    }
    (run_dir / "tool_calls.jsonl").write_text(json.dumps(entry) + "\n", encoding="utf-8")
    return load_authoritative_mqtt_observations(run_dir)


def test_core_aggregates_from_explicit_context_without_pipeline_or_graph(context, monkeypatch):
    candidate = finding(suggested_tools=["http_request", "invented-cli"])
    source = write_candidates(context.run_dir, [candidate])
    before = source.read_bytes()
    monkeypatch.setattr(runtime, "get_attack_surface", forbid_ambient)
    monkeypatch.setattr(runtime, "available_tool_names", forbid_ambient)
    monkeypatch.setattr(graph_tools, "_scenario_topology", {"broken": "ambient graph"})

    result = aggregate(context)

    assert result.canonical["summary"]["total"] == 1
    assert result.canonical["vulnerabilities"][0]["suggested_tools"] == ["http_request"]
    assert result.raw["candidates"][0]["raw_finding"] == candidate
    assert source.read_bytes() == before
    assert json.loads((context.run_dir / "03_vuln_analysis.json").read_text()) == result.canonical
    assert json.loads((context.run_dir / "03_vuln_analysis_raw.json").read_text()) == result.raw
    assert not (context.run_dir / "03_config_observations.json").exists()


def test_loaded_stages_do_not_read_or_write_files_again(context, monkeypatch):
    original = finding(
        type="misconfiguration", service="ssh", port="22", protocol=None, endpoint=None,
        details="SSH advertises CBC weak algorithms", suggested_tools=["ssh-audit"],
    )
    write_candidates(context.run_dir, [original])
    inputs = load_inputs(context)
    source_records = deepcopy(inputs.records)
    context_before = deepcopy(context)
    monkeypatch.setattr(runtime, "get_attack_surface", forbid_ambient)
    monkeypatch.setattr(mqtt_grouping, "load_authoritative_mqtt_observations", forbid_ambient)
    with monkeypatch.context() as no_io:
        no_io.setattr(Path, "read_text", forbid_ambient)
        no_io.setattr(Path, "write_text", forbid_ambient)
        eligible = normalize_candidates(context, inputs)
        final = project_candidates(
            eligible, inputs.records,
            mqtt_observations=inputs.mqtt_observations, previous_ids=inputs.previous_ids,
        )
        result = render_projection(context, final, inputs.records)

    assert context == context_before
    assert inputs.records[0]["raw_finding"] == source_records[0]["raw_finding"]
    assert inputs.records[0]["candidate_finding"]["type"] == "misconfiguration"
    assert result.canonical["vulnerabilities"][0]["type"] == "weak_cipher"
    assert not (context.run_dir / "03_vuln_analysis.json").exists()


def test_mqtt_group_keeps_each_members_proof_on_that_member(context, monkeypatch):
    observations = mqtt_observations(context.run_dir)
    model = finding(
        service="mqtt", port=1883, endpoint=MQTT_TOPIC,
        product="Mosquitto", version="2.0.21", evidence_ref="model-proof",
        details=f"Credentials exposed on {MQTT_TOPIC}", exploitation_status="confirmed",
    )
    scanner = finding(
        service="mqtt", port=1883, endpoint="", evidence_ref="scanner-proof",
        details="Credentials exposed in MQTT messages", evidence=MQTT_PAYLOAD,
    )
    registry = CandidateRegistry()
    registry.add([model], "03_device_review-web.json", "model")
    registry.add([scanner], "review-web.json", "scanner_full")
    inputs = AggregationInputs(registry.findings, registry.records, {}, observations, {})
    observation_before = deepcopy(observations)
    monkeypatch.setattr(mqtt_grouping, "load_authoritative_mqtt_observations", forbid_ambient)
    with monkeypatch.context() as no_io:
        no_io.setattr(Path, "read_text", forbid_ambient)
        eligible = normalize_candidates(context, inputs)
        final = project_candidates(eligible, inputs.records, mqtt_observations=observations, previous_ids={})

    assert len(final) == 1
    chosen = final[0]
    provenance = chosen["_provenance"]
    assert chosen["canonical_source"] == "model"
    assert chosen["evidence_ref"] == "model-proof"
    assert "evidence_refs" not in chosen
    assert provenance["grouping_basis"] == "archived_phase3_mqtt_observation"
    assert provenance["evidence_refs"] == ["model-proof"]
    assert provenance["candidate_evidence_refs"] == {
        "CAND-0001": ["model-proof"], "CAND-0002": ["scanner-proof"],
    }
    assert observations == observation_before
    assert [record["raw_finding"] for record in inputs.records] == [model, scanner]
    assert {record["canonical_finding_id"] for record in inputs.records} == {chosen["id"]}


def test_enriched_group_inherits_id_from_previous_incomplete_member(context):
    original = finding(id="VULN-007", evidence_refs=["old-proof"])
    (context.run_dir / "03_vuln_analysis.json").write_text(
        json.dumps({"vulnerabilities": [original]}), encoding="utf-8",
    )
    enriched = finding(product="nginx", version="1.22", evidence_refs=["new-proof"])
    write_candidates(context.run_dir, [enriched, finding(endpoint="/new"), original])

    result = aggregate(context)

    findings = result.canonical["vulnerabilities"]
    assert len(findings) == 2
    chosen = next(item for item in findings if item["endpoint"] == "/config")
    new = next(item for item in findings if item["endpoint"] == "/new")
    assert chosen["id"] == "VULN-007"
    assert chosen["product"] == "nginx"
    assert chosen["version"] == "1.22"
    assert set(chosen["evidence_refs"]) == {"old-proof", "new-proof"}
    assert new["id"] == "VULN-008"
    assert result.raw["candidate_count"] == 3
    assert [r["canonical_finding_id"] for r in result.raw["candidates"]] == ["VULN-007", "VULN-008", "VULN-007"]


def test_snapshot_reads_graph_once_and_excludes_oracle_fields(tmp_path, monkeypatch):
    surface = {"nodes": [{
        "id": "review-web", "ip": HOST, "role": "web_server",
        "security_profile": "hardened", "vulnerabilities": ["oracle-secret"],
    }]}
    topology = {
        "edges": [{"source": "review-web", "target": "dst", "oracle": "private"}],
        "node_index": {
            "review-web": surface["nodes"][0],
            "dst": {"ip": "192.0.2.11", "security_profile": "vulnerable"},
        },
        "ground_truth": {"private": "oracle-secret"},
    }
    calls = []
    monkeypatch.setattr(runtime, "get_attack_surface", lambda: calls.append(1) or json.dumps(surface))
    monkeypatch.setattr(graph_tools, "_scenario_topology", topology)

    context = capture_context(tmp_path)
    snapshot = deepcopy(context)
    surface["nodes"][0]["role"] = "changed"
    topology["node_index"]["dst"]["ip"] = "192.0.2.99"
    topology["edges"].clear()

    assert calls == [1]
    assert context == snapshot
    assert context.surface_nodes == [{"id": "review-web", "ip": HOST, "role": "web_server"}]
    assert context.topology == {
        "edges": [{"source": "review-web", "target": "dst"}],
        "node_index": {"review-web": {"ip": HOST}, "dst": {"ip": "192.0.2.11"}},
    }


@pytest.mark.parametrize("device_id", [None, 17])
def test_malformed_device_id_does_not_abort_other_findings(context, device_id):
    write_candidates(context.run_dir, [finding(device_id=device_id), finding(endpoint="/healthy")])

    result = aggregate(context)

    assert result.raw["candidate_count"] == 2
    assert len(result.canonical["vulnerabilities"]) == 2
    assert any(item["endpoint"] == "/healthy" for item in result.canonical["vulnerabilities"])
    assert any(item["device_id"] == device_id for item in result.canonical["vulnerabilities"])


def test_concurrent_explicit_contexts_keep_provenance_and_ids_separate(tmp_path, monkeypatch):
    contexts = []
    for label in ("first", "second"):
        run_dir = tmp_path / label
        run_dir.mkdir()
        contexts.append(AggregationContext(run_dir=run_dir, tool_names=frozenset({"http_request"})))
        write_candidates(run_dir, [finding(endpoint=f"/{label}", evidence_ref=f"proof-{label}")])
    monkeypatch.setattr(runtime, "get_attack_surface", forbid_ambient)
    monkeypatch.setattr(graph_tools, "_scenario_topology", {"broken": "ambient graph"})

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(aggregate, contexts))

    for label, context, result in zip(("first", "second"), contexts, results):
        item, = result.canonical["vulnerabilities"]
        assert item["id"] == "VULN-001"
        assert item["endpoint"] == f"/{label}"
        assert item["evidence_refs"] == [f"proof-{label}"]
        assert item["_provenance"]["evidence_refs"] == [f"proof-{label}"]
        assert json.loads((context.run_dir / "03_vuln_analysis.json").read_text()) == result.canonical
