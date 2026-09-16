"""S1 regression tests for observation-backed MQTT Phase 3 grouping."""
import json
from unittest.mock import MagicMock

import pytest

from src.agent.phases.analysis.mqtt_grouping import group_mqtt_producer_findings
from src.agent.pipeline import Pipeline
from src.agent.registry import AGENTS


HOST = "192.0.2.11"
TOPIC = "smartcity/admin/credentials"
OTHER_TOPIC = "smartcity/config/network"
PAYLOAD = '{"db_pass":"P@ssw0rd123","api_key":"fixture-token"}'


def _frame(topic=TOPIC, payload=PAYLOAD):
    return json.dumps({
        "tst": "fixture", "topic": topic, "qos": 0, "retain": 1,
        "payload": payload,
    })


def _archive(tmp_path, *, messages=None, stdout=None, topic="#", port=1883, username=None):
    messages = messages if messages is not None else [(TOPIC, PAYLOAD)]
    complete_stdout = stdout if stdout is not None else "\n".join(_frame(*message) for message in messages) + "\n"
    args = {"broker": HOST, "port": port, "topic": topic}
    if username is not None:
        args["username"] = username
    entry = {
        "tool": "mqtt_listen", "phase": 3, "args": args,
        "result": {
            "stdout": complete_stdout, "stderr": "", "return_code": 0,
            "execution_attestation": {
                "protocol": "TCP", "host": HOST, "port": port,
                "topic": topic, "output_format": "mosquitto-json-v1",
            },
        },
    }
    (tmp_path / "tool_calls.jsonl").write_text(json.dumps(entry) + "\n")
    return entry


def _candidate(kind, *, vuln_type="data_exposure", endpoint="", details="candidate", **changes):
    value = {
        "id": kind, "_source_kind": kind,
        "device_id": "mqtt-1", "device_ip": HOST,
        "type": vuln_type, "severity": "MEDIUM", "service": "mqtt",
        "port": 1883, "protocol": "tcp", "endpoint": endpoint,
        "product": "", "version": "", "details": details, "evidence": "",
    }
    value.update(changes)
    return value


def _ids(groups):
    return [[item["id"] for item in group] for group, _ in groups]


def test_s1_data_exposure_model_and_scanner_share_complete_ledger_observation(tmp_path):
    _archive(tmp_path)
    model = _candidate(
        "model", endpoint=TOPIC,
        details="Credentials are exposed on the explicit MQTT topic",
        product="Mosquitto", version="2.0.21",
    )
    scanner = _candidate(
        "scanner", _source_kind="scanner_full",
        details="Credentials exposed in MQTT messages",
    )

    groups = group_mqtt_producer_findings([model, scanner], run_dir=tmp_path)

    assert _ids(groups) == [["model", "scanner"]]
    assert groups[0][1] is True
    assert "evidence_refs" not in model and "evidence_refs" not in scanner


@pytest.mark.parametrize("change", [
    {"endpoint": OTHER_TOPIC},
    {"product": "OtherBroker", "_source_kind": "scanner_full"},
    {"claim_id": "claim-other"},
    {"mqtt_topic": OTHER_TOPIC},
    {"topic_filter": OTHER_TOPIC},
    {"auth_mode": "authenticated"},
])
def test_s1_mqtt_grouping_keeps_conflicting_resources_and_claims_separate(tmp_path, change):
    _archive(tmp_path)
    model = _candidate("model", endpoint=TOPIC, details="Credentials on the admin topic", product="Mosquitto")
    scanner_changes = {"_source_kind": "scanner_full", "details": "Credentials exposed in MQTT messages", **change}
    scanner = _candidate("scanner", **scanner_changes)

    groups = group_mqtt_producer_findings([model, scanner], run_dir=tmp_path)

    assert _ids(groups) == [["model"], ["scanner"]]
    assert all(producer is False for _, producer in groups)


def test_no_auth_subscribe_pair_merges_but_publish_claim_does_not(tmp_path):
    _archive(tmp_path, messages=[("sensors/temp", "22")])
    model = _candidate(
        "model", vuln_type="no_auth",
        details="MQTT broker allows anonymous connections (subscribe without credentials)",
        evidence="mqtt_listen(topic=#) returned messages",
        product="Mosquitto",
    )
    scanner = _candidate(
        "scanner", vuln_type="no_auth", _source_kind="scanner_full",
        details="MQTT broker allows anonymous connections",
    )
    assert _ids(group_mqtt_producer_findings([model, scanner], run_dir=tmp_path)) == [["model", "scanner"]]

    publish = dict(model, id="publish", details="MQTT broker allows anonymous publish without credentials")
    groups = group_mqtt_producer_findings([publish, scanner], run_dir=tmp_path)
    assert {frozenset(group) for group in _ids(groups)} == {frozenset({"publish"}), frozenset({"scanner"})}


def test_s1_no_auth_invocation_hint_disambiguates_sys_capture_without_becoming_proof(tmp_path):
    general = _archive(tmp_path, messages=[("sensors/temp", "22")])
    system = _archive(tmp_path, topic="$SYS/#", messages=[("$SYS/broker/version", "2.0.21")])
    (tmp_path / "tool_calls.jsonl").write_text("\n".join(map(json.dumps, [general, system])))
    model = _candidate("model", vuln_type="no_auth", product="Mosquitto",
                       details="subscribe anonymously", evidence="mqtt_listen(topic=#) returned retained messages")
    scanner = _candidate("scanner", vuln_type="no_auth", _source_kind="scanner_full",
                         evidence='mqtt_listen(topic=#) — return_code=27, messages received:\n{"topic":"sens')
    assert _ids(group_mqtt_producer_findings([model, scanner], run_dir=tmp_path)) == [["model", "scanner"]]
    # Without an archived matching capture, the same prose proves nothing.
    (tmp_path / "tool_calls.jsonl").write_text(json.dumps(system))
    assert len(group_mqtt_producer_findings([model, scanner], run_dir=tmp_path)) == 2


def test_truncated_scanner_excerpt_and_model_verified_flag_are_not_proof(tmp_path):
    _archive(tmp_path, stdout='{"tst":"fixture","topic":"smartcity/admin/credentials","payload":"{"')
    model = _candidate("model", endpoint=TOPIC, verified=True, details="Credentials are exposed")
    scanner = _candidate("scanner", _source_kind="scanner_full", details="Credentials exposed in MQTT messages")

    groups = group_mqtt_producer_findings([model, scanner], run_dir=tmp_path)

    assert _ids(groups) == [["model"], ["scanner"]]


@pytest.mark.parametrize("field", ["username", "user", "auth_identity", "client_id"])
def test_different_mqtt_auth_identities_do_not_merge(tmp_path, field):
    _archive(tmp_path, messages=[("sensors/temp", "22")])
    model = _candidate(
        "model", vuln_type="no_auth",
        details="MQTT broker allows anonymous connections (subscribe without credentials)",
        **{field: "alice"},
    )
    scanner = _candidate(
        "scanner", vuln_type="no_auth", _source_kind="scanner_full",
        details="MQTT broker allows anonymous connections",
    )

    groups = group_mqtt_producer_findings([model, scanner], run_dir=tmp_path)

    assert {frozenset(group) for group in _ids(groups)} == {frozenset({"model"}), frozenset({"scanner"})}


def test_mismatched_explicit_port_does_not_use_a_same_host_observation(tmp_path):
    _archive(tmp_path, port=1883)
    model = _candidate("model", endpoint=TOPIC)
    scanner = _candidate("scanner", _source_kind="scanner_full", port=1884)

    groups = group_mqtt_producer_findings([model, scanner], run_dir=tmp_path)

    assert {frozenset(group) for group in _ids(groups)} == {frozenset({"model"}), frozenset({"scanner"})}


def test_mqtt_topics_remain_case_sensitive(tmp_path):
    _archive(tmp_path, messages=[("SmartCity/admin/credentials", PAYLOAD)])
    model = _candidate("model", endpoint=TOPIC)
    scanner = _candidate("scanner", _source_kind="scanner_full")

    groups = group_mqtt_producer_findings([model, scanner], run_dir=tmp_path)

    assert {frozenset(group) for group in _ids(groups)} == {frozenset({"model"}), frozenset({"scanner"})}


def test_auth_identity_values_remain_exact_and_case_sensitive(tmp_path):
    _archive(tmp_path, messages=[("sensors/temp", "22")])
    model = _candidate(
        "model", vuln_type="no_auth",
        details="MQTT broker allows anonymous connections (subscribe without credentials)",
        auth_identity="Alice",
    )
    scanner = _candidate(
        "scanner", vuln_type="no_auth", _source_kind="scanner_full",
        details="MQTT broker allows anonymous connections", auth_identity="alice",
    )

    groups = group_mqtt_producer_findings([model, scanner], run_dir=tmp_path)

    assert {frozenset(group) for group in _ids(groups)} == {frozenset({"model"}), frozenset({"scanner"})}


def test_ambiguous_generic_candidate_is_not_greedily_bridged_between_product_anchors(tmp_path):
    _archive(tmp_path)
    first = _candidate("model-x", endpoint=TOPIC, product="BrokerX", version="1")
    second = _candidate("model-y", endpoint=TOPIC, product="BrokerY", version="2")
    generic = _candidate("scanner", _source_kind="scanner_full", details="Credentials exposed in MQTT messages")

    groups = group_mqtt_producer_findings([generic, second, first], run_dir=tmp_path)

    assert {frozenset(group) for group in _ids(groups)} == {
        frozenset({"model-x"}), frozenset({"model-y"}), frozenset({"scanner"}),
    }


def test_missing_complete_record_keeps_candidates_separate_even_when_text_matches(tmp_path):
    model = _candidate("model", endpoint=TOPIC, details="Credentials exposed", evidence=PAYLOAD)
    scanner = _candidate("scanner", _source_kind="scanner_full", details="Credentials exposed in MQTT messages", evidence=PAYLOAD)

    groups = group_mqtt_producer_findings([model, scanner], run_dir=tmp_path)

    assert _ids(groups) == [["model"], ["scanner"]]


@pytest.mark.parametrize("change", [
    {"return_code": "9" * 5000}, {"return_code": 0.5},
    {"output_truncated": True}, {"success": False}, {"cancelled": True},
])
def test_invalid_archived_outcome_never_supports_grouping(tmp_path, change):
    entry = _archive(tmp_path)
    entry["result"].update(change)
    (tmp_path / "tool_calls.jsonl").write_text(json.dumps(entry) + "\n")
    model = _candidate("model", endpoint=TOPIC, product="Mosquitto")
    scanner = _candidate("scanner", _source_kind="scanner_full")
    assert len(group_mqtt_producer_findings([model, scanner], run_dir=tmp_path)) == 2


def test_group_order_is_deterministic_and_ambiguous_broad_observation_does_not_bridge(tmp_path):
    _archive(tmp_path, messages=[(TOPIC, PAYLOAD), (OTHER_TOPIC, "password=other")])
    model = _candidate("model", endpoint=TOPIC, details="Credentials on admin topic")
    scanner = _candidate("scanner", _source_kind="scanner_full", details="Credentials exposed in MQTT messages")
    first = group_mqtt_producer_findings([model, scanner], run_dir=tmp_path)
    second = group_mqtt_producer_findings([scanner, model], run_dir=tmp_path)
    assert _ids(first) == _ids(second) == [["model"], ["scanner"]]


def test_pipeline_s1_aggregation_schedules_each_distinct_claim_once_without_laundering_refs(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr("src.agent.pipeline.OUTPUT_DIR", tmp_path)
    monkeypatch.setattr(
        "src.agent.core.runtime.get_attack_surface",
        lambda: json.dumps([{"id": "mqtt-1", "ip": HOST, "role": "mqtt_broker"}]),
    )
    provider = MagicMock()
    provider.provider = "test"
    provider.model = "test"
    provider.chat_with_tools.return_value = "Done."
    pipeline = Pipeline(provider=provider, execution_profile="full")
    scan_entry = _archive(pipeline.run_dir)
    (pipeline.run_dir / "03_scans").mkdir()
    (pipeline.run_dir / "03_scans" / "mqtt-1.json").write_text(
        json.dumps({"mqtt": [{**scan_entry, "kwargs": scan_entry.pop("args")}]}),
    )
    (pipeline.run_dir / "03_device_mqtt-1.json").write_text(json.dumps({
        "vulnerabilities": [{
            "id": "VULN005", "device_id": "mqtt-1", "device_ip": HOST,
            "type": "data_exposure", "severity": "MEDIUM", "service": "mqtt",
            "port": 1883, "protocol": "tcp", "endpoint": TOPIC,
            "product": "Mosquitto", "version": "2.0.21",
            "details": "Credentials are exposed on smartcity/admin/credentials",
            "evidence": "",
        }, {
            "id": "VULN008", "device_id": "mqtt-1", "device_ip": HOST,
            "type": "no_auth", "severity": "HIGH", "service": "mqtt",
            "port": 1883, "protocol": "tcp", "endpoint": "",
            "product": "Mosquitto", "version": "",
            "details": "MQTT broker allows anonymous connections (subscribe without credentials)",
            "evidence": "mqtt_listen(topic=#) returned messages",
        }],
    }))

    pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])

    pipeline._run_exploit_agents(AGENTS["exploitation"])

    canonical = json.loads((pipeline.run_dir / "03_vuln_analysis.json").read_text())
    raw = json.loads((pipeline.run_dir / "03_vuln_analysis_raw.json").read_text())
    assert len(canonical["vulnerabilities"]) == 2
    assert {item["type"] for item in canonical["vulnerabilities"]} == {"data_exposure", "no_auth"}
    assert pipeline._phase4_schedule["candidate_count"] == 2
    assert pipeline._phase4_schedule["scheduled_count"] == 2
    assert all(
        item["_provenance"]["grouping_basis"] == "archived_phase3_mqtt_observation"
        and "evidence_refs" not in item
        and {source["source_kind"] for source in item["_provenance"]["candidate_sources"].values()} == {"model", "scanner_full"}
        for item in canonical["vulnerabilities"]
    )
    assert raw["candidate_count"] == 4
    assert {item["raw_finding"]["id"] for item in raw["candidates"] if item["source_kind"] == "model"} == {"VULN005", "VULN008"}
    assert sum(item["source_kind"] == "scanner_full" for item in raw["candidates"]) == 2
