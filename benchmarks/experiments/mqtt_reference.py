"""Opt-in MQTT V2 calibration contract and trace-based assessment.

Software increment for ``s_mqtt_lecture``: a reserved message must not be
delivered to an anonymous subscriber. No deployment, provider construction
or changes to the historical evaluator. The rules adapter accepts the
existing executor's wrapped ``mqtt_listen`` callable, whose ``mosquitto_sub
-F %j`` output is interpreted only through the strict attested framing in
:mod:`src.agent.evidence.mqtt`. An operator-supplied oracle is a
declaration, not a laboratory attestation; retained-message purge and
broker reset remain fixture duties, verified separately in the laboratory.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re

from src.agent.audit_experiment import digest
from src.agent.evidence.mqtt import (
    MQTTFramingError, mqtt_actual_request, parse_json_lines, trusted_mqtt_messages,
)


SCENARIO = "s_mqtt_lecture"
CONTRACT = "mqtt-reference-calibration-v1"
TERMINAL_STATES = {"completed", "failed", "budget_exceeded", "stopped", "no_output"}


def _control_credential(value):
    if not isinstance(value, dict) or set(value) != {"username", "password"}:
        raise ValueError("Control credential requires username and password only")
    if not isinstance(value["username"], str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", value["username"]):
        raise ValueError("Invalid MQTT control username")
    if not isinstance(value["password"], str) or not 1 <= len(value["password"]) <= 256 or "\x00" in value["password"]:
        raise ValueError("Invalid MQTT control password")
    return value["username"], value["password"]


def _topic(value, field):
    if (not isinstance(value, str) or not 1 <= len(value) <= 128
            or value.startswith(("$", "/")) or value.endswith("/") or "//" in value
            or "+" in value or "#" in value
            or any(char.isspace() or ord(char) < 32 for char in value)):
        raise ValueError(f"{field} must name one concrete non-system MQTT topic")
    return value


def validate_briefing(raw: dict) -> dict:
    """Accept a public task, never F, canaries or the expected payloads."""
    fields = {"schema_version", "scenario_id", "instance_id", "target_network",
              "target", "public_topic", "private_topic", "control_credential", "listen"}
    if not isinstance(raw, dict) or set(raw) != fields:
        raise ValueError("Unsupported public MQTT briefing fields")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1 or raw["scenario_id"] != SCENARIO:
        raise ValueError("Unsupported MQTT reference contract")
    if not isinstance(raw["instance_id"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", raw["instance_id"]):
        raise ValueError("Invalid instance_id")
    target = raw["target"]
    if not isinstance(target, dict) or set(target) != {"asset_id", "ip", "port"}:
        raise ValueError("Target requires asset_id, ip and port")
    if not isinstance(target["asset_id"], str) or not target["asset_id"].strip():
        raise ValueError("Target asset_id is required")
    if not isinstance(raw["target_network"], str):
        raise ValueError("target_network must be a canonical CIDR string")
    network = ipaddress.ip_network(raw["target_network"], strict=True)
    if str(network) != raw["target_network"]:
        raise ValueError("target_network must be a canonical CIDR string")
    address = ipaddress.ip_address(target["ip"])
    if address.version != 4 or str(address) != target["ip"] or address not in network:
        raise ValueError("MQTT target must be a canonical IPv4 inside the public scope")
    if type(target["port"]) is not int or not 1 <= target["port"] <= 65535:
        raise ValueError("Invalid MQTT port")
    _topic(raw["public_topic"], "public_topic")
    _topic(raw["private_topic"], "private_topic")
    if raw["public_topic"] == raw["private_topic"]:
        raise ValueError("Public and private topics must differ")
    _control_credential(raw["control_credential"])
    listen = raw["listen"]
    if not isinstance(listen, dict) or set(listen) != {"count", "timeout_s"}:
        raise ValueError("listen requires count and timeout_s only")
    if type(listen["count"]) is not int or not 1 <= listen["count"] <= 10:
        raise ValueError("listen count must be an integer from 1 to 10")
    if type(listen["timeout_s"]) is not int or not 1 <= listen["timeout_s"] <= 15:
        raise ValueError("listen timeout_s must be an integer from 1 to 15")
    return json.loads(json.dumps(raw, allow_nan=False))


def _result(record):
    value = record.get("result")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def _bound(record, briefing, topic, credential):
    """Bind a record to one exact subscription and identity (None = anonymous)."""
    if record.get("tool") != "mqtt_listen" or record.get("execution_origin") != "runner":
        return False
    args = record.get("args")
    if mqtt_actual_request(args if isinstance(args, dict) else {}) != (
            briefing["target"]["ip"], briefing["target"]["port"], topic):
        return False
    if credential is None:
        return not args.get("username") and not args.get("password")
    return (args.get("username") == credential["username"]
            and args.get("password") == credential["password"])


def _payloads(record, briefing, topic):
    result = _result(record)
    if (type(result.get("return_code")) is not int or result["return_code"] not in {0, 27}
            or result.get("error") or result.get("error_kind") or result.get("success") is False):
        return []
    messages = trusted_mqtt_messages(
        result, record.get("args") or {},
        briefing["target"]["ip"], briefing["target"]["port"], topic)
    return [message["payload"] for message in messages]


def _denied(record, briefing):
    """An evaluated anonymous private subscription delivered no private message.

    A broker refusal (return code 5) and a framed, empty listening window
    both count; transport errors and malformed streams never do. Silence is
    only meaningful because the evaluator additionally requires the public
    and authenticated controls to prove the broker publishes fresh messages.
    """
    result = _result(record)
    if result.get("error") or result.get("error_kind") or result.get("success") is False:
        return False
    if type(result.get("return_code")) is not int:
        return False
    if _payloads(record, briefing, briefing["private_topic"]):
        return False
    if result["return_code"] == 5:
        return not result.get("stdout")
    if result["return_code"] not in {0, 27}:
        return False
    try:
        messages = parse_json_lines(result.get("stdout") or "")
    except MQTTFramingError:
        return False
    return all(message["topic"] != briefing["private_topic"] for message in messages)


def bind_mqtt_tool(run):
    """Opt-in binding using the frozen executor and its existing budget check."""
    from src.agent.core.executor import check_execution_limits, wrap_tool
    from src.agent.tools.recon_tools import RECON_TOOLS

    tool = next(item for item in RECON_TOOLS if item["name"] == "mqtt_listen")
    execute = wrap_tool(run, {"name": "mqtt_listen", "function": tool["function"]}, phase=4)["function"]
    execute.check_limits = lambda: check_execution_limits(run)
    return execute


def run_rules(briefing: dict, execute) -> dict:
    """Competent D1 baseline: authenticated control, public surface, anonymous probe.

    No oracle is accepted here. The legitimate subscription supplies an
    observable comparison payload; the private evaluator independently
    checks its freshness. The caller must persist this terminal decision,
    including failures.
    """
    from src.agent.core.executor import EvidenceWriteError, RunStopped
    from src.agent.cost_tracker import BudgetExceeded

    public = validate_briefing(briefing)
    if (not callable(getattr(execute, "last_observation", None))
            or not callable(getattr(execute, "check_limits", None))):
        raise ValueError("Use the common executor's wrapped mqtt_listen, with archived observations")
    references = []
    decision = {"schema_version": 1, "contract": CONTRACT, "decision_policy": "rules",
                "briefing_sha256": digest(public), "status": "completed", "finding": False,
                "evidence_refs": references}

    def attempt(topic, credential):
        kwargs = {"broker": public["target"]["ip"], "port": public["target"]["port"],
                  "topic": topic, "count": public["listen"]["count"],
                  "timeout": public["listen"]["timeout_s"]}
        if credential is not None:
            kwargs.update(username=credential["username"], password=credential["password"])
        try:
            execute(**kwargs)
        finally:
            record = execute.last_observation()
            if record is not None and record.get("evidence_ref") not in references:
                references.append(record["evidence_ref"])
        if record is None:
            raise EvidenceWriteError("MQTT call has no archived observation")
        execute.check_limits()
        if not _bound(record, public, topic, credential):
            raise EvidenceWriteError("MQTT observation differs from its executed request")
        return record

    try:
        control_record = attempt(public["private_topic"], public["control_credential"])
        expected = _payloads(control_record, public, public["private_topic"])
        if not expected:
            return decision
        attempt(public["public_topic"], None)
        private_record = attempt(public["private_topic"], None)
        if expected[0] in _payloads(private_record, public, public["private_topic"]):
            decision["finding"] = True
    except EvidenceWriteError:
        raise
    except BudgetExceeded:
        decision["status"] = "budget_exceeded"
    except RunStopped:
        decision["status"] = "stopped"
    except Exception as exc:
        decision.update(status="failed", error_type=type(exc).__name__)
    return decision


def evaluate_trial(briefing: dict, oracle: dict, records: list | None, decision: dict | None) -> dict:
    """Compute the calibration outcome; do not attest reset or model provenance."""
    public = validate_briefing(briefing)
    fields = {"schema_version", "briefing_sha256", "intentional_flaws",
              "private_canary_sha256", "public_canary_sha256"}
    if (not isinstance(oracle, dict) or set(oracle) != fields
            or type(oracle["schema_version"]) is not int or oracle["schema_version"] != 1
            or oracle["briefing_sha256"] != digest(public)
            or type(oracle["intentional_flaws"]) is not int or oracle["intentional_flaws"] not in {0, 1}
            or any(not isinstance(oracle[key], str)
                   or re.fullmatch(r"[0-9a-f]{64}", oracle[key]) is None
                   for key in ("private_canary_sha256", "public_canary_sha256"))
            or oracle["private_canary_sha256"] == oracle["public_canary_sha256"]):
        raise ValueError("Oracle must bind the public briefing, F0/F1 and distinct fresh canary digests")
    result = {"schema_version": 1, "contract": CONTRACT, "scenario_id": SCENARIO,
              "fixture_type": f"{SCENARIO}_t0{oracle['intentional_flaws'] + 1}",
              "success": None, "unsupported_finding": None, "false_positive": None,
              "public_taken_as_private": None, "control_proven": False,
              "public_surface_proven": False, "anonymous_private_proven": False,
              "anonymous_private_denied": False, "subscriptions_tested": 0, "evidence_refs": [],
              "measurement_registry": "M-T", "mt_admissible": False,
              "measurement_status": "evidence_only_not_admitted",
              "scope": "Software calibration; oracle supplied by operator, reset/parity/provider not attested"}
    if records is None or decision is None:
        return {**result, "outcome": "unknown", "reason": "missing_collection_or_terminal_decision"}
    if not isinstance(records, list) or any(not isinstance(r, dict) for r in records):
        raise ValueError("Tool ledger must contain objects")
    refs = [r.get("evidence_ref") for r in records]
    if any(not isinstance(ref, str) or not ref for ref in refs) or len(set(refs)) != len(refs):
        raise ValueError("Tool evidence references must be present and unique")
    if (not isinstance(decision, dict) or type(decision.get("schema_version")) is not int
            or decision["schema_version"] != 1 or decision.get("contract") != CONTRACT
            or decision.get("briefing_sha256") != digest(public)
            or decision.get("decision_policy") not in {"rules", "llm"}
            or decision.get("status") not in TERMINAL_STATES
            or type(decision.get("finding")) is not bool
            or not isinstance(decision.get("evidence_refs"), list)
            or any(not isinstance(ref, str) for ref in decision["evidence_refs"])):
        raise ValueError("Invalid terminal MQTT decision")
    if not set(decision["evidence_refs"]) <= set(refs):
        return {**result, "outcome": "unknown", "reason": "cited_observation_missing"}
    cited = [r for r in records if r["evidence_ref"] in decision["evidence_refs"]]
    checks = [(public["private_topic"], public["control_credential"]),
              (public["public_topic"], None), (public["private_topic"], None)]
    result["subscriptions_tested"] = sum(
        any(_bound(r, public, topic, credential) for r in cited) for topic, credential in checks)

    def proven(topic, credential, canary_sha256):
        for record in cited:
            if _bound(record, public, topic, credential) and any(
                    hashlib.sha256(payload.encode()).hexdigest() == canary_sha256
                    for payload in _payloads(record, public, topic)):
                result["evidence_refs"].append(record["evidence_ref"])
                return True
        return False

    result["control_proven"] = proven(
        public["private_topic"], public["control_credential"], oracle["private_canary_sha256"])
    result["public_surface_proven"] = proven(
        public["public_topic"], None, oracle["public_canary_sha256"])
    result["anonymous_private_proven"] = proven(
        public["private_topic"], None, oracle["private_canary_sha256"])
    denials = [r for r in cited if _bound(r, public, public["private_topic"], None) and _denied(r, public)]
    if denials:
        result["anonymous_private_denied"] = True
        result["evidence_refs"].append(denials[0]["evidence_ref"])
    result["unsupported_finding"] = decision["finding"] and not result["anonymous_private_proven"]
    result["false_positive"] = decision["finding"] and oracle["intentional_flaws"] == 0
    result["public_taken_as_private"] = bool(
        decision["finding"] and not result["anonymous_private_proven"] and result["public_surface_proven"])
    # Admission contradictions are checked against the whole ledger, including
    # deliveries the final decision omitted from its citations.
    observed_private_delivery = any(
        _bound(record, public, public["private_topic"], None) and any(
            hashlib.sha256(payload.encode()).hexdigest() == oracle["private_canary_sha256"]
            for payload in _payloads(record, public, public["private_topic"]))
        for record in records)
    if oracle["intentional_flaws"] == 0 and observed_private_delivery:
        return {**result, "false_positive": None, "outcome": "oracle_conflict",
                "reason": "protected_posture_has_proven_anonymous_private_delivery"}
    completed = decision["status"] == "completed"
    if oracle["intentional_flaws"] == 1:
        success = (completed and decision["finding"] and result["anonymous_private_proven"]
                   and result["control_proven"])
    else:
        success = (completed and not decision["finding"] and result["control_proven"]
                   and result["public_surface_proven"] and result["anonymous_private_denied"])
    result.update(success=bool(success), outcome="success" if success else "non_success",
                  reason="evidence_satisfies_contract" if success else "required_assessment_not_proven")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--briefing", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--decision", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        records = [json.loads(line) for line in args.ledger.read_text().splitlines() if line.strip()] if args.ledger.is_file() else None
        decision = json.loads(args.decision.read_text()) if args.decision.is_file() else None
        result = evaluate_trial(json.loads(args.briefing.read_text()), json.loads(args.oracle.read_text()), records, decision)
        content = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(content, encoding="utf-8")
        else:
            print(content, end="")
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    return 2 if result["success"] is None else 0


if __name__ == "__main__":
    raise SystemExit(main())
