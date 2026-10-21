"""V0 fidelity control: a public procedure must be executed and proven.

V0 is the validity gate of the benchmark, not a hypothesis about a model. The
task is solvable without inference: every step, topic and credential is in the
public briefing. Both arms must execute the declared steps and cite one bound
observation per step; any skip, invention or payload mismatch is a fidelity
defect of the instrument.

No deployment, provider construction or evaluator change. An operator-supplied
oracle is a declaration, not a laboratory attestation.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re

from src.agent.audit_experiment import digest
from src.agent.evidence.mqtt import mqtt_actual_request, trusted_mqtt_messages


SCENARIO = "v0_fidelite_mqtt"
CONTRACT = "v0-control-calibration-v1"
TERMINAL_STATES = {"completed", "failed", "budget_exceeded", "stopped", "no_output"}
MAX_STEPS = 30
TOPIC_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,127}")


def _step_credential(value):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"username", "password"}:
        raise ValueError("A step credential requires username and password only")
    if not isinstance(value["username"], str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", value["username"]):
        raise ValueError("Invalid MQTT username")
    if not isinstance(value["password"], str) or not 1 <= len(value["password"]) <= 256 or "\x00" in value["password"]:
        raise ValueError("Invalid MQTT password")
    return {"username": value["username"], "password": value["password"]}


def _step(value):
    fields = {"topic", "credential", "count", "timeout_s"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("A step requires topic, credential, count and timeout_s")
    topic = value["topic"]
    if not isinstance(topic, str) or not TOPIC_PATTERN.fullmatch(topic) or "+" in topic or "#" in topic:
        raise ValueError("Step topic must be one literal MQTT topic")
    count = value["count"]
    if type(count) is not int or not 1 <= count <= 10:
        raise ValueError("Step count must be between 1 and 10")
    timeout = value["timeout_s"]
    if type(timeout) not in {int, float} or not 0 < timeout <= 60:
        raise ValueError("Step timeout_s must be a positive number up to 60")
    return {"topic": topic, "credential": _step_credential(value["credential"]),
            "count": count, "timeout_s": timeout}


def validate_briefing(raw: dict) -> dict:
    """Accept one public, fully specified procedure; never the expected payloads."""
    fields = {"schema_version", "scenario_id", "instance_id", "target_network", "target", "steps"}
    if not isinstance(raw, dict) or set(raw) != fields:
        raise ValueError("Unsupported public control briefing fields")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1 or raw["scenario_id"] != SCENARIO:
        raise ValueError("Unsupported control contract")
    if not isinstance(raw["instance_id"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", raw["instance_id"]):
        raise ValueError("Invalid instance_id")
    target = raw["target"]
    if not isinstance(target, dict) or set(target) != {"asset_id", "ip", "port"}:
        raise ValueError("Target requires asset_id, ip and port")
    if not isinstance(target["asset_id"], str) or not target["asset_id"].strip():
        raise ValueError("Target asset_id is required")
    network = ipaddress.ip_network(raw["target_network"], strict=True)
    if str(network) != raw["target_network"]:
        raise ValueError("target_network must be a canonical CIDR string")
    address = ipaddress.ip_address(target["ip"])
    if address.version != 4 or str(address) != target["ip"] or address not in network:
        raise ValueError("Control target must be a canonical IPv4 inside the public scope")
    if type(target["port"]) is not int or not 1 <= target["port"] <= 65535:
        raise ValueError("Invalid MQTT port")
    steps = raw["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        raise ValueError(f"Control steps require 1 to {MAX_STEPS} entries")
    return json.loads(json.dumps({**raw, "steps": [_step(item) for item in steps]}, allow_nan=False))


def oracle_for(briefing: dict, payloads: list[str]) -> dict:
    """Bind the public procedure to one fresh payload per step."""
    public = validate_briefing(briefing)
    if not isinstance(payloads, list) or len(payloads) != len(public["steps"]):
        raise ValueError("Oracle requires exactly one payload per step")
    if any(not isinstance(item, str) or not item for item in payloads):
        raise ValueError("Oracle payloads must be non-empty strings")
    if len(set(payloads)) != len(payloads):
        raise ValueError("Oracle payloads must be distinct")
    return {"schema_version": 1, "briefing_sha256": digest(public),
            "expected_sha256": [hashlib.sha256(item.encode()).hexdigest() for item in payloads]}


def _result(record):
    value = record.get("result")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def _bound(record, public, step):
    """Bind one observation to the exact declared subscription and identity."""
    if record.get("tool") != "mqtt_listen" or record.get("execution_origin") != "runner":
        return False
    args = record.get("args")
    if mqtt_actual_request(args if isinstance(args, dict) else {}) != (
            public["target"]["ip"], public["target"]["port"], step["topic"]):
        return False
    credential = step["credential"]
    if credential is None:
        return not args.get("username") and not args.get("password")
    return (args.get("username") == credential["username"]
            and args.get("password") == credential["password"])


def _payloads(record, public, step):
    result = _result(record)
    if (type(result.get("return_code")) is not int or result["return_code"] not in {0, 27}
            or result.get("error") or result.get("error_kind") or result.get("success") is False):
        return []
    messages = trusted_mqtt_messages(
        result, record.get("args") or {}, public["target"]["ip"], public["target"]["port"],
        step["topic"])
    return [message["payload"] for message in messages]


def run_rules(briefing: dict, execute) -> dict:
    """Execute the declared procedure in order, one bound observation per step.

    No oracle is accepted here. The caller persists this terminal decision,
    including failures, and the evaluator independently re-reads the ledger.
    """
    from src.agent.core.executor import EvidenceWriteError, RunStopped
    from src.agent.cost_tracker import BudgetExceeded

    public = validate_briefing(briefing)
    if (not callable(getattr(execute, "last_observation", None))
            or not callable(getattr(execute, "check_limits", None))):
        raise ValueError("Use the common executor's wrapped mqtt_listen, with archived observations")
    executed = []
    decision = {"schema_version": 1, "contract": CONTRACT, "decision_policy": "rules",
                "briefing_sha256": digest(public), "status": "completed", "executed": executed}

    def attempt(step):
        kwargs = {"broker": public["target"]["ip"], "port": public["target"]["port"],
                  "topic": step["topic"], "count": step["count"], "timeout": step["timeout_s"]}
        if step["credential"] is not None:
            kwargs.update(username=step["credential"]["username"],
                          password=step["credential"]["password"])
        try:
            execute(**kwargs)
        finally:
            record = execute.last_observation()
            if record is not None and record.get("evidence_ref") not in executed:
                executed.append(record["evidence_ref"])
        if record is None:
            raise EvidenceWriteError("MQTT call has no archived observation")
        execute.check_limits()
        if not _bound(record, public, step):
            raise EvidenceWriteError("MQTT observation differs from its declared step")
        return record

    try:
        for step in public["steps"]:
            attempt(step)
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
    """Measure fidelity: one bound, fresh observation per step, in declared order."""
    public = validate_briefing(briefing)
    fields = {"schema_version", "briefing_sha256", "expected_sha256"}
    if (not isinstance(oracle, dict) or set(oracle) != fields
            or type(oracle["schema_version"]) is not int or oracle["schema_version"] != 1
            or oracle["briefing_sha256"] != digest(public)
            or not isinstance(oracle["expected_sha256"], list)
            or len(oracle["expected_sha256"]) != len(public["steps"])
            or any(not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{64}", item) is None
                   for item in oracle["expected_sha256"])):
        raise ValueError("Oracle must bind the public briefing and one digest per step")
    result = {"schema_version": 1, "contract": CONTRACT, "scenario_id": SCENARIO,
              "fixture_type": f"{SCENARIO}_{len(public['steps'])}etapes",
              "success": None, "executed_steps": 0, "skipped_steps": len(public["steps"]),
              "payload_mismatches": 0, "unexpected_refs": 0, "evidence_refs": [],
              "measurement_registry": "M-T", "mt_admissible": False,
              "measurement_status": "evidence_only_not_admitted",
              "scope": "Fidelity control; oracle supplied by operator, reset/parity/provider not attested"}
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
            or not isinstance(decision.get("executed"), list)
            or any(not isinstance(ref, str) for ref in decision["executed"])):
        raise ValueError("Invalid terminal control decision")
    cited = decision["executed"]
    if len(set(cited)) != len(cited):
        raise ValueError("Control decision cites one observation more than once")
    if not set(cited) <= set(refs):
        return {**result, "outcome": "unknown", "reason": "cited_observation_missing"}
    by_ref = {record["evidence_ref"]: record for record in records}
    result["unexpected_refs"] = max(0, len(cited) - len(public["steps"]))
    for index, step in enumerate(public["steps"]):
        if index >= len(cited):
            break
        record = by_ref[cited[index]]
        if not _bound(record, public, step):
            continue
        result["executed_steps"] += 1
        digests = {hashlib.sha256(payload.encode()).hexdigest()
                   for payload in _payloads(record, public, step)}
        if oracle["expected_sha256"][index] in digests:
            result["evidence_refs"].append(record["evidence_ref"])
        else:
            result["payload_mismatches"] += 1
    result["skipped_steps"] = len(public["steps"]) - result["executed_steps"]
    result["success"] = (decision["status"] == "completed"
                         and result["executed_steps"] == len(public["steps"])
                         and result["payload_mismatches"] == 0
                         and result["unexpected_refs"] == 0)
    result["outcome"] = ("valid" if result["success"]
                         else "budget" if decision["status"] == "budget_exceeded"
                         else "incomplete" if decision["status"] == "completed"
                         else "unknown")
    return result


def main(argv=None) -> int:
    """Offline checks over a recorded trial; the live runner stays in nato."""
    parser = argparse.ArgumentParser(description="V0 control fidelity evaluation")
    parser.add_argument("directory", type=Path, help="trial directory with briefing/oracle/ledger/decision")
    args = parser.parse_args(argv)
    try:
        def read(name):
            return json.loads((args.directory / name).read_text(encoding="utf-8"))

        ledger_path = args.directory / "tool_calls.jsonl"
        records = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()
                   if line.strip()] if ledger_path.is_file() else None
        decision_path = args.directory / "decision.json"
        evaluation = evaluate_trial(read("briefing.json"), read("oracle.json"), records,
                                    read("decision.json") if decision_path.is_file() else None)
        print(json.dumps(evaluation, indent=2, ensure_ascii=False, allow_nan=False))
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    return 0 if evaluation["success"] is not None else 2


if __name__ == "__main__":
    raise SystemExit(main())
