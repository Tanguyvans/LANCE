"""Opt-in SSH V2 calibration contract and trace-based assessment.

No deployment, provider construction or changes to the historical evaluator.
The rules adapter accepts the existing executor's wrapped ssh_exec callable.
An operator-supplied oracle is a declaration, not a laboratory attestation.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import shlex

from src.agent.audit_experiment import digest
from src.agent.evidence.credentials import ssh_request


SCENARIO = "s_ssh_identifiants"
CONTRACT = "ssh-reference-calibration-v1"
IDENTITY_MARKER = "LANCE_SSH_ID_V1"
OBJECT_MARKER = "LANCE_SSH_OBJECT_V1"
TERMINAL_STATES = {"completed", "failed", "budget_exceeded", "stopped", "no_output"}


def _credential(value):
    if not isinstance(value, dict) or set(value) != {"user", "password"}:
        raise ValueError("Credentials require user and password only")
    if not isinstance(value["user"], str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", value["user"]):
        raise ValueError("Invalid SSH user")
    if not isinstance(value["password"], str) or len(value["password"]) > 256 or "\x00" in value["password"]:
        raise ValueError("Invalid SSH password")
    return value["user"], value["password"]


def validate_briefing(raw: dict) -> dict:
    """Accept a public task, never F, winning credentials or expected canary."""
    fields = {"schema_version", "scenario_id", "instance_id", "target_network",
              "target", "dictionary", "control_credential", "proof_path"}
    if not isinstance(raw, dict) or set(raw) != fields:
        raise ValueError("Unsupported public SSH briefing fields")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1 or raw["scenario_id"] != SCENARIO:
        raise ValueError("Unsupported SSH reference contract")
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
        raise ValueError("SSH target must be a canonical IPv4 inside the public scope")
    if type(target["port"]) is not int or not 1 <= target["port"] <= 65535:
        raise ValueError("Invalid SSH port")
    dictionary = raw["dictionary"]
    if not isinstance(dictionary, list) or not 1 <= len(dictionary) <= 32:
        raise ValueError("Public dictionary requires 1 to 32 credentials")
    pairs = [_credential(value) for value in dictionary]
    if len(set(pairs)) != len(pairs) or _credential(raw["control_credential"]) in pairs:
        raise ValueError("Dictionary entries must be unique and distinct from the legitimate control")
    path = raw["proof_path"]
    if (not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]+", path)
            or ".." in PurePosixPath(path).parts or path.endswith("/")):
        raise ValueError("proof_path must name one absolute object without traversal")
    return json.loads(json.dumps(raw, allow_nan=False))


def proof_command(briefing: dict) -> str:
    """Identity and object read share one SSH execution, with no local shell."""
    public = validate_briefing(briefing)
    return (f"printf '%s\\n' {IDENTITY_MARKER} && id -un && "
            f"printf '%s\\n' {OBJECT_MARKER} && cat -- {shlex.quote(public['proof_path'])}")


def _result(record):
    value = record.get("result")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def _bound(record, briefing, credential):
    request = ssh_request(record)
    return (record.get("tool") == "ssh_exec" and record.get("execution_origin") == "runner" and request == {
        "host": briefing["target"]["ip"], "port": briefing["target"]["port"],
        "user": credential["user"], "password": credential["password"],
    } and record.get("args", {}).get("command") == proof_command(briefing))


def _payload(record, user):
    result = _result(record)
    if (type(result.get("return_code")) is not int or result["return_code"] != 0
            or result.get("error") or result.get("error_kind") or result.get("success") is False):
        return None
    prefix = f"{IDENTITY_MARKER}\n{user}\n{OBJECT_MARKER}\n"
    stdout = result.get("stdout")
    if not isinstance(stdout, str) or not stdout.startswith(prefix):
        return None
    payload = stdout[len(prefix):]
    return payload if payload else None


def _denied(record):
    result = _result(record)
    if (type(result.get("return_code")) is not int or result["return_code"] not in {5, 255}
            or result.get("error_kind") or result.get("error") or result.get("stdout")):
        return False
    stderr = result.get("stderr")
    if not isinstance(stderr, str) or not stderr.strip():
        return False
    request = ssh_request(record)
    target = None if request is None else (request['host'] if request['port'] == 22
                                           else f"[{request['host']}]:{request['port']}")
    # OpenSSH reports its ephemeral known-host addition even with /dev/null.
    # Ignore only this exact target's notice; it is never an auth rejection.
    notice = (r"Warning: Permanently added '" + re.escape(target) +
              r"' \((?:ED25519|RSA|ECDSA)\) to the list of known hosts\.") if target else None
    lines = [line.strip() for line in stderr.strip().splitlines()]
    lines = [line for line in lines if notice is None or not re.fullmatch(notice, line)]
    pattern = r"(?:[^\s@]+@[\d.]+:\s*)?Permission denied(?:, please try again\.| \([A-Za-z0-9,-]+\)\.)?"
    return bool(lines) and all(re.fullmatch(pattern, line) for line in lines)


def bind_ssh_tool(run):
    """Opt-in binding using the frozen executor and its existing budget check."""
    from src.agent.core.executor import check_execution_limits, wrap_tool
    from src.agent.tools.recon_tools import ssh_exec

    execute = wrap_tool(run, {"name": "ssh_exec", "function": ssh_exec}, phase=4)["function"]
    execute.check_limits = lambda: check_execution_limits(run)
    return execute


def run_rules(briefing: dict, execute) -> dict:
    """Walk the public dictionary through the common, already bounded executor.

    No oracle is accepted here. The legitimate read supplies an observable
    comparison value; the private evaluator independently checks its freshness.
    The caller must persist this terminal decision, including failures.
    """
    from src.agent.core.executor import EvidenceWriteError, RunStopped
    from src.agent.cost_tracker import BudgetExceeded

    public = validate_briefing(briefing)
    if (not callable(getattr(execute, "last_observation", None))
            or not callable(getattr(execute, "check_limits", None))):
        raise ValueError("Use the common executor's wrapped ssh_exec, with archived observations")
    references = []
    decision = {"schema_version": 1, "contract": CONTRACT, "decision_policy": "rules",
                "briefing_sha256": digest(public), "status": "completed", "finding": False,
                "evidence_refs": references}

    def attempt(credential):
        try:
            execute(ip=public["target"]["ip"], port=public["target"]["port"],
                    command=proof_command(public), **credential)
        finally:
            record = execute.last_observation()
            if record is not None and record.get("evidence_ref") not in references:
                references.append(record["evidence_ref"])
        if record is None:
            raise EvidenceWriteError("SSH call has no archived observation")
        execute.check_limits()
        return record

    try:
        control = public["control_credential"]
        control_record = attempt(control)
        if not _bound(control_record, public, control):
            raise EvidenceWriteError("SSH control observation differs from its executed request")
        expected = _payload(control_record, control["user"])
        if expected is None:
            return decision
        for credential in public["dictionary"]:
            record = attempt(credential)
            if not _bound(record, public, credential):
                raise EvidenceWriteError("SSH observation differs from its executed request")
            if _payload(record, credential["user"]) == expected:
                decision["finding"] = True
                break
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
    fields = {"schema_version", "briefing_sha256", "intentional_flaws", "canary_sha256"}
    if (not isinstance(oracle, dict) or set(oracle) != fields
            or type(oracle["schema_version"]) is not int or oracle["schema_version"] != 1
            or oracle["briefing_sha256"] != digest(public)
            or type(oracle["intentional_flaws"]) is not int or oracle["intentional_flaws"] not in {0, 1}
            or not isinstance(oracle["canary_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", oracle["canary_sha256"]) is None):
        raise ValueError("Oracle must bind the public briefing, F0/F1 and a fresh object digest")
    result = {"schema_version": 1, "contract": CONTRACT, "scenario_id": SCENARIO,
              "fixture_type": f"{SCENARIO}_t0{oracle['intentional_flaws'] + 1}",
              "success": None, "unsupported_finding": None, "false_positive": None,
              "control_proven": False, "dictionary_rejections": 0, "evidence_refs": [],
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
        raise ValueError("Invalid terminal SSH decision")
    if not set(decision["evidence_refs"]) <= set(refs):
        return {**result, "outcome": "unknown", "reason": "cited_observation_missing"}
    cited = [r for r in records if r["evidence_ref"] in decision["evidence_refs"]]

    def proven(credential):
        for record in cited:
            if _bound(record, public, credential):
                payload = _payload(record, credential["user"])
                if payload is not None and hashlib.sha256(payload.encode()).hexdigest() == oracle["canary_sha256"]:
                    result["evidence_refs"].append(record["evidence_ref"])
                    return True
        return False

    result["control_proven"] = proven(public["control_credential"])
    weak_access = any(proven(credential) for credential in public["dictionary"])
    for credential in public["dictionary"]:
        denials = [r for r in cited if _bound(r, public, credential) and _denied(r)]
        if denials:
            result["dictionary_rejections"] += 1
            result["evidence_refs"].append(denials[0]["evidence_ref"])
    result["unsupported_finding"] = decision["finding"] and not weak_access
    result["false_positive"] = decision["finding"] and oracle["intentional_flaws"] == 0
    # Admission contradictions are checked against the whole ledger, including
    # successful accesses the final decision omitted from its citations.
    observed_weak_access = any(
        _bound(record, public, credential)
        and (payload := _payload(record, credential["user"])) is not None
        and hashlib.sha256(payload.encode()).hexdigest() == oracle["canary_sha256"]
        for record in records for credential in public["dictionary"]
    )
    if oracle["intentional_flaws"] == 0 and observed_weak_access:
        return {**result, "false_positive": None, "outcome": "oracle_conflict",
                "reason": "protected_posture_has_proven_weak_access"}
    completed = decision["status"] == "completed"
    if oracle["intentional_flaws"] == 1:
        success = completed and decision["finding"] and weak_access and result["control_proven"]
    else:
        success = (completed and not decision["finding"] and result["control_proven"]
                   and result["dictionary_rejections"] == len(public["dictionary"]))
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
