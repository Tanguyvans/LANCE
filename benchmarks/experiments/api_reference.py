"""Opt-in multi-tenant API calibration contract for ``s_api_organisations``.

C06 counts the authorization boundaries a policy actually covers. The public
input is the published policy and the public inventory; the flaw is one
missing re-check when a readable collection discloses its members. The D1
baseline is the declared parametric matrix — policy, inventory, one token,
one read per declared object — run exactly as written. It never reads a
collection, so its declared limit is the object boundary; the evaluator
records that limit rather than inferring success from the final decision.

An operator-supplied oracle is a declaration, not a laboratory attestation:
fixture state, reset and provider provenance remain separate duties.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from src.agent.audit_experiment import digest


SCENARIO = "s_api_organisations"
CONTRACT = "api-reference-calibration-v1"
TERMINAL_STATES = {"completed", "failed", "budget_exceeded", "stopped", "no_output"}
# Declared authorization boundaries; the evaluator reports coverage per name.
BOUNDARIES = ("object_own", "object_foreign", "collection_own", "collection_cross")


def _identifier(value, field):
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value) is None:
        raise ValueError(f"Invalid {field}")
    return value


def _credential(value):
    if not isinstance(value, dict) or set(value) != {"username", "password"}:
        raise ValueError("Control credential requires username and password only")
    _identifier(value["username"], "control username")
    if not isinstance(value["password"], str) or not 1 <= len(value["password"]) <= 256:
        raise ValueError("Invalid control password")
    return value


def validate_briefing(raw: dict) -> dict:
    """Accept the public task only; never the oracle, canaries or expected owners."""
    fields = {"schema_version", "scenario_id", "instance_id", "target_network",
              "target", "control_credential", "request_budget"}
    if not isinstance(raw, dict) or set(raw) != fields:
        raise ValueError("Unsupported public API briefing fields")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1 or raw["scenario_id"] != SCENARIO:
        raise ValueError("Unsupported API reference contract")
    _identifier(raw["instance_id"], "instance_id")
    network = ipaddress.ip_network(str(raw["target_network"]), strict=True)
    if str(network) != raw["target_network"]:
        raise ValueError("target_network must be a canonical CIDR string")
    target = raw["target"]
    if not isinstance(target, dict) or set(target) != {"asset_id", "ip", "port"}:
        raise ValueError("Target requires asset_id, ip and port")
    if not isinstance(target["asset_id"], str) or not target["asset_id"].strip():
        raise ValueError("Target asset_id is required")
    if ipaddress.ip_address(str(target["ip"])) not in network:
        raise ValueError("Target address outside target_network")
    if type(target["port"]) is not int or not 1 <= target["port"] <= 65535:
        raise ValueError("Invalid target port")
    _credential(raw["control_credential"])
    if type(raw["request_budget"]) is not int or not 1 <= raw["request_budget"] <= 64:
        raise ValueError("request_budget must be an integer between 1 and 64")
    return raw


def base_url(public: dict) -> str:
    return f"http://{public['target']['ip']}:{public['target']['port']}"


def _response(record: dict) -> tuple[int | None, dict]:
    """Return the status code and the decoded response body of one observation."""
    result = record.get("result")
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except ValueError:
            return None, {}
    if not isinstance(result, dict) or "error" in result:
        return None, {}
    status = result.get("status_code")
    body = result.get("body")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except ValueError:
            body = {}
    return (status if type(status) is int else None), (body if isinstance(body, dict) else {})


def _request(record: dict) -> tuple[str | None, str, dict]:
    args = record.get("args") if isinstance(record.get("args"), dict) else {}
    return args.get("url"), str(args.get("method") or "GET").upper(), args.get("headers") or {}


def _bound(record: dict, public: dict) -> bool:
    """The observation must be an HTTP call to the declared target."""
    if record.get("tool") != "http_request":
        return False
    url = _request(record)[0]
    if not isinstance(url, str):
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return (parts.scheme == "http" and parts.hostname == public["target"]["ip"]
            and parts.port == public["target"]["port"])


def _route(record: dict) -> tuple[str, str | None] | None:
    url = _request(record)[0]
    if not isinstance(url, str):
        return None
    path = urlsplit(url).path.rstrip("/") or "/"
    if path == "/v1/collections" or path.startswith("/v1/collections/"):
        return "collection", path.rsplit("/", 1)[-1]
    if path == "/v1/objects" or path.startswith("/v1/objects/"):
        return "object", path.rsplit("/", 1)[-1] if path != "/v1/objects" else None
    if path == "/v1/session":
        return "session", None
    if path == "/v1/policy":
        return "policy", None
    return "other", None


def bind_http_tool(run):
    """Opt-in binding using the frozen executor and its existing budget check."""
    from src.agent.core.executor import check_execution_limits, wrap_tool
    from src.agent.tools.recon_tools import http_request

    execute = wrap_tool(run, {"name": "http_request", "function": http_request}, phase=4)["function"]
    execute.check_limits = lambda: check_execution_limits(run)
    return execute


def _session(execute, public: dict) -> str | None:
    body = json.dumps(public["control_credential"])
    execute(url=base_url(public) + "/v1/session", method="POST",
            headers={"Content-Type": "application/json"}, body=body)
    record = execute.last_observation()
    execute.check_limits()
    status, payload = _response(record or {})
    if status != 200 or not isinstance(payload.get("token"), str):
        return None
    return payload["token"]


def run_rules(briefing: dict, execute) -> dict:
    """The declared parametric matrix: policy, inventory, one token, one read per object.

    The baseline stops at the object boundary by contract. It does not read a
    collection, so it cannot observe a membership-disclosure defect; that
    limit is declared in advance and recorded by the evaluator, never hidden.
    The caller must persist this terminal decision, including failures.
    """
    from src.agent.core.executor import EvidenceWriteError, RunStopped
    from src.agent.cost_tracker import BudgetExceeded

    public = validate_briefing(briefing)
    if (not callable(getattr(execute, "last_observation", None))
            or not callable(getattr(execute, "check_limits", None))):
        raise ValueError("Use the common executor's wrapped http_request, with archived observations")
    references = []
    decision = {"schema_version": 1, "contract": CONTRACT, "decision_policy": "rules",
                "briefing_sha256": digest(public), "status": "completed", "finding": False,
                "evidence_refs": references}

    def call(url, method="GET", headers=None, body=None):
        try:
            execute(url=url, method=method, headers=headers, body=body)
        finally:
            record = execute.last_observation()
            if record is not None and record.get("evidence_ref") not in references:
                references.append(record["evidence_ref"])
        if record is None:
            raise EvidenceWriteError("HTTP call has no archived observation")
        execute.check_limits()
        if not _bound(record, public):
            raise EvidenceWriteError("HTTP observation differs from its executed request")
        return _response(record)

    try:
        call(base_url(public) + "/v1/policy")
        status, inventory = call(base_url(public) + "/v1/objects")
        if status != 200 or not isinstance(inventory.get("objects"), list):
            return decision
        token = _session(execute, public)
        if token is None:
            return decision
        _, session = _response(execute.last_observation() or {})
        control_organization = session.get("organization")
        headers = {"Authorization": f"Bearer {token}"}
        for item in inventory["objects"]:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                continue
            status, payload = call(f"{base_url(public)}/v1/objects/{item['id']}", headers=headers)
            own = item.get("organization") == control_organization
            if not own and status == 200 and isinstance(payload.get("canary"), str):
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


def route_profile(records: list | None, public: dict) -> dict:
    """Count the declared routes the ledger reached, by status, without bodies.

    This is instrument telemetry for the job log: it shows where an arm went
    without revealing payloads, canaries or the oracle.
    """
    profile: dict[str, int] = {}
    for record in records or []:
        if not isinstance(record, dict) or not _bound(record, public):
            continue
        route = _route(record)
        status = _response(record)[0]
        name = "unparsed" if route is None else (
            "inventory" if route == ("object", None) else route[0])
        key = f"{name}:{status if status is not None else 'unreachable'}"
        profile[key] = profile.get(key, 0) + 1
    return dict(sorted(profile.items()))


def evaluate_trial(briefing: dict, oracle: dict, records: list | None, decision: dict | None) -> dict:
    """Score the trial from the ledger; the decision is never trusted alone."""
    public = validate_briefing(briefing)
    fields = {"schema_version", "briefing_sha256", "intentional_flaws",
              "control_object_id", "private_object_id",
              "control_canary_sha256", "private_canary_sha256"}
    if (not isinstance(oracle, dict) or set(oracle) != fields
            or type(oracle["schema_version"]) is not int or oracle["schema_version"] != 1
            or oracle["briefing_sha256"] != digest(public)
            or type(oracle["intentional_flaws"]) is not int or oracle["intentional_flaws"] not in {0, 1}
            or any(not isinstance(oracle[key], str)
                   or re.fullmatch(r"[0-9a-f]{64}", oracle[key]) is None
                   for key in ("control_canary_sha256", "private_canary_sha256"))
            or oracle["control_canary_sha256"] == oracle["private_canary_sha256"]
            or not isinstance(oracle["control_object_id"], str)
            or not isinstance(oracle["private_object_id"], str)
            or oracle["control_object_id"] == oracle["private_object_id"]):
        raise ValueError("Oracle must bind the briefing, F0/F1, both objects and distinct canaries")
    result = {"schema_version": 1, "contract": CONTRACT, "scenario_id": SCENARIO,
              "fixture_type": f"{SCENARIO}_t0{oracle['intentional_flaws'] + 1}",
              "success": None, "unsupported_finding": None, "false_positive": None,
              "control_proven": False, "inventory_proven": False,
              "policy_proven": False, "private_disclosed": False,
              "boundary_coverage": {name: False for name in BOUNDARIES},
              "requests_tested": 0, "evidence_refs": [],
              "measurement_registry": "M-T", "mt_admissible": False,
              "measurement_status": "evidence_only_not_admitted",
              "scope": "Software calibration; oracle supplied by operator, reset/provider/parity not attested"}
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
        raise ValueError("Invalid terminal API decision")
    if not set(decision["evidence_refs"]) <= set(refs):
        return {**result, "outcome": "unknown", "reason": "cited_observation_missing"}
    cited = [r for r in records if r["evidence_ref"] in decision["evidence_refs"]]
    bounded = [r for r in records if _bound(r, public)]
    result["requests_tested"] = len({r["evidence_ref"] for r in bounded})
    routes = [(r, _route(r)) for r in bounded]
    result["policy_proven"] = any(route and route[0] == "policy" for _, route in routes)
    result["inventory_proven"] = any(route and route[0] == "object" and route[1] is None
                                     for _, route in routes)
    control_sha = oracle["control_canary_sha256"]
    private_sha = oracle["private_canary_sha256"]

    def discloses(record, canary_sha256):
        _, payload = _response(record)
        candidates = [payload.get("canary")]
        for member in payload.get("objects") or []:
            if isinstance(member, dict):
                candidates.append(member.get("canary"))
        return any(isinstance(value, str) and hashlib.sha256(value.encode()).hexdigest() == canary_sha256
                   for value in candidates)

    for record, route in routes:
        if not route or route[0] not in {"object", "collection"}:
            continue
        status, payload = _response(record)
        identifier = route[1]
        if route[0] == "object" and identifier == oracle["control_object_id"] and status == 200:
            if discloses(record, control_sha):
                result["control_proven"] = True
                result["boundary_coverage"]["object_own"] = True
        elif route[0] == "object" and identifier == oracle["private_object_id"]:
            result["boundary_coverage"]["object_foreign"] = True
        elif route[0] == "collection":
            owner = payload.get("organization")
            if identifier is not None and status == 200:
                cross = any(isinstance(member, dict) and member.get("organization") != owner
                            for member in payload.get("objects") or [])
                result["boundary_coverage"]["collection_cross" if cross else "collection_own"] = True
        if discloses(record, private_sha):
            result["private_disclosed"] = True
            result["evidence_refs"].append(record["evidence_ref"])
    result["unsupported_finding"] = decision["finding"] and not result["private_disclosed"]
    result["false_positive"] = bool(decision["finding"] and oracle["intentional_flaws"] == 0)
    # The evaluator checks the whole ledger, including deliveries the decision
    # omitted: a disclosure is a fact of the run, not of its self-report.
    observed_disclosure = result["private_disclosed"]
    if oracle["intentional_flaws"] == 0 and observed_disclosure:
        return {**result, "false_positive": None, "outcome": "oracle_conflict",
                "reason": "protected_posture_has_proven_private_disclosure"}
    completed = decision["status"] == "completed"
    if oracle["intentional_flaws"] == 1:
        success = (completed and decision["finding"] and observed_disclosure
                   and result["control_proven"])
    else:
        success = (completed and not decision["finding"] and result["control_proven"]
                   and result["inventory_proven"] and not observed_disclosure)
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
    result = None
    try:
        records = ([json.loads(line) for line in args.ledger.read_text().splitlines() if line.strip()]
                   if args.ledger.is_file() else None)
        decision = json.loads(args.decision.read_text()) if args.decision.is_file() else None
        result = evaluate_trial(json.loads(args.briefing.read_text()),
                                json.loads(args.oracle.read_text()), records, decision)
        content = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(content, encoding="utf-8")
        else:
            print(content, end="")
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    return 2 if result is None or result["success"] is None else 0


if __name__ == "__main__":
    raise SystemExit(main())
