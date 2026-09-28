"""Bounded verification policy using the same plans, executor and evidence rules."""
from __future__ import annotations

import errno
import json
import re
import subprocess
import threading

from src.agent.core.executor import EvidenceWriteError, check_execution_limits
from src.agent.cost_tracker import BudgetExceeded
from src.agent.phases.verification.contract import _phase4_verification_plan
from src.agent.phases.verification.evidence import _exploit_relpath, _tool_records_for_vuln
from src.agent.exploit_evidence import synthesize_exploit_result


# These are observation rules, never proof rules. Verdicts stay in the common
# evidence synthesizer. Both the version and resource hash are archived.
MAX_TRANSIENT_RETRIES = 1
READ_ONLY_TOOLS = {"http_get", "curl_headers", "ssh_audit", "tls_inspect", "ftp_list"}


def _observation(raw, error=None, *, tool=None):
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = {}
    data = raw if isinstance(raw, dict) else {}
    return_code = data.get("return_code")
    code = data.get("status_code")
    if type(code) is not int:
        match = re.search(r"(?im)^HTTP/\S+\s+(\d{3})\b", str(data.get("stdout", "")))
        code = int(match[1]) if match else None
    if code in {401, 403} or (
            tool in {"mqtt_listen", "mqtt_ws_listen"} and return_code == 5):
        return "access_denied"
    if tool == "tls_inspect" and data.get("status") == "not_tls":
        return "negative_response"
    if data.get("error_kind"):
        return "tool_refused"
    transient_exception = isinstance(error, (TimeoutError, ConnectionResetError, subprocess.TimeoutExpired)) or (
        isinstance(error, OSError) and error.errno in {errno.ETIMEDOUT, errno.ECONNRESET, errno.ECONNABORTED}
    )
    # Tool adapters sometimes return errors instead of raising them. Match only
    # their diagnostic fields, never arbitrary response-body prose.
    diagnostic = str(data.get("error") or "")
    transient_exit = type(return_code) is int and (
        tool in {"http_get", "curl_headers", "ftp_list"} and return_code in {28, 52, 55, 56}
        or tool in {"mqtt_listen", "mqtt_ws_listen"} and return_code == 27
        or return_code == -1 and str(data.get("stderr", "")).startswith("Command timed out after ")
    )
    if (transient_exception or data.get("timed_out") is True
            or code in {408, 502, 503, 504}
            or transient_exit
            or re.match(r"^(?:Timeout|ReadTimeout|ConnectTimeout|TimeoutError|ConnectionResetError|ConnectionAbortedError):", diagnostic)):
        return "transient_error"
    if error or data.get("error") or data.get("ok") is False or data.get("return_code", 0) not in (0, None):
        return "tool_error"
    if code is not None and code >= 300:
        return "negative_response"
    return "response"


def _repeatable(tool, args):
    if tool == "ftp_list":
        return args.get("user") in (None, "", "anonymous:")
    if tool == "http_request":
        return str(args.get("method", "GET")).upper() in {"GET", "HEAD"} and not args.get("body")
    if tool in {"mqtt_listen", "mqtt_ws_listen"}:
        return not args.get("username") and not args.get("password")
    return tool in READ_ONLY_TOOLS


def _record_decision(run, identifier, attempt, tool, observation, decision, entry):
    record = {"vuln_id": identifier, "attempt": attempt, "tool": tool,
              "observation": observation, "decision": decision,
              "evidence_ref": entry.get("evidence_ref") if entry else None}
    try:
        with (run.run_dir / "04_rules_decisions.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
    except OSError as exc:
        run._evidence_integrity_failed = True
        raise EvidenceWriteError("Cannot archive rules decision") from exc


def _verify_candidate(run, vuln, tools):
    identifier = vuln["id"]
    plan = _phase4_verification_plan(vuln, compact=False)
    name, args = plan.get("tool"), plan.get("args_hint")
    if plan.get("plan_error") or not args or not callable(tools.get(name, {}).get("function")):
        run._phase4_execution_errors[identifier] = [{
            "stage": "rules_plan", "kind": "unsupported",
            "reason": str(plan.get("plan_error") or "No available bounded probe with complete arguments"),
        }]
        _record_decision(run, identifier, 0, name, "unsupported", "stop_indeterminate", None)
        return
    retries, attempt, used_alternative = 0, 0, False
    while True:
        check_execution_limits(run)
        attempt += 1
        fn = tools[name]["function"]
        raw, error = None, None
        try:
            raw = fn(**args)
        except (BudgetExceeded, EvidenceWriteError):
            raise
        except Exception as exc:
            error = exc
        observation = _observation(raw, error, tool=name)
        verdict = synthesize_exploit_result(
            vuln, _tool_records_for_vuln(run.run_dir, identifier), compact=False,
        )
        alternative = (
            not used_alternative and observation == "response"
            and name in {"http_get", "curl_headers"} and set(args) == {"url"}
            and callable(tools.get("http_request", {}).get("function"))
        )
        retry = (observation == "transient_error" and _repeatable(name, args)
                 and retries < MAX_TRANSIENT_RETRIES)
        if verdict["status"] == "EXPLOITED":
            decision = "stop_confirmed"
        elif retry:
            decision = "retry_same_probe"
        elif alternative:
            decision = "inspect_http_response"
        else:
            decision = "stop_unconfirmed"
        entry = fn.last_observation() if hasattr(fn, "last_observation") else None
        _record_decision(run, identifier, attempt, name, observation, decision, entry)
        if decision == "retry_same_probe":
            retries += 1
            continue
        if decision == "inspect_http_response":
            # Same URL and anonymous GET; no new path, identity, redirect or
            # write operation is invented. The structured response adds status
            # and headers to body-only/truncated curl observations.
            name, args = "http_request", {"url": args["url"], "method": "GET", "follow_redirects": False}
            used_alternative = True
            continue
        if decision != "stop_confirmed" and observation in {"transient_error", "tool_error", "tool_refused"}:
            run._phase4_execution_errors[identifier] = [{
                "stage": "rules_probe", "kind": observation,
                "exception_type": type(error).__name__ if error else None,
            }]
        return


def verify(run, config, stream_callback=None):
    candidates = json.loads((run.run_dir / "03_vuln_analysis.json").read_text())["vulnerabilities"]
    tools = {t["name"]: t for t in run._resolve_tools(config)}
    run._exploit_tool_context = threading.local()
    run._phase4_execution_errors = {}
    run._phase4_execution_status = "completed"
    run._phase4_schedule = {
        "candidate_count": len(candidates), "scheduled_count": len(candidates),
        "scheduled_vuln_ids": [v["id"] for v in candidates],
        "skipped_count": 0, "skipped_candidates": [],
    }
    for vuln in candidates:
        check_execution_limits(run)
        identifier = vuln["id"]
        run._exploit_tool_context.vulnerability = {
            "vuln_id": identifier, "device_id": vuln.get("device_id"),
            "device_ip": vuln.get("device_ip"), "vuln_type": vuln.get("type"),
            **{key: vuln.get(key, "") for key in ("service", "port", "protocol", "endpoint", "product")},
        }
        run.tracker.start_phase(f"rules_verify_{identifier}")
        try:
            _verify_candidate(run, vuln, tools)
            if identifier in run._phase4_execution_errors:
                run._phase4_execution_status = "executed_with_worker_errors"
        finally:
            run._exploit_tool_context.vulnerability = None
            run.tracker.end_phase()
        result = synthesize_exploit_result(vuln, _tool_records_for_vuln(run.run_dir, identifier), compact=False)
        path = run.run_dir / _exploit_relpath(vuln.get("device_id", "unknown"), vuln.get("type", ""), identifier)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    run._aggregate_exploit_results()
