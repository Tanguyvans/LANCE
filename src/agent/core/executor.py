"""The common tool execution boundary for every phase and model profile.

Destination checks here are application guards, not an OS sandbox. Free-form
programs without a verifiable destination cannot be authorized by these guards.
"""
from __future__ import annotations

from datetime import datetime
import json
import time
import threading
from uuid import uuid4

from src.agent.phases.intrusion.scope import _intrusion_scope_violation
from src.agent.tools.deliverable import bind_deliverable_tool
from src.agent.tools.skill_tools import skill_tool_context
from src.agent.registry import AGENTS
from src.agent.cost_tracker import BudgetExceeded
from src.agent.tools.outcomes import tool_execution_failed


class EvidenceWriteError(RuntimeError):
    """An executed action could not be archived reliably."""


class RunStopped(KeyboardInterrupt):
    """Cooperative cancellation crossing scanner and worker boundaries."""


def check_execution_limits(run) -> None:
    if getattr(run, "_evidence_integrity_failed", False):
        raise EvidenceWriteError("Earlier tool evidence could not be archived")
    stop = getattr(run, "_stop_event", None)
    if stop is not None and stop.is_set() and getattr(run, "experiment_scope", None):
        raise RunStopped("Run stopped")
    if getattr(run, "_execution_limit_reason", None):
        raise BudgetExceeded(run._execution_limit_reason)
    limit = getattr(run, "max_duration_s", None)
    started = getattr(run, "_run_started", None)
    if limit is not None and started is not None and time.monotonic() - started >= limit:
        run._execution_limit_reason = "Elapsed-time budget exhausted"
        raise BudgetExceeded(run._execution_limit_reason)
    tracker = getattr(run, "tracker", None)
    if tracker is not None:
        try:
            tracker.check_budget()
        except BudgetExceeded as exc:
            run._execution_limit_reason = str(exc)
            raise


def wrap_tool(run, tool: dict, *, phase=None, agent=None, decision_source=None, config=None) -> dict:
    tool = bind_deliverable_tool(tool, run.run_dir)
    original = tool["function"]
    if original is None:
        return tool
    name = tool["name"]
    if config is None:
        config = next((item for item in AGENTS.values() if item.phase == phase), None)
    skill_filter = getattr(config, "skill_filter", None) or {}
    skill_tags = list(skill_filter.get("tags") or [])
    cache_only = getattr(run, "cve_lookup_policy", "live_on_miss") == "cache_only"

    def execute(**kwargs):
        observation_local.last = None
        check_execution_limits(run)
        tracker = getattr(run, "tracker", None)
        with run._artifact_log_lock:
            if run.max_tool_calls is not None and run._tool_call_count >= run.max_tool_calls:
                run._execution_limit_reason = f"Tool-call budget exhausted ({run.max_tool_calls} calls)"
                raise BudgetExceeded(run._execution_limit_reason)
            run._tool_call_count += 1
            sequence = run._tool_call_count
        started_at = datetime.now().astimezone().isoformat()
        started = time.monotonic()
        evidence_ref = f"tc-{uuid4().hex}"
        claim = dict(getattr(getattr(run, "_exploit_tool_context", None), "vulnerability", None) or {})

        def archive(result):
            # Context belongs to the claim. It never overrides execution facts.
            entry = {
                **claim, "claim_context": claim,
                "timestamp": datetime.now().astimezone().isoformat(),
                "started_at": started_at, "duration_s": time.monotonic() - started,
                "sequence": sequence, "tool": name, "args": kwargs,
                "result": result, "phase": phase, "agent": agent,
                "evidence_ref": evidence_ref, "execution_origin": "runner",
                "decision_source": decision_source or getattr(run, "decision_policy", "llm"),
            }
            if tracker is not None and hasattr(tracker, "record_execution"):
                failed = tool_execution_failed(name, result)
                tracker.record_execution(started, entry["duration_s"], error=failed)
            try:
                with run._artifact_log_lock:
                    with (run.run_dir / "tool_calls.jsonl").open("a", encoding="utf-8") as handle:
                        handle.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
            except (OSError, TypeError, ValueError) as exc:
                run._evidence_integrity_failed = True
                raise EvidenceWriteError("Cannot archive tool evidence; run is not verifiable") from exc
            observation_local.last = entry

        refusal = None
        stop = getattr(run, "_stop_event", None)
        if stop is not None and stop.is_set():
            refusal = {"ok": False, "error_kind": "run_stopped", "error": "Run stopped"}
        elif (getattr(run, "benchmark_split", "unassigned") not in (None, "unassigned") or getattr(run, "experiment_scope", None)) and (
            name == "search_history" or name == "search_knowledge"
            and kwargs.get("collection", "cve_knowledge") != "skills"
        ):
            refusal = {"error_kind": "benchmark_memory_disabled", "error": "Persistent benchmark memory is disabled; use the frozen CVE snapshot."}
        elif name == "python_exec":
            refusal = {"error_kind": "unverifiable_execution_scope", "error": "Free Python has no verifiable network/filesystem scope. Use structured tools; isolated execution is required for arbitrary scripts."}
        elif any(kwargs.get(key) not in (None, "") for key in (
            "ip", "host", "broker", "target", "target_ip", "device_ip", "url", "command_string",
        )):
            scope_args = dict(kwargs)
            for key in ("target_ip", "device_ip"):
                if kwargs.get(key):
                    scope_args["target"] = kwargs[key]
            refusal = _intrusion_scope_violation(name, scope_args, run.context.get("target_subnet", ""))

        if refusal is not None:
            result = json.dumps(refusal, ensure_ascii=False)
            archive(result)
            return result
        try:
            with skill_tool_context(cache_only=cache_only, tags=skill_tags):
                result = original(**kwargs)
        except Exception as exc:
            archive({"error": str(exc), "exception_type": type(exc).__name__})
            raise
        archive(result)
        return result

    observation_local = threading.local()
    execute.last_observation = lambda: getattr(observation_local, "last", None)
    return {**tool, "function": execute}
