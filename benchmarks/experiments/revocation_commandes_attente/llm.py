"""LLM approach of the revocation challenge: the same journal and documentation.

The model receives exactly what the scripts receive — the gateway journal and
the product documentation — and closes with one call that carries its verdict
and the documentation sentences it relies on. A quotation that does not appear
in the documentation is refused, so a verdict always rests on text the model
was actually given.
"""
from __future__ import annotations

import json
import re
import time

from benchmarks.experiments.ssh_reference_llm import append_json
from benchmarks.experiments.v0_control_llm import routing
from src.agent.core.executor import check_execution_limits

VERDICTS = ("flaw", "expected")
# One close, plus room for a refused quotation to be corrected.
MAX_TOOL_CALLS = 3
TURN_RESERVE = 2
ROUTING_SLACK = 6
MAX_TURNS = MAX_TOOL_CALLS + TURN_RESERVE + ROUTING_SLACK

SYSTEM_PROMPT = """You audit an IoT gateway. You are given the gateway's event
journal and an excerpt of the product's documentation; nothing else is
available and no network is reachable.

In the journal, an operator submitted a command for a device that was offline,
the gateway queued it, the operator's permissions were revoked, and the command
was dispatched afterwards. Decide, from this product's documentation, whether
that dispatch is a security flaw (the product should have prevented it) or the
expected behaviour of the product.

Close with finish_verdict, carrying:
1. the verdict, "flaw" or "expected";
2. the documentation sentences your verdict relies on, each quoted exactly;
3. a short reasoning of two sentences at most.

A quotation that is not in the documentation is refused. Stay within the
supplied budgets.
"""


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().casefold()


def check_budget(max_tool_calls, max_turns):
    """Refuse a budget that cannot hold the close and its routing slack."""
    if type(max_tool_calls) is not int or max_tool_calls < 1:
        raise ValueError("A tool budget under 1 cannot close the case")
    required_turns = max_tool_calls + TURN_RESERVE + ROUTING_SLACK
    if type(max_turns) is not int or max_turns < required_turns:
        raise ValueError(f"A turn budget under {required_turns} leaves no routing slack")
    return {"max_tool_calls": max_tool_calls, "max_turns": max_turns,
            "required_turns": required_turns}


def run_llm(documentation: str, journal, run, provider):
    check_budget(run.max_tool_calls, run.max_turns)
    decision = {"schema_version": 1, "decision_policy": "llm", "status": "no_output",
                "verdict": None, "evidence": [], "reasoning": None}
    source = _normalise(documentation)

    def finish_verdict(verdict, evidence, reasoning):
        started = time.monotonic()
        run._tool_call_count += 1
        tracker = getattr(run, "tracker", None)
        if tracker is not None:
            tracker.record_execution(started, time.monotonic() - started)
        check_execution_limits(run)
        if verdict not in VERDICTS:
            return {"ok": False, "error_kind": "invalid_verdict"}
        if (not isinstance(evidence, list) or not evidence
                or not all(isinstance(item, str) and item.strip() for item in evidence)):
            return {"ok": False, "error_kind": "missing_evidence"}
        unknown = [item for item in evidence if _normalise(item) not in source]
        if unknown:
            return {"ok": False, "error_kind": "quotation_not_in_documentation",
                    "unknown": unknown}
        decision.update(status="completed", verdict=verdict, evidence=evidence,
                        reasoning=reasoning if isinstance(reasoning, str) else None)
        return {"ok": True, "success": True}

    tools = [{
        "name": "finish_verdict",
        "description": ("Save the verdict with the documentation sentences it relies on, "
                        "quoted exactly. Quotations absent from the documentation are refused."),
        "input_schema": {"type": "object", "properties": {
            "verdict": {"type": "string", "enum": list(VERDICTS)},
            "evidence": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "reasoning": {"type": "string"}},
            "required": ["verdict", "evidence", "reasoning"], "additionalProperties": False},
        "function": finish_verdict,
    }]
    user = json.dumps({"journal": list(journal), "documentation": documentation,
                       "budgets": {"max_tool_calls": run.max_tool_calls,
                                   "max_turns": run.max_turns,
                                   "max_duration_s": run.max_duration_s}},
                      ensure_ascii=False)
    (run.run_dir / "prompt.json").write_text(json.dumps({
        "system": SYSTEM_PROMPT, "user": json.loads(user),
        "tools": [{k: v for k, v in tool.items() if k != "function"} for tool in tools],
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    events = []

    def event_callback(event):
        try:
            append_json(run.run_dir / "provider-events.jsonl", event)
            if isinstance(event, dict) and event.get("type") == "provider_diagnostic":
                events.append(event)
        except Exception:
            run._evidence_integrity_failed = True
            raise

    event_callback._provider_diagnostics = True
    try:
        text = provider.chat_with_tools(
            SYSTEM_PROMPT, user, tools, max_turns=run.max_turns, max_tokens=4096,
            cost_tracker=run.tracker, stream_callback=event_callback,
            required_tool="finish_verdict", terminate_after_tool="finish_verdict",
            strict_required_tool=True,
            deadline=(run._run_started + run.max_duration_s
                      if run.max_duration_s is not None else None),
            max_data_tool_calls=run.max_tool_calls, repeat_guard=True,
        )
        (run.run_dir / "model-final.txt").write_text(text or "", encoding="utf-8")
        if run._tool_call_count >= run.max_tool_calls and decision["status"] != "completed":
            decision["status"] = "budget_exceeded"
        check_execution_limits(run)
    except BaseException as exc:
        kind = type(exc).__name__
        state = ("budget_exceeded" if kind in {"BudgetExceeded", "TimeoutError"}
                 else "stopped" if isinstance(exc, (KeyboardInterrupt, SystemExit)) else "failed")
        decision.update(status=state, error_type=kind)
        (run.run_dir / "decision.json").write_text(json.dumps(decision, indent=2) + "\n")
        raise
    finally:
        (run.run_dir / "routing.json").write_text(
            json.dumps({"turns": run.max_turns, "events": routing(events)},
                       indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return decision
