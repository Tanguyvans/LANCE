"""LLM arm of the V0 fidelity control, using the existing provider/tool runtime."""
from __future__ import annotations

import json

from src.agent.audit_experiment import digest
from src.agent.core.executor import check_execution_limits
from benchmarks.experiments.ssh_reference_llm import append_json
from benchmarks.experiments.v0_control import CONTRACT, validate_briefing


SYSTEM_PROMPT = """Execute the public MQTT procedure supplied by the user.
Every step is fully specified: topic, credential and listening window. Do not
infer, reorder or omit steps. Call run_step once per step, in the declared
order, starting at step 0. Each result carries an immutable evidence reference.
When every step has been executed, call finish_control with the reference of
each step, in the same order. Do not invent references, repeat a step, or
report a conclusion beyond the executed procedure. Stay within the supplied
budgets. No other brokers, topics or credentials are available.
"""


ROUTING_FIELDS = ("event", "reason", "response_type", "finish_reason", "cause",
                  "accepted", "error_kind", "status_code")


def routing(events):
    """Turn routing as counts, never as content.

    A control that closed without a terminal decision has to be diagnosable
    from the job log: this says which non-data turns occurred and why the loop
    stopped, and carries no argument, payload or credential.
    """
    counts = {}
    for event in events:
        if not isinstance(event, dict) or event.get("type") != "provider_diagnostic":
            continue
        for field in ROUTING_FIELDS:
            value = event.get(field)
            if isinstance(value, bool):
                value = "true" if value else "false"
            elif isinstance(value, int):
                value = str(value)
            if not isinstance(value, str):
                continue
            key = f"{field}={value}"
            counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def run_llm(briefing, execute, run, provider):
    public = validate_briefing(briefing)
    decision = {"schema_version": 1, "contract": CONTRACT, "decision_policy": "llm",
                "briefing_sha256": digest(public), "status": "no_output", "executed": []}
    observed = []
    steps = public["steps"]

    def run_step(index):
        if type(index) is not int or not 0 <= index < len(steps):
            return {"ok": False, "error_kind": "invalid_step_index"}
        step = steps[index]
        kwargs = {"broker": public["target"]["ip"], "port": public["target"]["port"],
                  "topic": step["topic"], "count": step["count"], "timeout": step["timeout_s"]}
        if step["credential"] is not None:
            kwargs.update(username=step["credential"]["username"],
                          password=step["credential"]["password"])
        value = execute(**kwargs)
        record = execute.last_observation()
        if record is None:
            from src.agent.core.executor import EvidenceWriteError
            raise EvidenceWriteError("MQTT result has no archived observation")
        observed.append(record["evidence_ref"])
        execute.check_limits()
        return {"step": index, "evidence_ref": record["evidence_ref"],
                "result": json.loads(value)}

    def finish_control(evidence_refs):
        check_execution_limits(run)
        if (not isinstance(evidence_refs, list)
                or any(not isinstance(item, str) for item in evidence_refs)
                or len(set(evidence_refs)) != len(evidence_refs)
                or not set(evidence_refs) <= set(observed)):
            return {"ok": False, "error_kind": "invalid_control_references"}
        # The procedure declares one evidence reference per step: a shorter
        # list would end the run as a completed but truncated control, which
        # reads as a model failure when it is the instrument accepting it.
        if len(evidence_refs) != len(steps):
            return {"ok": False, "error_kind": "incomplete_control",
                    "expected_refs": len(steps), "observed_refs": len(evidence_refs)}
        decision.update(status="completed", executed=list(evidence_refs))
        return {"ok": True, "success": True}

    tools = [
        {"name": "run_step",
         "description": "Execute one declared step and return its evidence reference.",
         "input_schema": {"type": "object",
                          "properties": {"index": {"type": "integer", "minimum": 0,
                                                   "maximum": len(steps) - 1}},
                          "required": ["index"], "additionalProperties": False},
         "function": run_step},
        {"name": "finish_control",
         "description": ("Save the executed steps: one evidence reference per declared step, "
                         "in order. A partial list is refused."),
         "input_schema": {"type": "object",
                          "properties": {"evidence_refs": {"type": "array",
                                                           "items": {"type": "string"}}},
                          "required": ["evidence_refs"], "additionalProperties": False},
         "function": finish_control},
    ]
    user = json.dumps({"briefing": public, "budgets": {
        "max_tool_calls": run.max_tool_calls, "max_duration_s": run.max_duration_s,
        "max_cost_usd": run.tracker.max_cost_usd, "max_turns": run.max_turns,
    }}, ensure_ascii=False)
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
            required_tool="finish_control", terminate_after_tool="finish_control",
            strict_required_tool=True,
            deadline=(run._run_started + run.max_duration_s
                      if run.max_duration_s is not None else None),
            max_data_tool_calls=run.max_tool_calls, repeat_guard=True,
        )
        (run.run_dir / "model-final.txt").write_text(text or "", encoding="utf-8")
        # The provider stops accepting tool calls at max_data_tool_calls and
        # forces completion, so an unfinished control ended on its budget even
        # though no exception was raised. The rules arm reaches the same state
        # by raising BudgetExceeded on its next call; both must read alike.
        if (run.max_tool_calls is not None
                and run._tool_call_count >= run.max_tool_calls
                and len(decision["executed"]) != len(steps)):
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
