"""LLM arm of H2: the same frozen dossier, the same tools, no parser."""
from __future__ import annotations

import json
import time

from src.agent.audit_experiment import digest
from src.agent.core.executor import check_execution_limits
from benchmarks.experiments.mqtt_formats import (
    CONTRACT, VERDICTS, Journal, validate_dossier,
)
from benchmarks.experiments.ssh_reference_llm import append_json
from benchmarks.experiments.v0_control_llm import routing

# Same two turn reservations as the V0 control: the provider keeps its last
# turns for the terminal call, and a turn that produces no data call (a text
# answer, a rejected repeat, malformed arguments) must not consume the budget
# the dossier needs. Reading N messages plus one terminal call is the floor.
TURN_RESERVE = 2
ROUTING_SLACK = 6
MAX_MESSAGES = 12
MAX_TOOL_CALLS = MAX_MESSAGES + 1
MAX_TURNS = MAX_TOOL_CALLS + TURN_RESERVE + ROUTING_SLACK

SYSTEM_PROMPT = """Interpret a frozen set of MQTT messages and answer one
question about them. The messages, their topics and their encoding are given;
nothing else is available and no network is reachable.

Call read_message once per message identifier to obtain its presentation, as
received, together with an immutable evidence reference. Then call
finish_interpretation with exactly three things:

1. one verdict per message, as a list of entries carrying the message identifier,
   the verdict and the evidence reference of that message's own read;
2. one conclusion for the dossier;
3. no other field.

A verdict is "exposed" when the message carries the asked reading of the asked
device, "not_exposed" when it demonstrably does not, and "abstain" when the
message does not let you decide. Do not guess: an abstention is a correct
answer where the message is genuinely undecidable, and a wrong verdict is
worse than an abstention. The conclusion uses the same three words for the
dossier as a whole.

Stay within the supplied budgets. Do not invent references, do not decide a
message you did not read, and do not report anything beyond the messages.
"""


def check_budget(messages, max_tool_calls, max_turns):
    """Refuse a budget that cannot hold the reads and the terminal call."""
    if type(messages) is not int or not 1 <= messages <= MAX_MESSAGES:
        raise ValueError(f"Dossier requires 1 to {MAX_MESSAGES} messages")
    required_calls = messages + 1
    required_turns = required_calls + TURN_RESERVE + ROUTING_SLACK
    if type(max_tool_calls) is not int or max_tool_calls < required_calls:
        raise ValueError(f"A tool budget under {required_calls} cannot read the dossier "
                         f"and close it")
    if type(max_turns) is not int or max_turns < required_turns:
        raise ValueError(f"A turn budget under {required_turns} leaves no routing slack")
    return {"messages": messages, "max_tool_calls": max_tool_calls,
            "max_turns": max_turns, "required_calls": required_calls,
            "required_turns": required_turns}


def run_llm(dossier, run, provider, journal=None):
    public = validate_dossier(dossier)
    identifiers = [message["message_id"] for message in public["messages"]]
    check_budget(len(identifiers), run.max_tool_calls, run.max_turns)
    journal = journal or Journal(public, public["view"])
    decision = {"schema_version": 1, "contract": CONTRACT, "decision_policy": "llm",
                "dossier_sha256": journal.dossier_sha256, "status": "no_output",
                "conclusion": None, "verdicts": {}}
    observed = {}

    def count_tool_call(started):
        """Every data call reaches the tracker and the run counter.

        The tools here are the family's own, not the executor's wrapper, so
        nothing else would count them: without this, an arm that read five
        messages and closed publishes zero tool calls, and the budget the
        summary reports is the budget nobody spent.
        """
        run._tool_call_count += 1
        tracker = getattr(run, "tracker", None)
        if tracker is not None:
            tracker.record_execution(started, time.monotonic() - started)

    def read_message(message_id):
        started = time.monotonic()
        if not isinstance(message_id, str) or message_id not in identifiers:
            count_tool_call(started)
            return {"ok": False, "error_kind": "unknown_message"}
        evidence_ref, body = journal.read(message_id)
        observed[evidence_ref] = message_id
        count_tool_call(started)
        check_execution_limits(run)
        return {"ok": True, "message_id": message_id, "evidence_ref": evidence_ref,
                "presentation": body}

    def finish_interpretation(verdicts, conclusion):
        """One entry per message, as a flat list.

        A free-form object keyed by identifier would be a nested schema the
        provider has to support; the list keeps the call to shapes every
        endpoint accepts, so a failed close is about the dossier, not about
        the tool contract.
        """
        started = time.monotonic()
        count_tool_call(started)
        check_execution_limits(run)
        if conclusion not in VERDICTS:
            return {"ok": False, "error_kind": "invalid_conclusion"}
        if not isinstance(verdicts, list):
            return {"ok": False, "error_kind": "invalid_verdict_shape"}
        decided, cited = {}, set()
        for entry in verdicts:
            if not isinstance(entry, dict) or set(entry) != {"message_id", "verdict",
                                                             "evidence_ref"}:
                return {"ok": False, "error_kind": "invalid_verdict_shape"}
            message_id = entry["message_id"]
            if message_id in decided:
                return {"ok": False, "error_kind": "repeated_message",
                        "message_id": message_id}
            if entry["verdict"] not in VERDICTS:
                return {"ok": False, "error_kind": "invalid_verdict",
                        "message_id": message_id}
            if observed.get(entry["evidence_ref"]) != message_id:
                return {"ok": False, "error_kind": "unbound_evidence",
                        "message_id": message_id}
            decided[message_id] = {"verdict": entry["verdict"],
                                   "evidence_ref": entry["evidence_ref"]}
            cited.add(entry["evidence_ref"])
        if set(decided) != set(identifiers):
            return {"ok": False, "error_kind": "incomplete_interpretation",
                    "expected_ids": identifiers}
        if len(cited) != len(identifiers):
            return {"ok": False, "error_kind": "shared_evidence"}
        decision.update(status="completed", conclusion=conclusion, verdicts=decided)
        return {"ok": True, "success": True}

    tools = [
        {"name": "read_message",
         "description": ("Read one message of the dossier and return its presentation "
                         "with an immutable evidence reference."),
         "input_schema": {"type": "object",
                          "properties": {"message_id": {"type": "string",
                                                        "enum": identifiers}},
                          "required": ["message_id"], "additionalProperties": False},
         "function": read_message},
        {"name": "finish_interpretation",
         "description": ("Save one verdict and one evidence reference per message, plus "
                         "one conclusion for the dossier. Partial lists and references "
                         "that do not come from a read of that message are refused."),
         "input_schema": {"type": "object",
                          "properties": {
                              "verdicts": {"type": "array",
                                           "items": {
                                               "type": "object",
                                               "properties": {
                                                   "message_id": {
                                                       "type": "string",
                                                       "enum": identifiers},
                                                   "verdict": {"type": "string",
                                                               "enum": list(VERDICTS)},
                                                   "evidence_ref": {"type": "string"}},
                                               "required": ["message_id", "verdict",
                                                            "evidence_ref"],
                                               "additionalProperties": False}},
                              "conclusion": {"type": "string", "enum": list(VERDICTS)}},
                          "required": ["verdicts", "conclusion"],
                          "additionalProperties": False},
         "function": finish_interpretation},
    ]
    user = json.dumps({"dossier": public, "budgets": {
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
            required_tool="finish_interpretation",
            terminate_after_tool="finish_interpretation",
            strict_required_tool=True,
            deadline=(run._run_started + run.max_duration_s
                      if run.max_duration_s is not None else None),
            max_data_tool_calls=run.max_tool_calls, repeat_guard=True,
        )
        (run.run_dir / "model-final.txt").write_text(text or "", encoding="utf-8")
        if (run.max_tool_calls is not None
                and run._tool_call_count >= run.max_tool_calls
                and decision["status"] != "completed"):
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
        # The evidence log belongs to the arm: every verdict it submitted has
        # to be recountable against the reads it actually performed.
        (run.run_dir / "journal.jsonl").write_text(
            "".join(json.dumps(record) + "\n" for record in journal.records),
            encoding="utf-8")
        (run.run_dir / "routing.json").write_text(
            json.dumps({"turns": run.max_turns, "events": routing(events)},
                       indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return decision
