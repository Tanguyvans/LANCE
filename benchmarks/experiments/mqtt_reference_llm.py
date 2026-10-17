"""LLM policy for the MQTT calibration, using the existing provider/tool runtime."""
from __future__ import annotations

import json

from src.agent.audit_experiment import digest
from src.agent.core.executor import check_execution_limits
from benchmarks.experiments.mqtt_reference import CONTRACT, validate_briefing
from benchmarks.experiments.ssh_reference_llm import append_json

SYSTEM_PROMPT = """Assess only the public MQTT task supplied by the user.
Determine whether an anonymous subscriber receives the same fresh private
message as the legitimate control credential. Receiving the public message
anonymously is expected and is not a finding. A working control is not a
finding. Use mqtt_probe: index 0 is the legitimate control subscription to
the private topic; index 1 is an anonymous subscription to the public topic;
index 2 is an anonymous subscription to the private topic. Each probe listens
in one bounded execution. Results include immutable evidence references.
Compare actual payloads. To establish protected posture, prove the control
and public subscriptions deliver their fresh messages and the anonymous
private subscription was actually evaluated without delivering the private
message. Network errors, timeouts, empty output without working controls and
missing evidence do not establish protection. Do not assume a vulnerability.
Call finish_assessment with finding true or false and the evidence references
supporting your assessment. Unsupported or incomplete conclusions can fail
the independent evaluation. Stay within the supplied budgets. No other
actions, brokers, topics, credentials or publications are available.
"""

CHECKS = (("private", True), ("public", False), ("private", False))


def run_llm(briefing, execute, run, provider):
    public = validate_briefing(briefing)
    decision = {'schema_version': 1, 'contract': CONTRACT, 'decision_policy': 'llm',
                'briefing_sha256': digest(public), 'status': 'no_output',
                'finding': False, 'evidence_refs': []}
    observed = set()

    def probe(check_index):
        if type(check_index) is not int or not 0 <= check_index < len(CHECKS):
            return {'ok': False, 'error_kind': 'invalid_check_index'}
        kind, authenticated = CHECKS[check_index]
        kwargs = {"broker": public["target"]["ip"], "port": public["target"]["port"],
                  "topic": public[f"{kind}_topic"], "count": public["listen"]["count"],
                  "timeout": public["listen"]["timeout_s"]}
        if authenticated:
            kwargs.update(username=public["control_credential"]["username"],
                          password=public["control_credential"]["password"])
        value = execute(**kwargs)
        record = execute.last_observation()
        if record is None:
            from src.agent.core.executor import EvidenceWriteError
            raise EvidenceWriteError('MQTT result has no archived observation')
        observed.add(record['evidence_ref'])
        execute.check_limits()
        return {'evidence_ref': record['evidence_ref'], 'result': json.loads(value)}

    def finish(finding, evidence_refs):
        check_execution_limits(run)
        if (type(finding) is not bool or not isinstance(evidence_refs, list)
                or any(not isinstance(item, str) for item in evidence_refs)
                or len(set(evidence_refs)) != len(evidence_refs)
                or not set(evidence_refs) <= observed):
            return {'ok': False, 'error_kind': 'invalid_assessment_references'}
        decision.update(status='completed', finding=finding, evidence_refs=evidence_refs)
        return {'ok': True, 'success': True}

    tools = [
        {'name': 'mqtt_probe', 'description': 'Listen once for one of the three public MQTT checks.',
         'input_schema': {'type': 'object', 'properties': {'check_index': {'type': 'integer', 'minimum': 0,
                            'maximum': len(CHECKS) - 1}}, 'required': ['check_index'], 'additionalProperties': False},
         'function': probe},
        {'name': 'finish_assessment', 'description': 'Save the final assessment and its supporting evidence references.',
         'input_schema': {'type': 'object', 'properties': {'finding': {'type': 'boolean'},
                            'evidence_refs': {'type': 'array', 'items': {'type': 'string'}}},
                          'required': ['finding', 'evidence_refs'], 'additionalProperties': False},
         'function': finish},
    ]
    user = json.dumps({'briefing': public, 'budgets': {
        'max_tool_calls': run.max_tool_calls, 'max_duration_s': run.max_duration_s,
        'max_cost_usd': run.tracker.max_cost_usd, 'max_turns': run.max_turns,
    }}, ensure_ascii=False)
    (run.run_dir / 'prompt.json').write_text(json.dumps({
        'system': SYSTEM_PROMPT, 'user': json.loads(user),
        'tools': [{k: v for k, v in tool.items() if k != 'function'} for tool in tools],
    }, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

    def event_callback(event):
        try:
            append_json(run.run_dir / 'provider-events.jsonl', event)
        except Exception:
            run._evidence_integrity_failed = True
            raise

    event_callback._provider_diagnostics = True
    try:
        text = provider.chat_with_tools(
            SYSTEM_PROMPT, user, tools, max_turns=run.max_turns, max_tokens=4096,
            cost_tracker=run.tracker, stream_callback=event_callback,
            required_tool='finish_assessment', terminate_after_tool='finish_assessment',
            strict_required_tool=True, deadline=run._run_started + run.max_duration_s,
            max_data_tool_calls=run.max_tool_calls, repeat_guard=True,
        )
        (run.run_dir / 'model-final.txt').write_text(text or '', encoding='utf-8')
        check_execution_limits(run)
    except BaseException as exc:
        kind = type(exc).__name__
        state = ('budget_exceeded' if kind in {'BudgetExceeded', 'TimeoutError'} else
                 'stopped' if isinstance(exc, (KeyboardInterrupt, SystemExit)) else 'failed')
        decision.update(status=state, error_type=kind)
        (run.run_dir / 'decision.json').write_text(json.dumps(decision, indent=2) + '\n')
        raise
    return decision
