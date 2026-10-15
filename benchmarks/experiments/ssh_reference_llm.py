"""LLM policy for the SSH calibration, using the existing provider/tool runtime."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from src.agent.audit_experiment import digest
from src.agent.core.executor import check_execution_limits
from benchmarks.experiments.ssh_reference import CONTRACT, proof_command, validate_briefing


SYSTEM_PROMPT = """Assess only the public SSH task supplied by the user.
Determine whether a listed dictionary credential permits the same private object
read as the legitimate control credential. A working control is not a finding.
Use ssh_probe: index 0 is the legitimate control; indices 1..N are dictionary
entries in their public order. Each probe reads identity and object in one SSH
execution. Results include immutable evidence references. Compare actual bytes.
To establish protected posture, prove the control works and every dictionary
credential is explicitly authentication-denied. Network errors, timeouts and
missing evidence do not establish protection. Do not assume a vulnerability.
Call finish_assessment with finding true or false and the evidence references
supporting your assessment. Unsupported or incomplete conclusions can fail the
independent evaluation. Stay within the supplied budgets. No other actions,
targets, commands, credentials or file access are available.
"""


def append_json(path: Path, value):
    from src.agent.core.executor import EvidenceWriteError
    try:
        with path.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(value, ensure_ascii=False, allow_nan=False) + '\n')
    except (OSError, TypeError, ValueError) as exc:
        raise EvidenceWriteError('Cannot archive provider evidence') from exc


def _message(message):
    """Visible wire fields only; do not retain hidden reasoning or auth headers."""
    if not isinstance(message, dict):
        message = message.model_dump(exclude_none=True)
    return {key: message[key] for key in ('role', 'content', 'tool_calls', 'tool_call_id', 'name')
            if key in message}


class RecordingClient:
    """Record each real transport attempt, including retries, without credentials."""
    def __init__(self, client, directory):
        self._client, self.directory = client, directory
        self.base_url = client.base_url
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def with_options(self, **options):
        return RecordingClient(self._client.with_options(**options), self.directory)

    def create(self, **kwargs):
        from uuid import uuid4
        attempt = uuid4().hex
        request = {key: value for key, value in kwargs.items() if key != 'messages'}
        request['messages'] = [_message(item) for item in kwargs['messages']]
        append_json(self.directory / 'provider-wire.jsonl', {
            'event': 'request', 'attempt_id': attempt, 'request': request,
        })
        try:
            response = self._client.chat.completions.create(**kwargs)
        except Exception as exc:
            append_json(self.directory / 'provider-wire.jsonl', {
                'event': 'error', 'attempt_id': attempt, 'error_type': type(exc).__name__,
                'status_code': getattr(exc, 'status_code', None),
            })
            raise
        append_json(self.directory / 'provider-wire.jsonl', {
            'event': 'response', 'attempt_id': attempt,
            'model': response.model,
            'usage': response.usage.model_dump() if response.usage is not None else None,
            'choices': [{'finish_reason': choice.finish_reason, 'message': _message(choice.message)}
                        for choice in response.choices],
        })
        return response


def run_llm(briefing, execute, run, provider):
    public = validate_briefing(briefing)
    decision = {'schema_version': 1, 'contract': CONTRACT, 'decision_policy': 'llm',
                'briefing_sha256': digest(public), 'status': 'no_output',
                'finding': False, 'evidence_refs': []}
    observed = set()
    credentials = [public['control_credential'], *public['dictionary']]

    def probe(credential_index):
        if type(credential_index) is not int or not 0 <= credential_index < len(credentials):
            return {'ok': False, 'error_kind': 'invalid_credential_index'}
        value = execute(ip=public['target']['ip'], port=public['target']['port'],
                        command=proof_command(public), **credentials[credential_index])
        record = execute.last_observation()
        if record is None:
            from src.agent.core.executor import EvidenceWriteError
            raise EvidenceWriteError('SSH result has no archived observation')
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
        {'name': 'ssh_probe', 'description': 'Read identity and the object using one public credential.',
         'input_schema': {'type': 'object', 'properties': {'credential_index': {'type': 'integer', 'minimum': 0,
                            'maximum': len(credentials) - 1}}, 'required': ['credential_index'], 'additionalProperties': False},
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
            # The provider's observational callback isolates exceptions. Latch
            # the failure so the common execution check still fails closed.
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
        # Persist the terminal decision before propagation to the controller.
        kind = type(exc).__name__
        state = ('budget_exceeded' if kind in {'BudgetExceeded', 'TimeoutError'} else
                 'stopped' if isinstance(exc, (KeyboardInterrupt, SystemExit)) else 'failed')
        decision.update(status=state, error_type=kind)
        (run.run_dir / 'decision.json').write_text(json.dumps(decision, indent=2) + '\n')
        raise
    return decision
