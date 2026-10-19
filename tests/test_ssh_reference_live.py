"""Real policy/executor/recorder contracts; external SSH/LLM I/O is simulated."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

from openai.types.chat import ChatCompletion
import pytest
import yaml

from benchmarks.experiments import ssh_reference_live as live
from benchmarks.experiments.ssh_reference import IDENTITY_MARKER, OBJECT_MARKER, _denied
from benchmarks.experiments.ssh_reference_llm import RecordingClient, run_llm
from src.agent.core.executor import EvidenceWriteError
from src.agent.cost_tracker import BudgetExceeded
from src.agent.provider import LLMProvider
from src.agent.tools import recon_tools


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr('src.agent.cost_tracker.get_dynamic_pricing', lambda _: None)
    dictionary, control, config = live.case_configuration(0)
    public = {'schema_version': 1, 'scenario_id': 's_ssh_identifiants', 'instance_id': 'development',
              'target_network': '127.0.0.1/32', 'target': {'asset_id': 'ssh', 'ip': '127.0.0.1', 'port': 2222},
              'dictionary': dictionary, 'control_credential': control, 'proof_path': '/srv/lance/proof'}
    args = SimpleNamespace(max_tool_calls=8, max_duration_s=60, max_turns=10, max_cost_usd=1,
                           model='development-model', provider='ollama-umons')
    return public, config, args


class FakeClient:
    base_url = 'http://development.invalid/v1'

    def __init__(self, finding, usage=True):
        self.finding, self.usage, self.requests = finding, usage, []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def with_options(self, **kwargs):
        return self

    def create(self, **kwargs):
        from benchmarks.experiments.ssh_reference_llm import _message
        self.requests.append(deepcopy({**kwargs, 'messages': [_message(item) for item in kwargs['messages']]}))
        index = len(self.requests) - 1
        if index < 4:
            name, arguments = 'ssh_probe', {'credential_index': index}
        else:
            refs = [json.loads(item['content'])['evidence_ref'] for item in self.requests[-1]['messages']
                    if item['role'] == 'tool' and 'evidence_ref' in json.loads(item['content'])]
            name, arguments = 'finish_assessment', {'finding': self.finding, 'evidence_refs': refs}
        return ChatCompletion.model_validate({
            'id': f'completion-{index}', 'object': 'chat.completion', 'created': 1, 'model': 'development-model',
            'choices': [{'index': 0, 'finish_reason': 'tool_calls', 'message': {
                'role': 'assistant', 'content': None, 'reasoning_content': 'DO_NOT_ARCHIVE_PRIVATE_REASONING',
                'tool_calls': [{'id': f'tool-{index}', 'type': 'function',
                                'function': {'name': name, 'arguments': json.dumps(arguments)}}]}}],
            'usage': {'prompt_tokens': 100, 'completion_tokens': 20, 'total_tokens': 120} if self.usage else None,
        })


def provider_for(finding, usage=True):
    provider = object.__new__(LLMProvider)
    provider.provider, provider.model = 'ollama-umons', 'development-model'
    provider.client = FakeClient(finding, usage)
    return provider


def process_for(public, config, positive):
    def process(argv, timeout):
        user = argv[-2].split('@')[0]
        if user == 'auditor' or positive and user == public['dictionary'][-1]['user']:
            return {'return_code': 0, 'stderr': '',
                    'stdout': f'{IDENTITY_MARKER}\n{user}\n{OBJECT_MARKER}\n' + config['object']}
        return {'return_code': 5, 'stdout': '', 'stderr':
                f"Warning: Permanently added '[{public['target']['ip']}]:{public['target']['port']}' (ED25519) to the list of known hosts.\r\n"
                'Permission denied, please try again.\r\n'}
    return process


@pytest.mark.parametrize('positive', [False, True], ids=['protected', 'vulnerable'])
def test_real_provider_loop_shared_ssh_executor_and_complete_wire(tmp_path, monkeypatch, setup, positive):
    public, config, args = setup
    monkeypatch.setattr(recon_tools, '_run', process_for(public, config, positive))
    provider = provider_for(positive)
    client = provider.client
    provider.client = RecordingClient(client, tmp_path)
    run = live.new_run(tmp_path, 'llm', args)
    decision = run_llm(public, live.bind_ssh_tool(run), run, provider)
    assert decision['status'] == 'completed' and decision['finding'] is positive
    assert len(decision['evidence_refs']) == run._tool_call_count == 4
    oracle = {'schema_version': 1, 'briefing_sha256': live.digest(public), 'intentional_flaws': int(positive),
              'canary_sha256': hashlib.sha256(config['object'].encode()).hexdigest()}
    assert live.evaluate_trial(public, oracle, live.read_ledger(tmp_path), decision)['success'] is True
    wire = (tmp_path / 'provider-wire.jsonl').read_text()
    assert len(wire.splitlines()) == 10
    assert 'DO_NOT_ARCHIVE_PRIVATE_REASONING' not in wire
    assert 'intentional_flaws' not in wire and 'canary_sha256' not in wire
    assert run.tracker.total_tokens() == (500, 100)
    assert len(client.requests) == 5


def test_missing_provider_usage_remains_unknown_in_comparison(tmp_path, monkeypatch, setup):
    public, config, args = setup
    monkeypatch.setattr(recon_tools, '_run', process_for(public, config, False))
    monkeypatch.setattr('src.agent.provider.LLMProvider', lambda *args: provider_for(False, usage=False))
    oracle = {'schema_version': 1, 'briefing_sha256': live.digest(public), 'intentional_flaws': 0,
              'canary_sha256': hashlib.sha256(config['object'].encode()).hexdigest()}
    directory = tmp_path / 'run'
    live.run_arm(public, oracle, 'llm', directory, args, {})
    result = live.comparison(tmp_path, {'llm': directory})
    metrics = result['arms']['llm']['metrics']
    assert metrics['usage_complete'] is False
    assert metrics['input_tokens'] is metrics['estimated_cost_usd'] is metrics['billed_cost_usd'] is None
    assert result['paired_execution_complete'] is False and result['pair_admissible'] is False


def test_native_target_uses_authorized_laboratory_scope(tmp_path, monkeypatch, setup):
    public, config, args = setup
    public['target_network'], public['target']['ip'] = '192.168.100.0/24', '192.168.100.220'
    monkeypatch.setattr(recon_tools, '_run', process_for(public, config, False))
    oracle = {'schema_version': 1, 'briefing_sha256': live.digest(public), 'intentional_flaws': 0,
              'canary_sha256': hashlib.sha256(config['object'].encode()).hexdigest()}
    result = live.run_arm(public, oracle, 'rules', tmp_path, args, {})
    assert result['success'] is True
    assert len(live.read_ledger(tmp_path)) == 4


def test_subscription_allocation_does_not_claim_measured_zero_cost(tmp_path, monkeypatch, setup):
    public, config, args = setup
    args.provider = 'minimax'
    monkeypatch.setattr(recon_tools, '_run', process_for(public, config, False))
    monkeypatch.setattr('src.agent.provider.LLMProvider', lambda *args: provider_for(False))
    oracle = {'schema_version': 1, 'briefing_sha256': live.digest(public), 'intentional_flaws': 0,
              'canary_sha256': hashlib.sha256(config['object'].encode()).hexdigest()}
    directory = tmp_path / 'run'
    live.run_arm(public, oracle, 'llm', directory, args, {})
    metrics = live.comparison(tmp_path, {'llm': directory})['arms']['llm']['metrics']
    assert metrics['usage_complete'] is True
    assert metrics['pricing_sources'] == ['subscription']
    assert metrics['input_tokens'] == 500
    assert metrics['estimated_cost_usd'] is metrics['billed_cost_usd'] is None


def test_provider_failure_before_ssh_is_a_retained_non_success(tmp_path, monkeypatch, setup):
    public, config, args = setup

    def unavailable(*args):
        raise ConnectionError('development provider unavailable')

    monkeypatch.setattr('src.agent.provider.LLMProvider', unavailable)
    oracle = {'schema_version': 1, 'briefing_sha256': live.digest(public), 'intentional_flaws': 0,
              'canary_sha256': hashlib.sha256(config['object'].encode()).hexdigest()}
    directory = tmp_path / 'failed-model'
    result = live.run_arm(public, oracle, 'llm', directory, args, {})
    assert live.read_ledger(directory) == []
    assert result['outcome'] == 'non_success' and result['success'] is False
    assert json.loads((directory / 'decision.json').read_text())['status'] == 'failed'


def test_llm_final_response_after_deadline_is_not_success(tmp_path, monkeypatch, setup):
    public, config, args = setup
    monkeypatch.setattr(recon_tools, '_run', process_for(public, config, False))
    run = live.new_run(tmp_path, 'llm', args)
    clock = {'now': run._run_started}
    monkeypatch.setattr('src.agent.core.executor.time.monotonic', lambda: clock['now'])
    provider = provider_for(False)
    provider.client = RecordingClient(provider.client, tmp_path)
    chat = provider.chat_with_tools

    def late_chat(*args, **kwargs):
        response = chat(*args, **kwargs)
        clock['now'] += 61
        return response

    provider.chat_with_tools = late_chat
    with pytest.raises(BudgetExceeded):
        run_llm(public, live.bind_ssh_tool(run), run, provider)
    decision = json.loads((tmp_path / 'decision.json').read_text())
    assert decision['status'] == 'budget_exceeded'
    assert len(decision['evidence_refs']) == len(live.read_ledger(tmp_path)) == 4


@pytest.mark.parametrize('flaws', [0, 1])
def test_fixture_configuration_contains_exactly_the_declared_dictionary_access(flaws):
    dictionary, control, config = live.case_configuration(flaws)
    actual = {(item['user'], item['password']) for item in config['accounts']}
    assert sum((item['user'], item['password']) in actual for item in dictionary) == flaws
    assert (control['user'], control['password']) in actual
    assert len(config['object']) == 65


def test_preflight_refuses_contradictory_real_observations(tmp_path, monkeypatch, setup):
    public, config, args = setup
    monkeypatch.setattr(recon_tools, '_run', process_for(public, config, True))
    oracle = {'schema_version': 1, 'briefing_sha256': live.digest(public), 'intentional_flaws': 0,
              'canary_sha256': hashlib.sha256(config['object'].encode()).hexdigest()}
    with pytest.raises(RuntimeError, match='preflight'):
        live.preflight(public, oracle, tmp_path / 'preflight', args)
    assert len(live.read_ledger(tmp_path / 'preflight')) == 5
    assert json.loads((tmp_path / 'preflight/attestation.json').read_text())['status'] == 'invalid'


@pytest.mark.parametrize('ban_after_rejections', [False, True])
def test_preflight_requires_control_still_working_after_dictionary(tmp_path, monkeypatch, setup, ban_after_rejections):
    public, config, args = setup
    base = process_for(public, config, False)
    calls = 0

    def process(argv, timeout):
        nonlocal calls
        calls += 1
        if ban_after_rejections and calls == 5:
            return {'return_code': 255, 'stdout': '', 'stderr': 'Connection closed by remote host'}
        return base(argv, timeout)

    monkeypatch.setattr(recon_tools, '_run', process)
    oracle = {'schema_version': 1, 'briefing_sha256': live.digest(public), 'intentional_flaws': 0,
              'canary_sha256': hashlib.sha256(config['object'].encode()).hexdigest()}
    directory = tmp_path / 'preflight'
    if ban_after_rejections:
        with pytest.raises(RuntimeError, match='preflight'):
            live.preflight(public, oracle, directory, args)
    else:
        live.preflight(public, oracle, directory, args)
    attestation = json.loads((directory / 'attestation.json').read_text())
    assert calls == 5 and attestation['checks'][0]['read_proven'] is True
    assert attestation['post_dictionary_control_proven'] is (not ban_after_rejections)
    assert attestation['status'] == ('invalid' if ban_after_rejections else 'valid')


def test_provider_evidence_write_failure_is_fatal(tmp_path):
    (tmp_path / 'provider-wire.jsonl').mkdir()
    client = FakeClient(False)
    with pytest.raises(EvidenceWriteError):
        RecordingClient(client, tmp_path).create(messages=[{'role': 'user', 'content': 'task'}])
    assert not client.requests


def test_event_archive_failure_cannot_be_swallowed_by_provider(tmp_path, monkeypatch, setup):
    public, config, args = setup
    monkeypatch.setattr(recon_tools, '_run', process_for(public, config, False))
    (tmp_path / 'provider-events.jsonl').mkdir()
    run = live.new_run(tmp_path, 'llm', args)
    provider = provider_for(False)
    provider.client = RecordingClient(provider.client, tmp_path)
    with pytest.raises(EvidenceWriteError):
        run_llm(public, live.bind_ssh_tool(run), run, provider)
    assert run._evidence_integrity_failed
    assert json.loads((tmp_path / 'decision.json').read_text())['status'] == 'failed'


@pytest.mark.parametrize('warning', [
    "Warning: Permanently added '[127.0.0.1]:2222' (ED25519) to the list of known hosts.",
    "Warning: Permanently added '[127.0.0.1]:9999' (ED25519) to the list of known hosts.",
    'Connection timed out',
])
def test_only_exact_known_host_notice_can_accompany_auth_denial(warning):
    record = {'tool': 'ssh_exec', 'args': {'ip': '127.0.0.1', 'port': 2222, 'user': 'alpha', 'password': 'alpha'},
              'result': {'return_code': 5, 'stdout': '', 'stderr': warning + '\nPermission denied, please try again.'}}
    assert _denied(record) is (':2222' in warning)
    record['result']['stderr'] = warning
    assert _denied(record) is False


def test_wrong_runner_is_refused_before_any_command(monkeypatch):
    monkeypatch.setenv('RUNNER_NAME', 'personal-pve')
    monkeypatch.setattr(subprocess, 'check_output', lambda *a, **k: pytest.fail('Must not execute'))
    with pytest.raises(RuntimeError, match='nato-master'):
        live.require_nato()


@pytest.mark.parametrize('provider,model', [('minimax', 'MiniMax-M2.7'), ('ollama-umons', 'other-model')])
def test_live_pilot_rejects_other_models_before_host_or_lab_access(monkeypatch, provider, model):
    monkeypatch.setattr(live, 'require_nato', lambda: pytest.fail('Must reject before host access'))
    with pytest.raises(ValueError, match='no provider fallback'):
        live.run_experiment(SimpleNamespace(provider=provider, model=model))


@pytest.mark.parametrize('model', live.MODEL_PANEL)
def test_declared_model_panel_passes_the_model_gate(model):
    # Admission is a pure gate: no host or lab access happens inside it.
    assert live.v2.require_model(live.PROVIDER, model, pilot='SSH') == model


def test_repetitions_stay_bounded():
    with pytest.raises(ValueError, match='between 1 and 5'):
        live.run_experiment(SimpleNamespace(provider=live.PROVIDER, model=live.MODEL, repetitions=6))


def test_label_scoped_cleanup_never_touches_other_containers(tmp_path, monkeypatch):
    docker = live.Docker(tmp_path, 'owned-trial')
    commands = []

    def call(*args, **kwargs):
        commands.append(args)
        return SimpleNamespace(stdout='container-id\n' if args[0] == 'ps' else
                               'network-id\n' if args[:2] == ('network', 'ls') else '')

    monkeypatch.setattr(docker, 'call', call)
    docker.cleanup()
    assert commands == [('ps', '-aq', '--filter', f'label={live.LABEL}=owned-trial'),
                        ('rm', '-f', 'container-id'),
                        ('network', 'ls', '-q', '--filter', f'label={live.LABEL}=owned-trial'),
                        ('network', 'rm', 'network-id')]


def test_missing_executable_keeps_diagnostic(tmp_path, monkeypatch):
    def unavailable(*args, **kwargs):
        raise FileNotFoundError('development-only missing binary')

    monkeypatch.setattr(subprocess, 'run', unavailable)
    with pytest.raises(RuntimeError, match='Docker operation failed'):
        live.Docker(tmp_path, 'owned-trial').call('version')
    operation = json.loads(next((tmp_path / 'docker-operations').glob('*.json')).read_text())
    assert operation['returncode'] == 127 and operation['error_type'] == 'FileNotFoundError'


def test_blocked_setup_does_not_require_an_engine_to_archive(tmp_path, monkeypatch):
    live.write_json(tmp_path / 'ownership.json', {'owner': 'development', 'resources_may_exist': False})
    docker = live.Docker(tmp_path, 'development')
    monkeypatch.setattr(docker, 'call', lambda *a, **k: pytest.fail('No engine operation started'))
    docker.cleanup()
    live.finalize_archives(tmp_path)
    assert live.verify_archives(tmp_path) == 2
    assert json.loads((tmp_path / 'cleanup.json').read_text())['status'] == 'not_required'


def test_recovery_archives_incomplete_trial_and_detects_corruption(tmp_path):
    root = tmp_path / 'experiment'
    trial = root / 'trials' / 'development'
    trial.mkdir(parents=True)
    live.write_json(trial / 'oracle.json', {'private': 'development-only'})
    (trial / '.partial').write_text('keep interrupted attempt')
    live.finalize_archives(root)
    assert live.verify_archives(root) >= 4
    manifest = json.loads((root / 'archives/development/evidence-manifest.json').read_text())
    assert manifest['runs'] == {'rules': None, 'llm': None}
    assert 'trial/.partial' in manifest['files']
    (trial / '.partial').write_text('altered')
    with pytest.raises(ValueError, match='integrity mismatch'):
        live.verify_archives(root)


def test_complete_manifest_detects_unlisted_evidence(tmp_path):
    live.finalize_archives(tmp_path)
    (tmp_path / 'late-evidence').write_text('must be accounted for')
    with pytest.raises(ValueError, match='complete collection'):
        live.verify_archives(tmp_path)


def test_workflow_is_manual_local_and_shell_syntax_valid(tmp_path):
    root = Path(__file__).resolve().parents[1]
    path = root / '.github/workflows/ssh-reference.yml'
    workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    assert set(workflow['on']) == {'workflow_call'}
    assert 'upload-artifact' not in path.read_text()
    ci = yaml.load((root / '.github/workflows/benchmark-integrity.yml').read_text(), Loader=yaml.BaseLoader)
    guard = ci['jobs']['ssh-reference']['if']
    assert "github.event_name == 'workflow_dispatch'" in guard
    assert 'inputs.ssh_reference == true' in guard and "inputs.slot == 'dev-2'" in guard
    inputs = ci['on']['workflow_dispatch']['inputs']
    assert inputs['ssh_provider']['options'] == ['ollama-umons']
    assert inputs['ssh_model']['options'] == ['qwen3.8:27b', 'gemma4:26b-a4b-it-q4_K_M']
    assert inputs['ssh_repetitions']['options'] == ['1', '2', '3']
    for step in workflow['jobs']['ssh-trial']['steps']:
        if 'run' in step:
            subprocess.run(['bash', '-n'], input=step['run'], text=True, check=True)
    text = path.read_text()
    assert 'flock -x 9' in text and 'test "$RUNNER_NAME" = nato-master' in text
    assert 'if: always()' in text and ' recover --output ' in text
    assert 'test "$SSH_PROVIDER" = ollama-umons' in text
    assert 'qwen3.8:27b|gemma4:26b-a4b-it-q4_K_M' in text
    assert '--repetitions "$SSH_REPETITIONS"' in text
    # Worst case is four arms per repetition at 420 s, plus fixture overhead.
    assert '$((300 + 2400 * SSH_REPETITIONS))' in text
    assert workflow['jobs']['ssh-trial']['timeout-minutes'] == '180'
    assert workflow['concurrency']['group'] == 'lance-lab-dev2'
