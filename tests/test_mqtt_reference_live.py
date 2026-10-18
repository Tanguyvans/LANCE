"""Real MQTT policy/executor/recorder contracts; broker/LLM/lab I/O is simulated."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from openai.types.chat import ChatCompletion
import pytest
import yaml

from benchmarks.experiments import mqtt_reference_live as live
from benchmarks.experiments.mqtt_reference import bind_mqtt_tool, evaluate_trial
from benchmarks.experiments.mqtt_reference_llm import run_llm
from benchmarks.experiments.ssh_reference_llm import RecordingClient, _message
from src.agent.provider import LLMProvider
from src.agent.tools import recon_tools

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def setup(monkeypatch):
    monkeypatch.setattr('src.agent.cost_tracker.get_dynamic_pricing', lambda _: None)
    control, config = live.case_configuration(0)
    public = live.build_briefing('development', '127.0.0.1', control)
    public['target_network'] = '127.0.0.1/32'
    from benchmarks.experiments.mqtt_reference import validate_briefing
    public = validate_briefing(public)
    args = SimpleNamespace(max_tool_calls=8, max_duration_s=60, max_turns=10, max_cost_usd=1,
                           model='development-model', provider='ollama-umons')
    return public, config, args


class FakeClient:
    base_url = 'http://development.invalid/v1'

    def __init__(self, finding):
        self.finding, self.requests = finding, []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def with_options(self, **kwargs):
        return self

    def create(self, **kwargs):
        self.requests.append(deepcopy({**kwargs, 'messages': [_message(item) for item in kwargs['messages']]}))
        index = len(self.requests) - 1
        if index < 3:
            name, arguments = 'mqtt_probe', {'check_index': index}
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
            'usage': {'prompt_tokens': 100, 'completion_tokens': 20, 'total_tokens': 120},
        })


def provider_for(finding):
    provider = object.__new__(LLMProvider)
    provider.provider, provider.model = 'ollama-umons', 'development-model'
    provider.client = FakeClient(finding)
    return provider


def _msg(topic, payload):
    return json.dumps({"tst": "2026-10-16T00:00:00+02:00", "topic": topic,
                       "qos": 0, "retain": 1, "payload": payload}) + "\n"


def process_for(config, positive):
    def process(argv, timeout):
        flags = {argv[i]: argv[i + 1] for i in range(len(argv) - 1) if argv[i].startswith("-")}
        topic, user = flags.get("-t"), flags.get("-u")
        if topic == config['public_topic']:
            return {"return_code": 0, "stdout": _msg(topic, config['public_canary']), "stderr": ""}
        if user == config['control_user'] or positive:
            return {"return_code": 0, "stdout": _msg(topic, config['private_canary']), "stderr": ""}
        return {"return_code": 5, "stdout": "", "stderr": "Connection Refused: not authorised."}
    return process


@pytest.mark.parametrize('positive', [False, True], ids=['protected', 'vulnerable'])
def test_real_provider_loop_shared_mqtt_executor_and_complete_wire(tmp_path, monkeypatch, setup, positive):
    public, config, args = setup
    monkeypatch.setattr(recon_tools, '_run', process_for(config, positive))
    provider = provider_for(positive)
    client = provider.client
    provider.client = RecordingClient(client, tmp_path)
    run = live.new_run(tmp_path, 'llm', args)
    decision = run_llm(public, bind_mqtt_tool(run), run, provider)
    assert decision['status'] == 'completed' and decision['finding'] is positive
    assert len(decision['evidence_refs']) == run._tool_call_count == 3
    oracle = live.oracle_for(public, int(positive), config)
    assert evaluate_trial(public, oracle, live.read_ledger(tmp_path), decision)['success'] is True
    wire = (tmp_path / 'provider-wire.jsonl').read_text()
    assert len(wire.splitlines()) == 8
    assert 'DO_NOT_ARCHIVE_PRIVATE_REASONING' not in wire
    assert 'intentional_flaws' not in wire and 'canary_sha256' not in wire
    assert config['seeder_password'] not in wire
    assert len(client.requests) == 4


@pytest.mark.parametrize('positive', [False, True], ids=['protected', 'vulnerable'])
def test_preflight_accepts_matching_real_posture(tmp_path, monkeypatch, setup, positive):
    public, config, args = setup
    monkeypatch.setattr(recon_tools, '_run', process_for(config, positive))
    live.preflight(public, live.oracle_for(public, int(positive), config), tmp_path / 'preflight', args)
    attestation = json.loads((tmp_path / 'preflight/attestation.json').read_text())
    assert attestation['status'] == 'valid'
    assert attestation['post_probe_control_proven'] is True
    assert len(attestation['checks']) == 4


def test_preflight_refuses_contradictory_real_observations(tmp_path, monkeypatch, setup):
    public, config, args = setup
    monkeypatch.setattr(recon_tools, '_run', process_for(config, True))
    with pytest.raises(RuntimeError, match='preflight disagrees'):
        live.preflight(public, live.oracle_for(public, 0, config), tmp_path / 'preflight', args)
    assert json.loads((tmp_path / 'preflight/attestation.json').read_text())['status'] == 'invalid'


def test_briefing_never_carries_fixture_secrets_or_posture(setup):
    public, config, _ = setup
    text = json.dumps(public)
    for secret in (config['seeder_password'], config['public_canary'], config['private_canary']):
        assert secret not in text
    assert 'intentional_flaws' not in text and 'seeder' not in text
    oracle = live.oracle_for(public, 1, config)
    assert oracle['private_canary_sha256'] == hashlib.sha256(config['private_canary'].encode()).hexdigest()
    assert oracle['public_canary_sha256'] == hashlib.sha256(config['public_canary'].encode()).hexdigest()


@pytest.mark.parametrize('flaws', [0, 1])
def test_case_configuration_has_fresh_distinct_secrets(flaws):
    control, config = live.case_configuration(flaws)
    assert config['intentional_flaws'] == flaws
    assert config['control_user'] == control['username'] == 'auditor'
    assert len({control['password'], config['seeder_password'],
                config['public_canary'], config['private_canary']}) == 4
    other_control, other = live.case_configuration(flaws)
    assert other['private_canary'] != config['private_canary']
    assert other_control['password'] != control['password']


def test_wrong_runner_is_refused_before_any_command(monkeypatch):
    monkeypatch.delenv('RUNNER_NAME', raising=False)
    with pytest.raises(RuntimeError, match='nato-master'):
        live.require_nato()


@pytest.mark.parametrize('provider,model', [('ollama-umons', 'other-model'), ('minimax', 'qwen3.8:27b')])
def test_live_pilot_rejects_other_models_before_host_or_lab_access(monkeypatch, provider, model):
    monkeypatch.setattr(live, 'require_nato', lambda: pytest.fail('host access before model check'))
    args = SimpleNamespace(provider=provider, model=model, output=Path('/unused'))
    with pytest.raises(ValueError, match='no provider fallback'):
        live.run_experiment(args)


def test_guest_controller_validates_fixture_and_lease(monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'mqtt_guest_controller', ROOT / 'benchmarks/ansible/files/mqtt_reference_proxmox.py')
    guest = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guest)
    _, config = live.case_configuration(1)
    guest.validate_fixture(config)
    with pytest.raises(RuntimeError, match='invalid_fixture'):
        guest.validate_fixture({**config, 'private_topic': 'lance/public/status'})
    with pytest.raises(RuntimeError, match='invalid_fixture'):
        guest.validate_fixture({**config, 'seeder_password': config['control_password']})
    lease = {'vmid': 7001, 'owner': 'a' * 32, 'hostname': 'lance-mqtt-' + 'a' * 12,
             'ip': '192.168.100.220', 'template_vmid': 9000}
    monkeypatch.setattr(guest, 'config', lambda vmid: {'hostname': lease['hostname']})
    assert guest.guest_owned(lease)['hostname'] == lease['hostname']
    with pytest.raises(RuntimeError, match='invalid_owned_guest_lease'):
        guest.guest_owned({**lease, 'hostname': 'lance-ssh-' + 'a' * 12})


def test_guest_network_uses_laboratory_gateway_and_dns():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'mqtt_guest_controller_net', ROOT / 'benchmarks/ansible/files/mqtt_reference_proxmox.py')
    guest = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guest)
    # Laboratory apt path (group_vars benchmark_gateway/benchmark_dns); without
    # it apt-get inside the disposable guest failed with exit code 100.
    assert guest.LAB_GATEWAY == guest.LAB_DNS == '192.168.100.1'
    assert guest.net0_spec({'ip': '192.168.100.220'}) == \
        'name=eth0,bridge=vmbr1,ip=192.168.100.220/24,gw=192.168.100.1'


def test_verify_archives_detects_unlisted_evidence(tmp_path):
    (tmp_path / 'trials').mkdir()
    (tmp_path / 'archives').mkdir()
    (tmp_path / 'runs').mkdir()
    live.finalize_archives(tmp_path)
    assert live.verify_archives(tmp_path) == 0
    (tmp_path / 'unlisted.json').write_text('{}')
    with pytest.raises(ValueError, match='does not cover'):
        live.verify_archives(tmp_path)


def test_workflow_is_manual_dev2_only_and_keeps_evidence_local():
    path = ROOT / '.github/workflows/mqtt-reference.yml'
    text = path.read_text()
    document = yaml.safe_load(text)
    assert 'workflow_dispatch' in document[True]  # YAML parses the `on` key as True.
    assert 'nato-master' in text and 'refs/heads/dev/2' in text
    assert 'mqtt_reference_live run' in text and 'mqtt_reference_live recover' in text
    assert 'upload-artifact' not in text
    assert 'ollama-umons' in text and 'qwen3.8:27b' in text
