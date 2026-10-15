"""Native fixture boundaries with external Proxmox/Ansible/model I/O simulated."""
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest
import yaml

from benchmarks.experiments import ssh_reference_live as live
from benchmarks.experiments import ssh_reference_proxmox as runtime


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'ssh_guest_controller', ROOT / 'benchmarks/ansible/files/ssh_reference_proxmox.py')
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)
fixture_spec = importlib.util.spec_from_file_location(
    'ssh_fixture_start', ROOT / 'benchmarks/experiments/ssh-reference/fixture/start.py')
fixture_module = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture_module)
OWNER = 'a' * 32


def lease(**changes):
    return {'owner': OWNER, 'hostname': 'lance-ssh-' + OWNER[:12], 'vmid': 7000,
            'ip': '192.168.100.220', 'template_vmid': 9000, **changes}


def test_wrong_host_rejected_before_state_or_guest_access(monkeypatch):
    commands = []

    def command(*argv, **kwargs):
        commands.append(argv)
        return SimpleNamespace(stdout=json.dumps([{'addr_info': [{'local': '192.0.2.1'}]}]))

    monkeypatch.setattr(guest, 'command', command)
    with pytest.raises(RuntimeError, match='pve_nato_identity_mismatch'):
        guest.main({'owner': OWNER, 'operation': 'cleanup'})
    assert commands == [('ip', '-j', '-4', 'addr')]


@pytest.mark.parametrize('changes', [
    {'vmid': 200}, {'owner': '../other'}, {'hostname': 'nato-master'},
    {'ip': '192.168.100.200'}, {'template_vmid': 200},
])
def test_invalid_lease_cannot_start_or_destroy_any_guest(monkeypatch, changes):
    monkeypatch.setattr(guest, 'command', lambda *a, **k: pytest.fail('No Proxmox access allowed'))
    for operation in (lambda: guest.stop_guest(lease(**changes)),
                      lambda: guest.start_guest({}, lease(**changes))):
        with pytest.raises(RuntimeError, match='invalid_owned_guest_lease'):
            operation()


def test_reused_id_with_different_owner_is_never_destroyed(monkeypatch):
    monkeypatch.setattr(guest, 'config', lambda _: {'hostname': 'other-campaign'})
    monkeypatch.setattr(guest, 'command', lambda *a, **k: pytest.fail('No mutation allowed'))
    with pytest.raises(RuntimeError, match='guest_ownership_mismatch'):
        guest.stop_guest(lease())


def test_configuration_failure_cannot_be_mistaken_for_absent_guest(monkeypatch):
    monkeypatch.setattr(guest, 'command', lambda *a, **k:
                        SimpleNamespace(returncode=1, stderr='permission denied', stdout=''))
    with pytest.raises(RuntimeError, match='guest_configuration_unreadable'):
        guest.config(7000)


def allocation_inventory(monkeypatch, extra):
    resources = [{'vmid': 9000, 'type': 'lxc', 'status': 'stopped'},
                 {'vmid': 200, 'type': 'lxc', 'status': 'running'}, *extra]
    configurations = {
        9000: {'template': '1', 'unprivileged': '1', 'net0': 'name=eth0,bridge=vmbr2,ip=dhcp'},
        200: {'hostname': 'nato-master', 'net0': 'name=eth1,bridge=vmbr1,ip=192.168.100.200/24'},
        7000: {'hostname': 'other-stopped-guest', 'net0': 'name=eth0,bridge=vmbr1,ip=192.168.100.220/24'},
    }
    monkeypatch.setattr(guest, 'config', lambda vmid: configurations[vmid])

    def command(*argv, **kwargs):
        assert argv == ('pvesh', 'get', '/cluster/resources', '--type', 'vm', '--output-format', 'json')
        return SimpleNamespace(stdout=json.dumps(resources))

    monkeypatch.setattr(guest, 'command', command)


def test_active_campaign_is_refused_without_allocating(monkeypatch, tmp_path):
    allocation_inventory(monkeypatch, [{'vmid': 7000, 'type': 'lxc', 'status': 'running'}])
    state = tmp_path / 'lease.json'
    with pytest.raises(RuntimeError, match='another_benchmark_guest_is_running'):
        guest.allocate({'owner': OWNER}, state)
    assert not state.exists()


def test_allocation_skips_occupied_id_and_address(monkeypatch, tmp_path):
    allocation_inventory(monkeypatch, [{'vmid': 7000, 'type': 'lxc', 'status': 'stopped'}])
    state = tmp_path / 'lease.json'
    result = guest.allocate({'owner': OWNER}, state)
    assert result['vmid'] == 7001 and result['ip'] == '192.168.100.221'
    assert json.loads(state.read_text()) == result
    assert state.stat().st_mode & 0o777 == 0o600


def test_cleanup_rechecks_ownership_after_stop(monkeypatch):
    configs = iter([{'hostname': lease()['hostname']}, {'hostname': 'replacement'}])
    monkeypatch.setattr(guest, 'config', lambda _: next(configs))
    commands = []

    def command(*argv, **kwargs):
        commands.append(argv)
        return SimpleNamespace(stdout='status: running')

    monkeypatch.setattr(guest, 'command', command)
    with pytest.raises(RuntimeError, match='guest_ownership_mismatch'):
        guest.stop_guest(lease())
    assert ('pct', 'stop', '7000') in commands
    assert not any('destroy' in args for args in commands)


def test_rpc_preserves_private_input_and_response_without_shell(monkeypatch, tmp_path):
    config = {'accounts': [{'user': 'auditor', 'password': 'private-password'}], 'object': 'private-object'}

    def run(argv, **kwargs):
        assert kwargs['cwd'] == ROOT / 'benchmarks/ansible'
        assert 'shell' not in kwargs
        assert all('private-password' not in arg and 'private-object' not in arg for arg in argv)
        path = Path(argv[-1][1:])
        assert path.stat().st_mode & 0o777 == 0o600
        variables = json.loads(path.read_text())
        request = variables['ssh_reference_request']
        assert request['fixture'] == config
        assert base64.b64decode(request['start_source']) == (
            ROOT / 'benchmarks/experiments/ssh-reference/fixture/start.py').read_bytes()
        runtime.write(Path(variables['ssh_reference_result']), {'ok': True, 'result': {'status': 'started'}})
        return SimpleNamespace(returncode=0, stdout='Ansible task log', stderr='')

    monkeypatch.setattr(subprocess, 'run', run)
    assert runtime.Proxmox(tmp_path, OWNER).call('start', config)['ok'] is True
    executions = list((tmp_path / 'proxmox-operations').glob('*.execution.json'))
    assert len(executions) == 1 and 'Ansible task log' in executions[0].read_text()


def test_rpc_timeout_is_retained(monkeypatch, tmp_path):
    def timeout(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 420, output='partial operation log')

    monkeypatch.setattr(subprocess, 'run', timeout)
    with pytest.raises(subprocess.TimeoutExpired):
        runtime.Proxmox(tmp_path, OWNER).call('stop')
    execution = json.loads(next((tmp_path / 'proxmox-operations').glob('*.execution.json')).read_text())
    assert execution['error_type'] == 'TimeoutExpired' and 'partial operation log' in execution['stdout']


def test_partial_guest_setup_is_still_cleaned_up(tmp_path):
    calls = []

    def call(operation, *args):
        calls.append(operation)
        if operation == 'start':
            raise RuntimeError('interrupted after clone')
        return {'ok': True, 'status': 'destroyed'}

    config = tmp_path / 'private.json'
    runtime.write(config, {})
    backend = SimpleNamespace(allocation=lease(), call=call)
    fixture = runtime.Fixture(backend, config, tmp_path / 'fixture')
    with pytest.raises(RuntimeError, match='interrupted after clone'):
        fixture.start()
    fixture.close()
    assert calls == ['start', 'stop'] and not fixture.started


def test_unavailable_qwen_prevents_any_allocation_and_seals_diagnostics(tmp_path, monkeypatch):
    args = SimpleNamespace(output=tmp_path / 'experiment', provider=live.PROVIDER, model=live.MODEL,
                           max_tool_calls=8, max_duration_s=60, max_cost_usd=1, max_turns=10)
    monkeypatch.setattr(live, 'require_nato', lambda: None)
    monkeypatch.setattr(live.shutil, 'which', lambda _: '/existing-binary')
    monkeypatch.setattr(runtime.Proxmox, 'prepare', lambda _: pytest.fail('No allocation allowed'))
    monkeypatch.setattr(runtime.Proxmox, 'call', lambda *a, **k: pytest.fail('No remote mutation allowed'))

    def catalogue():
        raise ConnectionError('private endpoint diagnostic')

    provider = SimpleNamespace(client=SimpleNamespace(with_options=lambda **k:
                               SimpleNamespace(models=SimpleNamespace(list=catalogue))))
    monkeypatch.setattr('src.agent.provider.LLMProvider', lambda *a: provider)
    with pytest.raises(ConnectionError):
        live.run_experiment(args)
    summary = live.public_summary(args.output)
    assert summary['provider-preflight-error']['error_type'] == 'ConnectionError'
    assert 'private endpoint diagnostic' not in json.dumps(summary)
    assert json.loads((args.output / 'ownership.json').read_text())['resources_may_exist'] is False
    assert summary['verified_files'] >= 6 and not summary['cases']


def test_safe_summary_excludes_raw_proxmox_operations(tmp_path):
    runtime.write(tmp_path / 'proxmox-operations' / '1.response.json', {
        'ok': False, 'error_type': 'RuntimeError', 'reason': 'another_benchmark_guest_is_running',
        'operations': [{'stdout': 'private infrastructure details'}]})
    live.finalize_archives(tmp_path)
    summary = live.public_summary(tmp_path)
    assert summary['proxmox_failures'] == [{'error_type': 'RuntimeError', 'reason': 'another_benchmark_guest_is_running'}]
    assert 'private infrastructure details' not in json.dumps(summary)


def test_playbook_checks_identity_before_transfer_or_mutation():
    playbook = yaml.load((ROOT / 'benchmarks/ansible/playbooks/ssh_reference.yml').read_text(),
                         Loader=yaml.BaseLoader)
    tasks = playbook[0]['tasks']
    assert tasks[0]['ansible.builtin.command'] == 'ip -j -4 addr'
    assert '100.76.206.65' in tasks[1]['ansible.builtin.assert']['that'][0]
    assert 'ansible.builtin.file' in tasks[2] and 'ansible.builtin.copy' in tasks[3]
    assert tasks[4]['no_log'] == tasks[5]['no_log'] == 'true'


@pytest.mark.skipif(not Path('/usr/sbin/sshd').is_file(), reason='OpenSSH server binary not installed')
def test_fixture_launch_reaches_openssh_config_loader_with_absolute_argv0(tmp_path):
    # A deliberately absent config makes the real binary exit before any key
    # loading or socket binding, even if this test is run by root.
    missing = tmp_path / 'absent-sshd-config'
    result = subprocess.run(fixture_module.sshd_command(str(missing)), executable='/usr/sbin/sshd',
                            capture_output=True, text=True, timeout=5)
    assert 'requires execution with an absolute path' not in result.stderr
    assert str(missing) in result.stderr and result.returncode != 0
