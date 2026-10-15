"""Disposable SSH guest controller, executed only on the identified pve-nato.

No runner packages, host service, bridge or firewall configuration is changed.
Every destructive operation checks the guest's UUID-derived name first.
"""
from __future__ import annotations

import fcntl
import json
from pathlib import Path
import re
import subprocess
import sys
import time

OPERATIONS = []


def command(*argv, data=None, timeout=180, check=True):
    started = time.monotonic()
    try:
        result = subprocess.run(list(argv), input=data, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        OPERATIONS.append({'argv': list(argv), 'error_type': type(exc).__name__,
                           'duration_s': time.monotonic() - started})
        raise
    OPERATIONS.append({'argv': list(argv), 'returncode': result.returncode,
                       'stdout': result.stdout, 'stderr': result.stderr,
                       'duration_s': time.monotonic() - started})
    if check and result.returncode:
        raise RuntimeError('guest_operation_failed')
    return result


def config(vmid):
    result = command('pct', 'config', str(vmid), check=False)
    if result.returncode:
        if re.search(r"Configuration file .+ does not exist", result.stderr):
            return None
        raise RuntimeError('guest_configuration_unreadable')
    return dict(line.split(': ', 1) for line in result.stdout.splitlines() if ': ' in line)


def guest_owned(lease):
    if (type(lease.get('vmid')) is not int or not 7000 <= lease['vmid'] < 7100
            or re.fullmatch(r'[0-9a-f]{32}', lease.get('owner', '')) is None
            or lease.get('hostname') != 'lance-ssh-' + lease['owner'][:12]
            or lease.get('ip') not in {f'192.168.100.{suffix}' for suffix in range(220, 240)}
            or lease.get('template_vmid') != 9000):
        raise RuntimeError('invalid_owned_guest_lease')
    actual = config(lease['vmid'])
    if actual is not None and actual.get('hostname') != lease['hostname']:
        raise RuntimeError('guest_ownership_mismatch')
    return actual


def stop_guest(lease):
    actual = guest_owned(lease)
    if actual is None:
        return {'status': 'absent'}
    logs = command('pct', 'exec', str(lease['vmid']), '--', 'journalctl', '-u', 'lance-ssh-fixture',
                   '--no-pager', check=False).stdout
    status = command('pct', 'status', str(lease['vmid'])).stdout.strip()
    if status.endswith('running'):
        command('pct', 'stop', str(lease['vmid']))
    guest_owned(lease)
    command('pct', 'destroy', str(lease['vmid']))
    return {'status': 'destroyed', 'config_before': actual, 'server_log': logs}


def allocate(request, state):
    if state.is_file():
        raise RuntimeError('allocation_already_exists')
    template = config(9000)
    if template is None or template.get('template') != '1':
        raise RuntimeError('expected_debian_template_missing')
    if template.get('unprivileged') != '1' or any(key.startswith('net') and key != 'net0' for key in template):
        raise RuntimeError('template_requires_single_nic_unprivileged_guest')
    resources = json.loads(command('pvesh', 'get', '/cluster/resources', '--type', 'vm',
                                   '--output-format', 'json').stdout)
    used = {int(item['vmid']) for item in resources}
    addresses = set()
    for item in resources:
        vmid = int(item['vmid'])
        if item['type'] == 'lxc':
            actual = config(vmid) or {}
        else:
            output = command('qm', 'config', str(vmid)).stdout
            actual = dict(line.split(': ', 1) for line in output.splitlines() if ': ' in line)
        interfaces = [value for key, value in actual.items() if key.startswith('net')]
        for value in interfaces:
            addresses.update(re.findall(r'(?:^|,)ip=(\d+\.\d+\.\d+\.\d+)', value))
        on_benchmark = any(re.search(r'(?:^|,)bridge=vmbr1(?:,|$)', value) for value in interfaces)
        is_master = (item['type'] == 'lxc' and actual.get('hostname') == 'nato-master'
                     and any('ip=192.168.100.200/' in value for value in interfaces))
        if item.get('status') == 'running' and on_benchmark and not is_master:
            raise RuntimeError('another_benchmark_guest_is_running')
    vmid = next((candidate for candidate in range(7000, 7100) if candidate not in used), None)
    address = next((f'192.168.100.{suffix}' for suffix in range(220, 240)
                    if f'192.168.100.{suffix}' not in addresses), None)
    if vmid is None or address is None:
        raise RuntimeError('no_free_fixture_allocation')
    lease = {'owner': request['owner'], 'vmid': vmid, 'ip': address,
             'hostname': 'lance-ssh-' + request['owner'][:12], 'template_vmid': 9000,
             'template_config': template}
    state.write_text(json.dumps(lease))
    state.chmod(0o600)
    return lease


def start_guest(request, lease):
    if guest_owned(lease) is not None:
        raise RuntimeError('fixture_guest_must_be_absent_before_reset')
    fixture = request['fixture']
    if set(fixture) != {'accounts', 'object'}:
        raise RuntimeError('invalid_fixture_fields')
    users = [item['user'] for item in fixture['accounts']]
    if users != ['auditor', 'alpha', 'beta', 'gamma']:
        raise RuntimeError('invalid_fixture_users')
    if (any(set(item) != {'user', 'password'} or not isinstance(item['password'], str)
            or not re.fullmatch(r'[A-Za-z0-9_-]{1,256}', item['password']) for item in fixture['accounts'])
            or not isinstance(fixture['object'], str)
            or re.fullmatch(r'[0-9a-f]{64}\n', fixture['object']) is None):
        raise RuntimeError('invalid_fixture_data')
    command('pct', 'clone', '9000', str(lease['vmid']), '--hostname', lease['hostname'], '--full', timeout=300)
    guest_owned(lease)
    command('pct', 'set', str(lease['vmid']), '--memory', '256', '--cores', '1',
            '--features', 'nesting=0',
            '--net0', f"name=eth0,bridge=vmbr1,ip={lease['ip']}/24")
    command('pct', 'start', str(lease['vmid']))
    for _ in range(40):
        if command('pct', 'exec', str(lease['vmid']), '--', 'true', check=False).returncode == 0:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError('fixture_guest_not_ready')
    # Content travels on stdin, never as shell source or a process argument.
    payload = json.dumps({'fixture': {**fixture, 'listen_address': lease['ip']},
                          'start_source': request['start_source']})
    installer = """import base64,json,pathlib,sys
p=json.load(sys.stdin)
pathlib.Path('/fixture.json').write_text(json.dumps(p['fixture']))
pathlib.Path('/fixture.json').chmod(0o600)
pathlib.Path('/lance-ssh-start.py').write_bytes(base64.b64decode(p['start_source'],validate=True))
"""
    command('pct', 'exec', str(lease['vmid']), '--', 'python3', '-c', installer, data=payload)
    command('pct', 'exec', str(lease['vmid']), '--', 'systemctl', 'stop', 'ssh.service', 'ssh.socket', check=False)
    command('pct', 'exec', str(lease['vmid']), '--', 'systemd-run', '--unit=lance-ssh-fixture',
            '--property=Restart=no', '/usr/bin/python3', '/lance-ssh-start.py')
    return {**lease, 'config_after': guest_owned(lease), 'port': 2222}


def main(request):
    owner = request.get('owner', '')
    if not re.fullmatch(r'[0-9a-f]{32}', owner):
        raise RuntimeError('invalid_owner')
    addresses = json.loads(command('ip', '-j', '-4', 'addr').stdout)
    if not any(item.get('local') == '100.76.206.65' for interface in addresses
               for item in interface.get('addr_info', [])):
        raise RuntimeError('pve_nato_identity_mismatch')
    version = command('pveversion').stdout.strip()
    if not version.startswith('pve-manager/'):
        raise RuntimeError('not_a_proxmox_host')
    state = Path('/var/lib/lance/ssh-reference') / owner / 'lease.json'
    with (state.parent.parent / '.allocation.lock').open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if request['operation'] == 'allocate':
            result = allocate(request, state)
        else:
            if not state.is_file():
                if request['operation'] == 'cleanup':
                    return {'ok': True, 'status': 'no_allocation'}
                raise RuntimeError('missing_allocation')
            lease = json.loads(state.read_text())
            if lease['owner'] != owner:
                raise RuntimeError('lease_owner_mismatch')
            if request['operation'] == 'start':
                result = start_guest(request, lease)
            elif request['operation'] in {'stop', 'cleanup'}:
                result = stop_guest(lease)
                if request['operation'] == 'cleanup':
                    state.unlink()
            else:
                raise RuntimeError('unsupported_operation')
    return {'ok': True, 'result': result, 'proxmox_version': version,
            'host': command('hostname', '-s').stdout.strip(), 'verified_tailnet_ip': '100.76.206.65'}


if __name__ == '__main__':
    try:
        response = main(json.load(sys.stdin))
    except Exception as exc:
        reason = str(exc) if type(exc) is RuntimeError else 'operation_failed'
        response = {'ok': False, 'error_type': type(exc).__name__, 'reason': reason}
    print(json.dumps({**response, 'operations': OPERATIONS}))
