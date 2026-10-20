"""NATO's existing Ansible/LXC runtime for the bounded API fixture."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import socket
import subprocess
import time


ROOT = Path(__file__).resolve().parents[2]
PORT = 8080


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    path.chmod(0o600)


class Proxmox:
    def __init__(self, root, owner):
        self.root, self.owner, self.allocation = root, owner, None

    def call(self, operation, fixture=None):
        token = str(time.time_ns())
        directory = self.root / 'proxmox-operations'
        directory.mkdir(parents=True, exist_ok=True)
        request = {'owner': self.owner, 'operation': operation}
        if fixture is not None:
            request.update(fixture=fixture, start_source=base64.b64encode(
                (ROOT / 'benchmarks/experiments/api-reference/fixture/start.py').read_bytes()).decode())
        response_path = (directory / f'{token}.response.json').resolve()
        variables_path = directory / f'{token}.request.json'
        write(variables_path, {'api_reference_request': request, 'api_reference_result': str(response_path)})
        argv = [
            'ansible-playbook', '-i', 'inventory.yml', 'playbooks/api_reference.yml',
            '--vault-password-file', '/root/.vault_pass', '--extra-vars', '@' + str(variables_path.resolve()),
        ]
        try:
            result = subprocess.run(argv, cwd=ROOT / 'benchmarks/ansible',
                                    capture_output=True, text=True, timeout=420)
        except (OSError, subprocess.TimeoutExpired) as exc:
            write(directory / f'{token}.execution.json', {'operation': operation,
                  'error_type': type(exc).__name__, 'returncode': None,
                  'stdout': str(getattr(exc, 'stdout', '') or ''),
                  'stderr': str(getattr(exc, 'stderr', '') or '')})
            raise
        write(directory / f'{token}.execution.json', {'operation': operation, 'returncode': result.returncode,
                                                    'stdout': result.stdout, 'stderr': result.stderr})
        if result.returncode or not response_path.is_file():
            raise RuntimeError('Proxmox fixture operation could not be attested')
        response = json.loads(response_path.read_text())
        if response.get('ok') is not True:
            raise RuntimeError('Proxmox fixture refused: ' + response.get('reason', 'unknown'))
        return response

    def prepare(self):
        response = self.call('allocate')
        self.allocation = response['result']
        write(self.root / 'allocation.json', response)
        return self.allocation

    def cleanup(self):
        ownership = self.root / 'ownership.json'
        if ownership.is_file() and json.loads(ownership.read_text()).get('resources_may_exist') is False:
            write(self.root / 'cleanup.json', {'status': 'not_required', 'reason': 'environment_creation_not_started'})
            return
        response = self.call('cleanup')
        write(self.root / 'cleanup.json', {'status': 'completed', 'response': response})


class Fixture:
    def __init__(self, backend, config, directory):
        self.backend, self.config, self.directory, self.started = backend, config, directory, False
        self.address = backend.allocation['ip']
        self.port = PORT

    def start(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        self.started = True  # Also recover a clone interrupted during setup.
        response = self.backend.call('start', json.loads(self.config.read_text()))
        write(self.directory / 'guest-before.json', response)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((self.address, self.port), timeout=1):
                    write(self.directory / 'readiness.json',
                          {'tcp_connected': True, 'ip': self.address, 'port': self.port})
                    return self.port
            except (OSError, TimeoutError):
                pass
            time.sleep(0.25)
        raise RuntimeError('Disposable API guest did not become ready')

    def close(self):
        if self.started:
            response = self.backend.call('stop')
            write(self.directory / 'guest-after.json', response)
            self.started = False
