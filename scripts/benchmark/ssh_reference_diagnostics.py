"""Read existing SSH evidence and emit only explicitly authorized diagnostics.

Never emit raw log text, command arguments, passwords, paths or object content.
Every textual output field is selected from a fixed allowlist.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path, PurePosixPath
import re


ERRORS = {'RuntimeError', 'ValueError', 'OSError', 'FileNotFoundError', 'FileExistsError',
          'PermissionError', 'CalledProcessError', 'TimeoutExpired', 'ConnectionError',
          'KeyError', 'TypeError', 'JSONDecodeError', 'AssertionError'}
UTILITIES = {'groupadd', 'useradd', 'chpasswd', 'chown', 'ssh-keygen', 'sshd', 'ssh',
             'sshpass', 'python3', 'systemctl', 'systemd-run', 'pct', 'qm', 'pvesh', 'journalctl'}
CONTROLLER_REASONS = {
    'Disposable OpenSSH guest did not become ready': 'ssh_fixture_not_ready',
    'Real SSH preflight disagrees with the private posture': 'ssh_posture_preflight_failed',
    'Proxmox fixture operation could not be attested': 'proxmox_operation_not_attested',
}
SERVER_REASONS = {
    'no hostkeys available': 'sshd_host_keys_missing',
    'Missing privilege separation directory': 'sshd_runtime_directory_missing',
    'Cannot bind any address': 'sshd_listen_failed',
    'Cannot assign requested address': 'sshd_bind_address_unavailable',
    'Bad configuration option': 'sshd_invalid_configuration',
    'status=226/NAMESPACE': 'systemd_namespace_setup_failed',
    'status=203/EXEC': 'systemd_executable_start_failed',
    'Failed at step': 'systemd_startup_step_failed',
    'Failed to start': 'service_start_failed',
    'Failed to execute': 'service_execute_failed',
    'No journal files were found': 'startup_journal_unavailable',
    '-- No entries --': 'startup_journal_empty',
    'code=killed, status=9/KILL': 'service_process_killed',
    'oom-kill': 'service_out_of_memory',
    'unable to bind': 'sshd_listen_failed',
}


def entry(error=None, utility=None, returncode=None, reason='unclassified'):
    return {'error_type': error if error in ERRORS else None,
            'utility': utility if utility in UTILITIES else None,
            'returncode': returncode if type(returncode) is int and -255 <= returncode <= 255 else None,
            'reason': reason}


def server_diagnostics(log):
    diagnostics = []
    for line in log.splitlines():
        for text, reason in SERVER_REASONS.items():
            if text in line:
                utility = ('journalctl' if reason.startswith('startup_journal_') else
                           None if reason.startswith(('systemd_', 'service_')) else 'sshd')
                diagnostics.append(entry(utility=utility, reason=reason))
        error = re.search(r'\b(' + '|'.join(sorted(ERRORS)) + r'):', line)
        if not error:
            continue
        value = entry(error[1], reason='guest_startup_exception')
        command = re.search(r"Command '(\[.*\])' returned non-zero exit status (\d+)", line)
        if command:
            try:
                utility = PurePosixPath(ast.literal_eval(command[1])[0]).name
                value = entry(error[1], utility, int(command[2]), 'guest_startup_command_failed')
            except (ValueError, SyntaxError, TypeError, IndexError):
                pass
        for utility in UTILITIES:
            if f"No such file or directory: '{utility}'" in line:
                value = entry(error[1], utility, reason='guest_startup_utility_missing')
        diagnostics.append(value)
    return diagnostics


def inspect(root):
    def read(path):
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('Evidence path outside the selected experiment')
        return path.read_text()

    diagnostics = []
    console = root / 'controller-console.log'
    if console.is_file():
        text = read(console)
        diagnostics.extend(entry('RuntimeError', reason=reason)
                           for marker, reason in CONTROLLER_REASONS.items() if marker in text)
    for path in sorted((root / 'proxmox-operations').glob('*.response.json')):
        response = json.loads(read(path))
        for operation in response.get('operations', []):
            diagnostics.extend(server_diagnostics(operation.get('stdout', '') + '\n' + operation.get('stderr', '')))
            if operation.get('returncode', 0) != 0 or operation.get('error_type'):
                utility = PurePosixPath(operation['argv'][0]).name
                reason = 'external_operation_failed'
                if operation['argv'][:2] == ['pct', 'config'] and 'does not exist' in operation.get('stderr', ''):
                    reason = 'guest_configuration_absent'
                elif operation['argv'][:2] == ['pct', 'exec'] and 'journalctl' in operation['argv']:
                    reason, utility = 'fixture_journal_read_failed', 'journalctl'
                diagnostics.append(entry(operation.get('error_type'), utility,
                                         operation.get('returncode'), reason))
        diagnostics.extend(server_diagnostics(response.get('result', {}).get('server_log', '')))
        if response.get('result', {}).get('status') == 'absent':
            diagnostics.append(entry(utility='pct', reason='fixture_absent_during_cleanup'))
        if 'server_log' in response.get('result', {}) and not response['result']['server_log'].strip():
            diagnostics.append(entry(utility='journalctl', reason='startup_journal_unavailable'))
    # stop/recovery can record the same failure more than once.
    return [json.loads(value) for value in dict.fromkeys(json.dumps(item, sort_keys=True) for item in diagnostics)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--experiment', required=True)
    args = parser.parse_args()
    try:
        if not re.fullmatch(r'[0-9]+-[0-9]+', args.experiment):
            raise ValueError('Invalid experiment')
        store = Path('/opt/lance-dev-2/output/ssh-reference').resolve()
        root = store / args.experiment
        if not root.is_dir() or root.resolve().parent != store:
            raise FileNotFoundError('Selected evidence unavailable')
        result = inspect(root)
    except Exception as exc:
        print(json.dumps([entry(type(exc).__name__, 'python3', reason='diagnostic_collection_failed')]))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
