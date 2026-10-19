"""Read existing MQTT evidence and emit only explicitly authorized diagnostics.

Never emit raw log text, command arguments, passwords, paths or canary content.
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
UTILITIES = {'mosquitto', 'mosquitto_passwd', 'mosquitto_pub', 'mosquitto_sub', 'python3',
             'systemctl', 'systemd-run', 'pct', 'qm', 'pvesh', 'journalctl', 'apt-get'}
CONTROLLER_REASONS = {
    'Disposable Mosquitto guest did not become ready': 'mqtt_fixture_not_ready',
    'Real MQTT preflight disagrees with the private posture': 'mqtt_posture_preflight_failed',
    'Proxmox fixture operation could not be attested': 'proxmox_operation_not_attested',
    'Mosquitto binaries unavailable in fixture guest': 'mosquitto_binaries_unavailable',
}
# Fixed refusal strings emitted by the owned-guest controller itself; mapping is
# one-to-one and never copies free text from the response.
GUEST_REASONS = {
    'guest_operation_failed', 'guest_configuration_unreadable', 'invalid_owned_guest_lease',
    'guest_ownership_mismatch', 'invalid_fixture_fields', 'invalid_fixture_flaws',
    'invalid_fixture_topics', 'invalid_fixture_identity', 'invalid_fixture_data',
    'allocation_already_exists', 'expected_debian_template_missing',
    'template_requires_single_nic_unprivileged_guest', 'another_benchmark_guest_is_running',
    'no_free_fixture_allocation', 'fixture_guest_must_be_absent_before_reset',
    'fixture_guest_not_ready', 'invalid_owner', 'pve_nato_identity_mismatch',
    'not_a_proxmox_host', 'missing_allocation', 'lease_owner_mismatch',
    'unsupported_operation', 'operation_failed',
}
BROKER_REASONS = {
    'MQTT seed publish identifier rejected': 'mqtt_seed_identifier_rejected',
    'MQTT seed publish not authorised': 'mqtt_seed_not_authorised',
    'MQTT seed publish connection failed': 'mqtt_seed_connection_failed',
    'MQTT seed publish timed out': 'mqtt_seed_timed_out',
    'MQTT seed publish protocol error': 'mqtt_seed_protocol_error',
    'MQTT seed publish failed': 'mqtt_seed_failed',
    'Mosquitto system user unavailable in fixture guest': 'mosquitto_system_user_unavailable',
    'Mosquitto broker exited before seeding': 'mosquitto_broker_exited_before_seeding',
    'Mosquitto broker did not listen before seeding': 'mosquitto_broker_not_listening_before_seeding',
    'Address already in use': 'mosquitto_listen_address_in_use',
    'Cannot assign requested address': 'mosquitto_bind_address_unavailable',
    'unable to bind': 'mosquitto_listen_failed',
    'Unable to open pwfile': 'mosquitto_password_file_unavailable',
    'Error opening password file': 'mosquitto_password_file_unavailable',
    'Unable to open auth file': 'mosquitto_acl_file_unavailable',
    'Denied PUBLISH from': 'mqtt_publish_acl_denied',
    'ACL denying access': 'mqtt_acl_access_denied',
    'disconnected, not authorised': 'mqtt_connection_not_authorised',
    'Connection Refused: not authorised': 'mqtt_connection_not_authorised',
    'Connection Refused: identifier rejected': 'mqtt_identifier_rejected',
    'disconnected due to protocol error': 'mqtt_client_protocol_error',
    'Connection refused': 'broker_connection_refused',
    'E: Unable to locate package': 'guest_package_unavailable',
    'Failed to fetch': 'guest_package_fetch_failed',
    'Temporary failure in name resolution': 'guest_package_fetch_failed',
    'Could not resolve host': 'guest_package_fetch_failed',
    'status=226/NAMESPACE': 'systemd_namespace_setup_failed',
    'status=203/EXEC': 'systemd_executable_start_failed',
    'Failed at step': 'systemd_startup_step_failed',
    'Failed to start': 'service_start_failed',
    'Failed to execute': 'service_execute_failed',
    'No journal files were found': 'startup_journal_unavailable',
    '-- No entries --': 'startup_journal_empty',
    'code=killed, status=9/KILL': 'service_process_killed',
    'oom-kill': 'service_out_of_memory',
}


PREFLIGHT_CHECKS = ('control_private', 'anonymous_public',
                    'anonymous_private', 'control_private_after')


def entry(error=None, utility=None, returncode=None, reason='unclassified'):
    return {'error_type': error if error in ERRORS else None,
            'utility': utility if utility in UTILITIES else None,
            'returncode': returncode if type(returncode) is int and -255 <= returncode <= 255 else None,
            'reason': reason}


def broker_diagnostics(log):
    diagnostics = []
    for line in log.splitlines():
        for text, reason in BROKER_REASONS.items():
            if text in line:
                utility = ('journalctl' if reason.startswith('startup_journal_') else
                           'apt-get' if reason.startswith('guest_package_') else
                           None if reason.startswith(('systemd_', 'service_')) else 'mosquitto')
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


def _record_result(record):
    result = record.get('result')
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except ValueError:
            return None
    return result if isinstance(result, dict) else None


def _framing_outcome(stdout, topic):
    if not isinstance(stdout, str):
        return 'framing_invalid'
    present = False
    for line in stdout.split('\n'):
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except ValueError:
            return 'framing_invalid'
        if (not isinstance(message, dict)
                or set(message) != {'tst', 'topic', 'qos', 'retain', 'payload'}
                or not isinstance(message['tst'], str) or not isinstance(message['topic'], str)
                or type(message['qos']) is not int or message['qos'] not in (0, 1, 2)
                or type(message['retain']) is not int or message['retain'] not in (0, 1)
                or not isinstance(message['payload'], str)):
            return 'framing_invalid'
        present = present or message['topic'] == topic
    return 'messages_present' if present else 'no_messages'


def _preflight_diagnostics(root, read):
    """Project preflight tool outcomes; never emit args, topics or payloads."""
    diagnostics = []
    for ledger in sorted((root / 'trials').glob('*/preflight/*/tool_calls.jsonl')):
        trial = ledger.parents[2]
        try:
            briefing = json.loads(read(trial / 'briefing.json'))
            target = briefing['target']
            expected_topics = {
                'control_private': briefing['private_topic'],
                'anonymous_public': briefing['public_topic'],
                'anonymous_private': briefing['private_topic'],
                'control_private_after': briefing['private_topic']}
            control = briefing['control_credential']
            if not (isinstance(target['ip'], str) and type(target['port']) is int
                    and all(isinstance(value, str) for value in expected_topics.values())
                    and isinstance(control['username'], str) and isinstance(control['password'], str)):
                raise ValueError
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            diagnostics.append(entry(utility='python3', reason='mqtt_preflight_briefing_unavailable'))
            continue
        try:
            records = [json.loads(line) for line in read(ledger).splitlines() if line.strip()]
        except ValueError:
            diagnostics.append(entry(utility='mosquitto_sub', reason='mqtt_preflight_ledger_invalid'))
            continue
        if not records:
            diagnostics.append(entry(utility='mosquitto_sub', reason='mqtt_preflight_ledger_empty'))
            continue
        records = [record for _, record in sorted(
            enumerate(records),
            key=lambda item: (0, item[1]['sequence'], item[0])
            if isinstance(item[1], dict) and type(item[1].get('sequence')) is int
            else (1, 0, item[0]))]
        for index, record in enumerate(records[:len(PREFLIGHT_CHECKS)]):
            check = PREFLIGHT_CHECKS[index]
            result = _record_result(record) if isinstance(record, dict) else None
            returncode = result.get('return_code') if result is not None else None
            if type(returncode) is not int or isinstance(returncode, bool):
                returncode = None
            args = record.get('args') if isinstance(record, dict) else None
            topic = expected_topics[check]
            authenticated = check in ('control_private', 'control_private_after')
            bound = (isinstance(record, dict) and record.get('tool') == 'mqtt_listen'
                     and record.get('execution_origin') == 'runner' and isinstance(args, dict)
                     and args.get('broker') == target['ip'] and args.get('port') == target['port']
                     and args.get('topic') == topic
                     and ((args.get('username') == control['username']
                           and args.get('password') == control['password'])
                          if authenticated else
                          (not args.get('username') and not args.get('password'))))
            error = None
            if not bound:
                outcome = 'binding_mismatch'
            elif result is None:
                outcome = 'result_invalid'
            elif result.get('error') or result.get('error_kind') or result.get('success') is False:
                outcome, error = 'result_error', result.get('exception_type')
            elif returncode is None:
                outcome = 'result_invalid'
            elif returncode == 5:
                outcome = 'broker_refused'
            elif returncode not in (0, 27):
                outcome = 'unexpected_return_code'
            else:
                attestation = result.get('execution_attestation')
                if (not isinstance(attestation, dict) or attestation.get('protocol') != 'TCP'
                        or attestation.get('output_format') != 'mosquitto-json-v1'
                        or attestation.get('host') != target['ip']
                        or attestation.get('port') != target['port']
                        or attestation.get('topic') != topic):
                    outcome = 'attestation_invalid'
                else:
                    outcome = _framing_outcome(result.get('stdout'), topic)
            diagnostics.append(entry(error, 'mosquitto_sub', returncode,
                                     f'mqtt_preflight_{check}_{outcome}'))
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
        if response.get('ok') is False and response.get('reason') in GUEST_REASONS:
            diagnostics.append(entry(response.get('error_type'), reason=response['reason']))
        for operation in response.get('operations', []):
            diagnostics.extend(broker_diagnostics(operation.get('stdout', '') + '\n' + operation.get('stderr', '')))
            if operation.get('returncode', 0) != 0 or operation.get('error_type'):
                utility = PurePosixPath(operation['argv'][0]).name
                reason = 'external_operation_failed'
                if operation['argv'][:2] == ['pct', 'config'] and 'does not exist' in operation.get('stderr', ''):
                    reason = 'guest_configuration_absent'
                elif operation['argv'][:2] == ['pct', 'exec'] and 'journalctl' in operation['argv']:
                    reason, utility = 'fixture_journal_read_failed', 'journalctl'
                diagnostics.append(entry(operation.get('error_type'), utility,
                                         operation.get('returncode'), reason))
        diagnostics.extend(broker_diagnostics(response.get('result', {}).get('broker_log', '')))
        if response.get('result', {}).get('status') == 'absent':
            diagnostics.append(entry(utility='pct', reason='fixture_absent_during_cleanup'))
        if 'broker_log' in response.get('result', {}) and not response['result']['broker_log'].strip():
            diagnostics.append(entry(utility='journalctl', reason='startup_journal_unavailable'))
    diagnostics.extend(_preflight_diagnostics(root, read))
    # stop/recovery can record the same failure more than once.
    return [json.loads(value) for value in dict.fromkeys(json.dumps(item, sort_keys=True) for item in diagnostics)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--experiment', required=True)
    args = parser.parse_args()
    try:
        if not re.fullmatch(r'[0-9]+-[0-9]+', args.experiment):
            raise ValueError('Invalid experiment')
        store = Path('/opt/lance-dev-2/output/mqtt-reference').resolve()
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
