"""Ensure private MQTT evidence cannot become arbitrary GitHub log output."""
import json
from pathlib import Path
import subprocess

import yaml

from scripts.benchmark import mqtt_reference_diagnostics as diagnostics


def test_diagnostic_projection_never_copies_private_values(tmp_path):
    secret = 'NEVER_PUBLISH_THIS_CANARY_OR_PASSWORD'
    (tmp_path / 'controller-console.log').write_text(secret + '\nDisposable Mosquitto guest did not become ready')
    operations = tmp_path / 'proxmox-operations'
    operations.mkdir()
    (operations / '1.response.json').write_text(json.dumps({'ok': False, 'error_type': 'RuntimeError',
        'reason': 'guest_operation_failed', 'operations': [
        {'argv': ['/' + secret, '--password', secret], 'returncode': 2, 'error_type': secret,
         'stdout': secret, 'stderr': secret}],
        'result': {'broker_log': secret + "\nFileNotFoundError: [Errno 2] No such file or directory: 'mosquitto'\n"
                   + "CalledProcessError: Command '['apt-get', '--password', '" + secret
                   + "']' returned non-zero exit status 100."}}))
    result = diagnostics.inspect(tmp_path)
    assert secret not in json.dumps(result)
    assert diagnostics.entry('FileNotFoundError', 'mosquitto', reason='guest_startup_utility_missing') in result
    assert diagnostics.entry('CalledProcessError', 'apt-get', 100, 'guest_startup_command_failed') in result
    assert diagnostics.entry('RuntimeError', reason='guest_operation_failed') in result
    assert all(set(item) == {'error_type', 'utility', 'returncode', 'reason'} for item in result)
    assert {item['reason'] for item in result} <= {
        'mqtt_fixture_not_ready', 'guest_operation_failed', 'external_operation_failed',
        'guest_startup_utility_missing', 'guest_startup_command_failed'}


def test_diagnostic_duplicates_are_not_counted_as_distinct_errors(tmp_path):
    operations = tmp_path / 'proxmox-operations'
    operations.mkdir()
    response = {'result': {'broker_log': 'private-address Mosquitto failed: Address already in use'}}
    for i in range(2):
        (operations / f'{i}.response.json').write_text(json.dumps(response))
    result = diagnostics.inspect(tmp_path)
    assert result == [diagnostics.entry(utility='mosquitto', reason='mosquitto_listen_address_in_use')]
    assert 'private-address' not in json.dumps(result)


def test_unit_failures_and_missing_journal_are_classified_without_raw_output(tmp_path):
    operations = tmp_path / 'proxmox-operations'
    operations.mkdir()
    (operations / '1.response.json').write_text(json.dumps({'operations': [
        {'argv': ['pct', 'exec', '7000'], 'returncode': 0,
         'stdout': 'private-hostname systemd[1]: status=203/EXEC', 'stderr': ''}],
        'result': {'broker_log': '-- No entries --'}}))
    result = diagnostics.inspect(tmp_path)
    assert diagnostics.entry(reason='systemd_executable_start_failed') in result
    assert diagnostics.entry(utility='journalctl', reason='startup_journal_empty') in result
    assert 'private-hostname' not in json.dumps(result)


def test_fixed_guest_refusal_reason_is_surfaced_without_free_text(tmp_path):
    operations = tmp_path / 'proxmox-operations'
    operations.mkdir()
    (operations / '1.response.json').write_text(json.dumps(
        {'ok': False, 'error_type': 'RuntimeError', 'reason': 'another_benchmark_guest_is_running', 'operations': []}))
    assert diagnostics.inspect(tmp_path) == [
        diagnostics.entry('RuntimeError', reason='another_benchmark_guest_is_running')]


def test_inspection_workflow_is_manual_and_shell_syntax_valid():
    root = Path(__file__).resolve().parents[1]
    path = root / '.github/workflows/mqtt-reference-inspect.yml'
    workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    assert set(workflow['on']) == {'workflow_call'}
    ci = yaml.load((root / '.github/workflows/benchmark-integrity.yml').read_text(), Loader=yaml.BaseLoader)
    assert "github.event_name == 'workflow_dispatch'" in ci['jobs']['mqtt-inspect']['if']
    assert "inputs.mqtt_inspect_experiment != ''" in ci['jobs']['mqtt-inspect']['if']
    assert 'upload-artifact' not in path.read_text()
    script = workflow['jobs']['inspect']['steps'][-1]['run']
    assert '100\\.103\\.253\\.86/' in script and 'refs/heads/dev/2' in script
    assert 'mqtt_reference_diagnostics.py' in script
    subprocess.run(['bash', '-n'], input=script, text=True, check=True)
