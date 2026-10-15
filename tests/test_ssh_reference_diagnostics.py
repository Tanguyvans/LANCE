"""Ensure private evidence cannot become arbitrary GitHub log output."""
import json
from pathlib import Path
import subprocess

import yaml

from scripts.benchmark import ssh_reference_diagnostics as diagnostics


def test_diagnostic_projection_never_copies_private_values(tmp_path):
    secret = 'NEVER_PUBLISH_THIS_PRIVATE_OBJECT_OR_PASSWORD'
    (tmp_path / 'controller-console.log').write_text(secret + '\nDisposable OpenSSH guest did not become ready')
    operations = tmp_path / 'proxmox-operations'
    operations.mkdir()
    (operations / '1.response.json').write_text(json.dumps({'operations': [
        {'argv': ['/' + secret, '--password', secret], 'returncode': 2, 'error_type': secret,
         'stdout': secret, 'stderr': secret}],
        'result': {'server_log': secret + "\nFileNotFoundError: [Errno 2] No such file or directory: 'groupadd'\n"
                   + "CalledProcessError: Command '['useradd', '--password', '" + secret
                   + "']' returned non-zero exit status 9."}}))
    result = diagnostics.inspect(tmp_path)
    assert secret not in json.dumps(result)
    assert diagnostics.entry('FileNotFoundError', 'groupadd', reason='guest_startup_utility_missing') in result
    assert diagnostics.entry('CalledProcessError', 'useradd', 9, 'guest_startup_command_failed') in result
    assert all(set(item) == {'error_type', 'utility', 'returncode', 'reason'} for item in result)
    assert {item['reason'] for item in result} <= {
        'ssh_fixture_not_ready', 'external_operation_failed',
        'guest_startup_utility_missing', 'guest_startup_command_failed'}


def test_diagnostic_duplicates_are_not_counted_as_distinct_errors(tmp_path):
    operations = tmp_path / 'proxmox-operations'
    operations.mkdir()
    response = {'result': {'server_log': 'Missing privilege separation directory: /run/sshd'}}
    for i in range(2):
        (operations / f'{i}.response.json').write_text(json.dumps(response))
    assert diagnostics.inspect(tmp_path) == [diagnostics.entry(utility='sshd', reason='sshd_runtime_directory_missing')]


def test_unit_failures_and_missing_journal_are_classified_without_raw_output(tmp_path):
    operations = tmp_path / 'proxmox-operations'
    operations.mkdir()
    (operations / '1.response.json').write_text(json.dumps({'operations': [
        {'argv': ['pct', 'exec', '7000'], 'returncode': 0,
         'stdout': 'private-hostname systemd[1]: status=203/EXEC', 'stderr': ''}],
        'result': {'server_log': '-- No entries --'}}))
    result = diagnostics.inspect(tmp_path)
    assert diagnostics.entry(reason='systemd_executable_start_failed') in result
    assert diagnostics.entry(utility='journalctl', reason='startup_journal_empty') in result
    assert 'private-hostname' not in json.dumps(result)


def test_inspection_workflow_is_manual_and_shell_syntax_valid():
    root = Path(__file__).resolve().parents[1]
    path = root / '.github/workflows/ssh-reference-inspect.yml'
    workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    assert set(workflow['on']) == {'workflow_call'}
    ci = yaml.load((root / '.github/workflows/benchmark-integrity.yml').read_text(), Loader=yaml.BaseLoader)
    assert "github.event_name == 'workflow_dispatch'" in ci['jobs']['ssh-inspect']['if']
    assert "inputs.ssh_inspect_experiment != ''" in ci['jobs']['ssh-inspect']['if']
    assert 'upload-artifact' not in path.read_text()
    script = workflow['jobs']['inspect']['steps'][-1]['run']
    assert '100\\.103\\.253\\.86/' in script and 'refs/heads/dev/2' in script
    subprocess.run(['bash', '-n'], input=script, text=True, check=True)
