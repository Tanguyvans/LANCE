"""Real OpenSSH D1/LLM qualification on nato; never deploys a Proxmox scenario."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import socket
import subprocess
import tarfile
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

from benchmarks.experiments.ssh_reference import (
    CONTRACT, _bound, _denied, _payload, bind_ssh_tool, evaluate_trial,
    proof_command, run_rules, validate_briefing,
)
from benchmarks.experiments.ssh_reference_llm import RecordingClient, run_llm
from scripts.benchmark.pilot_support import archive_trial
from src.agent.audit_experiment import digest, resource_manifest
from src.agent.cost_tracker import CostTracker


ROOT = Path(__file__).resolve().parents[2]
LABEL = 'lance.ssh-reference'


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + '\n', encoding='utf-8')
    path.chmod(0o600)


def read_ledger(directory):
    path = directory / 'tool_calls.jsonl'
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.is_file() else None


def require_nato():
    if os.environ.get('RUNNER_NAME') != 'nato-master':
        raise RuntimeError('This controller requires the nato-master Actions runner')
    addresses = json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr'], text=True, timeout=10))
    if not any(item.get('local') == '100.103.253.86' for interface in addresses
               for item in interface.get('addr_info', [])):
        raise RuntimeError('Runner identity mismatch: nato Tailscale address absent')
    if os.environ.get('LANCE_SSH_LOCK_HELD') != '1':
        raise RuntimeError('Acquire the shared laboratory lock before running this controller')


class Docker:
    def __init__(self, root, owner):
        self.root, self.owner, self.sequence = root, owner, 0

    def call(self, *args, timeout=60, check=True):
        self.sequence += 1
        result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=timeout)
        write_json(self.root / 'docker-operations' / f'{time.time_ns()}-{self.sequence}.json', {
            'argv': ['docker', *args], 'returncode': result.returncode,
            'stdout': result.stdout, 'stderr': result.stderr,
        })
        if check and result.returncode:
            raise RuntimeError(f'Docker operation failed: {args[0]}')
        return result

    def cleanup(self):
        containers = self.call('ps', '-aq', '--filter', f'label={LABEL}={self.owner}').stdout.split()
        if containers:
            self.call('rm', '-f', *containers)
        networks = self.call('network', 'ls', '-q', '--filter', f'label={LABEL}={self.owner}').stdout.split()
        if networks:
            self.call('network', 'rm', *networks)
        write_json(self.root / 'cleanup.json', {'status': 'completed', 'owner': self.owner})


class Fixture:
    def __init__(self, docker, image, network, config, directory, port=None):
        self.docker, self.directory, self.cid = docker, directory, None
        self.image, self.network, self.config, self.port = image, network, config, port

    def start(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        published = f'127.0.0.1:{self.port or ""}:22'
        self.cid = self.docker.call(
            'run', '-d', '--label', f'{LABEL}={self.docker.owner}',
            '--network', self.network, '--publish', published,
            '--pids-limit', '128', '--memory', '256m', '--cpus', '1',
            '--cap-drop', 'NET_RAW', '--security-opt', 'no-new-privileges',
            '--mount', f'type=bind,source={self.config.resolve()},target=/fixture.json,readonly',
            self.image,
        ).stdout.strip()
        inspection = json.loads(self.docker.call('inspect', self.cid).stdout)[0]
        binding = inspection['NetworkSettings']['Ports']['22/tcp']
        if len(binding) != 1 or binding[0]['HostIp'] != '127.0.0.1':
            raise RuntimeError('SSH fixture must be published only on loopback')
        self.port = int(binding[0]['HostPort'])
        write_json(self.directory / 'container-before.json', inspection)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=1) as client:
                    client.settimeout(1)
                    banner = client.recv(256).decode('ascii', errors='replace')
                if banner.startswith('SSH-2.0-OpenSSH_'):
                    write_json(self.directory / 'readiness.json', {'banner': banner, 'port': self.port})
                    return self.port
            except (OSError, TimeoutError):
                pass
            time.sleep(0.25)
        raise RuntimeError('OpenSSH fixture did not become ready')

    def close(self):
        if self.cid is None:
            return
        logs = self.docker.call('logs', '--timestamps', self.cid, check=False)
        (self.directory / 'server.log').write_text(logs.stdout + logs.stderr, encoding='utf-8')
        result = self.docker.call('inspect', self.cid, check=False)
        if result.returncode == 0:
            write_json(self.directory / 'container-after.json', json.loads(result.stdout)[0])
        self.docker.call('rm', '-f', self.cid)
        self.cid = None


def new_run(directory, policy, args):
    directory.mkdir(parents=True, exist_ok=True)
    # An explicitly opened empty collection is distinct from missing evidence
    # when the provider fails before its first SSH operation.
    (directory / 'tool_calls.jsonl').touch(exist_ok=False)
    run = SimpleNamespace(
        run_dir=directory, max_tool_calls=args.max_tool_calls,
        max_duration_s=args.max_duration_s, max_turns=args.max_turns,
        _artifact_log_lock=threading.Lock(), _tool_call_count=0,
        _run_started=time.monotonic(), _execution_limit_reason=None,
        experiment_scope='ssh-reference-calibration', context={'target_subnet': '127.0.0.1/32'},
        decision_policy=policy,
        tracker=CostTracker(model=args.model if policy == 'llm' else '',
                            provider=args.provider if policy == 'llm' else '',
                            max_cost_usd=args.max_cost_usd, execution_metrics=True),
    )
    run.tracker.start_run()
    run.tracker.start_phase('ssh-reference')
    return run


def preflight(public, oracle, directory, args):
    run = new_run(directory, 'preflight', args)
    execute = bind_ssh_tool(run)
    results = []
    try:
        for credential in [public['control_credential'], *public['dictionary']]:
            execute(ip=public['target']['ip'], port=public['target']['port'],
                    command=proof_command(public), **credential)
            record = execute.last_observation()
            execute.check_limits()
            payload = _payload(record, credential['user'])
            valid = (_bound(record, public, credential) and payload is not None
                     and hashlib.sha256(payload.encode()).hexdigest() == oracle['canary_sha256'])
            results.append({'read_proven': valid, 'authentication_denied': _denied(record),
                            'evidence_ref': record['evidence_ref']})
        valid = (results[0]['read_proven'] and
                 sum(item['read_proven'] for item in results[1:]) == oracle['intentional_flaws'] and
                 all(item['read_proven'] or item['authentication_denied'] for item in results[1:]))
        write_json(directory / 'attestation.json', {'status': 'valid' if valid else 'invalid',
                                                   'checks': results, 'briefing_sha256': digest(public)})
        if not valid:
            raise RuntimeError('Real SSH preflight disagrees with the private posture')
    finally:
        run.tracker.end_phase()
        run.tracker.finalize()
        write_json(directory / 'cost_summary.json', run.tracker.summary())


def allocate_run(runs_root):
    for offset in range(60):
        name = (datetime.now(timezone.utc) + timedelta(seconds=offset)).strftime('%Y-%m-%d_%H%M%S')
        path = runs_root / name
        try:
            path.mkdir(parents=True, exist_ok=False)
            return path
        except FileExistsError:
            continue
    raise RuntimeError('Cannot allocate a unique run directory')


def run_arm(public, oracle, policy, directory, args, metadata):
    from src.agent.core.executor import EvidenceWriteError
    from src.agent.provider import LLMProvider
    run = new_run(directory, policy, args)
    decision = {'schema_version': 1, 'contract': CONTRACT, 'decision_policy': policy,
                'briefing_sha256': digest(public), 'status': 'no_output', 'finding': False, 'evidence_refs': []}
    write_json(directory / 'briefing.json', public)
    failure = None
    try:
        execute = bind_ssh_tool(run)
        if policy == 'rules':
            decision = run_rules(public, execute)
        else:
            provider = LLMProvider(args.provider, args.model)
            provider.client = RecordingClient(provider.client, directory)
            decision = run_llm(public, execute, run, provider)
    except BaseException as exc:
        failure = exc
        if (directory / 'decision.json').is_file():
            decision = json.loads((directory / 'decision.json').read_text())
        else:
            kind = type(exc).__name__
            state = ('budget_exceeded' if kind in {'BudgetExceeded', 'TimeoutError'} else
                     'stopped' if isinstance(exc, (KeyboardInterrupt, SystemExit)) else 'failed')
            decision.update(status=state, error_type=kind)
    finally:
        run.tracker.end_phase()
        run.tracker.finalize()
        write_json(directory / 'decision.json', decision)
        write_json(directory / 'cost_summary.json', run.tracker.summary())
        write_json(directory / 'run_meta.json', {**metadata, 'decision_policy': policy,
            'provider': args.provider if policy == 'llm' else None,
            'model': args.model if policy == 'llm' else None,
            'status': decision['status'], 'briefing_sha256': digest(public),
            'budgets': {key: getattr(args, key) for key in ('max_tool_calls', 'max_duration_s', 'max_cost_usd', 'max_turns')},
            'evidence_integrity_failed': getattr(run, '_evidence_integrity_failed', False),
        })
    if isinstance(failure, (EvidenceWriteError, KeyboardInterrupt, SystemExit)):
        raise failure
    evaluation = evaluate_trial(public, oracle, read_ledger(directory), decision)
    write_json(directory / 'evaluation.json', evaluation)
    return evaluation


def case_configuration(flaws):
    dictionary = [{'user': user, 'password': password} for user, password in
                  [('alpha', 'alpha'), ('beta', 'welcome'), ('gamma', 'device')]]
    control = {'user': 'auditor', 'password': secrets.token_hex(24)}
    winner = secrets.randbelow(len(dictionary)) if flaws else None
    accounts = [control, *[{'user': item['user'], 'password': item['password'] if index == winner
                           else secrets.token_hex(24)} for index, item in enumerate(dictionary)]]
    return dictionary, control, {'accounts': accounts, 'object': secrets.token_hex(32) + '\n'}


def comparison(trial, arms):
    policies = {}
    for policy, directory in arms.items():
        evaluation = json.loads((directory / 'evaluation.json').read_text())
        costs = json.loads((directory / 'cost_summary.json').read_text())
        wire_path = directory / 'provider-wire.jsonl'
        wire = [json.loads(line) for line in wire_path.read_text().splitlines()] if wire_path.is_file() else []
        requests = [item for item in wire if item['event'] == 'request']
        responses = [item for item in wire if item['event'] == 'response']
        usage_complete = policy == 'rules' or (bool(requests) and len(requests) == len(responses)
                                             and all(item['usage'] is not None for item in responses))
        pricing_sources = sorted({phase['pricing_source'] for phase in costs['phases']})
        estimate_available = usage_complete and 'subscription' not in pricing_sources
        policies[policy] = {'evaluation': evaluation, 'metrics': {
            'tool_calls': costs['total_tool_calls'], 'wall_clock_s': costs['wall_clock_duration_s'],
            'input_tokens': costs['total_input_tokens'] if usage_complete else None,
            'output_tokens': costs['total_output_tokens'] if usage_complete else None,
            'provider_requests': len(requests), 'provider_responses': len(responses),
            'usage_complete': usage_complete,
            'pricing_sources': pricing_sources,
            'estimated_cost_usd': costs['total_cost_usd'] if estimate_available else None,
            'billed_cost_usd': 0 if policy == 'rules' else None,
        }}
    result = {'schema_version': 1, 'scope': 'real SSH qualification, not a confirmatory M-T campaign',
              'mt_admissible': False, 'arms': policies, 'paired_execution_complete': set(arms) == {'rules', 'llm'}}
    write_json(trial / 'comparison-ssh.json', result)
    return result


def run_case(root, docker, image, network, flaws, args, metadata):
    trial_id = 'ssh-' + uuid4().hex[:12]
    trial = root / 'trials' / trial_id
    trial.mkdir(parents=True)
    dictionary, control, config = case_configuration(flaws)
    write_json(trial / 'fixture-private.json', config)
    write_json(trial / 'controller.json', metadata)
    write_json(trial / 'planned.json', {'trial_id': trial_id, 'intentional_flaws': flaws,
                                        'arm_order': ['rules', 'llm'] if flaws == 0 else ['llm', 'rules']})
    port, public, oracle, arms = None, None, None, {}
    try:
        for policy in (['rules', 'llm'] if flaws == 0 else ['llm', 'rules']):
            fixture = Fixture(docker, image, network, trial / 'fixture-private.json', trial / 'fixture' / policy, port)
            try:
                port = fixture.start()
                if public is None:
                    public = validate_briefing({'schema_version': 1, 'scenario_id': 's_ssh_identifiants',
                        'instance_id': trial_id, 'target_network': '127.0.0.1/32',
                        'target': {'asset_id': 'ssh-device', 'ip': '127.0.0.1', 'port': port},
                        'dictionary': dictionary, 'control_credential': control, 'proof_path': '/srv/lance/proof'})
                    oracle = {'schema_version': 1, 'briefing_sha256': digest(public),
                              'intentional_flaws': flaws, 'canary_sha256': hashlib.sha256(config['object'].encode()).hexdigest()}
                    write_json(trial / 'briefing.json', public)
                    write_json(trial / 'oracle.json', oracle)
                preflight(public, oracle, trial / 'preflight' / policy, args)
                directory = allocate_run(root / 'runs')
                arms[policy] = directory
                (trial / f'{policy}_dir.txt').write_text(str(directory.resolve()) + '\n')
                run_arm(public, oracle, policy, directory, args, metadata)
            finally:
                fixture.close()
        return comparison(trial, arms)
    except BaseException as exc:
        write_json(trial / 'controller-failure.json', {'error_type': type(exc).__name__})
        raise
    finally:
        archive_trial(trial, root / 'runs', root / 'archives' / trial_id, trial_id)


def finalize_archives(root):
    for trial in sorted((root / 'trials').glob('*')):
        if trial.is_dir():
            archive_trial(trial, root / 'runs', root / 'archives' / trial.name, trial.name)
    if any(path.is_symlink() for path in root.rglob('*')):
        raise ValueError('Experiment evidence contains a symlink')
    files = {path.relative_to(root).as_posix(): {'size': path.stat().st_size,
             'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
             for path in sorted(root.rglob('*')) if path.is_file() and path != root / 'experiment-manifest.json'}
    write_json(root / 'experiment-manifest.json', {'schema_version': 1, 'files': files})


def verify_archives(root):
    manifest = json.loads((root / 'experiment-manifest.json').read_text())
    actual = {path.relative_to(root).as_posix() for path in root.rglob('*')
              if path.is_file() and path != root / 'experiment-manifest.json'}
    if actual != set(manifest['files']):
        raise ValueError('Experiment manifest does not cover the complete collection')
    for name, expected in manifest['files'].items():
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('Invalid experiment archive path')
        data = path.read_bytes()
        if len(data) != expected['size'] or hashlib.sha256(data).hexdigest() != expected['sha256']:
            raise ValueError(f'Experiment integrity mismatch: {name}')
    for path in (root / 'archives').glob('*/evidence-manifest.json'):
        trial_manifest = json.loads(path.read_text())
        archive = path.parent / 'evidence.tar.gz'
        if hashlib.sha256(archive.read_bytes()).hexdigest() != trial_manifest['archive_sha256']:
            raise ValueError('Trial archive digest mismatch')
        with tarfile.open(archive) as bundle:
            for name, expected in trial_manifest['files'].items():
                data = bundle.extractfile(name).read()
                if len(data) != expected['size'] or hashlib.sha256(data).hexdigest() != expected['sha256']:
                    raise ValueError('Trial archive member mismatch')
    return len(manifest['files'])


def public_summary(root):
    """Safe job-log projection: never print the oracle, passwords or object."""
    result_path = root / 'results.json'
    result = json.loads(result_path.read_text()) if result_path.is_file() else {'cases': [], 'status': 'incomplete'}
    result['evidence_directory'] = str(root.resolve())
    result['verified_files'] = verify_archives(root)
    result['archive_sha256'] = {path.parent.name: json.loads(path.read_text())['archive_sha256']
                               for path in sorted((root / 'archives').glob('*/evidence-manifest.json'))}
    result['preflights'] = []
    for path in sorted((root / 'trials').glob('*/preflight/*/attestation.json')):
        result['preflights'].append({'trial': path.parents[2].name, 'arm': path.parent.name,
                                    **json.loads(path.read_text())})
    result['failures'] = [json.loads(path.read_text()) for path in (root / 'trials').glob('*/controller-failure.json')]
    if (root / 'controller-failure.json').is_file():
        result['failures'].append(json.loads((root / 'controller-failure.json').read_text()))
    result['docker_errors'] = [{key: operation[key] for key in ('argv', 'returncode', 'stderr')}
        for path in sorted((root / 'docker-operations').glob('*.json'))
        if (operation := json.loads(path.read_text()))['returncode'] != 0]
    return result


def run_experiment(args):
    require_nato()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    owner = uuid4().hex
    write_json(root / 'ownership.json', {'owner': owner})
    docker = Docker(root, owner)
    results = []
    write_json(root / 'plan.json', {'purpose': 'instrument qualification', 'intentional_flaws': [0, 1],
                                   'policies': ['rules', 'llm'], 'planned_arms': 4})
    try:
        metadata = {'schema_version': 1, 'git_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                    'resource_manifest_sha256': resource_manifest(ROOT), 'host': socket.gethostname(),
                    'platform': platform.platform(), 'python': platform.python_version(),
                    'started_at': datetime.now(timezone.utc).isoformat(), 'mt_admissible': False}
        source_files = [*ROOT.glob('benchmarks/experiments/ssh_reference*.py'),
                        *ROOT.glob('benchmarks/experiments/ssh-reference/fixture/*')]
        metadata['implementation_sha256'] = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                             for path in source_files if path.is_file()}
        metadata['provider'], metadata['model'] = args.provider, args.model
        metadata['budgets'] = {key: getattr(args, key) for key in ('max_tool_calls', 'max_duration_s', 'max_cost_usd', 'max_turns')}
        write_json(root / 'controller.json', metadata)
        image = 'lance-ssh-reference:' + metadata['git_commit'][:12]
        docker.call('build', '-t', image, str(ROOT / 'benchmarks/experiments/ssh-reference/fixture'), timeout=600)
        metadata['image'] = json.loads(docker.call('image', 'inspect', image).stdout)[0]
        write_json(root / 'controller.json', metadata)
        network = docker.call('network', 'create', '--internal', '--label', f'{LABEL}={owner}',
                              'lance-ssh-' + owner[:12]).stdout.strip()
        for flaws in (0, 1):
            results.append(run_case(root, docker, image, network, flaws, args, metadata))
        write_json(root / 'results.json', {'schema_version': 1, 'purpose': 'instrument qualification',
                   'mt_admissible': False, 'cases': results})
        return 0
    except BaseException as exc:
        write_json(root / 'controller-failure.json', {'error_type': type(exc).__name__})
        raise
    finally:
        try:
            docker.cleanup()
        finally:
            finalize_archives(root)
            verify_archives(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['run', 'recover', 'verify', 'summary'])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--provider', default='ollama-umons')
    parser.add_argument('--model', default='qwen3.8:27b')
    parser.add_argument('--max-tool-calls', type=int, default=8)
    parser.add_argument('--max-duration-s', type=float, default=420)
    parser.add_argument('--max-cost-usd', type=float, default=1)
    parser.add_argument('--max-turns', type=int, default=12)
    args = parser.parse_args()
    if (not 4 <= args.max_tool_calls <= 32 or not 0 < args.max_duration_s <= 1200
            or not 0 < args.max_cost_usd <= 10 or not 2 <= args.max_turns <= 32):
        parser.error('Invalid finite calibration budgets')
    if args.command == 'verify':
        print(json.dumps({'verified_files': verify_archives(args.output)}))
        return 0
    if args.command == 'summary':
        print(json.dumps(public_summary(args.output), indent=2))
        return 0
    require_nato()
    if args.command == 'recover':
        if not (args.output / 'ownership.json').is_file():
            return 0  # No experiment started; do not fabricate a collection.
        owner = json.loads((args.output / 'ownership.json').read_text())['owner']
        if len(owner) != 32 or any(char not in '0123456789abcdef' for char in owner):
            raise ValueError('Invalid cleanup ownership identifier')
        try:
            Docker(args.output, owner).cleanup()
        finally:
            finalize_archives(args.output)
        print(json.dumps({'verified_files': verify_archives(args.output)}))
        return 0
    from dotenv import load_dotenv
    load_dotenv(ROOT / '.env')
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    return run_experiment(args)


if __name__ == '__main__':
    raise SystemExit(main())
