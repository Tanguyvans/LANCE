"""Real Mosquitto D1/LLM qualification using an owned disposable LXC on pve-nato."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import signal
import socket
import subprocess
import tarfile
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

from benchmarks.experiments.mqtt_reference import (
    CONTRACT, _bound, _denied, _payloads, bind_mqtt_tool, evaluate_trial,
    run_rules, validate_briefing,
)
from benchmarks.experiments.mqtt_reference_llm import run_llm
from benchmarks.experiments.mqtt_reference_proxmox import Proxmox, Fixture as ProxmoxFixture
from benchmarks.experiments.ssh_reference_llm import RecordingClient
from benchmarks.experiments import v2_campaign as v2
from scripts.benchmark.pilot_support import archive_trial
from src.agent.audit_experiment import digest, resource_manifest
from src.agent.cost_tracker import CostTracker


ROOT = Path(__file__).resolve().parents[2]
PROVIDER = v2.PROVIDER
MODEL = v2.DEFAULT_MODEL
MODEL_PANEL = v2.MODEL_PANEL
SCENARIO_ID = 's_mqtt_lecture'
PUBLIC_TOPIC = 'lance/public/status'
PRIVATE_TOPIC = 'lance/private/telemetry'
PORT = 1883


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
    if os.environ.get('LANCE_MQTT_LOCK_HELD') != '1':
        raise RuntimeError('Acquire the shared laboratory lock before running this controller')


def new_run(directory, policy, args, network='127.0.0.1/32'):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'tool_calls.jsonl').touch(exist_ok=False)
    run = SimpleNamespace(
        run_dir=directory, max_tool_calls=args.max_tool_calls,
        max_duration_s=args.max_duration_s, max_turns=args.max_turns,
        _artifact_log_lock=threading.Lock(), _tool_call_count=0,
        _run_started=time.monotonic(), _execution_limit_reason=None,
        experiment_scope='mqtt-reference-calibration', context={'target_subnet': network},
        decision_policy=policy,
        tracker=CostTracker(model=args.model if policy == 'llm' else '',
                            provider=args.provider if policy == 'llm' else '',
                            max_cost_usd=args.max_cost_usd, execution_metrics=True),
    )
    run.tracker.start_run()
    run.tracker.start_phase('mqtt-reference')
    return run


def case_configuration(flaws):
    if flaws not in (0, 1):
        raise ValueError('intentional_flaws must be 0 or 1')
    control = {'username': 'auditor', 'password': secrets.token_hex(24)}
    config = {'intentional_flaws': flaws, 'public_topic': PUBLIC_TOPIC,
              'private_topic': PRIVATE_TOPIC, 'control_user': control['username'],
              'control_password': control['password'], 'seeder_password': secrets.token_hex(24),
              'public_canary': secrets.token_hex(32), 'private_canary': secrets.token_hex(32),
              'port': PORT}
    return control, config


def build_briefing(trial_id, address, control, network='192.168.100.0/24'):
    return {'schema_version': 1, 'scenario_id': 's_mqtt_lecture', 'instance_id': trial_id,
            'target_network': network,
            'target': {'asset_id': 'mqtt-broker', 'ip': address, 'port': PORT},
            'public_topic': PUBLIC_TOPIC, 'private_topic': PRIVATE_TOPIC,
            'control_credential': control, 'listen': {'count': 2, 'timeout_s': 5}}


def oracle_for(public, flaws, config):
    return {'schema_version': 1, 'briefing_sha256': digest(public), 'intentional_flaws': flaws,
            'private_canary_sha256': hashlib.sha256(config['private_canary'].encode()).hexdigest(),
            'public_canary_sha256': hashlib.sha256(config['public_canary'].encode()).hexdigest()}


def preflight(public, oracle, directory, args):
    run = new_run(directory, 'preflight', args, public['target_network'])
    execute = bind_mqtt_tool(run)
    checks = [('control_private', public['private_topic'], public['control_credential'],
               oracle['private_canary_sha256']),
              ('anonymous_public', public['public_topic'], None, oracle['public_canary_sha256']),
              ('anonymous_private', public['private_topic'], None, oracle['private_canary_sha256']),
              ('control_private_after', public['private_topic'], public['control_credential'],
               oracle['private_canary_sha256'])]
    results = []
    try:
        for name, topic, credential, canary_sha256 in checks:
            kwargs = {"broker": public["target"]["ip"], "port": public["target"]["port"],
                      "topic": topic, "count": public["listen"]["count"],
                      "timeout": public["listen"]["timeout_s"]}
            if credential is not None:
                kwargs.update(username=credential["username"], password=credential["password"])
            execute(**kwargs)
            record = execute.last_observation()
            execute.check_limits()
            proven = (_bound(record, public, topic, credential) and any(
                hashlib.sha256(payload.encode()).hexdigest() == canary_sha256
                for payload in _payloads(record, public, topic)))
            results.append({'check': name, 'read_proven': proven,
                            'anonymous_private_denied': bool(name == 'anonymous_private' and _denied(record, public)),
                            'evidence_ref': record['evidence_ref']})
        anonymous = results[2]
        valid = (results[0]['read_proven'] and results[1]['read_proven'] and results[-1]['read_proven']
                 and anonymous['read_proven'] == (oracle['intentional_flaws'] == 1)
                 and (oracle['intentional_flaws'] == 1 or anonymous['anonymous_private_denied']))
        write_json(directory / 'attestation.json', {'status': 'valid' if valid else 'invalid',
                   'checks': results, 'post_probe_control_proven': results[-1]['read_proven'],
                   'briefing_sha256': digest(public)})
        if not valid:
            raise RuntimeError('Real MQTT preflight disagrees with the private posture')
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
    run = new_run(directory, policy, args, public['target_network'])
    decision = {'schema_version': 1, 'contract': CONTRACT, 'decision_policy': policy,
                'briefing_sha256': digest(public), 'status': 'no_output', 'finding': False, 'evidence_refs': []}
    write_json(directory / 'briefing.json', public)
    failure = None
    try:
        execute = bind_mqtt_tool(run)
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


def comparison(trial, arms, family_id=SCENARIO_ID):
    policies = {}
    evidence = {}
    for policy, directory in arms.items():
        evaluation = json.loads((directory / 'evaluation.json').read_text())
        attestation = trial / 'preflight' / policy / 'attestation.json'
        evidence[policy] = {'run_meta': json.loads((directory / 'run_meta.json').read_text())
                            if (directory / 'run_meta.json').is_file() else {},
                            'evaluation': evaluation,
                            'preflight': json.loads(attestation.read_text())
                            if attestation.is_file() else {},
                            'usage_complete': None}
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
        evidence[policy]['usage_complete'] = usage_complete
    planned = json.loads((trial / 'planned.json').read_text()) if (trial / 'planned.json').is_file() else {}
    experiment = planned.get('experiment') or {}
    admission = v2.pair_admission(evidence, experiment=experiment, planned=planned)
    result = {'schema_version': 1, 'scope': 'real MQTT qualification, not a confirmatory M-T campaign',
              'family_id': family_id, 'pair_admissible': admission['met'],
              'unmet_conditions': admission['unmet'], 'conditions': admission['conditions'],
              'arms': policies, 'paired_execution_complete': set(arms) == {'rules', 'llm'}}
    write_json(trial / 'comparison-mqtt.json', result)
    return result


def run_case(root, backend, flaws, args, metadata, repetition=1):
    trial_id = 'mqtt-' + uuid4().hex[:12]
    trial = root / 'trials' / trial_id
    trial.mkdir(parents=True)
    control, config = case_configuration(flaws)
    experiment = v2.trial_identity(metadata['campaign_id'], SCENARIO_ID, flaws, repetition,
                                   configuration_id=f"{metadata['provider']}:{metadata['model']}")
    trial_metadata = {**metadata, 'experiment': experiment}
    write_json(trial / 'fixture-private.json', config)
    write_json(trial / 'controller.json', trial_metadata)
    # The posture fixes the baseline order; parity counterbalances it across
    # repetitions so that a first-passage effect is not confounded with posture.
    order = v2.arm_order(flaws, repetition)
    write_json(trial / 'planned.json', {'trial_id': trial_id, 'intentional_flaws': flaws,
                                        'repetition': repetition, 'experiment': experiment,
                                        'arm_order': order,
                                        'arm_order_rule': 'posture order on odd repetitions, reversed on even'})
    public, oracle, arms = None, None, {}
    try:
        for policy in order:
            fixture = ProxmoxFixture(backend, trial / 'fixture-private.json', trial / 'fixture' / policy)
            try:
                fixture.start()
                if public is None:
                    public = validate_briefing(build_briefing(trial_id, fixture.address, control))
                    oracle = oracle_for(public, flaws, config)
                    write_json(trial / 'briefing.json', public)
                    write_json(trial / 'oracle.json', oracle)
                preflight(public, oracle, trial / 'preflight' / policy, args)
                directory = allocate_run(root / 'runs')
                arms[policy] = directory
                (trial / f'{policy}_dir.txt').write_text(str(directory.resolve()) + '\n')
                run_arm(public, oracle, policy, directory, args, trial_metadata)
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
    """Safe job-log projection: never print the oracle, passwords or canaries."""
    result_path = root / 'results.json'
    result = json.loads(result_path.read_text()) if result_path.is_file() else {'cases': [], 'status': 'incomplete'}
    result['evidence_directory'] = str(root.resolve())
    result['verified_files'] = verify_archives(root)
    if (root / 'preconditions.json').is_file():
        result['preconditions'] = json.loads((root / 'preconditions.json').read_text())
    for name in ('provider-preflight', 'provider-preflight-error'):
        if (root / f'{name}.json').is_file():
            result[name] = json.loads((root / f'{name}.json').read_text())
    result['proxmox_failures'] = [{key: response.get(key) for key in ('error_type', 'reason')}
                                 for path in sorted((root / 'proxmox-operations').glob('*.response.json'))
                                 if (response := json.loads(path.read_text())).get('ok') is not True]
    result['archive_sha256'] = {path.parent.name: json.loads(path.read_text())['archive_sha256']
                               for path in sorted((root / 'archives').glob('*/evidence-manifest.json'))}
    result['preflights'] = []
    for path in sorted((root / 'trials').glob('*/preflight/*/attestation.json')):
        result['preflights'].append({'trial': path.parents[2].name, 'arm': path.parent.name,
                                    **json.loads(path.read_text())})
    result['failures'] = [json.loads(path.read_text()) for path in (root / 'trials').glob('*/controller-failure.json')]
    if (root / 'controller-failure.json').is_file():
        result['failures'].append(json.loads((root / 'controller-failure.json').read_text()))
    return result


def run_experiment(args):
    v2.require_model(args.provider, args.model, pilot='MQTT')
    repetitions = getattr(args, 'repetitions', 1)
    if not 1 <= repetitions <= 5:
        raise ValueError('repetitions must stay between 1 and 5 for a bounded calibration')
    require_nato()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    owner = uuid4().hex
    write_json(root / 'ownership.json', {'owner': owner, 'backend': 'proxmox-lxc', 'resources_may_exist': False})
    backend = Proxmox(root, owner)
    results = []
    # Interleave postures by repetition instead of running every F0 then every F1.
    planned = v2.planned_cases(repetitions)
    write_json(root / 'plan.json', {'purpose': 'instrument qualification', 'intentional_flaws': [0, 1],
                                   'policies': ['rules', 'llm'], 'repetitions': repetitions,
                                   'scenario_id': SCENARIO_ID, 'planned_arms': 2 * len(planned),
                                   'planned_pairs': len(planned),
                                   'arm_order_rule': 'posture order on odd repetitions, reversed on even',
                                   'posture_order': ['f1' if flaws else 'f0' for flaws, _ in planned]})
    try:
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        config = {'provider': args.provider, 'model': args.model,
                  'budgets': {key: getattr(args, key) for key in ('max_tool_calls', 'max_duration_s', 'max_cost_usd', 'max_turns')}}
        metadata = {'schema_version': 1, 'git_commit': commit, 'campaign_id': v2.default_campaign_id('mqtt', commit),
                    'resource_manifest_sha256': resource_manifest(ROOT), 'host': socket.gethostname(),
                    'platform': platform.platform(), 'python': platform.python_version(),
                    'started_at': datetime.now(timezone.utc).isoformat(), **config}
        source_files = [ROOT / 'benchmarks/ansible/files/mqtt_reference_proxmox.py',
                        ROOT / 'benchmarks/ansible/playbooks/mqtt_reference.yml',
                        *ROOT.glob('benchmarks/experiments/mqtt_reference*.py'),
                        *ROOT.glob('benchmarks/experiments/mqtt-reference/fixture/*')]
        metadata['implementation_sha256'] = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                             for path in source_files if path.is_file()}
        write_json(root / 'controller.json', metadata)
        prerequisites = {name: shutil.which(name) is not None for name in ('ansible-playbook', 'mosquitto_sub')}
        write_json(root / 'preconditions.json', {'status': 'binaries_present' if all(prerequisites.values()) else 'blocked',
                   'binaries': prerequisites, 'reason': None if all(prerequisites.values()) else 'missing_runtime_prerequisite'})
        if not all(prerequisites.values()):
            raise RuntimeError('Missing runtime prerequisites; no environment creation attempted')
        from src.agent.provider import LLMProvider
        try:
            provider = LLMProvider(args.provider, args.model)
            catalogue = provider.client.with_options(timeout=15, max_retries=0).models.list()
            available = any(item.id == args.model for item in catalogue.data)
            write_json(root / 'provider-preflight.json', {'provider': args.provider, 'model': args.model,
                                                        'available': available, 'purpose': 'catalogue only; no model generation'})
            if not available:
                raise RuntimeError('Selected model not present at configured UMONS endpoint')
        except Exception as exc:
            write_json(root / 'provider-preflight-error.json', {'error_type': type(exc).__name__,
                       'status_code': getattr(exc, 'status_code', None), 'provider': args.provider, 'model': args.model})
            raise
        write_json(root / 'ownership.json', {'owner': owner, 'backend': 'proxmox-lxc', 'resources_may_exist': True})
        metadata['backend'] = 'proxmox-lxc'
        metadata['allocation'] = backend.prepare()
        write_json(root / 'controller.json', metadata)
        failures = []
        for flaws, repetition in planned:
            try:
                results.append(run_case(root, backend, flaws, args, metadata, repetition))
            except Exception as exc:
                # One failed pair must not erase the pairs already collected.
                failure = {'intentional_flaws': flaws, 'repetition': repetition,
                           'error_type': type(exc).__name__}
                failures.append(failure)
                write_json(root / 'failures' / f'{flaws}-r{repetition}.json', failure)
        admission = v2.campaign_admission(
            [{'met': case['pair_admissible']} for case in results],
            families=1,
            repetitions={SCENARIO_ID: {'f0': repetitions, 'f1': repetitions}},
            configurations=[config], excluded=len(failures))
        write_json(root / 'results.json', {'schema_version': 1, 'purpose': 'instrument qualification',
                   'scenario_id': SCENARIO_ID, 'repetitions': repetitions,
                   'mt_admissible': admission['mt_admissible'],
                   'admission_unmet': admission['unmet'], 'admission': admission,
                   'cases': results, 'failures': failures})
        return 0
    except BaseException as exc:
        write_json(root / 'controller-failure.json', {'error_type': type(exc).__name__})
        raise
    finally:
        try:
            backend.cleanup()
        finally:
            finalize_archives(root)
            verify_archives(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['run', 'recover', 'verify', 'summary', 'seal'])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--provider', choices=[PROVIDER], default=PROVIDER)
    parser.add_argument('--model', choices=list(MODEL_PANEL), default=MODEL)
    parser.add_argument('--repetitions', type=int, default=1,
                        help='Independent repetitions per posture (bounded 1-5)')
    parser.add_argument('--max-tool-calls', type=int, default=8)
    parser.add_argument('--max-duration-s', type=float, default=420)
    parser.add_argument('--max-cost-usd', type=float, default=1)
    parser.add_argument('--max-turns', type=int, default=12)
    args = parser.parse_args()
    if (not 3 <= args.max_tool_calls <= 32 or not 0 < args.max_duration_s <= 1200
            or not 0 < args.max_cost_usd <= 10 or not 2 <= args.max_turns <= 32):
        parser.error('Invalid finite calibration budgets')
    if args.command == 'verify':
        print(json.dumps({'verified_files': verify_archives(args.output)}))
        return 0
    if args.command == 'summary':
        print(json.dumps(public_summary(args.output), indent=2))
        return 0
    if args.command == 'seal':
        finalize_archives(args.output)
        print(json.dumps({'verified_files': verify_archives(args.output)}))
        return 0
    require_nato()
    if args.command == 'recover':
        if not (args.output / 'ownership.json').is_file():
            return 0
        owner = json.loads((args.output / 'ownership.json').read_text())['owner']
        if len(owner) != 32 or any(char not in '0123456789abcdef' for char in owner):
            raise ValueError('Invalid cleanup ownership identifier')
        try:
            Proxmox(args.output, owner).cleanup()
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
