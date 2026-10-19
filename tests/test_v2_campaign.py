"""V2 campaign identity, admission and offline summary contracts."""
import json
from pathlib import Path

import pytest

from benchmarks.experiments import v2_campaign as v2

BRIEFING = 'b' * 64
RESOURCE = 'r' * 64


def _identity(family='s_mqtt_lecture', posture='f0', repetition=1,
              configuration=v2.DEFAULT_MODEL):
    return v2.trial_identity('campaign', family, int(posture == 'f1'), repetition,
                             configuration_id=f'{v2.PROVIDER}:{configuration}')


def _arm(*, budget=(8, 420, 1, 12), preflight='valid', briefing=BRIEFING, integrity=False,
         success=True, tool_calls=6, wall_clock=20.0, cost=0.004, model=v2.DEFAULT_MODEL,
         resource=RESOURCE, usage=True, experiment=None):
    return {
        'run_meta': {'provider': v2.PROVIDER, 'model': model,
                     'experiment': _identity() if experiment is None else experiment,
                     'briefing_sha256': briefing, 'resource_manifest_sha256': resource,
                     'budgets': {'max_tool_calls': budget[0], 'max_duration_s': budget[1],
                                 'max_cost_usd': budget[2], 'max_turns': budget[3]},
                     'evidence_integrity_failed': integrity},
        'evaluation': {'success': success, 'outcome': 'success' if success else 'non_success'},
        'preflight': {'status': preflight, 'briefing_sha256': briefing},
        'usage_complete': usage,
        'metrics': {'tool_calls': tool_calls, 'wall_clock_s': wall_clock,
                    'estimated_cost_usd': cost, 'usage_complete': usage},
    }


def _planned(experiment=None, flaws=0, repetition=1):
    return {'intentional_flaws': flaws, 'repetition': repetition,
            'experiment': _identity(posture='f1' if flaws else 'f0', repetition=repetition)
            if experiment is None else experiment}


def _pair(**kwargs):
    experiment = _identity()
    arms = {'rules': _arm(**kwargs), 'llm': _arm(**kwargs)}
    return v2.pair_admission(arms, experiment=experiment, planned=_planned(experiment))


def test_trial_identity_is_stable_for_the_same_frozen_commit():
    identity = v2.trial_identity('ssh-abcdef123456', 's_ssh_identifiants', 1, 2,
                                 configuration_id='ollama-umons:qwen3.8:27b')
    assert identity == {'id': 'ssh-abcdef123456', 'trial_id': 's_ssh_identifiants-f1-r2',
                        'family_id': 's_ssh_identifiants', 'posture': 'f1', 'repetition': 2,
                        'instance_id': 's_ssh_identifiants-f1-r2',
                        'configuration_id': 'ollama-umons:qwen3.8:27b'}
    assert v2.default_campaign_id('ssh', 'abcdef1234567890') == 'ssh-abcdef123456'


def test_arm_order_is_counterbalanced_and_postures_are_interleaved():
    assert v2.arm_order(0, 1) == ['rules', 'llm']
    assert v2.arm_order(0, 2) == ['llm', 'rules']
    assert v2.arm_order(1, 1) == ['llm', 'rules']
    assert v2.arm_order(1, 2) == ['rules', 'llm']
    assert v2.planned_cases(3) == [(0, 1), (1, 1), (0, 2), (1, 2), (0, 3), (1, 3)]


def test_model_gate_refuses_outside_the_declared_panel():
    with pytest.raises(ValueError, match='no provider fallback'):
        v2.require_model('minimax', v2.DEFAULT_MODEL, pilot='SSH')
    with pytest.raises(ValueError, match='no provider fallback'):
        v2.require_model(v2.PROVIDER, 'other-model', pilot='SSH')
    for model in v2.MODEL_PANEL:
        assert v2.require_model(v2.PROVIDER, model, pilot='SSH') == model


def test_pair_admission_accepts_a_complete_pair():
    admission = _pair()
    assert admission['met'] is True and admission['unmet'] == []


@pytest.mark.parametrize('mutate,expected', [
    (lambda arms: arms.pop('llm'), 'paired_execution_complete'),
    (lambda arms: arms['llm'].update(usage_complete=False), None),
    (lambda arms: arms['rules'].update(preflight={'status': 'invalid', 'briefing_sha256': BRIEFING}),
     'preflight_attested'),
    (lambda arms: arms['llm']['preflight'].update(briefing_sha256='x' * 64), 'preflight_attested'),
    (lambda arms: arms['llm']['run_meta'].update(evidence_integrity_failed=True), 'evidence_integrity'),
    (lambda arms: arms['llm']['evaluation'].update(success=None), 'evaluation_available'),
    (lambda arms: arms['llm']['run_meta'].update(budgets={'max_tool_calls': 9}), 'budget_parity'),
    (lambda arms: arms['llm']['run_meta'].update(resource_manifest_sha256='x' * 64), 'resource_parity'),
])
def test_pair_admission_names_the_unmet_condition(mutate, expected):
    arms = {'rules': _arm(), 'llm': _arm()}
    mutate(arms)
    admission = v2.pair_admission(arms, experiment=_identity(), planned=_planned())
    if expected is None:
        # Incomplete usage accounting leaves the pair published; only cost and
        # token metrics become unknown.
        assert admission['met'] is True
    else:
        assert admission['met'] is False
        assert expected in admission['unmet']
        assert admission['conditions'][expected]['met'] is False


def test_pair_admission_requires_identity_and_run_meta_on_both_arms():
    arms = {'rules': _arm(), 'llm': _arm()}
    arms['rules'].pop('run_meta')
    assert 'run_meta_present' in v2.pair_admission(
        arms, experiment=_identity(), planned=_planned())['unmet']
    missing = {'rules': _arm(), 'llm': _arm()}
    assert 'identity_present' in v2.pair_admission(missing, experiment={}, planned={})['unmet']
    wrong = v2.pair_admission({'rules': _arm(), 'llm': _arm()},
                              experiment=_identity(posture='f1'), planned=_planned(flaws=0))
    assert 'identity_present' in wrong['unmet']


def test_campaign_admission_refuses_a_single_family():
    admission = v2.campaign_admission([{'met': True}], families=1,
                                      repetitions={'s': {'f0': 3, 'f1': 3}},
                                      configurations=[{'model': 'm'}])
    assert admission['mt_admissible'] is False
    assert 'independent_families' in admission['unmet']
    assert 'strict_v3_metrics_adopted' in admission['unmet']


def test_campaign_admission_needs_repetitions_postures_and_uniformity():
    admission = v2.campaign_admission([{'met': True}], families=2,
                                      repetitions={'a': {'f0': 3, 'f1': 3}, 'b': {'f0': 1, 'f1': 3}},
                                      configurations=[{'model': 'a'}, {'model': 'b'}],
                                      strict_v3_metrics_adopted=True)
    assert 'minimum_repetitions' in admission['unmet']
    assert 'configuration_uniformity' in admission['unmet']
    missing_posture = v2.campaign_admission([{'met': True}], families=2,
                                            repetitions={'a': {'f0': 3}, 'b': {'f0': 3, 'f1': 3}},
                                            configurations=[{'model': 'a'}],
                                            strict_v3_metrics_adopted=True)
    assert 'posture_coverage' in missing_posture['unmet']


def test_campaign_admission_refuses_missing_or_duplicate_pairs():
    admission = v2.campaign_admission([{'met': True}], families=2,
                                      repetitions={'a': {'f0': 3, 'f1': 3},
                                                   'b': {'f0': 3, 'f1': 3}},
                                      configurations=[{'model': 'a'}],
                                      strict_v3_metrics_adopted=True,
                                      excluded=1)
    assert 'collection_complete' in admission['unmet']
    duplicate = v2.campaign_admission([{'met': True}], families=2,
                                      repetitions={'a': {'f0': 3, 'f1': 3},
                                                   'b': {'f0': 3, 'f1': 3}},
                                      configurations=[{'model': 'a'}],
                                      strict_v3_metrics_adopted=True, duplicates=1)
    assert 'unique_trials' in duplicate['unmet']


def _write_trial(root, family, posture, repetition, *, model=v2.DEFAULT_MODEL, usage=True,
                 preflight='valid', integrity=False, success=True, tool_calls=9,
                 plan_repetitions=None, cost=0.006):
    trial = root / 'trials' / f'{family}-{posture}-{repetition}'
    (trial / 'preflight' / 'rules').mkdir(parents=True)
    (trial / 'preflight' / 'llm').mkdir(parents=True)
    identity = _identity(family, posture, repetition, model)
    flaws = int(posture == 'f1')
    for policy in ('rules', 'llm', 'x'):
        run = root / 'runs' / f'{family}-{posture}-{repetition}-{policy}'
        run.mkdir(parents=True, exist_ok=True)
        if policy == 'x':
            continue
        (trial / f'{policy}_dir.txt').write_text(str(run) + '\n')
        (run / 'run_meta.json').write_text(json.dumps({
            'provider': v2.PROVIDER, 'model': model, 'experiment': identity,
            'briefing_sha256': BRIEFING, 'resource_manifest_sha256': RESOURCE,
            'budgets': {'max_tool_calls': 8, 'max_duration_s': 420,
                        'max_cost_usd': 1, 'max_turns': 12},
            'evidence_integrity_failed': integrity}))
        (trial / 'preflight' / policy / 'attestation.json').write_text(
            json.dumps({'status': preflight, 'briefing_sha256': BRIEFING}))
    arms = {}
    for policy, calls in (('rules', 5), ('llm', tool_calls)):
        arms[policy] = {
            'evaluation': {'success': success, 'outcome': 'success' if success else 'non_success',
                           'false_positive': False, 'control_proven': True},
            'metrics': {'tool_calls': calls, 'wall_clock_s': 15.0 if policy == 'rules' else 30.0,
                        'usage_complete': True if policy == 'rules' else usage,
                        'estimated_cost_usd': 0.0 if policy == 'rules' else cost}}
    (trial / 'comparison-mqtt.json').write_text(json.dumps({'arms': arms}))
    (trial / 'planned.json').write_text(json.dumps({
        'trial_id': identity['trial_id'], 'repetition': repetition,
        'intentional_flaws': flaws, 'experiment': identity}))
    repetitions = plan_repetitions or repetition
    (root / 'plan.json').write_text(json.dumps({
        'scenario_id': family, 'repetitions': repetitions, 'intentional_flaws': [0, 1],
        'policies': ['rules', 'llm'], 'planned_pairs': 2 * repetitions}))
    (trial / 'controller.json').write_text(json.dumps({
        'provider': v2.PROVIDER, 'model': model,
        'budgets': {'max_tool_calls': 8, 'max_duration_s': 420,
                    'max_cost_usd': 1, 'max_turns': 12}}))
    return trial


def test_summary_reports_planned_denominator_and_bounds(tmp_path):
    # Three repetitions are planned for F0; only two pairs are observable.
    for repetition in (1, 2):
        _write_trial(tmp_path, 's_mqtt_lecture', 'f0', repetition, plan_repetitions=3)
    summary = v2.summarize_experiments([tmp_path])
    cell = summary['descriptive'][json.dumps(
        summary['by_configuration'][next(iter(summary['by_configuration']))]['configuration'],
        sort_keys=True)]['s_mqtt_lecture']['f0']['llm']
    assert cell['planned'] == 3 and cell['evaluated'] == 2 and cell['unobservable'] == 1
    assert cell['successes'] == 2
    assert cell['planned_rate'] == pytest.approx(2 / 3)
    assert cell['observed_rate'] == pytest.approx(1.0)
    assert cell['success_bounds'] == pytest.approx([2 / 3, 1.0])
    assert summary['included_trials'] == 2


def test_summary_keeps_postures_separate_in_inference(tmp_path):
    for repetition in (1, 2, 3):
        _write_trial(tmp_path, 's_mqtt_lecture', 'f0', repetition, tool_calls=5)
        _write_trial(tmp_path, 's_mqtt_lecture', 'f1', repetition, tool_calls=9)
        _write_trial(tmp_path, 's_ssh_identifiants', 'f0', repetition, tool_calls=5)
        _write_trial(tmp_path, 's_ssh_identifiants', 'f1', repetition, tool_calls=9)
    summary = v2.summarize_experiments([tmp_path], minimum_repetitions=3)
    assert summary['included_trials'] == 12
    entry = next(iter(summary['by_configuration'].values()))
    assert entry['inference']['f0']['metrics']['tool_calls']['mean'] == pytest.approx(0.0)
    assert entry['inference']['f1']['metrics']['tool_calls']['mean'] == pytest.approx(4.0)
    assert summary['repetitions_per_family'] == {
        's_mqtt_lecture': {'f0': 3, 'f1': 3},
        's_ssh_identifiants': {'f0': 3, 'f1': 3}}
    assert summary['admission']['conditions']['posture_coverage']['met'] is True
    assert 'strict_v3_metrics_adopted' in summary['admission']['unmet']


def test_summary_does_not_pool_opposed_posture_effects(tmp_path):
    for family in ('s_mqtt_lecture', 's_ssh_identifiants'):
        for repetition in (1, 2, 3):
            _write_trial(tmp_path, family, 'f0', repetition, tool_calls=9)
            _write_trial(tmp_path, family, 'f1', repetition, tool_calls=1)
    entry = next(iter(v2.summarize_experiments([tmp_path])['by_configuration'].values()))
    assert entry['inference']['f0']['metrics']['tool_calls']['mean'] == pytest.approx(4.0)
    assert entry['inference']['f1']['metrics']['tool_calls']['mean'] == pytest.approx(-4.0)


def test_configuration_comes_from_the_trial_declaration_not_the_rules_arm(tmp_path):
    for family in ('s_mqtt_lecture', 's_ssh_identifiants'):
        for repetition in (1, 2, 3):
            trial = _write_trial(tmp_path, family, 'f0', repetition)
            meta_path = trial.parents[1] / 'runs' / f'{family}-f0-{repetition}-rules' / 'run_meta.json'
            meta = json.loads(meta_path.read_text())
            meta['provider'] = meta['model'] = None
            meta_path.write_text(json.dumps(meta))
    record = v2.read_trial(tmp_path / 'trials' / 's_mqtt_lecture-f0-1', root=tmp_path)
    assert record['configuration']['model'] == v2.DEFAULT_MODEL
    summary = v2.summarize_experiments([tmp_path], minimum_repetitions=3)
    assert summary['included_trials'] == 6
    assert summary['admission']['conditions']['configuration_uniformity']['met'] is True


def test_model_panel_is_summarized_per_configuration_not_pooled(tmp_path):
    roots = []
    for model in v2.MODEL_PANEL:
        root = tmp_path / model.replace(':', '_')
        roots.append(root)
        for family in ('s_mqtt_lecture', 's_ssh_identifiants'):
            for repetition in (1, 2, 3):
                for posture in ('f0', 'f1'):
                    _write_trial(root, family, posture, repetition, model=model,
                                 tool_calls=9 if posture == 'f1' else 5)
    summary = v2.summarize_experiments(roots, minimum_repetitions=3)
    assert len(summary['by_configuration']) == 2
    for entry in summary['by_configuration'].values():
        assert entry['inference']['f1']['metrics']['tool_calls']['mean'] == pytest.approx(4.0)
    assert summary['admission']['conditions']['configuration_uniformity']['met'] is False


def test_usage_incomplete_pair_remains_included_with_unknown_cost(tmp_path):
    _write_trial(tmp_path, 's_mqtt_lecture', 'f0', 1, usage=False)
    summary = v2.summarize_experiments([tmp_path])
    assert summary['included_trials'] == 1
    assert summary['excluded_trials'] == 0


def test_summary_excludes_pairs_with_an_unmet_condition(tmp_path):
    _write_trial(tmp_path, 's_mqtt_lecture', 'f0', 1, integrity=True)
    _write_trial(tmp_path, 's_ssh_identifiants', 'f1', 1)
    summary = v2.summarize_experiments([tmp_path])
    assert summary['evaluated_trials'] == 2
    assert summary['included_trials'] == 1
    assert 'evidence_integrity' in summary['excluded'][0]['unmet']
    assert 'collection_complete' in summary['admission']['unmet']


def test_summary_keeps_missing_measurements_unknown(tmp_path):
    trial = _write_trial(tmp_path, 's_mqtt_lecture', 'f0', 1)
    comparison = json.loads((trial / 'comparison-mqtt.json').read_text())
    comparison['arms']['llm']['metrics']['estimated_cost_usd'] = None
    (trial / 'comparison-mqtt.json').write_text(json.dumps(comparison))
    summary = v2.summarize_experiments([tmp_path])
    entry = next(iter(summary['by_configuration'].values()))
    assert entry['inference']['f0']['metrics']['llm_estimated_cost_usd']['available'] is False


def test_summary_reports_incomplete_trials_without_inventing_values(tmp_path):
    (tmp_path / 'trials' / 'broken').mkdir(parents=True)
    summary = v2.summarize_experiments([tmp_path])
    assert summary['included_trials'] == 0
    assert summary['incomplete'][0]['problem'].startswith('expected exactly one comparison')


def test_summary_refuses_pointers_outside_the_experiment_root(tmp_path):
    trial = _write_trial(tmp_path, 's_mqtt_lecture', 'f0', 1)
    outside = tmp_path.parent / 'outside-run'
    outside.mkdir(exist_ok=True)
    (outside / 'run_meta.json').write_text('{}')
    (trial / 'llm_dir.txt').write_text(str(outside) + '\n')
    summary = v2.summarize_experiments([tmp_path])
    assert summary['incomplete'][0]['problem'].startswith('llm run pointer escapes')
    assert summary['included_trials'] == 0


def test_summary_detects_duplicate_trial_identities(tmp_path):
    first = _write_trial(tmp_path, 's_mqtt_lecture', 'f0', 1)
    duplicate = tmp_path / 'trials' / 'duplicate'
    duplicate.mkdir()
    for name in ('comparison-mqtt.json', 'planned.json', 'rules_dir.txt', 'llm_dir.txt'):
        (duplicate / name).write_text((first / name).read_text())
    for policy in ('rules', 'llm'):
        (duplicate / 'preflight' / policy).mkdir(parents=True)
        (duplicate / 'preflight' / policy / 'attestation.json').write_text(
            (first / 'preflight' / policy / 'attestation.json').read_text())
    summary = v2.summarize_experiments([tmp_path])
    assert summary['included_trials'] == 1
    assert len(summary['duplicates']) == 1
    assert 'unique_trials' in summary['admission']['unmet']


def test_cli_refuses_fewer_than_two_families(tmp_path):
    with pytest.raises(SystemExit):
        v2.main(['--root', str(tmp_path), '--output', str(tmp_path / 'out.json'),
                 '--minimum-families', '1'])


def test_cli_refuses_a_root_without_trials(tmp_path):
    with pytest.raises(SystemExit):
        v2.main(['--root', str(tmp_path), '--output', str(tmp_path / 'out.json')])


def test_cli_writes_a_summary_without_an_invented_threshold(tmp_path):
    _write_trial(tmp_path, 's_mqtt_lecture', 'f0', 1)
    output = tmp_path / 'out.json'
    assert v2.main(['--root', str(tmp_path), '--output', str(output)]) == 0
    written = json.loads(output.read_text())
    assert written['schema_version'] == v2.SCHEMA_VERSION
    assert Path(written['roots'][0]) == tmp_path.resolve()
    entry = next(iter(written['by_configuration'].values()))
    if entry['inference']['f0']['metrics']['tool_calls'].get('available'):
        assert 'ci95_excludes_delta' not in entry['inference']['f0']['metrics']['tool_calls']
