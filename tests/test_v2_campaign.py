"""V2 campaign identity, admission and offline summary contracts."""
import json
from pathlib import Path

import pytest

from benchmarks.experiments import v2_campaign as v2


def _arm(*, budget=(8, 420, 1, 12), preflight='valid', integrity=False, usage=True,
         success=True, tool_calls=6, wall_clock=20.0, cost=0.004, model=v2.DEFAULT_MODEL):
    return {
        'run_meta': {'provider': v2.PROVIDER, 'model': model, 'budgets': {
            'max_tool_calls': budget[0], 'max_duration_s': budget[1],
            'max_cost_usd': budget[2], 'max_turns': budget[3]},
            'evidence_integrity_failed': integrity},
        'evaluation': {'success': success, 'outcome': 'success' if success else 'non_success'},
        'preflight': {'status': preflight},
        'usage_complete': usage,
        'metrics': {'tool_calls': tool_calls, 'wall_clock_s': wall_clock, 'estimated_cost_usd': cost},
    }


def test_trial_identity_is_stable_for_the_same_frozen_commit():
    identity = v2.trial_identity('ssh-abcdef123456', 's_ssh_identifiants', 1, 2)
    assert identity == {'id': 'ssh-abcdef123456', 'trial_id': 's_ssh_identifiants-f1-r2',
                        'family_id': 's_ssh_identifiants', 'instance_id': 's_ssh_identifiants-f1-r2'}
    assert v2.default_campaign_id('ssh', 'abcdef1234567890') == 'ssh-abcdef123456'


def test_model_gate_refuses_outside_the_declared_panel():
    with pytest.raises(ValueError, match='no provider fallback'):
        v2.require_model('minimax', v2.DEFAULT_MODEL, pilot='SSH')
    with pytest.raises(ValueError, match='no provider fallback'):
        v2.require_model(v2.PROVIDER, 'other-model', pilot='SSH')
    for model in v2.MODEL_PANEL:
        assert v2.require_model(v2.PROVIDER, model, pilot='SSH') == model


def test_pair_admission_accepts_a_complete_pair():
    admission = v2.pair_admission({'rules': _arm(), 'llm': _arm()})
    assert admission['met'] is True and admission['unmet'] == []


@pytest.mark.parametrize('mutate,expected', [
    (lambda arms: arms.pop('llm'), 'paired_execution_complete'),
    (lambda arms: arms['llm'].update(usage_complete=False), 'usage_complete'),
    (lambda arms: arms['rules'].update(preflight={'status': 'invalid'}), 'preflight_attested'),
    (lambda arms: arms['llm']['run_meta'].update(evidence_integrity_failed=True), 'evidence_integrity'),
    (lambda arms: arms['llm']['evaluation'].update(success=None), 'evaluation_available'),
    (lambda arms: arms['llm']['run_meta'].update(budgets={'max_tool_calls': 9}), 'budget_parity'),
])
def test_pair_admission_names_the_unmet_condition(mutate, expected):
    arms = {'rules': _arm(), 'llm': _arm()}
    mutate(arms)
    admission = v2.pair_admission(arms)
    assert admission['met'] is False
    assert expected in admission['unmet']
    assert admission['conditions'][expected]['met'] is False


def test_pair_admission_requires_run_meta_on_both_arms():
    arms = {'rules': _arm(), 'llm': _arm()}
    arms['rules'].pop('run_meta')
    assert 'run_meta_present' in v2.pair_admission(arms)['unmet']


def test_campaign_admission_refuses_a_single_family():
    admission = v2.campaign_admission([{'met': True}], families=1, repetitions={'s': 3},
                                      configurations=[{'model': 'm'}])
    assert admission['mt_admissible'] is False
    assert 'independent_families' in admission['unmet']
    assert 'strict_v3_metrics_adopted' in admission['unmet']


def test_campaign_admission_needs_repetitions_and_uniformity():
    admission = v2.campaign_admission([{'met': True}], families=2, repetitions={'a': 3, 'b': 1},
                                      configurations=[{'model': 'a'}, {'model': 'b'}],
                                      strict_v3_metrics_adopted=True)
    assert 'minimum_repetitions' in admission['unmet']
    assert 'configuration_uniformity' in admission['unmet']


def _write_trial(root, family, posture, repetition, *, model=v2.DEFAULT_MODEL, usage=True,
                 preflight='valid'):
    trial = root / 'trials' / f'{family}-{posture}-{repetition}'
    (trial / 'preflight' / 'rules').mkdir(parents=True)
    (trial / 'preflight' / 'llm').mkdir(parents=True)
    identity = v2.trial_identity('campaign', family, int(posture == 'f1'), repetition)
    for policy in ('rules', 'llm', 'x'):
        run = trial / f'run-{policy}'
        run.mkdir(exist_ok=True)
        if policy == 'x':
            continue
        (trial / f'{policy}_dir.txt').write_text(str(run) + '\n')
        (run / 'run_meta.json').write_text(json.dumps({
            'provider': v2.PROVIDER, 'model': model, 'experiment': identity,
            'resource_manifest_sha256': 'a' * 64,
            'budgets': {'max_tool_calls': 8, 'max_duration_s': 420,
                        'max_cost_usd': 1, 'max_turns': 12},
            'evidence_integrity_failed': False}))
        (trial / 'preflight' / policy / 'attestation.json').write_text(json.dumps({'status': preflight}))
    arms = {}
    for policy, calls in (('rules', 5), ('llm', 9 if usage else 7)):
        arms[policy] = {
            'evaluation': {'success': True, 'outcome': 'success'},
            'metrics': {'tool_calls': calls, 'wall_clock_s': 15.0 if policy == 'rules' else 30.0,
                        'usage_complete': True if policy == 'rules' else usage,
                        'estimated_cost_usd': 0.0 if policy == 'rules' else 0.006}}
    (trial / 'comparison-mqtt.json').write_text(json.dumps({'arms': arms}))
    (trial / 'planned.json').write_text(json.dumps({
        'trial_id': identity['trial_id'], 'repetition': repetition,
        'intentional_flaws': int(posture == 'f1'), 'experiment': identity}))
    return trial


def test_summary_reports_descriptive_statistics_without_enough_families(tmp_path):
    for repetition in (1, 2):
        _write_trial(tmp_path, 's_mqtt_lecture', 'f0', repetition)
        _write_trial(tmp_path, 's_mqtt_lecture', 'f1', repetition)
    summary = v2.summarize_experiments([tmp_path])
    assert summary['included_trials'] == 4 and summary['families'] == ['s_mqtt_lecture']
    assert summary['repetitions_per_family'] == {'s_mqtt_lecture': 2}
    assert summary['inference']['available'] is False
    assert 'independent_families' in summary['admission']['unmet']
    assert summary['admission']['mt_admissible'] is False
    descriptive = summary['descriptive']['s_mqtt_lecture']
    assert descriptive['f1']['llm']['trials'] == 2
    assert descriptive['f1']['llm']['success_rate'] == 1.0
    assert descriptive['f1']['llm']['mean_tool_calls'] == 9.0
    assert sum(summary['inference']['metrics']['tool_calls'].get('family_means', {}).values()) \
        == pytest.approx(4.0)


def test_summary_produces_family_inference_for_two_families(tmp_path):
    for family in ('s_mqtt_lecture', 's_ssh_identifiants'):
        for repetition in (1, 2, 3):
            _write_trial(tmp_path, family, 'f0', repetition)
            _write_trial(tmp_path, family, 'f1', repetition)
    summary = v2.summarize_experiments([tmp_path], minimum_repetitions=3)
    assert summary['included_trials'] == 12
    assert summary['inference']['available'] is True
    assert summary['inference']['metrics']['tool_calls']['families'] == 2
    # Six pairs per family, delta llm - rules == 9 - 5 == 4 on every trial.
    assert summary['inference']['metrics']['tool_calls']['mean'] == pytest.approx(4.0)
    # Boolean success is a measurement, not a missing value: both arms succeed,
    # so the paired delta is exactly zero.
    assert summary['inference']['metrics']['task_success']['available'] is True
    assert summary['inference']['metrics']['task_success']['mean'] == pytest.approx(0.0)
    assert 'strict_v3_metrics_adopted' in summary['admission']['unmet']


def test_configuration_comes_from_the_trial_declaration_not_the_rules_arm(tmp_path):
    # The real harnesses record provider/model only on the LLM arm; the rules
    # arm is not an LLM run and must not make the configuration look different.
    for family in ('s_mqtt_lecture', 's_ssh_identifiants'):
        for repetition in (1, 2, 3):
            trial = _write_trial(tmp_path, family, 'f0', repetition)
            meta_path = trial / 'run-rules' / 'run_meta.json'
            meta = json.loads(meta_path.read_text())
            meta['provider'] = meta['model'] = None
            meta_path.write_text(json.dumps(meta))
            (trial / 'controller.json').write_text(json.dumps({
                'provider': v2.PROVIDER, 'model': v2.DEFAULT_MODEL, 'budgets': meta['budgets']}))
    record = v2.read_trial(tmp_path / 'trials' / 's_mqtt_lecture-f0-1')
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
                    _write_trial(root, family, posture, repetition, model=model)
    summary = v2.summarize_experiments(roots, minimum_repetitions=3)
    assert len(summary['by_configuration']) == 2
    for entry in summary['by_configuration'].values():
        assert entry['inference']['metrics']['tool_calls']['mean'] == pytest.approx(4.0)
    # Two models are two configurations: no pooled inference, and the campaign
    # admission names the non-uniformity instead of hiding it.
    assert summary['inference']['available'] is False
    assert summary['admission']['conditions']['configuration_uniformity']['met'] is False


def test_summary_excludes_pairs_with_an_unmet_condition(tmp_path):
    _write_trial(tmp_path, 's_mqtt_lecture', 'f0', 1, usage=False)
    _write_trial(tmp_path, 's_ssh_identifiants', 'f1', 1)
    summary = v2.summarize_experiments([tmp_path])
    assert summary['evaluated_trials'] == 2
    assert summary['included_trials'] == 1
    assert summary['excluded'][0]['unmet'] == ['usage_complete']


def test_summary_keeps_missing_measurements_unknown(tmp_path):
    trial = _write_trial(tmp_path, 's_mqtt_lecture', 'f0', 1)
    comparison = json.loads((trial / 'comparison-mqtt.json').read_text())
    comparison['arms']['llm']['metrics']['estimated_cost_usd'] = None
    (trial / 'comparison-mqtt.json').write_text(json.dumps(comparison))
    summary = v2.summarize_experiments([tmp_path])
    assert summary['included_trials'] == 1
    assert summary['inference']['metrics']['estimated_cost_usd']['available'] is False


def test_summary_reports_incomplete_trials_without_inventing_values(tmp_path):
    (tmp_path / 'trials' / 'broken').mkdir(parents=True)
    summary = v2.summarize_experiments([tmp_path])
    assert summary['included_trials'] == 0
    assert summary['incomplete'][0]['problem'].startswith('expected exactly one comparison')


def test_cli_refuses_fewer_than_two_families(tmp_path):
    with pytest.raises(SystemExit):
        v2.main(['--root', str(tmp_path), '--output', str(tmp_path / 'out.json'),
                 '--minimum-families', '1'])


def test_cli_writes_a_summary(tmp_path):
    _write_trial(tmp_path, 's_mqtt_lecture', 'f0', 1)
    output = tmp_path / 'out.json'
    assert v2.main(['--root', str(tmp_path), '--output', str(output)]) == 0
    written = json.loads(output.read_text())
    assert written['schema_version'] == v2.SCHEMA_VERSION
    assert Path(written['roots'][0]) == tmp_path.resolve()
