import asyncio
import json
from unittest.mock import patch

import pytest

from src.agent.batch import _aggregate_batch_results
from src.agent.batch_outcomes import batch_run_status, batch_cost_summary
from src.api.routes import pipeline


@pytest.mark.parametrize('status', ['partial', 'failed', 'stopped', 'blocked', 'budget_exceeded', 'skipped'])
def test_batch_preserves_terminal_lifecycle_even_with_metrics(tmp_path, status):
    (tmp_path / 'run_meta.json').write_text(json.dumps({'status': status}))
    assert batch_run_status(tmp_path, {'intrusion': 'completed'}, phase5_status='completed', evaluated=True) == status


@pytest.mark.parametrize('metadata,expected', [
    ({'status': 'completed'}, 'ok'),
    ({'status': 'completed', 'cleanup_status': 'failed'}, 'partial'),
    ({'status': 'completed', 'usage_status': 'incomplete'}, 'partial'),
    ({'status': 'completed', 'evidence_integrity': False}, 'failed'),
])
def test_batch_metadata_and_cleanup_win_over_good_scores(tmp_path, metadata, expected):
    (tmp_path / 'run_meta.json').write_text(json.dumps(metadata))
    assert batch_run_status(tmp_path, {'report': 'completed'}, phase5_status='completed', evaluated=True) == expected


def test_batch_partial_without_metadata_is_not_ok(tmp_path):
    assert batch_run_status(tmp_path, {'vuln_analysis': 'partial:device_errors', 'intrusion': 'completed'}, phase5_status='completed', evaluated=True) == 'partial'
    assert batch_run_status(tmp_path, {'report': 'completed'}, phase5_status='completed', evaluated=False) == 'evaluation_failed'


def test_failed_attempt_is_in_total_even_without_evaluation():
    result = _aggregate_batch_results([], [{'scenario_id': '1', 'status': 'failed', 'cost_usd': 1.25, 'metrics': None}], ['1'])
    assert result['total_cost_usd'] == 1.25
    assert result['cost_missing_attempts'] == 0


def test_cost_is_counted_once_per_attempt_and_unknown_stays_unknown():
    results = [{'cost_usd': 1.25, 'metrics': {'total_cost_usd': 99}}, {'cost_usd': 0}, {'metrics': {'total_cost_usd': 0.5}}]
    assert batch_cost_summary(results)['total_cost_usd'] == 1.75
    results.append({'cost_usd': None, 'metrics': {'total_cost_usd': 100}})
    summary = batch_cost_summary(results)
    assert summary['total_cost_usd'] is None
    assert summary['known_cost_usd'] == 1.75
    assert summary['cost_missing_attempts'] == 1


@pytest.mark.parametrize('value', [True, -1, float('nan'), float('inf'), 'bad'])
def test_invalid_cost_never_poisons_the_total(value):
    assert batch_cost_summary([{'cost_usd': value}])['total_cost_usd'] is None


def test_stream_keeps_errors_cleanup_and_all_batch_events():
    async def check():
        events = [{'type': 'pipeline_done', 'batch_scenario_id': '1'},
                  {'type': 'batch_scenario_done', 'scenario_id': '1'},
                  {'type': 'error', 'message': 'controlled error'},
                  {'type': 'teardown_done', 'success': True},
                  {'type': 'batch_scenario_done', 'scenario_id': '2'},
                  {'type': 'batch_done'}]
        queue = asyncio.Queue()
        for event in [*events, {'type': '__done__'}]:
            queue.put_nowait(event)
        with patch.dict(pipeline._state, {'queue': queue}):
            response = await pipeline.stream_events()
            seen = [json.loads(event['data']) async for event in response.body_iterator]
        assert seen == events
        assert queue.empty()
    asyncio.run(check())
