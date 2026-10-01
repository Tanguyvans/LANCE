"""Cross-instance monitoring stays read-only and fails closed on stale peers."""
from types import SimpleNamespace
from unittest.mock import Mock

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
import requests

from src.api.routes import activity, pipeline


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv('LANCE_INSTANCE', 'main')
    monkeypatch.setattr(pipeline, '_state', {
        'running': False, 'teardown_running': False, 'lab_waiting': False,
        'phase': 6, 'model': 'previous-model', 'scenario_id': 'old',
        'recent_events': [{'secret': 'not-for-sharing'}], 'run_dir': '/private/run',
    })
    app = FastAPI()
    app.include_router(activity.router, prefix='/api/activity')
    return TestClient(app)


@pytest.mark.parametrize('flags,expected', [
    ({}, 'idle'), ({'running': True}, 'running'),
    ({'running': True, 'lab_waiting': True}, 'waiting'),
    ({'running': True, 'stopping': True}, 'stopping'),
    ({'running': True, 'deploy_status': 'deploying'}, 'deploying'),
    ({'teardown_running': True}, 'teardown'),
    ({'teardown_running': True, 'lab_waiting': True}, 'waiting'),
])
def test_compact_local_activity(client, flags, expected):
    pipeline._state.update(flags)
    response = client.get('/api/activity/local')
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    payload = response.json()
    assert payload['state'] == expected
    assert 'recent_events' not in payload and 'run_dir' not in payload
    assert 'not-for-sharing' not in response.text
    if expected == 'idle':
        assert payload['model'] is None and payload['scenario_id'] is None
        assert payload['phase'] == 0


def test_teardown_does_not_reuse_previous_run_metadata(client):
    pipeline._state.update(teardown_running=True, teardown_scenario_id='2')
    payload = client.get('/api/activity/local').json()
    assert payload['scenario_id'] == '2'
    assert payload['model'] is None and payload['phase'] == 0


def test_aggregate_queries_only_fixed_peers_without_credentials(client, monkeypatch):
    sessions = []
    class Session:
        trust_env = True
        def __enter__(self):
            sessions.append(self)
            return self
        def __exit__(self, *_): pass
        def get(self, url, **kwargs):
            assert self.trust_env is False
            assert kwargs == {'timeout': (0.5, 1), 'allow_redirects': False}
            assert url in ('http://127.0.0.1:8502/api/activity/local', 'http://127.0.0.1:8503/api/activity/local')
            instance = 'dev-1' if ':8502/' in url else 'dev-2'
            return SimpleNamespace(status_code=200, json=lambda: {
                'instance': instance, 'state': 'running' if instance == 'dev-1' else 'waiting',
                'scenario_id': '1', 'model': 'qwen', 'phase': 3,
                'secret': 'discard this',
            })
    monkeypatch.setattr(activity.requests, 'Session', Session)
    response = client.get('/api/activity?url=http://external.invalid', headers={'Authorization': 'Bearer do-not-forward'})
    data = response.json()
    assert response.headers['cache-control'] == 'no-store'
    assert data['current'] == 'main' and data['enabled']
    assert [item['state'] for item in data['instances']] == ['idle', 'running', 'waiting']
    assert [item['port'] for item in data['instances']] == [8501, 8502, 8503]
    assert len(sessions) == 2
    assert 'discard this' not in response.text


@pytest.mark.parametrize('failure', ['timeout', 'redirect', 'bad-json', 'wrong-identity', 'invalid-state'])
def test_peer_failure_is_unavailable_not_idle(monkeypatch, failure):
    session = Mock()
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    result = Mock(status_code=200)
    result.json.return_value = {'instance': 'dev-1', 'state': 'running'}
    session.get.return_value = result
    if failure == 'timeout': session.get.side_effect = requests.Timeout()
    if failure == 'redirect': result.status_code = 302
    if failure == 'bad-json': result.json.side_effect = ValueError()
    if failure == 'wrong-identity': result.json.return_value['instance'] = 'main'
    if failure == 'invalid-state': result.json.return_value['state'] = 'invented'
    monkeypatch.setattr(activity.requests, 'Session', lambda: session)
    assert activity._peer('dev-1', 8502).state == 'unavailable'


def test_standalone_does_not_probe_other_services(client, monkeypatch):
    monkeypatch.delenv('LANCE_INSTANCE')
    network = Mock(side_effect=AssertionError('No network for standalone'))
    monkeypatch.setattr(activity.requests, 'Session', network)
    data = client.get('/api/activity').json()
    assert not data['enabled']
    assert len(data['instances']) == 1
    network.assert_not_called()
