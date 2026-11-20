import re
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.routes import pipeline


MUTATIONS = [(method.upper(), re.sub(r'\{[^}]+\}', '1', path))
    for path, operations in app.openapi()['paths'].items()
    for method in operations if method in {'post', 'put', 'patch', 'delete'}
    and not (method == 'post' and path in {'/api/pipeline/start', '/api/pipeline/batch'})]
assert len(MUTATIONS) >= 15


@pytest.mark.parametrize('method,path', MUTATIONS)
@pytest.mark.parametrize('token,status', [(None, 503), ('test-admin-key', 401)])
def test_every_mutation_fails_closed_before_side_effects(monkeypatch, method, path, token, status):
    if token:
        monkeypatch.setenv('LANCE_ADMIN_TOKEN', token)
    else:
        monkeypatch.delenv('LANCE_ADMIN_TOKEN', raising=False)
    response = TestClient(app).request(method, path, json={})
    assert response.status_code == status, (method, path, response.text)
    assert 'test-admin-key' not in response.text


def test_authorized_stop_and_bad_token_do_not_share_authority(monkeypatch):
    monkeypatch.setenv('LANCE_ADMIN_TOKEN', 'test-admin-key')
    with patch.dict(pipeline._state, {'running': True, 'stop_event': SimpleNamespace(set=lambda: None), 'stopping': False}):
        client = TestClient(app)
        assert client.post('/api/pipeline/stop', headers={'Authorization': 'Bearer wrong'}).status_code == 401
        assert pipeline._state['stopping'] is False
        assert client.post('/api/pipeline/stop', headers={'Authorization': 'Bearer test-admin-key'}).status_code == 200
        assert pipeline._state['stopping'] is True


def test_status_remains_readable_and_cross_origin_mutations_are_not_allowed():
    client = TestClient(app)
    assert client.get('/api/pipeline/status').status_code == 200
    response = client.options('/api/pipeline/start', headers={
        'Origin': 'https://other.invalid', 'Access-Control-Request-Method': 'POST'})
    assert 'access-control-allow-origin' not in response.headers


@pytest.mark.parametrize("token", [None, "test-admin-key"])
@pytest.mark.parametrize("path,payload", [
    ("/api/pipeline/start", {"provider": "local", "model": "test", "scenario_id": "1"}),
    ("/api/pipeline/start", {"provider": "local", "model": "test", "scenario_id": "1", "deploy_only": True}),
    ("/api/pipeline/batch", {"provider": "local", "model": "test", "batch_ids": ["1"]}),
])
def test_launch_without_key_reaches_handler(monkeypatch, token, path, payload):
    if token is None:
        monkeypatch.delenv("LANCE_ADMIN_TOKEN", raising=False)
    else:
        monkeypatch.setenv("LANCE_ADMIN_TOKEN", token)
    with patch.dict(pipeline._state, {"running": True}):
        response = TestClient(app).post(path, json=payload)
    assert response.status_code == 409, response.text
    assert response.json()["detail"] == "Pipeline already running or stopping"


LAUNCH_PATHS = [
    ("/api/pipeline/start", {"provider": "local", "model": "test", "scenario_id": "1"}),
    ("/api/pipeline/batch", {"provider": "local", "model": "test", "batch_ids": ["1"]}),
]


@pytest.mark.parametrize("path,payload", LAUNCH_PATHS)
def test_launch_auth_required_fails_closed(monkeypatch, path, payload):
    monkeypatch.setenv("LANCE_REQUIRE_LAUNCH_AUTH", "1")
    # No server token configured -> 503 before the handler.
    monkeypatch.delenv("LANCE_ADMIN_TOKEN", raising=False)
    assert TestClient(app).post(path, json=payload).status_code == 503
    # Token configured but none supplied -> 401.
    monkeypatch.setenv("LANCE_ADMIN_TOKEN", "test-admin-key")
    assert TestClient(app).post(path, json=payload).status_code == 401
    # Correct Bearer reaches the handler (409: already running).
    with patch.dict(pipeline._state, {"running": True}):
        ok = TestClient(app).post(path, json=payload, headers={"Authorization": "Bearer test-admin-key"})
    assert ok.status_code == 409, ok.text


@pytest.mark.parametrize("path,payload", LAUNCH_PATHS)
def test_launch_public_when_flag_unset(monkeypatch, path, payload):
    monkeypatch.delenv("LANCE_REQUIRE_LAUNCH_AUTH", raising=False)
    monkeypatch.delenv("LANCE_ADMIN_TOKEN", raising=False)
    with patch.dict(pipeline._state, {"running": True}):
        resp = TestClient(app).post(path, json=payload)
    assert resp.status_code == 409, resp.text
