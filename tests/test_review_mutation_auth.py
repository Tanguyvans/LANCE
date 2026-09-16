import re
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.routes import pipeline


MUTATIONS = [(method.upper(), re.sub(r'\{[^}]+\}', '1', path))
    for path, operations in app.openapi()['paths'].items()
    for method in operations if method in {'post', 'put', 'patch', 'delete'}]
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
