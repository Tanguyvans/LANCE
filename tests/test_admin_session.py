import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from src.api import auth
from src.api.routes import admin_session


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("LANCE_ADMIN_TOKEN", "test-admin-key")
    monkeypatch.setattr(auth, "_sessions", {})
    app = FastAPI(dependencies=[Depends(auth.require_mutation_auth)])
    app.include_router(admin_session.router, prefix="/api/admin/session")

    @app.post("/api/action")
    def action():
        return {"ok": True}

    return TestClient(app, base_url="https://testserver")


def login(client):
    return client.post("/api/admin/session", headers={
        "Authorization": "Bearer test-admin-key",
        "X-Lance-Admin-Session": "1", "Origin": "https://testserver",
    })


def test_session_survives_page_reload_and_logout_revokes(client):
    response = login(client)
    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    for flag in ("HttpOnly", "Secure", "SameSite=strict", "Max-Age=28800", "Path=/api"):
        assert flag in cookie
    assert "test-admin-key" not in cookie + response.text
    assert client.get("/api/admin/session").json() == {"authenticated": True}
    headers = {"X-Lance-Admin-Session": "1"}
    assert client.post("/api/action", headers=headers).status_code == 200
    old_cookie = client.cookies.get(auth.SESSION_COOKIE)
    assert client.delete("/api/admin/session", headers=headers).status_code == 200
    client.cookies.set(auth.SESSION_COOKIE, old_cookie)
    assert client.post("/api/action", headers=headers).status_code == 401


def test_cookie_requires_csrf_header_and_same_origin(client):
    assert login(client).status_code == 200
    assert client.post("/api/action").status_code == 403
    assert client.post("/api/action", headers={"X-Lance-Admin-Session": "1", "Origin": "https://evil.test"}).status_code == 403
    assert client.post("/api/admin/session", headers={"X-Lance-Admin-Session": "1"}).status_code == 401


def test_expiry_and_key_rotation(client, monkeypatch):
    assert login(client).status_code == 200
    original_time = auth.time.time()
    monkeypatch.setattr(auth.time, "time", lambda: original_time + auth.SESSION_TTL + 1)
    assert client.get("/api/admin/session").json() == {"authenticated": False}
    assert login(client).status_code == 200
    monkeypatch.setenv("LANCE_ADMIN_TOKEN", "rotated-key")
    assert client.post("/api/action", headers={"X-Lance-Admin-Session": "1"}).status_code == 401


def test_invalid_key_and_missing_configuration(client, monkeypatch):
    assert client.post("/api/admin/session", headers={"Authorization": "Bearer wrong", "X-Lance-Admin-Session": "1"}).status_code == 401
    assert not auth._sessions
    monkeypatch.delenv("LANCE_ADMIN_TOKEN")
    assert login(client).status_code == 503


def test_bad_bearer_does_not_fall_back_to_cookie(client):
    login(client)
    assert client.post("/api/action", headers={"Authorization": "Bearer wrong", "X-Lance-Admin-Session": "1"}).status_code == 401


def test_browser_source_uses_cookie_not_persistent_token_storage():
    from pathlib import Path
    source = Path("src/static/app.js").read_text()
    section = source.split("async function loginAdminSession()", 1)[1].split("async function apiSend", 1)[0]
    assert "localStorage" not in section and "sessionStorage" not in section
    assert "field.value = ''" in section
    assert "DOMContentLoaded" in section


def test_browser_login_refresh_logout():
    import shutil
    import subprocess
    from pathlib import Path
    node = shutil.which("node")
    if not node:
        pytest.skip("node unavailable")
    source = Path("src/static/app.js").read_text()
    helpers = "async function loginAdminSession()" + source.split("async function loginAdminSession()", 1)[1].split("async function apiSend", 1)[0]
    script = '''
const assert = require('assert');
const fields = {'admin-action-token': {value: 'secret'}, 'mgr-admin-token': {value: 'secret'}, 'admin-action-help': {textContent: ''}};
const document = {getElementById: id => fields[id], addEventListener: () => {}};
const _mgr = {adminToken: 'secret'};
let method;
async function adminFetch(url, options) { method = options.method; return {ok: true}; }
async function fetch() { return {ok: true, json: async () => ({authenticated: true})}; }
''' + helpers + '''
(async () => {
 await loginAdminSession();
 assert.equal(method, 'POST');
 assert.equal(fields['admin-action-token'].value, '');
 assert.equal(fields['mgr-admin-token'].value, '');
 assert.equal(_mgr.adminToken, '');
 await refreshAdminSession();
 assert.match(fields['admin-action-help'].textContent, /active/);
 await logoutAdminSession();
 assert.equal(method, 'DELETE');
 assert.equal(fields['admin-action-help'].textContent, 'Déconnecté.');
})().catch(e => {console.error(e); process.exit(1);});
'''
    result = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
