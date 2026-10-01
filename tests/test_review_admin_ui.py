"""Browser request policy exercised without any network or persistent storage."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest


def test_admin_ui_only_sends_key_to_same_origin_mutations():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node.js required')
    source = (Path(__file__).parents[1] / 'src/static/app.js').read_text()
    helper = 'async function adminFetch' + source.split('async function adminFetch', 1)[1].split('\nasync function apiSend', 1)[0]
    cost = 'function setCost' + source.split('function setCost', 1)[1].split('// ── Event log', 1)[0]
    script = r'''
const assert = require('node:assert/strict');
const badge = {};
global.document = {getElementById: id => id === 'cost-val' ? badge : null};
global.window = {location: {href: 'https://dashboard.test/'}};
let request, status = 200, error = {};
global.fetch = async (url, options) => {
  request = {url, options};
  return {status, clone: () => ({json: async () => error})};
};
async function check() {
  for (const [url, method, allowed] of [
    ['/api/pipeline/start', 'POST', false], ['/api/pipeline/batch', 'POST', false],
    ['/api/pipeline/stop', 'POST', true], ['/api/models/1', 'DELETE', true],
    ['/api/providers/1', 'PATCH', true], ['/api/pipeline/status', 'GET', false],
    ['https://other.test/api/start', 'POST', false], ['/static/test', 'POST', false]
  ]) {
    await adminFetch(url, {method});
    assert.equal(request.options.headers.Authorization, undefined);
    if (allowed) assert.equal(request.options.redirect, 'error');
    await adminFetch(url, {method, headers: {'aUtHoRiZaTiOn': 'Bearer explicit'}});
    assert.equal(request.options.headers.Authorization, allowed ? 'Bearer explicit' : undefined);
    assert.equal(request.options.headers.aUtHoRiZaTiOn, undefined);
  }
  for (const url of ['/api/pipeline/start', '/api/pipeline/batch']) {
    for (const responseStatus of [200, 401, 503]) {
      status = responseStatus;
      error = {detail: {code: 'admin_auth_not_configured'}};
      await adminFetch(url, {method: 'POST', credentials: 'include',
        headers: {'Authorization': 'Bearer stale', 'Content-Type': 'application/json'}, body: '{}'});
      assert.equal(request.options.headers.Authorization, undefined);
      assert.equal(request.options.headers['X-Lance-Admin-Session'], undefined);
      assert.equal(request.options.credentials, 'omit');
      assert.equal(request.options.redirect, 'error');
      assert.equal(request.options.headers['Content-Type'], 'application/json');
      assert.equal(request.options.body, '{}');
    }
  }
  for (const responseStatus of [401, 503]) {
    status = responseStatus;
    const response = await adminFetch('/api/pipeline/stop', {method: 'POST'});
    assert.equal(response.status, responseStatus);
  }
  setCost(null); assert.equal(badge.textContent, 'Indisponible');
  setCost(0); assert.equal(badge.textContent, '$0.0000');
  setCost(1.25); assert.equal(badge.textContent, '$1.2500');
}
check().catch(e => {console.error(e); process.exit(1);});
'''
    result = subprocess.run([node, '-e', helper + cost + script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert 'localStorage' not in helper and 'sessionStorage' not in helper
