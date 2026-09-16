import io
import json
from threading import Lock
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import requests

from src.agent.core.executor import wrap_tool
from src.agent.tools.recon_tools import http_request
from src.agent.tools.tool_loader import load_tool_yaml, build_subprocess_function, DEFINITIONS_DIR
from src.agent.exploit_evidence import synthesize_exploit_result


class MemoryTransport(requests.adapters.BaseAdapter):
    def __init__(self):
        self.urls = []

    def send(self, request, **kwargs):
        self.urls.append(request.url)
        response = requests.Response()
        response.request, response.url = request, request.url
        response.status_code = 302
        response.headers['Location'] = 'http://198.51.100.9/admin'
        response._content = b''
        response.raw = io.BytesIO(b'')
        return response

    def close(self):
        pass


def test_redirect_requires_a_separate_scope_checked_tool_call(tmp_path):
    transport = MemoryTransport()
    session = requests.Session()
    session.trust_env = False
    session.mount('http://', transport)
    run = SimpleNamespace(run_dir=tmp_path, tracker=None, _artifact_log_lock=Lock(),
        max_tool_calls=None, _tool_call_count=0, context={'target_subnet': '192.0.2.0/24'})
    fn = wrap_tool(run, {'name': 'http_request', 'function': http_request}, phase=4)['function']
    with patch('requests.request', session.request):
        first = json.loads(fn(url='http://192.0.2.10/start'))
        second = json.loads(fn(url=first['headers']['Location']))
    assert first['status_code'] == 302
    assert second['error_kind'] == 'intrusion_target_out_of_scope'
    assert transport.urls == ['http://192.0.2.10/start']


def test_explicit_follow_redirects_cannot_bypass_guard():
    with patch('requests.request') as request:
        assert 'error' in json.loads(http_request('http://192.0.2.10', follow_redirects=True))
        request.assert_not_called()


@pytest.mark.parametrize('final_url', ['http://192.0.2.20/backup', 'http://192.0.2.10/other', 'https://192.0.2.10/backup'])
def test_redirected_sensitive_body_never_confirms_original_endpoint(final_url):
    finding = {'id': 'F1', 'type': 'data_exposure', 'service': 'http', 'device_ip': '192.0.2.10', 'port': 80, 'endpoint': '/backup'}
    record = {'tool': 'http_request', 'args': {'url': 'http://192.0.2.10/backup'},
        'result': {'status_code': 200, 'body': 'password=review-secret', 'final_url': final_url}}
    assert synthesize_exploit_result(finding, [record])['status'] != 'EXPLOITED'
    record['result']['final_url'] = 'http://192.0.2.10/backup'
    assert synthesize_exploit_result(finding, [record])['status'] == 'EXPLOITED'


def test_historical_curl_redirect_chain_is_not_proof():
    record = {'tool': 'curl_headers', 'args': {'url': 'http://192.0.2.10/backup'},
        'result': {'return_code': 0, 'stdout': 'HTTP/1.1 302 Found\r\nLocation: http://192.0.2.20/\r\n\r\nHTTP/1.1 200 OK\r\n\r\npassword=review-secret'}}
    assert synthesize_exploit_result({'type': 'data_exposure'}, [record])['status'] != 'EXPLOITED'


@pytest.mark.parametrize('name', ['http_get', 'curl_headers'])
def test_curl_cannot_expand_urls_or_load_ambient_redirect_config(name):
    fn = build_subprocess_function(load_tool_yaml(DEFINITIONS_DIR / f'{name}.yaml'))
    with patch('src.agent.tools.recon_tools._run', return_value={'return_code': 0}) as run:
        fn(url='http://192.0.2.10/path,a')
    argv = run.call_args.args[0]
    assert argv[:2] == ['curl', '-q']
    assert '-L' not in argv
    assert '--globoff' in argv
    assert argv[-1] == 'http://192.0.2.10/path,a'
