"""Independent regression checks for cross-run funnel consistency."""
import json
from types import SimpleNamespace

import pytest

from tests.test_evaluation_audit import _finding, _truth, _evaluate, _confirmed
from src.agent.finding_identity import finding_identity_key
from src.agent.phases.verification.run import VerificationPhase
from src.agent.phases.verification.contract import _phase4_requirement_matches
from src.benchmark.evaluator import _tool_call_matches_finding
from src.benchmark.funnel import unique_predictions


def finding(service='mqtt', **changes):
    base = dict(type='info_disclosure', service=service, port=1883,
                endpoint='$SYS/#', tool_used='mqtt_listen', evidence_refs=['proof-V1'])
    if service == 'ssh':
        base.update(type='default_credentials',port=22,endpoint='/',tool_used='ssh_login')
    return _finding(**{**base, **changes})


def record(tool='mqtt_listen', **args):
    if tool == 'mqtt_listen':
        defaults = {'broker':'192.0.2.1','topic':'$SYS/#','port':1883}
        stdout = '$SYS/broker/version fixture-1\n'
    else:
        defaults = {'command_string':'sshpass -p fixture-password ssh -p 22 operator@192.0.2.1 id'}
        stdout = 'uid=1000(operator) gid=1000(operator)\n'
    return {'tool':tool,'vuln_id':'V1','evidence_ref':'proof-V1','_evidence_ref':'proof-V1',
            'args':{**defaults, **args}, 'result':{'return_code':0,'stdout':stdout,'stderr':''}}


@pytest.mark.parametrize('endpoint', ['', '$SYS/#'])
def test_mqtt_topic_representation_does_not_lose_real_proof(tmp_path,endpoint):
    v = finding(endpoint=endpoint)
    assert _tool_call_matches_finding(v,record())
    gt = _truth(category='info_disclosure',accepted_types=['info_disclosure'],
                services=['mqtt'],ports=[1883],endpoints=[])
    result = _evaluate(tmp_path,[v],[gt],tests=[_confirmed(v,'mqtt_listen')],records=[record()])
    assert result.funnel['stages']['confirmed']['true_positives'] == 1


@pytest.mark.parametrize('args', [
    {'topic':'#'}, {'topic':'$sys/#'}, {'topic':'sensors/#'},
    {'topic':'$SYS/broker/version'}, {'broker':'192.0.2.2'}, {'port':1884},
    {'topic':'sensors/#','payload':'$SYS/#'},
])
def test_mqtt_different_destination_is_not_bound(args):
    assert not _tool_call_matches_finding(finding(),record(**args))


@pytest.mark.parametrize('change', [
    {'vuln_id':'V2'}, {'_evidence_ref':'proof-V2'}, {'tool':'http_get'},
])
def test_mqtt_resource_fix_keeps_reference_and_tool_checks(change):
    assert not _tool_call_matches_finding(finding(),{**record(),**change})


def test_mqtt_root_is_a_topic_not_an_ignorable_ssh_placeholder():
    assert not _tool_call_matches_finding(finding(endpoint='/'),record(topic='other'))
    assert _tool_call_matches_finding(finding(endpoint='/'),record(topic='/'))


def test_mqtt_secondary_topic_cannot_replace_explicit_primary():
    v=finding(endpoint='$SYS/#',endpoints=['$SYS/#','sensors/#'])
    assert not _tool_call_matches_finding(v,record(topic='sensors/#'))


def test_mqtt_topic_hash_and_slash_are_not_http_url_syntax():
    v=finding(type='data_exposure',endpoint='Devices/A/#',endpoints=[])
    assert _tool_call_matches_finding(v,record(topic='Devices/A/#'))
    assert not _tool_call_matches_finding(v,record(topic='Devices/B/#'))
    assert not _tool_call_matches_finding(v,record(topic='devices/A/#'))


@pytest.mark.parametrize('endpoint',['','/'])
def test_ssh_transport_proof_is_not_an_http_route(tmp_path,endpoint):
    v = finding('ssh',endpoint=endpoint)
    r = record('ssh_login')
    assert _tool_call_matches_finding(v,r)
    gt = _truth(category='default_credentials',accepted_types=['default_credentials'],
                services=['ssh'],ports=[22],endpoints=[])
    result = _evaluate(tmp_path,[v],[gt],tests=[_confirmed(v,'ssh_login')],records=[r])
    assert result.funnel['stages']['confirmed']['true_positives'] == 1


@pytest.mark.parametrize('args', [
    {'command_string':'ssh -p 22 operator@192.0.2.2 id'},
    {'command_string':'ssh -p 2222 operator@192.0.2.1 id'},
    {'command_string':'ssh operator@192.0.2.2 "echo 192.0.2.1"','host':'192.0.2.1'},
])
def test_ssh_placeholder_fix_never_relaxes_destination(args):
    assert not _tool_call_matches_finding(finding('ssh'),record('ssh_login',**args))


def test_ssh_nonplaceholder_resource_is_not_silently_ignored():
    assert not _tool_call_matches_finding(
        finding('ssh',type='data_exposure',endpoint='/etc/shadow'),record('ssh_login'))


@pytest.mark.parametrize('changes', [
    {'service':'http'}, {'service':'ssh','type':'data_exposure'},
])
def test_ssh_tool_is_not_a_license_to_ignore_meaningful_resource(changes):
    assert not _tool_call_matches_finding({**finding('ssh'),**changes},record('ssh_login'))


def ws(**changes):
    return _finding(**{'type':'no_auth','service':'mqtt-ws','port':9001,'endpoint':'',
                       'endpoints':[], 'details':'Unauthenticated WebSocket upgrade', **changes})


def test_default_websocket_root_duplicate_has_one_shared_identity():
    vague,root = ws(),ws(id='V2',endpoint='/',endpoints=['/'])
    assert finding_identity_key(vague) == finding_identity_key(root)
    assert len(unique_predictions([vague,root])) == 1


def test_websocket_implicit_root_is_also_the_required_proof_destination():
    v=ws(tool_used='http_request',evidence_refs=['proof-V1'])
    good={**record(),'tool':'http_request','args':{'url':'http://192.0.2.1:9001/'}}
    wrong={**good,'args':{'url':'http://192.0.2.1:9001/admin'}}
    assert _tool_call_matches_finding(v,good)
    assert not _tool_call_matches_finding(v,wrong)


@pytest.mark.parametrize('change', [
    {'endpoint':'/mqtt'}, {'endpoint':'/?tenant=A'}, {'endpoint':'/Root'},
    {'endpoint':'/', 'endpoints':['/','/admin']}, {'port':9002},
    {'device_ip':'192.0.2.2'}, {'type':'network_exposure'},
    {'protocol':'udp'}, {'details':'A different security property'},
    {'condition':'Different condition'}, {'cve_ids':['CVE-2020-0001']},
])
def test_websocket_dedup_keeps_distinct_claims(change):
    assert len(unique_predictions([ws(),ws(id='V2',**change)])) == 2


@pytest.mark.parametrize('service',['http','https'])
def test_unspecified_generic_http_path_is_not_automatically_root(service):
    assert finding_identity_key(ws(service=service)) != finding_identity_key(ws(service=service,endpoint='/'))


@pytest.mark.parametrize('expected,observed', [
    ('/','/admin'),('/Admin','/admin'),('/export?tenant=A','/export?tenant=B'),
])
def test_http_primary_matching_remains_exact(expected,observed):
    v = _finding(endpoint=expected,endpoints=[expected,observed],tool_used='http_get',evidence_refs=['proof-V1'])
    r = {**record(),'tool':'http_get','args':{'url':f'http://192.0.2.1{observed}'}}
    assert not _tool_call_matches_finding(v,r)


def header_finding():
    return _finding(type='missing_header',endpoint='/',details='Missing HTTP security headers: x-frame-options')


def header_record(positive=True):
    headers = '' if positive else 'X-Frame-Options: DENY\r\nStrict-Transport-Security: max-age=10\r\nContent-Security-Policy: default-src none\r\n'
    return {'vuln_id':'V1','tool':'curl_headers','args':{'url':'http://192.0.2.1/'},
            'evidence_ref':'proof-V1','result':{'return_code':0,'stdout':f'HTTP/1.1 200 OK\r\n{headers}\r\n'}}


def resolve(path,records,compact=False):
    instance = SimpleNamespace(_uses_compact_local_moe=lambda:compact)
    return VerificationPhase._resolve_exploit_verdict(instance,header_finding(),path,tool_records=records)


@pytest.mark.parametrize('compact',[False,True])
@pytest.mark.parametrize('status',['FAILED','ERROR','INCONCLUSIVE','EXPLOITED','CONFIRMED','COMPROMISED'])
def test_raw_proof_is_authoritative_regardless_of_model_label(tmp_path,status,compact):
    p=tmp_path/'missing_header_VULN-001.json'
    p.write_text(json.dumps({'status':status,'evidence':'A model opinion','evidence_level':99,
                             'evidence_refs':['fake-ref'],'device_ip':'192.0.2.99','endpoint':'/wrong'}))
    result=resolve(p,[header_record()],compact)
    assert result['status']=='CONFIRMED'
    assert result['evidence_level']==2
    assert result['device_ip']=='192.0.2.1'
    assert result['endpoint']=='/'
    assert result['tool_used']=='curl_headers'
    assert result['evidence_refs']==['proof-V1']
    assert 'A model opinion' not in result['evidence']


@pytest.mark.parametrize('status',['EXPLOITED','CONFIRMED','FAILED','ERROR'])
def test_model_alone_cannot_confirm(tmp_path,status):
    p=tmp_path/'missing_header_VULN-001.json'
    p.write_text(json.dumps({'status':status,'evidence':'HTTP evidence asserted by model','evidence_level':99}))
    result=resolve(p,[])
    assert result['status']=='ERROR'
    assert result['evidence_level']==0


@pytest.mark.parametrize('status',['EXPLOITED','CONFIRMED','FAILED','ERROR'])
def test_received_but_nonproving_headers_stay_inconclusive(tmp_path,status):
    p=tmp_path/'missing_header_VULN-001.json'
    p.write_text(json.dumps({'status':status,'evidence':'A model opinion','evidence_level':99}))
    result=resolve(p,[header_record(positive=False)])
    assert result['status']=='FAILED'
    assert result['verification_status']=='inconclusive'
    assert result['evidence_level']<=1


def test_uncommitted_contracts_do_not_relabel_history(tmp_path):
    from src.benchmark.evaluator import evaluate
    v=finding(); gt=_truth(category='info_disclosure',accepted_types=['info_disclosure'],services=['mqtt'],ports=[1883],endpoints=[])
    _evaluate(tmp_path,[v],[gt],tests=[_confirmed(v,'mqtt_listen')],records=[record()])
    metadata={'metric_contract_version':'strict-v3.8','evidence_contract_version':'evidence-v6'}
    (tmp_path/'run_meta.json').write_text(json.dumps(metadata))
    result=evaluate(tmp_path,tmp_path/'truth.yaml',policy='strict-v3')
    assert result.funnel['stages']['confirmed']['available'] is False
    assert json.loads((tmp_path/'run_meta.json').read_text())==metadata


def _http_requirement(url='http://192.0.2.1:9002/mqtt?tenant=A', **extra):
    return {'tool': 'http_request', 'target': '192.0.2.1', 'port': 9002,
            'endpoint': '/mqtt?tenant=A',
            'args_hint': {'url': url, 'method': 'GET',
                          'headers': {'Connection': 'Upgrade', 'Upgrade': 'websocket'}}, **extra}


@pytest.mark.parametrize('url', [
    'http://evil.example:9002/192.0.2.1/mqtt?tenant=A',
    'http://evil.example:9002/mqtt?tenant=A&target=192.0.2.1',
    'https://192.0.2.1:9002/mqtt?tenant=A',
    'http://192.0.2.1:9003/mqtt?tenant=A',
    'http://192.0.2.1:9002/MQTT?tenant=A',
    'http://192.0.2.1:9002/mqtt?tenant=B',
])
def test_phase4_http_requirement_rejects_url_near_misses(url):
    req = _http_requirement()
    assert not _phase4_requirement_matches(req, 'http_request', {'url': url, 'method': 'GET',
        'headers': {'Connection': 'Upgrade', 'Upgrade': 'websocket'}})


@pytest.mark.parametrize('url', [
    'http://192.0.2.1:invalid/mqtt?tenant=A',
    'http://[192.0.2.1:9002/mqtt?tenant=A',
    'http:///mqtt?tenant=A',
    '192.0.2.1:9002/mqtt?tenant=A',
])
def test_phase4_http_requirement_rejects_malformed_urls(url):
    req = _http_requirement()
    assert not _phase4_requirement_matches(req, 'http_request', {'url': url, 'method': 'GET',
        'headers': {'Connection': 'Upgrade', 'Upgrade': 'websocket'}})


def test_phase4_http_requirement_without_hint_url_checks_requirement_fields():
    req = _http_requirement()
    req['args_hint'].pop('url')
    good = {'url': 'http://192.0.2.1:9002/mqtt?tenant=A', 'method': 'GET',
            'headers': {'Connection': 'Upgrade', 'Upgrade': 'websocket'}}
    assert _phase4_requirement_matches(req, 'http_request', good)
    assert not _phase4_requirement_matches(req, 'http_request', {**good, 'url': 'http://192.0.2.1:9002/admin'})


@pytest.mark.parametrize('headers', [
    {}, {'Connection': 'Upgrade'}, {'Connection': 'keep-alive', 'Upgrade': 'websocket'},
])
def test_phase4_http_requirement_checks_explicit_websocket_headers_on_custom_port(headers):
    req = _http_requirement()
    assert not _phase4_requirement_matches(req, 'http_request', {'url': req['args_hint']['url'],
        'method': 'GET', 'headers': headers})


def test_phase4_http_requirement_accepts_header_name_case_variation():
    req = _http_requirement()
    assert _phase4_requirement_matches(req, 'http_request', {'url': req['args_hint']['url'], 'method': 'GET',
        'headers': {'connection': 'Upgrade', 'UPGRADE': 'websocket'}})


@pytest.mark.parametrize('kind', ['weak_cipher', 'weak_crypto', 'known_cve'])
def test_ssh_crypto_placeholders_use_canonical_type_names(kind):
    vuln = finding('ssh', type=kind, tool_used='ssh_audit')
    call = {**record('ssh_login'), 'tool':'ssh_audit',
            'args':{'host':'192.0.2.1', 'port':22}}
    assert _tool_call_matches_finding(vuln, call)


@pytest.mark.parametrize('content', ['{invalid', 'null', '[]', '"just a memo"'])
def test_model_file_format_cannot_change_observed_verdict(tmp_path, content):
    path = tmp_path/'missing_header_VULN-001.json'
    path.write_text(content)
    assert resolve(path, [header_record()])['status'] == 'CONFIRMED'
    absent = resolve(path, [])
    assert absent['status'] == 'ERROR'
    assert absent['evidence_level'] == 0


def test_another_finding_file_cannot_donate_proof(tmp_path):
    other = tmp_path/'missing_header_VULN-999.json'
    other.write_text(json.dumps({'status':'CONFIRMED', 'evidence_level':99,
                                 'evidence':'A model-only claim'}))
    missing = tmp_path/'missing_header_VULN-001.json'
    assert resolve(missing, [])['status'] == 'ERROR'
    assert resolve(missing, [header_record()])['status'] == 'CONFIRMED'


@pytest.mark.parametrize('port,endpoint', [
    (9001, ''), (9001, '/'), (9001, '/mqtt?tenant=A'), (9002, '/mqtt?tenant=A'),
])
def test_websocket_plan_and_proof_share_the_same_endpoint(port, endpoint):
    from src.agent.exploit_evidence import synthesize_exploit_result
    from src.agent.phases.verification.contract import (
        _phase4_requirement_matches, _phase4_verification_plan,
    )

    vuln = ws(port=port, endpoint=endpoint, tool_used='http_request',
              evidence_refs=['proof-V1'])
    plan = _phase4_verification_plan(vuln)
    assert plan['args_hint']['url'] == f'http://192.0.2.1:{port}{endpoint or "/"}'
    assert _phase4_requirement_matches(plan, 'http_request', plan['args_hint'])
    call = {**record(), 'tool':'http_request', 'args':plan['args_hint'],
            'result':{'status_code':101, 'body':'Switching Protocols'}}
    assert _tool_call_matches_finding(vuln, call)
    assert synthesize_exploit_result(vuln, [call])['status'] == 'EXPLOITED'
    wrong = {**call, 'args':{**call['args'], 'url':f'http://192.0.2.1:{port}/admin'}}
    assert not _phase4_requirement_matches(plan, 'http_request', wrong['args'])
    assert not _tool_call_matches_finding(vuln, wrong)
    assert synthesize_exploit_result(vuln, [wrong])['status'] != 'EXPLOITED'
