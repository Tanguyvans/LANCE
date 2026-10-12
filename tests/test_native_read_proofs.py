"""Native protocol proof boundaries; simulated records only, no probes."""
import copy
import pytest
from src.agent.exploit_evidence import synthesize_exploit_result
from src.agent.evidence.native import claim_paths, ftp_request_matches, redis_read_supported, snmp_public_read_supported
from src.benchmark.evaluator import _assign_evidence_refs, _matching_tool_calls, _tool_call_outcome


def finding(service, kind, port, endpoint='/'):
    return {'id': 'V-NATIVE', 'device_ip': '192.0.2.10', 'service': service,
            'port': port, 'type': kind, 'endpoint': endpoint, 'tools_used': [], 'evidence_refs': ['tc-native']}


def proof(f, tool, args, result):
    return synthesize_exploit_result(f, [{'tool': tool, 'args': args, 'result': result, 'evidence_ref': 'tc-native'}])


def tlv(tag, value):
    return bytes([tag, len(value)]) + value


def snmp(pdu=0xA2, value_tag=4, value=b'fixture system', community=b'public', request_id=b'\x01', oid=b'\x2b\x06\x01\x02\x01\x01\x01\x00', error=b'\x00'):
    pair = tlv(0x30, tlv(6, oid) + tlv(value_tag, value))
    fields = tlv(2, request_id) + tlv(2, error) + tlv(2, b'\x00') + tlv(0x30, pair)
    return tlv(0x30, tlv(2, b'\x00') + tlv(4, community) + tlv(pdu, fields))


def snmp_record():
    args = {'host': '192.0.2.10', 'port': 161, 'encoding': 'hex', 'payload': snmp(0xA0, 5, b'').hex()}
    response = snmp()
    return args, {'received_hex': response.hex(), 'received_bytes': len(response)}


def test_snmp_public_read_is_correlated_and_explicitly_read_only():
    f = finding('snmp', 'default_credentials', 161)
    f['details'] = 'private community permits read/write and device configuration'
    args, result = snmp_record()
    assert snmp_public_read_supported(args, result, f)
    p = proof(f, 'udp_send', args, result)
    assert p['status'] == 'EXPLOITED'
    assert 'no private community or write' in p['description']
    assert 'read only' in p['evidence'] and 'no private community or write' in p['evidence']


@pytest.mark.parametrize('field,value', [('host', '192.0.2.11'), ('port', 162), ('port', True), ('encoding', 'ascii'), ('payload', '3020')])
def test_snmp_wrong_request_is_not_proof(field, value):
    args, result = snmp_record(); args[field] = value
    assert not snmp_public_read_supported(args, result, finding('snmp', 'default_credentials', 161))


@pytest.mark.parametrize('response', [
    b'ACK', b'\x30\x80', snmp(community=b'private'), snmp(request_id=b'\x02'),
    snmp(oid=b'\x2b\x06\x01\x02\x01\x01\x02\x00'), snmp(error=b'\x01'),
    snmp(value_tag=0x80, value=b''), snmp(value_tag=5, value=b''), snmp(pdu=0xA3),
])
def test_snmp_arbitrary_datagram_private_error_and_set_are_not_public_read(response):
    args, _ = snmp_record()
    result = {'received_hex': response.hex(), 'received_bytes': len(response)}
    assert not snmp_public_read_supported(args, result, finding('snmp', 'default_credentials', 161))


@pytest.mark.parametrize('change', [{'timed_out': True}, {'error': 'timeout'}, {'received_bytes': 999}, {'peer': '192.0.2.11:161'}, {'return_code': 1}])
def test_snmp_failed_transport_is_not_proof(change):
    args, result = snmp_record(); result.update(change)
    assert not snmp_public_read_supported(args, result, finding('snmp', 'default_credentials', 161))


def test_redis_get_and_ping_use_native_resource_not_http_root():
    for kind, command, output in [('data_exposure', 'GET db_password', 'fixture-password'), ('no_auth', 'PING', 'PONG')]:
        f = finding('redis', kind, 6379); f['tools_used'] = ['redis_cmd']
        args = {'host': f['device_ip'], 'command': command}
        record = {'tool': 'redis_cmd', 'args': args, 'result': {'return_code': 0, 'stdout': output}, '_evidence_ref': 'tc-native', 'vuln_id': f['id']}
        _assign_evidence_refs([f], [record])
        assert _matching_tool_calls(f, [record]) == [record]
        assert _tool_call_outcome(record, f) is True
        assert proof(f, 'redis_cmd', args, record['result'])['status'] == 'EXPLOITED'


@pytest.mark.parametrize('command,output', [('SET key value', 'OK'), ('AUTH password', 'OK'), ('PING', 'password=value'), ('GET db_password', 'NOAUTH Authentication required.'), ('GET db_password', '(error) ERR unknown'), ('GET db_password', '(nil)'), ('GET db_password', '')])
def test_redis_zero_exit_is_not_a_sensitive_read(command, output):
    f = finding('redis', 'data_exposure', 6379)
    p = proof(f, 'redis_cmd', {'host': f['device_ip'], 'command': command}, {'return_code': 0, 'stdout': output})
    assert p['status'] != 'EXPLOITED'


@pytest.mark.parametrize('change', [{'host': '192.0.2.11'}, {'port': 6380}, {'password': 'fixture'}, {'user': 'admin'}])
def test_redis_other_target_or_authentication_does_not_prove_unauthenticated_read(change):
    args = {'host': '192.0.2.10', 'command': 'PING'}; args.update(change)
    assert not redis_read_supported(args, {'return_code': 0, 'stdout': 'PONG'}, finding('redis', 'no_auth', 6379))


def test_ftp_composite_directory_scope_binds_file_content_and_own_ref():
    f = finding('ftp', 'data_exposure', 21, '/backup/, /config/, /firmware/'); f['tools_used'] = ['ftp_list']
    args = {'url': 'ftp://192.0.2.10/config/network.conf'}
    result = {'return_code': 0, 'stdout': 'db_password=fixture-secret'}
    record = {'tool': 'ftp_list', 'args': args, 'result': result, '_evidence_ref': 'tc-native', 'vuln_id': f['id']}
    _assign_evidence_refs([f], [record])
    assert _matching_tool_calls(f, [record]) == [record]
    assert _tool_call_outcome(record, f) is True
    wrong = {**record, '_evidence_ref': 'other-proof'}
    assert not _matching_tool_calls(f, [wrong])


@pytest.mark.parametrize('url', ['ftp://192.0.2.11/config/network.conf', 'ftp://192.0.2.10:2121/config/network.conf', 'http://192.0.2.10/config/network.conf', 'ftp://admin:password@192.0.2.10/config/network.conf', 'ftp://192.0.2.10/other/network.conf', 'ftp://192.0.2.10/configuration/network.conf', 'ftp://192.0.2.10/config/../outside', 'ftp://192.0.2.10/config/%2e%2e/outside'])
def test_ftp_proof_cannot_escape_claim_resource_or_anonymous_destination(url):
    f = finding('ftp', 'data_exposure', 21, '/config/')
    assert not ftp_request_matches({'url': url}, f)
    assert proof(f, 'ftp_list', {'url': url}, {'return_code': 0, 'stdout': 'db_password=fixture-secret'})['status'] != 'EXPLOITED'


def test_ftp_listing_proves_names_without_claiming_file_content():
    f = finding('ftp', 'data_exposure', 21, '/backup/')
    p = proof(f, 'ftp_list', {'url': 'ftp://192.0.2.10/backup/'}, {'return_code': 0, 'stdout': '-rw-r--r-- db_dump.sql'})
    assert p['status'] == 'EXPLOITED' and p['evidence_level'] == 2
    assert 'not file contents' in p['evidence']


def test_path_list_parser_preserves_query_commas_and_case():
    assert claim_paths({'endpoint': '/backup/, /Config/'}) == {'/backup/', '/Config/'}
    assert claim_paths({'endpoint': '/search?q=a, /b'}) == {'/search?q=a, /b'}


def test_native_placeholder_exemptions_do_not_bind_http_other_resources_or_ref_reuse():
    f = finding('http', 'data_exposure', 80); f['tools_used'] = ['http_get']
    record = {'tool': 'http_get', 'args': {'url': 'http://192.0.2.10/config'}, '_evidence_ref': 'tc-native'}
    _assign_evidence_refs([f], [record]); assert not _matching_tool_calls(f, [record])
    redis = finding('redis', 'no_auth', 6379); redis['tools_used'] = ['redis_cmd']
    record = {'tool': 'redis_cmd', 'args': {'host': redis['device_ip'], 'command': 'PING'}, '_evidence_ref': 'tc-native'}
    duplicate = copy.deepcopy(redis)
    assert _assign_evidence_refs([redis, duplicate], [record]) == 1
    assert not _matching_tool_calls(redis, [record])


@pytest.mark.parametrize('port', [True, False, 6379.5, 'wrong'])
def test_malformed_claim_port_cannot_become_native_default(port):
    f = finding('redis', 'no_auth', port)
    assert not redis_read_supported({'host': '192.0.2.10', 'command': 'PING'}, {'return_code': 0, 'stdout': 'PONG'}, f)
