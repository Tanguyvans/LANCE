"""Bind native read proofs to executed resources; never execute a probe."""
from __future__ import annotations

import re
import shlex
from urllib.parse import urlsplit
from src.agent.evidence.records import has_authentication


def claim_paths(finding: dict) -> set[str]:
    """Parse explicit path lists only; preserve commas inside URL queries."""
    raw = finding.get('endpoint') or finding.get('endpoints') or []
    values = raw if isinstance(raw, (list, tuple)) else [raw]
    paths: set[str] = set()
    for value in values:
        text = str(value or '').strip()
        parts = re.split(r',\s+(?=/)', text) if '?' not in text and '://' not in text else [text]
        for part in parts:
            parsed = urlsplit(part)
            path = parsed.path or ('/' if parsed.scheme else '')
            if parsed.query:
                path += '?' + parsed.query
            if path:
                paths.add(path)
    return paths


def _destination(args: dict, finding: dict, default_port: int) -> bool:
    try:
        actual = args.get('port', default_port)
        expected = finding.get('port')
        expected = default_port if expected in (None, '') else expected
        return (isinstance(actual, (int, str)) and isinstance(expected, (int, str))
                and not isinstance(actual, bool) and not isinstance(expected, bool)
                and int(actual) == int(expected)
                and (not finding.get('device_ip') or args.get('host') == finding['device_ip']))
    except (TypeError, ValueError):
        return False


def ftp_request_matches(args: dict, finding: dict) -> bool:
    """Require the same anonymous FTP destination and explicit resource scope."""
    if finding.get('service') not in {None, '', 'ftp'} or has_authentication(args) or args.get('user') or args.get('username'):
        return False
    try:
        url = urlsplit(str(args.get('url') or ''))
        expected = finding.get('port')
        expected = 21 if expected in (None, '') else expected
        if (url.scheme != 'ftp' or not url.hostname or url.username or url.password
                or url.query or url.fragment or not isinstance(expected, (int, str)) or isinstance(expected, bool)
                or (url.port or 21) != int(expected)
                or (finding.get('device_ip') and url.hostname != finding['device_ip'])):
            return False
    except (TypeError, ValueError):
        return False
    path = url.path or '/'
    # Reject path traversal rather than interpreting it as a child resource.
    if any(part in {'.', '..'} for part in path.split('/')) or '%' in path:
        return False
    scopes = claim_paths(finding)
    return not scopes or any(path == scope or (scope.endswith('/') and path.startswith(scope)) for scope in scopes)


def redis_read_supported(args: dict, result: dict, finding: dict) -> bool:
    """A successful read response is separate from a CLI return code of zero."""
    if not _destination(args, finding, 6379) or has_authentication(args) or args.get('user') or args.get('username'):
        return False
    if isinstance(result.get('return_code'), bool) or result.get('return_code') != 0 or result.get('error') or result.get('timed_out'):
        return False
    try:
        command = shlex.split(str(args.get('command') or ''))
    except ValueError:
        return False
    if not command:
        return False
    name = command[0].upper()
    allowed = name == 'PING' and len(command) == 1 or name in {'GET', 'KEYS'} and len(command) == 2
    if not allowed:
        return False
    output = str(result.get('stdout') or '').strip()
    if not output or re.search(r'(?im)^\s*(?:\(error\)|-?(?:ERR|NOAUTH|WRONGPASS|NOPERM)\b)', output):
        return False
    if finding.get('type') == 'data_exposure':
        return name == 'GET' and output.casefold() not in {'(nil)', 'nil', '$-1', 'null', '(empty array)', '(empty list or set)', 'redacted', '[redacted]', 'masked'}
    return name != 'PING' or output.upper() in {'PONG', '+PONG'}


def _tlv(data: bytes, pos: int = 0) -> tuple[int, bytes, int]:
    if pos + 2 > len(data):
        raise ValueError('truncated BER')
    tag, length = data[pos:pos+2]; pos += 2
    if length & 128:
        count = length & 127
        if count not in {1, 2} or pos + count > len(data):
            raise ValueError('unsupported BER length')
        length = int.from_bytes(data[pos:pos+count], 'big'); pos += count
    end = pos + length
    if end > len(data):
        raise ValueError('truncated BER value')
    return tag, data[pos:end], end


def _fields(data: bytes) -> list[tuple[int, bytes]]:
    fields = []
    pos = 0
    while pos < len(data):
        tag, value, pos = _tlv(data, pos)
        fields.append((tag, value))
    return fields


def _snmp_message(data: bytes, pdu_tag: int) -> tuple[bytes, bytes, bytes, list[tuple[bytes, int, bytes]]]:
    tag, payload, end = _tlv(data)
    if tag != 0x30 or end != len(data):
        raise ValueError('invalid SNMP envelope')
    outer = _fields(payload)
    if (len(outer) != 3 or outer[0][0] != 2 or outer[0][1] not in {b'\x00', b'\x01'}
            or outer[1] != (4, b'public') or outer[2][0] != pdu_tag):
        raise ValueError('not a public SNMP v1/v2 read exchange')
    pdu = _fields(outer[2][1])
    if (len(pdu) != 4 or any(tag != 2 or not value or len(value) > 4 for tag, value in pdu[:3])
            or int.from_bytes(pdu[1][1], 'big') != 0 or int.from_bytes(pdu[2][1], 'big') != 0
            or pdu[3][0] != 0x30):
        raise ValueError('invalid/error SNMP PDU')
    bindings = []
    for tag, value in _fields(pdu[3][1]):
        pair = _fields(value)
        if tag != 0x30 or len(pair) != 2 or pair[0][0] != 6 or not pair[0][1]:
            raise ValueError('invalid SNMP varbind')
        bindings.append((pair[0][1], pair[1][0], pair[1][1]))
    if not bindings:
        raise ValueError('no SNMP values')
    return outer[0][1], outer[1][1], pdu[0][1], bindings


def snmp_public_read_supported(args: dict, result: dict, finding: dict) -> bool:
    """Require a correlated public GET response with returned OIDs, never SET."""
    if (finding.get('service') not in {None, '', 'snmp'} or not _destination(args, finding, 161)
            or args.get('encoding') != 'hex' or result.get('error') or result.get('timed_out')
            or result.get('return_code') not in (None, 0)
            or result.get('peer') not in (None, f"{args.get('host')}:{args.get('port', 161)}")):
        return False
    try:
        request = bytes.fromhex(str(args.get('payload') or ''))
        response = bytes.fromhex(str(result.get('received_hex') or ''))
        if result.get('received_bytes') != len(response) or not response or max(len(request), len(response)) > 65535:
            return False
        req = _snmp_message(request, 0xA0)
        reply = _snmp_message(response, 0xA2)
        return (req[:3] == reply[:3] and [v[0] for v in req[3]] == [v[0] for v in reply[3]]
                and all(tag == 5 and not value for _, tag, value in req[3])
                and all(tag in {2, 4, 6, 0x40, 0x41, 0x42, 0x43, 0x46} and value for _, tag, value in reply[3]))
    except (ValueError, TypeError):
        return False
