"""Verification requirements and bounded tool routing; full keeps autonomous tool choice."""
from __future__ import annotations
import json
import re
from urllib.parse import urlsplit
from src.agent.core.probes import (
    _COAP_GET_CORE_HEX,
    _ENIP_LIST_IDENTITY_HEX,
    _S7COMM_COTP_CR_HEX,
    _SNMP_V1_GET_SYS_DESCR_HEX,
)
from src.agent.vuln_taxonomy import canonicalize
from src.agent.exploit_evidence import (
    _is_mqtt_websocket_service,
    synthesize_exploit_result as _synthesize_exploit_result,
)
from src.agent.evidence.records import has_authentication
from src.agent.evidence.mqtt import normalize_mqtt_port
from src.agent.evidence.mqtt_ws import mqtt_ws_claim_path, mqtt_ws_claim_topic


# Full receives the same verification requirement as guidance but keeps its
# complete phase tool surface and autonomous verification sequence.
COMPACT_PHASE4_DEFAULT_MAX_WORKERS = 2


PHASE4_LOCAL_COMMON_TOOL_NAMES = frozenset({
    "decode_value", "list_skills", "load_skill", "search_knowledge",
})


PHASE4_LOCAL_CATEGORY_TOOL_NAMES = {
    "credentials": frozenset({
        "try_credential", "ssh_login", "mqtt_listen", "mysql_query",
        "redis_cmd", "ftp_list", "nmap_scan", "telnet_connect",
    }),
    "data_access": frozenset({
        "http_get", "http_request", "curl_headers", "mqtt_listen",
        "mqtt_ws_listen",
        "mysql_query", "redis_cmd", "ftp_list", "telnet_connect",
        "nmap_scan", "tcp_send", "udp_send",
    }),
    "injection": frozenset({
        "http_get", "http_request", "curl_headers",
        "tcp_send", "udp_send",
    }),
}


PHASE4_LOCAL_SERVICE_TOOL_NAMES = {
    "ssh": frozenset({"ssh_login", "try_credential", "ssh_audit", "nmap_scan"}),
    "mqtt": frozenset({"mqtt_listen", "try_credential", "nmap_scan"}),
    # Both paths remain available to the scope guard: the requirement
    # selects mqtt_ws_listen for application claims and http_request for the
    # historical network_exposure/HTTP-101 transport claim.
    "mqtt-ws": frozenset({"mqtt_ws_listen", "http_request", "http_get", "curl_headers"}),
    "mqtt_websocket": frozenset({"mqtt_ws_listen", "http_request", "http_get", "curl_headers"}),
    "mqtt-websocket": frozenset({"mqtt_ws_listen", "http_request", "http_get", "curl_headers"}),
    "mqttws": frozenset({"mqtt_ws_listen", "http_request", "http_get", "curl_headers"}),
    "websocket": frozenset({"mqtt_ws_listen", "http_request", "http_get", "curl_headers"}),
    "ws": frozenset({"mqtt_ws_listen", "http_request", "http_get", "curl_headers"}),
    "http": frozenset({"http_get", "http_request", "curl_headers"}),
    "https": frozenset({"http_get", "http_request", "curl_headers", "mtls_request"}),
    "telnet": frozenset({"telnet_connect", "try_credential", "nmap_scan"}),
    "mysql": frozenset({"mysql_query", "nmap_scan"}),
    "mariadb": frozenset({"mysql_query", "nmap_scan"}),
    "redis": frozenset({"redis_cmd", "nmap_scan"}),
    "ftp": frozenset({"ftp_list", "try_credential", "nmap_scan"}),
    "snmp": frozenset({"nmap_scan", "udp_send"}),
    "coap": frozenset({"nmap_scan", "udp_send"}),
    "s7comm": frozenset({"tcp_send", "nmap_scan"}),
    "enip": frozenset({"tcp_send", "nmap_scan"}),
    "ethernet/ip": frozenset({"tcp_send", "nmap_scan"}),
    "modbus": frozenset({"modbus_scan", "nmap_scan"}),
    "opcua": frozenset({"tcp_send", "nmap_scan"}),
    "bacnet": frozenset({"udp_send", "nmap_scan"}),
}


def _phase4_local_verification_tools(
    tools: list[dict], *, category: str, service: str,
    include_deliverable: bool = False
) -> list[dict]:
    """Narrow Phase 4 tools to the tested vulnerability family."""
    allowed = set(PHASE4_LOCAL_COMMON_TOOL_NAMES)
    service_allowed = PHASE4_LOCAL_SERVICE_TOOL_NAMES.get(
        str(service or "").casefold(), frozenset()
    )
    if service_allowed:
        allowed.update(service_allowed)
    else:
        allowed.update(PHASE4_LOCAL_CATEGORY_TOOL_NAMES.get(category, frozenset()))
    if include_deliverable:
        allowed.add("save_deliverable")
    return [tool for tool in tools if tool.get("name") in allowed]


def _normalise_phase4_endpoint(value: object) -> str:
    """Return a safe path for a deterministic Phase 4 HTTP probe.

    Device memos are model-authored and occasionally leave Markdown or prose
    punctuation attached to a path (for example ``/uploads/:``). Passing that
    value verbatim turns a valid finding into a guaranteed 404. Keep query
    strings intact, but remove only terminal prose punctuation.
    """
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.startswith(("http://", "https://")):
        parsed = urlsplit(raw)
        raw = parsed.path or "/"
        if parsed.query:
            raw = f"{raw}?{parsed.query}"
    raw = raw.strip().strip("`'\".,;)]}")
    if "?" not in raw and raw.endswith(":"):
        raw = raw[:-1]
    if raw and not raw.startswith("/"):
        raw = f"/{raw}"
    return raw or "/"


def _phase4_http_target(vuln: dict) -> tuple[str, int]:
    """Share the declared HTTP origin between probe plans and model guidance.

    The service determines the scheme, not the port: HTTP on 443 must not
    become HTTPS, and HTTPS on 80 must not become plaintext HTTP.
    """
    scheme = "https" if str(vuln.get("service") or "").strip().casefold() == "https" else "http"
    default_port = 443 if scheme == "https" else 80
    try:
        port = int(vuln.get("port")) or default_port
    except (TypeError, ValueError):
        port = default_port
    host = str(vuln.get("device_ip") or "").strip()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    authority = host if port == default_port else f"{host}:{port}"
    return f"{scheme}://{authority}", port


def _phase4_verification_plan(
    vuln: dict, *, compact: bool = False
) -> dict[str, object]:
    """Return the minimum fresh verification required for one finding."""
    vuln_type = canonicalize(str(vuln.get("type") or "").casefold())
    service = str(vuln.get("service") or "").strip().casefold()
    ip = str(vuln.get("device_ip") or "")
    port = vuln.get("port")
    try:
        port = int(port) if port not in (None, "") else None
    except (TypeError, ValueError):
        port = None
    endpoint = _normalise_phase4_endpoint(vuln.get("endpoint"))
    base_url, http_port = _phase4_http_target(vuln)
    suffix = endpoint if endpoint.startswith("/") else (f"/{endpoint}" if endpoint else "/")
    url = f"{base_url}{suffix}"

    # HTTP 101 remains the narrow, historical transport-only proof for a
    # network_exposure finding. Keep query-bearing HTTP paths intact here;
    # MQTT application claims use the dedicated paho exchange below.
    if _is_mqtt_websocket_service(service) and vuln_type == "network_exposure":
        ws_port = port or 9001
        return {"tool": "http_request", "target": ip, "port": ws_port,
                "endpoint": endpoint or "/",
                "args_hint": {"url": f"http://{ip}:{ws_port}{suffix}", "method": "GET",
                    "headers": {"Connection": "Upgrade", "Upgrade": "websocket",
                        "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="}},
                "success_condition": (
                    "Observed HTTP 101 WebSocket handshake proves only "
                    "network_exposure; it cannot prove MQTT authentication, "
                    "data exposure, or application access"
                )}

    if _is_mqtt_websocket_service(service):
        raw_port = vuln.get("port")
        ws_port = 9001 if raw_port in (None, "") else normalize_mqtt_port(raw_port)
        ws_path = mqtt_ws_claim_path(vuln)
        ws_topic = mqtt_ws_claim_topic(vuln)
        raw_path = vuln.get("path") if vuln.get("path") not in (None, "") else vuln.get("endpoint")
        plan = {"tool": "mqtt_ws_listen", "target": ip, "port": ws_port,
                # Preserve an invalid claim for diagnostics; never silently
                # turn '/mqtt?tenant=A' into '/mqtt'.
                "endpoint": ws_path if ws_path is not None else raw_path,
                "path": ws_path, "topic": ws_topic,
                "args_hint": {"ip": ip, "port": ws_port, "path": ws_path,
                    "topic": ws_topic, "count": 1, "timeout": 8},
                "success_condition": (
                    "Real MQTTv311 CONNECT/CONNACK and SUBSCRIBE/SUBACK over the "
                    "exact WebSocket path, followed by at least one matching "
                    "received PUBLISH. This anonymous read-only probe does not "
                    "test credentials or grant access/pivot credit."
                )}
        if ws_port is None or ws_path is None or ws_topic is None:
            plan["plan_error"] = (
                "MQTT WebSocket application verification requires a valid port, "
                "one exact HTTP path without a query/fragment/URL, and one "
                "unambiguous MQTT topic filter; the finding claim is not probeable"
            )
        return plan
    if vuln_type == "misconfiguration" and (service == "coap" or port == 5683):
        return {
            "tool": "udp_send", "target": ip, "port": 5683,
            "required_payload": _COAP_GET_CORE_HEX,
            "args_hint": {
                "host": ip, "port": 5683,
                "payload": _COAP_GET_CORE_HEX,
                "encoding": "hex", "recv_bytes": 4096, "timeout": 5,
            },
            "success_condition": "CoAP responds without a DTLS/authentication boundary",
        }
    if vuln_type == "missing_header":
        required_headers = sorted(set(re.findall(
            r"(?i)\b(?:x-frame-options|strict-transport-security|content-security-policy)\b",
            str(vuln.get("details") or ""),
        ))) or ["x-frame-options", "strict-transport-security", "content-security-policy"]
        return {"tool": "curl_headers", "target": ip, "port": http_port,
                "args_hint": {"url": url}, "required_headers": required_headers,
                "success_condition": "all required security headers are absent"}
    if vuln_type == "insecure_update" and service in {"http", "https"}:
        return {
            "tool": "http_request", "target": ip, "port": http_port,
            "endpoint": endpoint,
            "args_hint": {
                "url": url, "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": '{"version":"phase4-probe","firmware":"LANCE_PHASE4_PROBE","signature":""}',
                "follow_redirects": False, "verify_tls": False,
            },
            "require_body": True,
            "success_condition": "unsigned firmware upload accepted without an integrity check",
        }
    if vuln_type == "code_injection" and service in {"http", "https"}:
        return {
            "tool": "http_request", "target": ip, "port": http_port,
            "endpoint": endpoint,
            "args_hint": {
                "url": url, "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": '{"cmd":"id","command":"id"}',
                "follow_redirects": False, "verify_tls": False,
            },
            "require_body": True,
            "success_condition": "HTTP response contains command execution proof",
        }
    if vuln_type in {"directory_listing", "data_exposure", "code_injection", "no_auth", "broken_access_control"} and service in {"http", "https"}:
        return {"tool": "http_get", "target": ip, "port": http_port, "endpoint": endpoint,
                "args_hint": {"url": url}, "success_condition": "affected HTTP endpoint fetched"}
    if vuln_type == "data_exposure" and (service == "ftp" or port == 21):
        ftp_suffix = endpoint if endpoint.startswith("/") else (f"/{endpoint}" if endpoint else "/")
        return {
            "tool": "ftp_list", "target": ip, "port": port or 21,
            "args_hint": {"url": f"ftp://{ip}:{port or 21}{ftp_suffix}"},
            "success_condition": "anonymous FTP listing exposes sensitive entries",
        }
    if vuln_type in {"info_disclosure", "version_leak"}:
        if service in {"ssh", "telnet"} or port == 22:
            return {"tool": "ssh_audit", "target": ip, "port": port or 22,
                    "args_hint": {"host": ip, "port": port or 22}, "success_condition": "SSH banner or audit output captured"}
        if service == "mqtt" or port in {1883, 8883}:
            return {"tool": "mqtt_listen", "target": ip, "port": port or 1883,
                    "args_hint": {"broker": ip, "topic": "$SYS/#", "count": 5, "timeout": 5}, "success_condition": "$SYS metrics or broker version captured"}
        return {"tool": "curl_headers", "target": ip, "port": http_port,
                "args_hint": {"url": url}, "success_condition": "disclosing headers captured"}
    if vuln_type in {"weak_cipher", "terrapin", "known_cve"}:
        if service == "ssh" or port == 22:
            return {"tool": "ssh_audit", "target": ip, "port": port or 22,
                    "args_hint": {"host": ip, "port": port or 22}, "success_condition": (
                        "For weak_cipher, capture exact server-offered algorithm lines and a violation "
                        "of the versioned SSH policy. Generic warn/fail labels, NIST-curve suspicions "
                        "and HMAC-SHA1 alone are not proof. Configuration does not prove exploitation. "
                        "For CVEs require a specific positive verdict; strict-KEX support or a "
                        "conditional warning is not a Terrapin exploit."
                    )}
        if service in {"https", "tls", "mqtts"} or port in {443, 8443, 8883}:
            return {"tool": "tls_inspect", "target": ip, "port": port or 443,
                    "args_hint": {"host": ip, "port": port or 443}, "success_condition": "TLS algorithms captured"}
        return {"tool": "nmap_scan", "target": ip, "port": port,
                "args_hint": {"target": ip, "ports": str(port or "-"), "skip_discovery": True}, "success_condition": "service/version evidence captured"}
    if vuln_type == "insecure_protocol":
        if service == "telnet" or port == 23:
            return {"tool": "telnet_connect", "target": ip, "port": 23,
                    "args_hint": {"host": ip, "port": 23, "timeout": 3}, "success_condition": "Telnet interaction returns bytes after the fixed identity probe"}
        if service == "ftp" or port == 21:
            return {"tool": "ftp_list", "target": ip, "port": 21,
                    "args_hint": {"url": f"ftp://{ip}/"}, "success_condition": "FTP listing or anonymous response captured"}
        if service == "mqtt" or port == 1883:
            return {"tool": "mqtt_listen", "target": ip, "port": port or 1883,
                    "args_hint": {"broker": ip, "topic": "$SYS/#", "count": 5, "timeout": 5},
                    "success_condition": "plaintext MQTT broker response captured on port 1883"}
    if vuln_type == "no_auth":
        if service == "mqtt" or port in {1883, 8883}:
            return {"tool": "mqtt_listen", "target": ip, "port": port or 1883,
                    "args_hint": {"broker": ip, "topic": "#", "count": 10, "timeout": 8}, "success_condition": "anonymous MQTT connection result captured"}
        if service == "coap" or port == 5683:
            return {
                "tool": "udp_send", "target": ip, "port": 5683,
                "required_payload": _COAP_GET_CORE_HEX,
                "args_hint": {
                    "host": ip, "port": 5683,
                    "payload": _COAP_GET_CORE_HEX,
                    "encoding": "hex", "recv_bytes": 4096, "timeout": 5,
                },
                "success_condition": "CoAP response received over unauthenticated UDP",
            }
        if service == "modbus" or port == 502:
            return {"tool": "nmap_scan", "target": ip, "port": port or 502,
                    "required_port": port or 502, "required_scripts": "modbus-discover",
                    "args_hint": {"target": ip, "ports": str(port or 502),
                                  "scripts": "modbus-discover", "skip_discovery": True},
                    "success_condition": (
                        "The claimed host/port returns actual Slave ID data or Device "
                        "identification inside a modbus-discover SID block. An open "
                        "port, script name, SID alone or error does not prove no_auth. "
                        "Identification is not register read/write or machine compromise."
                    )}
        if compact and port in {102, 44818}:
            payload = _S7COMM_COTP_CR_HEX if port == 102 else _ENIP_LIST_IDENTITY_HEX
            return {
                "tool": "tcp_send", "target": ip, "port": port,
                "required_payload": payload,
                "args_hint": {
                    "host": ip, "port": port, "payload_hex": payload,
                    "recv_bytes": 4096, "timeout": 5,
                },
                "success_condition": "unauthenticated protocol negotiation or identity response",
            }
        if service in {"http", "https"}:
            return {"tool": "http_get", "target": ip, "port": http_port, "endpoint": endpoint,
                    "args_hint": {"url": url}, "success_condition": "unauthenticated endpoint fetched"}
    if vuln_type in {"default_credentials", "privilege_escalation"}:
        if service == "mqtt" or port in {1883, 8883}:
            return {
                "tool": "mqtt_listen", "target": ip, "port": port or 1883,
                "args_hint": {
                    "broker": ip, "topic": "#", "count": 5, "timeout": 5,
                    "username": "test", "password": "test",
                },
                "success_condition": "authenticated MQTT subscription with test:test",
            }
        if service == "snmp" or port == 161:
            return {
                "tool": "udp_send", "target": ip, "port": 161,
                "required_payload": _SNMP_V1_GET_SYS_DESCR_HEX,
                "args_hint": {
                    "host": ip, "port": 161,
                    "payload": _SNMP_V1_GET_SYS_DESCR_HEX,
                    "encoding": "hex", "recv_bytes": 4096, "timeout": 5,
                },
                "success_condition": "SNMP response to the public community read probe",
            }
        if service == "ssh" or port == 22:
            return {"tool": "ssh_login", "target": ip, "port": port or 22,
                    "args_hint": {"command_string": f"sshpass -p admin ssh -p {port or 22} -o StrictHostKeyChecking=no admin@{ip} 'id'"},
                    "success_condition": (
                        "Observed SSH authentication to the claimed host/port with an "
                        "explicit pair covered by ssh-weak-credentials-v1. A successful "
                        "login with arbitrary credentials proves access only, not a weak "
                        "credential or a vendor factory default."
                    )}
        if service in {"mysql", "mariadb"} or port == 3306:
            return {"tool": "mysql_query", "target": ip, "port": port or 3306,
                    "args_hint": {"host": ip, "port": port or 3306, "user": "root",
                                  "query": "SELECT USER(), CURRENT_USER();",
                                  "skip_ssl": True},
                    "success_condition": "TCP query returns root USER() and CURRENT_USER() with a fixed empty CLI password"}
        return {"tool": "try_credential", "target": ip, "port": port, "service": service or "http",
                "args_hint": {"ip": ip, "service": service or "http", "user": "admin", "password": "admin", "port": port}, "success_condition": "credential attempt result captured"}
    if vuln_type == "no_auth" and (service == "coap" or port == 5683):
        return {
            "tool": "udp_send", "target": ip, "port": 5683,
            "required_payload": _COAP_GET_CORE_HEX,
            "args_hint": {
                "host": ip, "port": 5683,
                "payload": _COAP_GET_CORE_HEX,
                "encoding": "hex", "recv_bytes": 4096, "timeout": 5,
            },
            "success_condition": "CoAP response received over unauthenticated UDP",
        }
    if service == "mqtt":
        return {"tool": "mqtt_listen", "target": ip, "port": port or 1883,
                "args_hint": {"broker": ip, "topic": "#", "count": 5, "timeout": 5}, "success_condition": "MQTT service response captured"}
    if service in {"http", "https"}:
        return {"tool": "http_get", "target": ip, "port": http_port, "endpoint": endpoint,
                "args_hint": {"url": url}, "success_condition": "HTTP response captured"}
    return {"tool": "nmap_scan", "target": ip, "port": port,
            "args_hint": {"target": ip, "ports": str(port or "-"), "skip_discovery": True}, "success_condition": "target service evidence captured"}


def _phase4_requirement_matches(requirement: dict, tool: str, args: dict) -> bool:
    """Check that a tool call is the required probe for its finding."""
    if tool != requirement.get("tool"):
        return False
    target = str(requirement.get("target") or "")
    if tool in {"ssh_audit", "nmap_scan", "modbus_scan", "mysql_query", "tcp_send", "udp_send"} and str(args.get("host") or args.get("target") or "") != target:
        return False
    if tool == "nmap_scan":
        required_port = requirement.get("required_port")
        if required_port not in (None, ""):
            requested_ports = str(args.get("ports") or "")
            if str(required_port) not in {part.strip() for part in requested_ports.split(",") if part.strip()}:
                return False
        required_scripts = str(requirement.get("required_scripts") or "").strip()
        if required_scripts and required_scripts not in str(args.get("scripts") or ""):
            return False
    if tool in {"tcp_send", "udp_send"}:
        expected_port = requirement.get("port")
        if expected_port not in (None, ""):
            try:
                if int(args.get("port")) != int(expected_port):
                    return False
            except (TypeError, ValueError):
                return False
        expected_payload = str(requirement.get("required_payload") or "").casefold()
        if expected_payload:
            payload_key = "payload_hex" if tool == "tcp_send" else "payload"
            if str(args.get(payload_key) or "").replace(" ", "").casefold() != expected_payload.replace(" ", ""):
                return False
    if tool == "mqtt_listen":
        if str(args.get("broker") or "") != target:
            return False
        hint = requirement.get("args_hint") or {}
        for key in ("username", "password"):
            if key in hint and str(args.get(key) or "") != str(hint[key]):
                return False
    if tool == "mqtt_ws_listen":
        hint = requirement.get("args_hint") or {}
        if (
            requirement.get("plan_error")
            or not isinstance(requirement.get("path"), str)
            or not isinstance(requirement.get("topic"), str)
        ):
            return False
        if set(args) - {"ip", "port", "path", "topic", "count", "timeout"}:
            return False
        for key in ("ip", "port", "path", "topic", "count", "timeout"):
            if key in hint and args.get(key) != hint[key]:
                return False
        if str(args.get("ip") or "") != target:
            return False
        if requirement.get("path") != str(args.get("path") or ""):
            return False
        if requirement.get("topic") != str(args.get("topic") or ""):
            return False
    if tool == "try_credential":
        expected_service = str(requirement.get("service") or "").casefold()
        actual_service = str(args.get("service") or "").casefold()
        if expected_service and actual_service != expected_service:
            if {expected_service, actual_service} != {"mysql", "mariadb"}:
                return False
        expected_port = requirement.get("port")
        actual_port = args.get("port")
        if expected_port not in (None, "") and actual_port not in (None, ""):
            try:
                if int(actual_port) != int(expected_port):
                    return False
            except (TypeError, ValueError):
                return False
    if tool == "mysql_query":
        hint = requirement.get("args_hint") or {}
        expected_host = str(requirement.get("target") or "")
        if expected_host and str(args.get("host") or "") != expected_host:
            return False
        expected_port = requirement.get("port")
        try:
            actual_port = args.get("port", 3306)
            if actual_port is None:
                return False
            if expected_port not in (None, "") and int(actual_port) != int(expected_port):
                return False
        except (TypeError, ValueError):
            return False
        expected_user = str(hint.get("user") or "").strip()
        if expected_user and str(args.get("user") or "").strip() != expected_user:
            return False
        if hint.get("skip_ssl") and not bool(args.get("skip_ssl")):
            return False
        if has_authentication(args):
            return False
        expected_query = str(hint.get("query") or "").strip()
        if expected_query and str(args.get("query") or "").strip() != expected_query:
            return False
    if tool in {"http_get", "curl_headers", "http_request"}:
        raw_url = str(args.get("url") or "").strip()
        hint = requirement.get("args_hint") or {}
        expected_url = str(hint.get("url") or "").strip()
        try:
            actual = urlsplit(raw_url)
            if actual.scheme.casefold() not in {"http", "https"} or not actual.hostname:
                return False
            actual_port = actual.port or (443 if actual.scheme.casefold() == "https" else 80)
            if expected_url:
                expected = urlsplit(expected_url)
                if expected.scheme.casefold() not in {"http", "https"} or not expected.hostname:
                    return False
                expected_port = expected.port or (443 if expected.scheme.casefold() == "https" else 80)
                if (actual.scheme.casefold(), actual.hostname, actual_port,
                        actual.path or "/", actual.query) != (
                        expected.scheme.casefold(), expected.hostname, expected_port,
                        expected.path or "/", expected.query):
                    return False
            else:
                expected_port = requirement.get("port")
                if target and actual.hostname != target:
                    return False
                if expected_port not in (None, "") and actual_port != int(expected_port):
                    return False
                endpoint = str(requirement.get("endpoint") or "")
                expected_path, _, expected_query = endpoint.partition("?")
                if endpoint and (actual.path or "/", actual.query) != (expected_path or "/", expected_query):
                    return False
        except (TypeError, ValueError):
            return False
        if tool == "http_request":
            expected_method = str(hint.get("method") or "").upper()
            if expected_method and str(args.get("method") or "").upper() != expected_method:
                return False
            if requirement.get("require_body") and not str(args.get("body") or "").strip():
                return False
            # Compact MQTT-WebSocket verification needs a real upgrade request;
            # accepting the URL alone lets a plain GET satisfy the required probe
            # while producing no useful Phase 4 evidence.
            expected_headers = {
                str(key).casefold(): str(value)
                for key, value in (hint.get("headers") or {}).items()
            }
            if expected_headers:
                supplied_headers_value = args.get("headers")
                if not isinstance(supplied_headers_value, dict):
                    return False
                supplied_headers = {
                    str(key).casefold(): str(value)
                    for key, value in supplied_headers_value.items()
                }
                if any(supplied_headers.get(key) != value for key, value in expected_headers.items()):
                    return False
    if tool == "telnet_connect":
        if str(args.get("host") or "") != target:
            return False
        try:
            if int(args.get("port")) != int(requirement.get("port") or 23):
                return False
        except (TypeError, ValueError):
            return False
        timeout = args.get("timeout", 3)
        try:
            if int(timeout) != 3:
                return False
        except (TypeError, ValueError):
            return False
    if tool == "ftp_list" and target not in str(args.get("url") or ""):
        return False
    if tool in {"ssh_login", "try_credential"} and target not in json.dumps(args, ensure_ascii=False):
        return False
    if tool == "mqtt_listen" and requirement.get("success_condition", "").startswith("$SYS"):
        return str(args.get("topic") or "") == "$SYS/#"
    return True


def _phase4_apply_verification_contract(
    tools: list[dict], requirement: dict, *,
    vuln: dict | None = None, stop_on_conclusive: bool = False,
) -> list[dict]:
    """Reject wrong-target probes, require the probe, and optionally mark proof."""
    required_tool = str(requirement.get("tool") or "")
    required_called = {"value": False}
    wrapped: list[dict] = []
    for tool in tools:
        name = tool.get("name")
        fn = tool.get("function")
        if not callable(fn):
            wrapped.append(tool)
            continue

        def guarded(*, _name=name, _fn=fn, **kwargs):
            if _name == required_tool:
                if not _phase4_requirement_matches(requirement, _name, kwargs):
                    return json.dumps({"ok": False, "error_kind": "phase4_required_probe_mismatch",
                        "error": f"This finding requires {_name} against {requirement.get('target')} with the affected port/endpoint.",
                        "required_probe": requirement}, ensure_ascii=False)
                required_called["value"] = True
                result = _fn(**kwargs)
                if stop_on_conclusive and vuln is not None:
                    try:
                        candidate = _synthesize_exploit_result(
                            vuln,
                            [{"tool": _name, "args": kwargs, "result": result}],
                            compact=False,
                        )
                        if candidate.get("status") == "EXPLOITED":
                            payload = (
                                json.loads(result)
                                if isinstance(result, str) else result
                            )
                            if isinstance(payload, dict):
                                payload["phase4_conclusive"] = True
                                return json.dumps(payload, ensure_ascii=False)
                    except (TypeError, ValueError, json.JSONDecodeError):
                        pass
                return result
            if _name == "save_deliverable" and not required_called["value"]:
                return json.dumps({"ok": False, "error_kind": "phase4_required_probe_missing",
                    "error": f"Run the required Phase 4 probe ({required_tool}) before saving this finding.",
                    "required_probe": requirement}, ensure_ascii=False)
            return _fn(**kwargs)

        wrapped.append({**tool, "function": guarded})
    return wrapped
