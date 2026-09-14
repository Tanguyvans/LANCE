"""Application-level destination checks shared by every execution profile."""
from __future__ import annotations
import ipaddress
import re
from urllib.parse import urlsplit


# Prevent compromised scenario hosts from bridging into management networks.
_INTRUSION_DIRECT_TARGET_FIELDS = frozenset({"ip", "host", "broker", "target", "url"})


_INTRUSION_NETWORK_COMMAND_RE = re.compile(
    r"\b(?:ping6?|nmap|nc|ncat|netcat|ssh|scp|sftp|curl|wget|telnet|ftp|"
    r"mosquitto_(?:sub|pub)|mysql|redis-cli|snmp(?:get|walk)?|smbclient|"
    r"rpcclient|traceroute|tracepath|dig|host|python(?:3)?|perl|ruby|node)\b",
    re.IGNORECASE,
)


_INTRUSION_IPV4_RE = re.compile(
    r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\d.])"
)


_INTRUSION_IPV4_PREFIX_RE = re.compile(
    r"(?<![\d.])(?:\d{1,3}\.){3}(?!\d)"
)


def _intrusion_scope_networks(raw_subnets: object) -> list[ipaddress._BaseNetwork]:
    """Parse the scenario CIDRs used as the Phase 5 authorization boundary."""
    networks: list[ipaddress._BaseNetwork] = []
    for raw in re.split(r"[\s,]+", str(raw_subnets or "").strip()):
        if not raw:
            continue
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if network not in networks:
            networks.append(network)
    return networks


def _intrusion_scope_candidates(value: object) -> list[tuple[str, ipaddress._BaseNetwork]]:
    """Extract IPv4 literals and shell prefixes from a tool argument."""
    text = str(value or "")
    candidates: list[tuple[str, ipaddress._BaseNetwork]] = []
    occupied: list[tuple[int, int]] = []
    for match in _INTRUSION_IPV4_RE.finditer(text):
        token = match.group(0)
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        candidates.append((token, network))
        occupied.append(match.span())
    for match in _INTRUSION_IPV4_PREFIX_RE.finditer(text):
        if any(start < match.end() and match.start() < end for start, end in occupied):
            continue
        token = match.group(0)
        try:
            network = ipaddress.ip_network(f"{token}0/24", strict=False)
        except ValueError:
            continue
        candidates.append((token, network))
    return candidates


def _intrusion_scope_violation(
    tool_name: str,
    kwargs: dict,
    raw_subnets: object,
) -> dict | None:
    """Return a structured refusal for an unverifiable Phase 5 destination.

    This is a capability boundary, not a model/profile limit: every model can
    still choose any tool, target, order, and command within the scenario
    networks.
    """
    allowed = _intrusion_scope_networks(raw_subnets)
    if not allowed:
        return {
            "ok": False,
            "error_kind": "intrusion_scope_unavailable",
            "error": "Phase 5 has no declared scenario CIDR; network action refused.",
        }

    def in_scope(candidate: ipaddress._BaseNetwork) -> bool:
        return any(candidate.version == network.version and candidate.subnet_of(network)
                   for network in allowed)

    def refusal(kind: str, target: str, message: str) -> dict:
        return {
            "ok": False,
            "error_kind": kind,
            "error": message,
            "target": target,
            "allowed_subnets": [str(network) for network in allowed],
        }

    # Direct tool destinations (including URL hosts) must be explicit IPv4
    # literals. Scenario targets are IP-addressed; an unresolvable hostname
    # cannot be proven to belong to the scenario and is therefore refused.
    direct_values = [
        (field, kwargs.get(field))
        for field in _INTRUSION_DIRECT_TARGET_FIELDS
        if kwargs.get(field) not in (None, "")
    ]
    for field, value in direct_values:
        raw_value = str(value).strip()
        try:
            if field == "url":
                # Only the URL authority is a destination. IPs in userinfo,
                # paths, queries and fragments are never authorization facts.
                if any(char.isspace() or ord(char) < 32 for char in raw_value):
                    raise ValueError("invalid URL whitespace")
                parsed = urlsplit(raw_value)
                if parsed.scheme.casefold() not in {"http", "https", "ftp", "mqtt", "mqtts", "ws", "wss"}:
                    raise ValueError("unsupported URL scheme")
                if not parsed.hostname:
                    raise ValueError("missing URL host")
                _ = parsed.port  # Reject malformed authorities, too.
                tokens = [str(ipaddress.ip_address(parsed.hostname))]
            elif field == "target":
                # Structured scanners support explicit IP/CIDR target lists,
                # not arbitrary text containing one acceptable address.
                tokens = re.split(r"[\s,]+", raw_value)
            else:
                tokens = [str(ipaddress.ip_address(raw_value))]
            candidates = [(token, ipaddress.ip_network(token, strict=False))
                          for token in tokens]
        except ValueError:
            return refusal(
                "intrusion_target_unverifiable",
                field,
                f"Phase 5 {field} must resolve to an explicit IP inside the scenario CIDRs.",
            )
        for token, candidate in candidates:
            if not in_scope(candidate):
                return refusal(
                    "intrusion_target_out_of_scope",
                    token,
                    f"Phase 5 target {token} is outside the scenario authorization boundary.",
                )

    # Commands passed to a compromised host are checked as well. Checking
    # only the SSH endpoint would still permit a router shell to scan its WAN
    # interface, which is exactly the failure mode this guard closes.
    command_fields: list[tuple[str, str]] = []
    if tool_name in {"ssh_exec", "ssh_login"} and kwargs.get("command") not in (None, ""):
        command_fields.append(("command", str(kwargs.get("command"))))
    if tool_name in {"ssh_login", "telnet_connect"} and kwargs.get("command_string") not in (None, ""):
        command_fields.append(("command_string", str(kwargs.get("command_string"))))

    for field, command in command_fields:
        candidates = _intrusion_scope_candidates(command)
        for token, candidate in candidates:
            if not in_scope(candidate):
                return refusal(
                    "intrusion_command_out_of_scope",
                    token,
                    f"Phase 5 command {field} contains a destination outside the scenario CIDRs.",
                )

        # Network-capable commands without an explicit in-scope literal can
        # derive a destination from a route, hostname, or shell variable. The
        # harness cannot authorize that destination, so fail closed. Local
        # inspection commands (ip route, ip neigh, cat, id, etc.) remain free.
        if _INTRUSION_NETWORK_COMMAND_RE.search(command) and not candidates:
            return refusal(
                "intrusion_command_destination_unverifiable",
                field,
                f"Phase 5 command {field} has a network action without an explicit in-scope destination.",
            )

        # Explicit hostnames in URI/user@host syntax bypass an IPv4-only
        # literal check; reject them even if another allowed IP appears in the
        # same command.
        if re.search(r"(?:https?|ftp|mqtt)://\s*[A-Za-z]", command, re.IGNORECASE):
            return refusal(
                "intrusion_command_hostname_unverifiable",
                field,
                f"Phase 5 command {field} contains a hostname destination that is not scenario-authorized.",
            )
        if re.search(r"@[A-Za-z][A-Za-z0-9_.-]*\b", command):
            return refusal(
                "intrusion_command_hostname_unverifiable",
                field,
                f"Phase 5 command {field} contains a hostname destination that is not scenario-authorized.",
            )

    return None
