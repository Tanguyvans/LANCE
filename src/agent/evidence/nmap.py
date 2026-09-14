"""Scope Nmap observations to one requested host, port and protocol.

Only stdout port blocks are evidence, never stderr or host-wide prose.
Modbus grammar follows https://nmap.org/nsedoc/scripts/modbus-discover.html.
"""
from __future__ import annotations

import ipaddress
import re


_PORT_ROW = re.compile(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+.*)?$")
_HOST_ROW = re.compile(r"^Nmap scan report for (.+)$")
_SERVICE_ALIASES = {"mbap": "modbus", "ssl/http": "https", "ssl/https": "https"}


def scoped_nmap_output(vuln: dict, args: dict, stdout: str) -> str:
    """Return exactly one matching port block or fail closed on ambiguity."""
    try:
        port = int(vuln.get("port"))
        if isinstance(vuln.get("port"), bool) or not 1 <= port <= 65535:
            return ""
        targets = [ipaddress.ip_network(token, strict=False) for token in
                   re.split(r"[\s,]+", str(args.get("target") or "").strip())]
        claimed_host = vuln.get("device_ip")
        host = ipaddress.ip_address(claimed_host) if claimed_host else None
        if host is None and len(targets) == 1 and targets[0].num_addresses == 1:
            host = targets[0].network_address
        if host is None or not any(host.version == net.version and host in net for net in targets):
            return ""
    except (TypeError, ValueError):
        return ""

    lines = stdout.splitlines()
    has_headers = any(_HOST_ROW.fullmatch(line) for line in lines)
    # A headerless excerpt is attributable only for a single-host request.
    current_host = host if not has_headers and len(targets) == 1 and targets[0].num_addresses == 1 else None
    service = str(vuln.get("service") or "").casefold()
    service = _SERVICE_ALIASES.get(service, service)
    protocol = str(vuln.get("protocol") or "tcp").casefold()
    blocks: list[list[str]] = []
    block: list[str] | None = None
    for line in lines:
        header = _HOST_ROW.fullmatch(line)
        if header:
            block = None
            raw_host = header.group(1)
            if raw_host.endswith(")") and " (" in raw_host:
                raw_host = raw_host.rsplit(" (", 1)[1][:-1]
            try:
                current_host = ipaddress.ip_address(raw_host)
            except ValueError:
                current_host = None
            continue
        row = _PORT_ROW.fullmatch(line)
        if row:
            block = None
            actual_port, actual_protocol, state, actual_service = row.groups()
            actual_service = _SERVICE_ALIASES.get(actual_service.casefold(), actual_service.casefold())
            if (current_host == host and int(actual_port) == port and actual_protocol == protocol
                    and state == "open" and (not service or service == actual_service)):
                block = [line]
                blocks.append(block)
            continue
        if block is not None:
            if line.startswith("|"):
                block.append(line)
            else:
                block = None
    return "\n".join(blocks[0]) if len(blocks) == 1 else ""


def modbus_identity_observed(scoped_stdout: str) -> bool:
    """Require returned device data, not an open port, SID guess or error.

    This proves an unauthenticated identification read only, never a register
    read/write, execution, or a compromised machine.
    """
    in_script = False
    in_sid = False
    for line in scoped_stdout.splitlines()[1:]:
        if re.fullmatch(r"\|[_ ]?modbus-discover:\s*", line):
            in_script, in_sid = True, False
            continue
        if re.match(r"\|[_ ]?[A-Za-z0-9][\w.-]*:", line):
            in_script, in_sid = False, False
        if not in_script:
            continue
        content = re.sub(r"^\|[_ ]*", "", line).strip()
        if re.fullmatch(r"sid (?:0x[0-9a-fA-F]+|\d+):", content):
            in_sid = True
            continue
        match = re.fullmatch(r"(?:Slave ID data|Device identification):\s*(\S.*)", content)
        if in_sid and match and not re.search(
            r"(?i)\b(?:error|unknown|none|null|denied|failed|timeout|unavailable)\b", match.group(1),
        ):
            return True
    return False
