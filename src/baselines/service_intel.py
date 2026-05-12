"""Service intelligence for external benchmark targets.

This module combines three layers:
1. Curated pentest guidance for services we care about in benchmarks.
2. Local Nmap service databases when installed on the host/VM.
3. Python's system service registry fallback (`/etc/services`).
"""
from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse


HTTP_SERVICE_NAMES = {
    "http",
    "https",
    "http-alt",
    "http-proxy",
    "webcache",
    "sun-answerbook",
    "caldav",
    "kibana",
    "elasticsearch",
    "couchdb",
    "weblogic",
}
HTTP_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 10086}
HTTPS_PORTS = {443, 8443}
NMAP_SERVICE_PATHS = (
    Path("/usr/share/nmap/nmap-services"),
    Path("/usr/local/share/nmap/nmap-services"),
    Path("/opt/homebrew/share/nmap/nmap-services"),
    Path("/opt/local/share/nmap/nmap-services"),
)


@dataclass(frozen=True)
class ServiceIntel:
    port: int
    service_port: int
    transport: str = "tcp"
    service: str = "unknown"
    protocol: str = "tcp"
    guidance: str = "Fingerprint the service with nmap -sV before choosing protocol-specific checks."
    source: str = "fallback"

    @property
    def is_http_like(self) -> bool:
        return self.protocol in {"http", "https"} or self.service in HTTP_SERVICE_NAMES

    @property
    def url_scheme(self) -> str:
        return "https" if self.protocol == "https" or self.service_port in HTTPS_PORTS else "http"

    def endpoint(self, host: str = "127.0.0.1") -> str:
        if self.is_http_like:
            return f"{self.url_scheme}://{host}:{self.port}"
        return f"{host}:{self.port}"

    def url(self, host: str = "127.0.0.1") -> str | None:
        return self.endpoint(host) if self.is_http_like else None

    def context(self) -> str:
        mapped = "" if self.port == self.service_port else f" mapped to container port {self.service_port}/tcp"
        return (
            f"Observed exposed port: {self.port}/tcp{mapped}. "
            f"Likely service: {self.service}. Protocol: {self.protocol}. "
            f"Knowledge source: {self.source}. "
            f"Operator guidance: {self.guidance}"
        )


CURATED_PORTS: dict[int, dict[str, str]] = {
    21: {"service": "ftp", "protocol": "ftp", "guidance": "Check anonymous login, writable directories, cleartext credentials, and known FTP CVEs."},
    22: {"service": "ssh", "protocol": "ssh", "guidance": "Fingerprint SSH, test provided/default credentials only, and check weak algorithms or banner leaks."},
    23: {"service": "telnet", "protocol": "telnet", "guidance": "Treat as cleartext shell access; test default credentials and command execution carefully."},
    25: {"service": "smtp", "protocol": "smtp", "guidance": "Fingerprint SMTP, enumerate capabilities, and test open relay or vulnerable mail software."},
    53: {"service": "dns", "protocol": "dns", "guidance": "Check zone transfer, recursion, and DNS service/version vulnerabilities."},
    80: {"service": "http", "protocol": "http", "guidance": "Start with HTTP enumeration: headers, paths, forms, auth, uploads, and CVE-specific endpoints."},
    110: {"service": "pop3", "protocol": "pop3", "guidance": "Fingerprint POP3 and check weak/default credentials or cleartext auth."},
    139: {"service": "netbios", "protocol": "smb", "guidance": "Enumerate SMB/NetBIOS shares, guest access, signing, and known Samba/Windows CVEs."},
    143: {"service": "imap", "protocol": "imap", "guidance": "Fingerprint IMAP and check weak/default credentials or cleartext auth."},
    161: {"service": "snmp", "protocol": "snmp", "guidance": "Test common communities such as public/private and enumerate exposed system data."},
    389: {"service": "ldap", "protocol": "ldap", "guidance": "Check anonymous bind, cleartext LDAP, weak bind credentials, and directory enumeration."},
    443: {"service": "https", "protocol": "https", "guidance": "Start with HTTPS enumeration, certificate info, paths, auth, uploads, and CVE-specific endpoints."},
    445: {"service": "smb", "protocol": "smb", "guidance": "Enumerate shares, guest/null sessions, signing, and known SMB/Samba vulnerabilities."},
    502: {"service": "modbus", "protocol": "modbus", "guidance": "Industrial protocol: enumerate coils/registers; do not write unless the benchmark explicitly requires it."},
    873: {"service": "rsync", "protocol": "rsync", "guidance": "List modules and check anonymous read/write access."},
    1099: {"service": "java-rmi", "protocol": "rmi", "guidance": "Enumerate Java RMI registry and check deserialization/RMI exploitation paths."},
    1433: {"service": "mssql", "protocol": "mssql", "guidance": "Fingerprint MSSQL, test known/default credentials, and check xp_cmdshell exposure if authenticated."},
    1521: {"service": "oracle", "protocol": "oracle", "guidance": "Fingerprint Oracle listener, enumerate SIDs, and check known/default credentials."},
    1883: {"service": "mqtt", "protocol": "mqtt", "guidance": "Check anonymous MQTT connect, subscribe to wildcard topics, and look for leaked credentials/data."},
    2049: {"service": "nfs", "protocol": "nfs", "guidance": "Enumerate exports and check no_root_squash or world-readable shares."},
    2375: {"service": "docker", "protocol": "docker-api", "guidance": "Docker API over TCP: check unauthenticated access and container breakout impact."},
    3306: {"service": "mysql", "protocol": "mysql", "guidance": "Fingerprint MySQL/MariaDB, test known/default credentials, and enumerate databases if authenticated."},
    3389: {"service": "rdp", "protocol": "rdp", "guidance": "Fingerprint RDP and check weak credentials or known RDP CVEs without brute force."},
    5000: {"service": "http", "protocol": "http", "guidance": "Often a web/API service; enumerate HTTP endpoints and framework-specific CVEs."},
    5432: {"service": "postgres", "protocol": "postgres", "guidance": "Fingerprint PostgreSQL, test known/default credentials, and enumerate databases if authenticated."},
    5601: {"service": "kibana", "protocol": "http", "guidance": "Kibana web UI/API: enumerate version, saved objects, auth bypass and Elasticsearch reachability."},
    5672: {"service": "amqp", "protocol": "amqp", "guidance": "RabbitMQ/AMQP: check management port too, default guest credentials, and exposed queues."},
    5683: {"service": "coap", "protocol": "coap", "guidance": "CoAP/UDP: enumerate resources and check missing DTLS/authentication."},
    5900: {"service": "vnc", "protocol": "vnc", "guidance": "Check unauthenticated or weakly authenticated VNC and version-specific issues."},
    5984: {"service": "couchdb", "protocol": "http", "guidance": "CouchDB HTTP API: check admin party mode, _all_dbs, _config, and known CVEs."},
    6379: {"service": "redis", "protocol": "redis", "guidance": "Check unauthenticated Redis INFO/keys/config and known Lua/RCE CVEs."},
    7001: {"service": "weblogic", "protocol": "http", "guidance": "WebLogic console/API: enumerate version and test CVE-specific deserialization endpoints."},
    8080: {"service": "http", "protocol": "http", "guidance": "Start with HTTP enumeration: headers, paths, forms, auth, uploads, and CVE-specific endpoints."},
    8081: {"service": "http", "protocol": "http", "guidance": "Start with HTTP enumeration; many benchmarks expose app/admin panels here."},
    8161: {"service": "activemq-web", "protocol": "http", "guidance": "ActiveMQ web console/fileserver. Enumerate console paths, default credentials, upload/file write endpoints, and CVE-specific web-console flows."},
    8443: {"service": "https", "protocol": "https", "guidance": "HTTPS web/API service; enumerate paths and CVE-specific endpoints."},
    8888: {"service": "http", "protocol": "http", "guidance": "Often a web/API service; enumerate HTTP endpoints and auth behavior."},
    9000: {"service": "http", "protocol": "http", "guidance": "Often a web/admin/API service; enumerate paths and version-specific CVEs."},
    9200: {"service": "elasticsearch", "protocol": "http", "guidance": "Elasticsearch HTTP API: check unauthenticated cluster/index access and known CVEs."},
    11211: {"service": "memcached", "protocol": "memcached", "guidance": "Check unauthenticated stats/items access and exposed cached secrets."},
    27017: {"service": "mongodb", "protocol": "mongodb", "guidance": "Check unauthenticated MongoDB access, database listing, and exposed collections."},
    61613: {"service": "activemq-stomp", "protocol": "stomp", "guidance": "ActiveMQ STOMP transport: fingerprint broker and test CVE-specific messaging/deserialization paths."},
    61616: {"service": "activemq-openwire", "protocol": "openwire", "guidance": "ActiveMQ OpenWire/JMS transport, not HTTP. Use nmap fingerprinting and CVE-specific ActiveMQ exploit logic instead of curl."},
    10086: {"service": "http", "protocol": "http", "guidance": "Web admin panel/API; enumerate HTTP routes, auth state, version, and CVE-specific endpoints."},
}


def infer_target_port(target: str) -> int | None:
    parsed = urlparse(target if "://" in target else f"//{target}")
    if parsed.port:
        return parsed.port
    match = re.search(r":(\d+)(?:/|$)", target)
    if match:
        return int(match.group(1))
    if target.startswith("https://"):
        return 443
    if target.startswith("http://"):
        return 80
    return None


def _normalize_protocol(service_name: str, port: int) -> str:
    name = service_name.lower()
    if name in {"https", "ssl/http"} or port in HTTPS_PORTS:
        return "https"
    if name in HTTP_SERVICE_NAMES or port in HTTP_PORTS:
        return "http"
    return name


@lru_cache(maxsize=1)
def _load_nmap_services() -> dict[tuple[int, str], str]:
    services: dict[tuple[int, str], str] = {}
    for path in NMAP_SERVICE_PATHS:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) < 2 or "/" not in parts[1]:
                continue
            port_text, transport = parts[1].split("/", 1)
            if not port_text.isdigit():
                continue
            services.setdefault((int(port_text), transport.lower()), parts[0].lower())
        if services:
            break
    return services


def _registry_service(port: int, transport: str) -> tuple[str, str] | None:
    nmap_name = _load_nmap_services().get((port, transport))
    if nmap_name:
        return nmap_name, "nmap-services"
    try:
        return socket.getservbyport(port, transport), "system-services"
    except OSError:
        return None


def service_intel_for_port(port: int, service_port: int | None = None, transport: str = "tcp") -> ServiceIntel:
    inner_port = service_port or port
    curated = CURATED_PORTS.get(port) or CURATED_PORTS.get(inner_port)
    if curated:
        return ServiceIntel(
            port=port,
            service_port=inner_port,
            transport=transport,
            service=curated["service"],
            protocol=curated["protocol"],
            guidance=curated["guidance"],
            source="curated",
        )

    registry = _registry_service(inner_port, transport) or _registry_service(port, transport)
    if registry:
        service, source = registry
        protocol = _normalize_protocol(service, inner_port)
        guidance = (
            f"Registered service name is {service}; confirm with nmap -sV, then use service-specific checks."
        )
        return ServiceIntel(
            port=port,
            service_port=inner_port,
            transport=transport,
            service=service,
            protocol=protocol,
            guidance=guidance,
            source=source,
        )

    protocol = "https" if inner_port in HTTPS_PORTS else "http" if inner_port in HTTP_PORTS else transport
    service = protocol if protocol in {"http", "https"} else "unknown"
    return ServiceIntel(port=port, service_port=inner_port, transport=transport, service=service, protocol=protocol)


def service_intelligence_for_target(target: str, hint: str = "") -> str:
    port = infer_target_port(target)
    lines = []
    if port:
        intel = service_intel_for_port(port)
        lines.append(f"Port intelligence: {port}/tcp is likely {intel.service} ({intel.protocol}); source={intel.source}.")
        lines.append(f"Recommended strategy: {intel.guidance}")
    else:
        lines.append("Port intelligence: unknown target; fingerprint the service first.")
    if "not HTTP" in hint or "Protocol: openwire" in hint or "Protocol: redis" in hint:
        lines.append("Do not assume the target is HTTP just because it is exposed on localhost; choose checks based on the protocol.")
    return "\n".join(lines)
