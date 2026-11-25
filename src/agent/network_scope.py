"""Shared IPv4 network scope & exclusion helpers for live/partner audits.

Provides:
- Canonical parsing of ``excluded_ips`` (single IPv4 or IPv4 CIDR).
- Optional admin-level `.env` ceilings: ``LANCE_ALLOWED_CIDR`` and ``LANCE_EXCLUDED_IPS``.
- Thread/async-safe ``ContextVar`` carrying active excluded networks so subprocess
  wrappers (notably ``tool_loader.py`` for ``nmap`` ``--exclude`` injection and
  ``arp_scan``) enforce exclusions even when called without explicit scope kwargs.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import ipaddress
import os
import re


_ACTIVE_EXCLUDED: ContextVar[tuple[ipaddress.IPv4Network, ...]] = ContextVar(
    "lance_excluded_networks", default=(),
)


def parse_ipv4_network_or_host(raw: object, *, min_prefix: int = 16) -> ipaddress.IPv4Network:
    """Normalize a bare IPv4 host to /32 and validate canonical auditable IPv4 CIDR."""
    if not isinstance(raw, str) or not raw.strip() or raw != raw.strip():
        raise ValueError("An explicit authorized IPv4 address or CIDR is required")
    value = raw
    if "/" not in value:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("target_network must be one canonical IPv4 CIDR or IPv4 address") from exc
        if not isinstance(addr, ipaddress.IPv4Address):
            raise ValueError("Only IPv4 addresses and CIDRs are supported")
        value = f"{addr}/32"
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ValueError("target_network must be one canonical IPv4 CIDR") from exc
    if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen < min_prefix:
        raise ValueError(f"target_network must be an IPv4 CIDR of /{min_prefix} or narrower")
    if network.is_multicast or network.is_unspecified or network.is_loopback:
        raise ValueError("target_network is not an auditable network")
    return network


def parse_excluded_ips(raw: object) -> list[str]:
    """Parse a list or comma/whitespace-separated string of IPv4 hosts or CIDRs."""
    if raw is None:
        return []
    if isinstance(raw, str):
        tokens = [tok.strip() for tok in re.split(r"[\s,;]+", raw) if tok.strip()]
    elif isinstance(raw, (list, tuple, set)):
        tokens = []
        for item in raw:
            if item is None:
                continue
            tokens.extend(tok.strip() for tok in re.split(r"[\s,;]+", str(item)) if tok.strip())
    else:
        raise ValueError("excluded_ips must be a list of IPv4 addresses or CIDRs")

    networks: list[ipaddress.IPv4Network] = []
    seen: set[str] = set()
    for token in tokens:
        candidate = token if "/" in token else f"{token}/32"
        try:
            net = ipaddress.ip_network(candidate, strict=True)
        except ValueError as exc:
            raise ValueError(f"Invalid excluded IP/CIDR: {token!r}") from exc
        if not isinstance(net, ipaddress.IPv4Network):
            raise ValueError(f"Only IPv4 exclusions are supported: {token!r}")
        canonical = str(net.network_address) if net.prefixlen == 32 else str(net)
        if canonical not in seen:
            seen.add(canonical)
            networks.append(net)
    return [str(net.network_address) if net.prefixlen == 32 else str(net) for net in networks]


def to_excluded_networks(raw: object) -> tuple[ipaddress.IPv4Network, ...]:
    """Convert raw excluded IP/CIDR values into IPv4Network objects."""
    result: list[ipaddress.IPv4Network] = []
    for entry in parse_excluded_ips(raw):
        result.append(ipaddress.ip_network(entry if "/" in entry else f"{entry}/32", strict=True))
    return tuple(result)


def env_allowed_cidr() -> ipaddress.IPv4Network | None:
    """Return optional admin-enforced maximum CIDR from ``LANCE_ALLOWED_CIDR``."""
    raw = (os.environ.get("LANCE_ALLOWED_CIDR") or "").strip()
    if not raw:
        return None
    return parse_ipv4_network_or_host(raw)


def env_excluded_ips() -> list[str]:
    """Return optional admin-enforced excluded IPs from ``LANCE_EXCLUDED_IPS``."""
    raw = (os.environ.get("LANCE_EXCLUDED_IPS") or "").strip()
    if not raw:
        return []
    return parse_excluded_ips(raw)


def merge_and_validate_scope(
    target_network: str,
    excluded_ips: list[str] | None = None,
) -> tuple[str, list[str]]:
    """Validate ``target_network`` against optional env ceilings and merge exclusions.

    Returns ``(canonical_target_cidr, canonical_excluded_list)``.
    Raises ``PermissionError`` when violating ``LANCE_ALLOWED_CIDR`` or when the
    target is completely covered by excluded networks.
    """
    target_net = parse_ipv4_network_or_host(target_network)
    allowed_ceiling = env_allowed_cidr()
    if allowed_ceiling is not None and not target_net.subnet_of(allowed_ceiling):
        raise PermissionError(
            f"Target {target_net} is outside the admin-enforced LANCE_ALLOWED_CIDR ({allowed_ceiling})."
        )

    merged = parse_excluded_ips([*env_excluded_ips(), *(excluded_ips or [])])
    excluded_nets = to_excluded_networks(merged)
    if any(target_net.subnet_of(excl) for excl in excluded_nets):
        raise PermissionError(
            f"Target {target_net} is completely covered by excluded IPs ({', '.join(merged)})."
        )
    return str(target_net), merged


def current_excluded_networks() -> tuple[ipaddress.IPv4Network, ...]:
    """Return excluded networks active for the current execution context."""
    active = _ACTIVE_EXCLUDED.get()
    if active:
        return active
    env_excl = env_excluded_ips()
    return to_excluded_networks(env_excl) if env_excl else ()


@contextmanager
def excluded_ips_context(excluded: object):
    """Bind excluded IPv4 networks for the duration of a tool or runner call."""
    merged = parse_excluded_ips([*env_excluded_ips(), *parse_excluded_ips(excluded)])
    token = _ACTIVE_EXCLUDED.set(to_excluded_networks(merged))
    try:
        yield merged
    finally:
        _ACTIVE_EXCLUDED.reset(token)


def nmap_exclude_args(excluded: object = None) -> list[str]:
    """Return ``['--exclude', 'ip1,ip2']`` for nmap invocations, or ``[]``."""
    nets = to_excluded_networks(excluded) if excluded else current_excluded_networks()
    if not nets:
        return []
    formatted = [str(net.network_address) if net.prefixlen == 32 else str(net) for net in nets]
    return ["--exclude", ",".join(formatted)]


def is_ip_excluded(ip_str: str, excluded: object = None) -> bool:
    """Return True if a single IPv4 address falls inside any excluded network."""
    nets = to_excluded_networks(excluded) if excluded is not None else current_excluded_networks()
    if not nets:
        return False
    try:
        addr = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return False
    return isinstance(addr, ipaddress.IPv4Address) and any(addr in net for net in nets)


def overlapping_exclusion(candidate: ipaddress._BaseNetwork, excluded: object = None) -> str | None:
    """Return the first excluded network overlapping ``candidate``, else ``None``."""
    nets = to_excluded_networks(excluded) if excluded is not None else current_excluded_networks()
    for net in nets:
        if candidate.version == net.version and candidate.overlaps(net):
            return str(net.network_address) if net.prefixlen == 32 else str(net)
    return None
