"""Bounded block recovery for truncated Phase 3 full-device analysis.

A full-mode device analysis can exhaust the provider's per-response output
budget (``finish_reason=length``) after its exploration tool calls but before
it saves a validated deliverable. Retrying the whole device analysis usually
truncates again on the same output budget, while promoting a partial or
scanner-only JSON would misrepresent model work as completed analysis.

This module implements the deterministic half of the recovery: split one
device into a bounded number of per-service blocks, scope the already
collected evidence per block, strictly validate each saved block, and
assemble the full device deliverable only after every required block
succeeds. It never calls the provider itself; orchestration lives in
``src/agent/phases/analysis/run.py`` so stop/deadline/budget guards stay
shared with the original attempt.

Design limits (all caps are exact configured values, not remote caps):

- ``max_blocks`` (default 4): at most this many sidecar blocks per device.
  Extra services merge into the last block; devices without services get one
  general block.
- ``max_attempts`` (default 2): retries per block only. A failed block never
  retries its siblings and never restarts the full device analysis.
- ``max_tokens`` (default 4096) / ``max_turns`` (default 4): per block
  attempt. The output allowance matches the full device response budget;
  the service scope and turn count remain smaller.
- Sidecars live under ``03_blocks/`` so the ``03_device_*.json`` aggregation
  glob never mistakes a partial block for a completed device deliverable.
- Assembly is deterministic concatenation with id-dedup, never a blind JSON
  merge: duplicate ids keep the automated finding, conflicting duplicates
  fail the device as incomplete, and severities/types are never rewritten.

The configured caps bound this harness's requests. The remote provider's
actual output cap is unknown from here; repeated truncation therefore ends
in an explicit incomplete state with the valid blocks preserved, never in a
declared success.
"""
from __future__ import annotations

import json
import os
import re

BLOCK_DIR = "03_blocks"

DEFAULT_MAX_BLOCKS = 4
DEFAULT_SERVICES_PER_BLOCK = 2
DEFAULT_MAX_ATTEMPTS = 2
DEFAULT_MAX_TOKENS = 4096
DEFAULT_MAX_TURNS = 4

MAX_OBSERVATION_ENTRIES = 16
MAX_OBSERVATION_CHARS = 1200
MAX_RENDERED_OBSERVATIONS_CHARS = 6000

SEVERITY_BUCKETS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

_PORT_RE = re.compile(r"\b(\d{1,5})\b")


def _positive_int_env(name: str, default: int) -> int:
    """Read a positive int knob; fall back to the default when unset/invalid."""
    try:
        value = int(str(os.environ.get(name, "")).strip())
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def block_config() -> dict[str, int]:
    """Return the exact configured recovery caps for metadata and tests."""
    return {
        "max_blocks": _positive_int_env(
            "LANCE_PHASE3_BLOCK_MAX_BLOCKS", DEFAULT_MAX_BLOCKS
        ),
        "services_per_block": _positive_int_env(
            "LANCE_PHASE3_BLOCK_SERVICES_PER_BLOCK", DEFAULT_SERVICES_PER_BLOCK
        ),
        "max_attempts": _positive_int_env(
            "LANCE_PHASE3_BLOCK_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS
        ),
        "max_tokens": _positive_int_env(
            "LANCE_PHASE3_BLOCK_MAX_TOKENS", DEFAULT_MAX_TOKENS
        ),
        "max_turns": _positive_int_env(
            "LANCE_PHASE3_BLOCK_MAX_TURNS", DEFAULT_MAX_TURNS
        ),
    }


def is_truncation(completion_metadata: dict | None) -> bool:
    """Distinguish terminal output truncation from a generic missing save.

    The provider records the last response's ``finish_reason`` in the
    caller-owned metadata dict. Only ``length`` means the model ran out of
    output budget; anything else (including absent metadata from a mocked
    provider) keeps the generic missing-receipt diagnosis.
    """
    if not isinstance(completion_metadata, dict):
        return False
    return str(completion_metadata.get("finish_reason") or "").strip() == "length"


def derive_blocks(
    device: dict,
    *,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    services_per_block: int = DEFAULT_SERVICES_PER_BLOCK,
) -> list[dict]:
    """Split a device into bounded per-service block specs.

    Services keep their topology order. Overflow services merge into the
    last block so the block count never exceeds ``max_blocks``.
    """
    device_id = str(device.get("id") or "unknown")
    services: list[dict] = []
    for service in device.get("services", []) or []:
        if not isinstance(service, dict):
            continue
        name = str(service.get("name") or service.get("service") or "").strip()
        port = service.get("port")
        port = port if isinstance(port, int) and not isinstance(port, bool) else None
        if not name and port is None:
            continue
        services.append({"name": name, "port": port})

    max_blocks = max(1, int(max_blocks))
    services_per_block = max(1, int(services_per_block))
    if not services:
        chunks: list[list[dict]] = [[]]
    else:
        chunks = [
            services[index:index + services_per_block]
            for index in range(0, len(services), services_per_block)
        ]
    while len(chunks) > max_blocks:
        overflow = chunks.pop()
        chunks[-1].extend(overflow)

    specs: list[dict] = []
    for index, chunk in enumerate(chunks):
        names = sorted({entry["name"] for entry in chunk if entry["name"]})
        ports = sorted({entry["port"] for entry in chunk if entry["port"] is not None})
        specs.append({
            "index": index,
            "services": chunk,
            "service_names": names,
            "ports": ports,
            "sidecar": f"{BLOCK_DIR}/{device_id}_part{index}.json",
        })
    return specs


def _entry_ports(entry: dict) -> set[int]:
    """Best-effort port attribution for one scanner result entry."""
    ports: set[int] = set()
    kwargs = entry.get("kwargs")
    if isinstance(kwargs, dict):
        raw_ports = kwargs.get("ports", kwargs.get("port"))
        candidates = raw_ports if isinstance(raw_ports, list) else [raw_ports]
        for candidate in candidates:
            if isinstance(candidate, int) and not isinstance(candidate, bool):
                if 0 < candidate <= 65535:
                    ports.add(candidate)
            elif isinstance(candidate, str):
                for match in _PORT_RE.findall(candidate):
                    number = int(match)
                    if 0 < number <= 65535:
                        ports.add(number)
    text = f"{entry.get('tool', '')} {json.dumps(entry.get('result', ''), default=str)}"
    for match in re.findall(r"\b(\d{1,5})/(?:tcp|udp)\b", text, flags=re.IGNORECASE):
        number = int(match)
        if 0 < number <= 65535:
            ports.add(number)
    return ports


def _finding_matches_block(finding: dict, spec: dict) -> bool:
    """Keep block-relevant findings; keep unattributed ones for the model."""
    names = {name.casefold() for name in spec["service_names"]}
    ports = set(spec["ports"])
    if not names and not ports:
        return True
    port = finding.get("port")
    if isinstance(port, int) and not isinstance(port, bool) and port in ports:
        return True
    service = str(finding.get("service") or "").casefold()
    if service and service in names:
        return True
    if (not isinstance(port, int) or isinstance(port, bool)) and not service:
        return True
    return False


def scope_scan_for_block(scan_data: dict, spec: dict) -> dict:
    """Project scanner evidence onto one block without dropping unknowns.

    Entries or findings that cannot be attributed to a port/service are kept:
    over-inclusion in a block prompt is harmless, while attribution errors
    are rejected later by :func:`validate_block_payload`.
    """
    if not isinstance(scan_data, dict):
        return {"scan_results": {}, "findings": []}
    ports = set(spec["ports"])
    scoped_results: dict = {}
    scan_results = scan_data.get("scan_results", {})
    if isinstance(scan_results, dict):
        for service_key, entries in scan_results.items():
            if not isinstance(entries, list):
                continue
            if not ports:
                scoped_results[service_key] = entries
                continue
            kept = [
                entry for entry in entries
                if not isinstance(entry, dict)
                or not _entry_ports(entry)
                or _entry_ports(entry) & ports
            ]
            if kept:
                scoped_results[service_key] = kept
    findings = scan_data.get("findings", [])
    scoped_findings = [
        finding for finding in findings
        if isinstance(finding, dict) and _finding_matches_block(finding, spec)
    ]
    return {"scan_results": scoped_results, "findings": scoped_findings}


def record_observation(log: list[dict], tool_name: str, result: str, *, kwargs: dict | None = None) -> None:
    """Retain one bounded exploration observation for block finalization."""
    text = result if isinstance(result, str) else str(result)
    log.append({"tool": str(tool_name), "args": dict(kwargs or {}),
                "result": text[:MAX_OBSERVATION_CHARS]})
    while len(log) > MAX_OBSERVATION_ENTRIES:
        log.pop(0)


def render_observations(log: list[dict], spec: dict, *, limit: int = MAX_RENDERED_OBSERVATIONS_CHARS) -> str:
    """Render retained observations, preferring ones that mention the block."""
    if not log:
        return "No exploration tool calls were recorded before truncation."
    markers = {str(port) for port in spec["ports"]}
    markers.update(name.casefold() for name in spec["service_names"])
    ranked = sorted(
        log,
        key=lambda entry: (
            0 if any(
                marker and marker in f"{entry.get('tool', '')} {entry.get('result', '')}".casefold()
                for marker in markers
            ) else 1
        ),
    )
    lines: list[str] = []
    used = 0
    for entry in ranked:
        line = f"- {entry.get('tool', '?')} {json.dumps(entry.get('args', {}), ensure_ascii=False, default=str)}: {entry.get('result', '')}"
        if used + len(line) > limit:
            break
        lines.append(line)
        used += len(line)
    return "\n".join(lines) if lines else "Prior observations exceeded the rendering budget."


def validate_block_payload(
    data: object,
    *,
    device_id: str,
    device_ip: str,
    spec: dict,
    device_ports: set[int],
    device_services: set[str],
) -> tuple[bool, str]:
    """Strictly validate one saved block before it can join the assembly.

    Rejects cross-device output, wrong service/port attribution, duplicate
    finding ids, and malformed envelopes. Severity and type values
    are never rewritten here; classification rules are out of scope.
    """
    if not isinstance(data, dict):
        return False, "block envelope must be a JSON object"
    if data.get("device_id") != device_id:
        return False, (
            f"block device_id {data.get('device_id')!r} does not match {device_id!r}"
        )
    if data.get("device_ip") != device_ip:
        return False, (
            f"block device_ip {data.get('device_ip')!r} does not match {device_ip!r}"
        )
    if type(data.get("block_index")) is not int or data["block_index"] != spec["index"] + 1:
        return False, "block_index does not match the requested block"
    findings = data.get("vulnerabilities")
    if not isinstance(findings, list):
        return False, "block 'vulnerabilities' must be an array"
    if len(findings) > 10:
        return False, "block exceeds the 10-finding output limit"

    spec_ports = set(spec.get("ports", []))
    spec_names = {str(name).casefold() for name in spec.get("service_names", [])}
    known_services = {str(name).casefold() for name in device_services}
    seen_ids: set[str] = set()
    prefix = f"{device_id}-"
    for index, finding in enumerate(findings):
        where = f"vulnerabilities[{index}]"
        if not isinstance(finding, dict):
            return False, f"block {where} must be an object"
        finding_id = finding.get("id")
        if not isinstance(finding_id, str) or not finding_id.strip():
            return False, f"block {where}.id must be non-empty"
        if not finding_id.startswith(prefix):
            return False, (
                f"block {where}.id {finding_id!r} is not scoped to {device_id!r}"
            )
        if finding_id in seen_ids:
            return False, f"block duplicate finding id {finding_id!r}"
        seen_ids.add(finding_id)
        if finding.get("device_id") != device_id:
            return False, (
                f"block {where} targets {finding.get('device_id')!r}, "
                f"expected {device_id!r}"
            )
        present_ip = finding.get("device_ip")
        if present_ip not in (None, "") and present_ip != device_ip:
            return False, (
                f"block {where} targets ip {present_ip!r}, expected {device_ip!r}"
            )
        port = finding.get("port")
        if isinstance(port, bool) or (port is not None and not isinstance(port, int)):
            return False, f"block {where}.port must be an integer or null"
        if isinstance(port, int):
            allowed = spec_ports or set(device_ports)
            if port not in allowed:
                return False, (
                    f"block {where}.port {port} is outside this block's services"
                )
        service = finding.get("service")
        if service not in (None, ""):
            if not isinstance(service, str):
                return False, f"block {where}.service must be a string"
            allowed_names = spec_names or known_services
            if allowed_names and service.casefold() not in allowed_names:
                return False, (
                    f"block {where}.service {service!r} is outside this block's services"
                )
        if port is not None and service and spec.get("services"):
            if not any(
                entry.get("port") == port
                and str(entry.get("name") or "").casefold() == service.casefold()
                for entry in spec["services"]
            ):
                return False, f"block {where} service/port pair is outside this block's services"
    return True, "OK"


def _finding_key(finding: dict) -> str:
    return str(finding.get("id") or "")


def assemble_device_deliverable(
    device: dict,
    automated_findings: list,
    block_payloads: list[dict],
) -> dict:
    """Deterministically merge automated findings with validated blocks.

    Automated scanner findings stay canonical and untouched. Block findings
    join unless their id duplicates an automated finding (kept) or another
    block finding with different content (assembly failure: ids encode
    identity, so a conflict means misattribution, not a merge).
    """
    device_id = str(device.get("id") or "")
    device_ip = str(device.get("ip") or "")
    merged: list[dict] = []
    seen: dict[str, str] = {}
    automated = [
        finding for finding in automated_findings or []
        if isinstance(finding, dict)
    ]
    for finding in automated:
        merged.append(finding)
        key = _finding_key(finding)
        if key:
            seen[key] = json.dumps(finding, sort_keys=True, default=str)
    for payload in block_payloads:
        for finding in payload.get("vulnerabilities", []):
            if not isinstance(finding, dict):
                raise ValueError("assembled block finding must be an object")
            key = _finding_key(finding)
            canonical = json.dumps(finding, sort_keys=True, default=str)
            if key and key in seen:
                if seen[key] != canonical:
                    raise ValueError(
                        f"conflicting duplicate finding id {key!r} for {device_id}"
                    )
                continue
            merged.append(finding)
            if key:
                seen[key] = canonical
    by_severity = {bucket: 0 for bucket in SEVERITY_BUCKETS}
    for finding in merged:
        severity = str(finding.get("severity") or "").upper()
        if severity in by_severity:
            by_severity[severity] += 1
    return {
        "device_id": device_id,
        "device_ip": device_ip,
        "vulnerabilities": merged,
        "summary": {
            "total": len(merged),
            "critical": by_severity["CRITICAL"],
            "high": by_severity["HIGH"],
            "medium": by_severity["MEDIUM"],
            "low": by_severity["LOW"],
            "info": by_severity["INFO"],
        },
    }
