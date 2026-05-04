"""Shared baseline finding schema.

Pydantic is intentionally optional here: these dataclasses document the contract
without adding a runtime dependency beyond what the project already uses.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    vuln_type: str
    severity: str
    target_ip: str
    evidence: str
    evidence_level: str = "L1"
    target_port: int | None = None
    target_service: str | None = None
    cve_id: str | None = None


@dataclass
class ScenarioReport:
    scope: str
    findings: list[Finding] = field(default_factory=list)
    discovered_ips: list[str] = field(default_factory=list)
    pivot_chains: list[list[str]] = field(default_factory=list)
    summary: str = ""
    duration_turns: int = 0

