"""CAI structured output schema from paper/integration_cai.md."""
from __future__ import annotations

try:
    from pydantic import BaseModel, Field
except ImportError:  # pragma: no cover - only used on the baseline VM without pydantic
    BaseModel = object  # type: ignore

    def Field(*args, **kwargs):  # type: ignore
        return None


class Finding(BaseModel):
    vuln_type: str = Field(
        description=(
            "Vulnerability type: default_credentials, no_authentication, known_cve, "
            "misconfiguration, info_disclosure, weak_crypto, data_exposure, "
            "code_injection, privilege_escalation"
        )
    )
    severity: str
    target_ip: str
    target_port: int | None = None
    target_service: str | None = None
    evidence: str = Field(description="Raw output proving the finding")
    cve_id: str | None = None
    evidence_level: str = Field(description="L1=detected, L2=exploited, L3=exfiltrated")


class CAIReport(BaseModel):
    target_ip: str
    scope: str
    findings: list[Finding]
    summary: str
    duration_turns: int


class ScenarioReport(BaseModel):
    scope: str
    discovered_ips: list[str]
    findings: list[Finding]
    pivot_chains: list[list[str]] = Field(default_factory=list)
    summary: str
    duration_turns: int

