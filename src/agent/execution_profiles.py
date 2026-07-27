"""Explicit execution profiles for model/tool orchestration.

Profiles change how capabilities are presented to a model, not the benchmark
ground truth or evaluator.  Compact mode routes a smaller phase-specific tool
surface; full mode exposes every tool allowed by the phase safety boundary.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass


EXECUTION_PROFILE_SCHEMA_VERSION = "2"
EXECUTION_PROFILE_AUTO_THRESHOLD_B = 32.0
EXECUTION_PROFILE_POLICIES = frozenset({"auto", "compact", "full"})


@dataclass(frozen=True)
class ExecutionProfile:
    name: str
    routed_tools: bool
    phase3_max_turns: int
    phase3_max_tokens: int
    phase4_max_turns: int
    phase4_max_tokens: int
    intrusion_max_turns: int
    intrusion_max_tokens: int
    report_max_turns: int
    report_max_tokens: int

    def metadata(self) -> dict:
        return {
            "schema_version": EXECUTION_PROFILE_SCHEMA_VERSION,
            **asdict(self),
        }


@dataclass(frozen=True)
class ExecutionProfileResolution:
    profile: ExecutionProfile
    requested_policy: str
    resolution_basis: str
    model_slug: str | None
    model_profile_policy: str
    parameter_count_b: float | None
    active_parameter_count_b: float | None
    threshold_b: float

    def metadata(self) -> dict:
        parameter_basis = None
        if self.resolution_basis == "active_parameters":
            parameter_basis = "active"
        elif self.resolution_basis == "total_parameters":
            parameter_basis = "total"
        return {
            "execution_profile": self.profile.name,
            "execution_profile_policy": self.requested_policy,
            "execution_profile_resolution_basis": self.resolution_basis,
            "model_profile_policy": self.model_profile_policy,
            "model_parameter_count_b": self.parameter_count_b,
            "model_active_parameter_count_b": self.active_parameter_count_b,
            "profile_parameter_basis": parameter_basis,
            "profile_threshold_b": self.threshold_b,
        }


EXECUTION_PROFILES: dict[str, ExecutionProfile] = {
    "compact": ExecutionProfile(
        name="compact",
        routed_tools=True,
        phase3_max_turns=8,
        phase3_max_tokens=2048,
        phase4_max_turns=6,
        phase4_max_tokens=3072,
        intrusion_max_turns=50,
        intrusion_max_tokens=8192,
        report_max_turns=12,
        report_max_tokens=8192,
    ),
    "full": ExecutionProfile(
        name="full",
        routed_tools=False,
        phase3_max_turns=10,
        phase3_max_tokens=4096,
        phase4_max_turns=10,
        phase4_max_tokens=4096,
        intrusion_max_turns=80,
        intrusion_max_tokens=16384,
        report_max_turns=25,
        report_max_tokens=16384,
    ),
}


PHASE3_FULL_TOOL_NAMES = frozenset({
    "cve_search", "curl_headers", "http_get", "http_request",
    "list_deliverables", "mtls_request", "read_deliverable",
    "save_deliverable", "tcp_send", "tls_inspect", "udp_send",
})


COMPACT_PHASE_TOOL_NAMES: dict[int, frozenset[str]] = {
    2: frozenset({
        "arp_scan", "curl_headers", "cve_search", "dig_query", "ftp_list",
        "get_attack_surface", "get_device_info", "http_get", "list_deliverables",
        "modbus_scan", "mqtt_listen", "nmap_discovery", "nmap_scan",
        "read_deliverable", "save_deliverable", "smbclient_list", "ssh_audit",
        "tls_inspect",
    }),
    6: frozenset({
        "list_deliverables", "read_deliverable", "save_deliverable",
    }),
}


def filter_profile_tools(
    profile: ExecutionProfile, phase: int, tools: list[dict]
) -> list[dict]:
    """Apply compact routing to generic phases; full preserves the safe surface."""
    if not profile.routed_tools:
        return tools
    allowed = COMPACT_PHASE_TOOL_NAMES.get(phase)
    if allowed is None:
        return tools
    return [tool for tool in tools if tool.get("name") in allowed]


def phase3_tool_names(
    profile: ExecutionProfile, device: dict, scan_data: dict
) -> frozenset[str]:
    """Return the Phase 3 tool surface, routed from observed evidence."""
    if not profile.routed_tools:
        return PHASE3_FULL_TOOL_NAMES

    rendered = json.dumps(
        {"device": device, "scan": scan_data}, ensure_ascii=False, default=str
    ).casefold()
    ports = {
        int(value)
        for value in re.findall(r"\b(\d{1,5})(?:\/(?:tcp|udp))?\b", rendered)
        if 0 < int(value) <= 65535
    }
    names = {
        "cve_search", "list_deliverables", "read_deliverable",
        "save_deliverable", "tcp_send",
    }

    http_markers = (
        "http", "https", "web", "nginx", "apache", "luci", "websocket", "mqtt-ws",
    )
    if ports.intersection({80, 443, 8000, 8080, 8443, 9001}) or any(
        marker in rendered for marker in http_markers
    ):
        names.update({"curl_headers", "http_get", "http_request"})
    if ports.intersection({443, 8443, 8883}) or any(
        marker in rendered for marker in ("tls", "ssl", "https", "mqtts", "mtls")
    ):
        names.update({"tls_inspect", "mtls_request"})
    if "udp" in rendered or ports.intersection({53, 123, 161, 5683, 47808}):
        names.add("udp_send")
    return frozenset(names)


def resolve_execution_profile(value: str | None) -> ExecutionProfile:
    name = str(value or "full").strip().casefold()
    try:
        return EXECUTION_PROFILES[name]
    except KeyError as exc:
        choices = ", ".join(sorted(EXECUTION_PROFILES))
        raise ValueError(
            f"Unknown execution profile '{value}'. Expected one of: {choices}"
        ) from exc


def _positive_float(value) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def resolve_execution_profile_for_model(
    policy: str | None,
    model_slug: str | None,
    *,
    model_metadata: dict | None = None,
    threshold_b: float = EXECUTION_PROFILE_AUTO_THRESHOLD_B,
) -> ExecutionProfileResolution:
    """Resolve run override, model override, then the active/total parameter rule."""
    requested = str(policy or "auto").strip().casefold()
    if requested not in EXECUTION_PROFILE_POLICIES:
        choices = ", ".join(sorted(EXECUTION_PROFILE_POLICIES))
        raise ValueError(
            f"Unknown execution profile policy '{policy}'. Expected one of: {choices}"
        )

    if requested in EXECUTION_PROFILES:
        return ExecutionProfileResolution(
            profile=EXECUTION_PROFILES[requested],
            requested_policy=requested,
            resolution_basis="run_override",
            model_slug=model_slug,
            model_profile_policy="auto",
            parameter_count_b=None,
            active_parameter_count_b=None,
            threshold_b=threshold_b,
        )

    metadata = model_metadata
    if metadata is None and model_slug:
        try:
            from src.db.database import get_model, init_db

            init_db()
            metadata = get_model(model_slug)
        except Exception:
            metadata = None
    metadata = metadata or {}

    model_policy = str(metadata.get("profile_policy") or "auto").strip().casefold()
    if model_policy not in EXECUTION_PROFILE_POLICIES:
        model_policy = "auto"
    total = _positive_float(metadata.get("parameter_count_b"))
    active = _positive_float(metadata.get("active_parameter_count_b"))

    if model_policy in EXECUTION_PROFILES:
        effective = model_policy
        basis = "model_override"
    elif active is not None:
        effective = "compact" if active <= threshold_b else "full"
        basis = "active_parameters"
    elif total is not None:
        effective = "compact" if total <= threshold_b else "full"
        basis = "total_parameters"
    else:
        effective = "full"
        basis = "missing_parameters"

    return ExecutionProfileResolution(
        profile=EXECUTION_PROFILES[effective],
        requested_policy=requested,
        resolution_basis=basis,
        model_slug=model_slug,
        model_profile_policy=model_policy,
        parameter_count_b=total,
        active_parameter_count_b=active,
        threshold_b=threshold_b,
    )
