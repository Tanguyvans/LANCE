"""Execution adapter contracts for manually composed Scenario Lab bundles.

Manual composition is deliberately provider-driven: a topology and a Ground
Truth can be authored freely, but a bundle is executable only when every node
maps to a provider that the existing Ansible runtime knows how to provision,
inject, and verify.  This module is the boundary between those authored
artifacts and the runtime deployment overlay.
"""
from __future__ import annotations

import copy
from typing import Any

from src.benchmark.scenario_spec import ScenarioSpecError
from src.benchmark.scenario_alterations import PREVIEW_ONLY_ALTERATIONS


ADAPTER_ID = "ansible-proxmox"

# These are intentionally small, explicit providers.  Adding a new service to
# the manual catalogue requires adding its injector/verifier contract here;
# otherwise a Ground Truth could claim a state that the runtime never creates.
FLAT_ROLE_PROVIDERS: dict[str, dict[str, Any]] = {
    "mqtt_broker": {"provider": "ansible.debian_role", "control": True},
    "mqtt_broker_v2": {"provider": "ansible.debian_role", "control": False},
    "web_server": {"provider": "ansible.debian_role", "control": True},
    "web_server_v2": {"provider": "ansible.debian_role", "control": False},
    "web_upload": {"provider": "ansible.debian_role", "control": False},
    "ssh_server": {"provider": "ansible.debian_role", "control": True},
    "ssh_server_v2": {"provider": "ansible.debian_role", "control": False},
    "db_server_v2": {"provider": "ansible.debian_role", "control": True},
    "db_server": {"provider": "ansible.debian_role", "control": False},
    "modbus_server": {"provider": "ansible.debian_role", "control": False},
    "iot_gateway": {"provider": "ansible.debian_role", "control": False},
    "camera_server": {"provider": "ansible.debian_role", "control": False},
    "nvr_server": {"provider": "ansible.debian_role", "control": False},
    "ftp_server": {"provider": "ansible.debian_role", "control": False},
    "snmp_server": {"provider": "ansible.debian_role", "control": False},
    "coap_server": {"provider": "ansible.debian_role", "control": False},
    "nodered_server": {"provider": "ansible.debian_role", "control": False},
}

MULTIHOP_ROLES = {
    "pivot_entry",
    "pivot_relay",
    "pivot_vault",
    "pivot_decoy",
}

PROFILE_DEFINITIONS: dict[str, dict[str, Any]] = {
    "flat_roles": {
        "source_scenario_id": "14",
        "description": "Flat Debian services with role-based injectors and controls",
        "capabilities": ["flat_topology", "logical_chain", "role_injection", "control_injection"],
    },
    "true_multihop": {
        "source_scenario_id": "20",
        "description": "The existing two-pivot VLAN provider and verifier",
        "capabilities": ["network_pivot", "vlan_routing", "role_injection", "control_injection"],
    },
    "preview": {
        "source_scenario_id": "preview",
        "description": "Declarative Scenario Lab preview without a provisioning provider",
        "capabilities": ["catalogue", "ground_truth", "metadata", "preview_only"],
    },
}


def _service_by_name(topology: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item["name"]): item for item in topology.get("services", [])}


def _findings_by_device(gt: dict[str, Any], field: str) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for item in gt.get(field, []) or []:
        result.setdefault(str(item.get("device")), []).append(item)
    return result


def _validate_offsets(topology: dict[str, Any]) -> None:
    offsets = []
    for item in topology.get("services", []) or []:
        if item.get("vmid_offset") is None:
            raise ScenarioSpecError(
                f"Execution adapter requires topology.services[{item.get('name')}] vmid_offset"
            )
        try:
            offset = int(item["vmid_offset"])
        except (TypeError, ValueError) as exc:
            raise ScenarioSpecError(f"Invalid vmid_offset for {item.get('name')}") from exc
        if offset < 1:
            raise ScenarioSpecError(f"Service vmid_offset must be >= 1: {item.get('name')}")
        offsets.append(offset)
    if len(offsets) != len(set(offsets)):
        raise ScenarioSpecError("Execution adapter requires unique service vmid_offset values")


def _validate_flat(topology: dict[str, Any], gt: dict[str, Any]) -> list[dict[str, Any]]:
    _validate_offsets(topology)
    if str(topology.get("router", {}).get("type", "openwrt")) != "openwrt":
        raise ScenarioSpecError("ansible-proxmox/flat_roles requires an OpenWrt router")
    if topology.get("router", {}).get("ip") != "192.168.100.1":
        raise ScenarioSpecError("flat_roles provider requires router IP 192.168.100.1")
    if topology.get("network_mode") not in {None, "flat"}:
        raise ScenarioSpecError("flat_roles cannot execute a segmented or multi-hop topology")
    if any(
        not str(item.get("ip", "")).startswith("192.168.100.")
        for item in topology.get("services", []) or []
    ):
        raise ScenarioSpecError("flat_roles provider requires services on 192.168.100.0/24")
    services = _service_by_name(topology)
    if not services:
        raise ScenarioSpecError("flat_roles requires at least one service")
    if topology.get("reachability_policy") or topology.get("observability"):
        raise ScenarioSpecError(
            "flat_roles does not implement custom reachability or observability alterations"
        )
    fixtures = []
    for item in topology.get("services", []) or []:
        role = str(item.get("role", ""))
        provider = FLAT_ROLE_PROVIDERS.get(role)
        if provider is None:
            raise ScenarioSpecError(
                f"No execution provider for role {role!r}; choose a supported role or add a provider"
            )
        if item.get("simulator"):
            raise ScenarioSpecError(
                f"Simulator {item['simulator']!r} is not compatible with flat_roles"
            )
        if any(item.get(field) is not None for field in (
            "vlan_id", "secondary_vlan_id", "bootstrap_ip", "secondary_ip",
            "port_override", "runtime", "configuration",
        )):
            raise ScenarioSpecError(
                f"Topology alteration on {item['name']} requires a provider other than flat_roles"
            )
        profile = str(item.get("security_profile", "vulnerable"))
        if profile not in {"vulnerable", "hardened", "near_miss"}:
            raise ScenarioSpecError(f"Unsupported security_profile {profile!r} for {item['name']}")
        if profile != "vulnerable" and not provider["control"]:
            raise ScenarioSpecError(
                f"Role {role!r} has no hardened provider in flat_roles"
            )
        fixtures.append({
            "device": item["name"],
            "ip": item["ip"],
            "vmid_offset": int(item["vmid_offset"]),
            "role": role,
            "provider": provider["provider"],
            "security_profile": profile,
            "vulnerability_keys": [],
            "control_keys": [],
        })

    # The source-14 playbooks inject by role/profile.  Reject findings on the
    # router or on a service absent from the runtime topology before writing a
    # lease, so deployability is a meaningful promise.
    for field in ("vulnerabilities", "controls"):
        for finding in gt.get(field, []) or []:
            device = str(finding.get("device", ""))
            item = services.get(device)
            if item is None:
                raise ScenarioSpecError(f"{field} references an undeployable device: {device}")
            if str(item.get("role")) not in FLAT_ROLE_PROVIDERS:
                raise ScenarioSpecError(
                    f"{field} role {item.get('role')!r} has no flat execution provider"
                )

    return fixtures


def _validate_multihop(topology: dict[str, Any], gt: dict[str, Any]) -> list[dict[str, Any]]:
    _validate_offsets(topology)
    router = topology.get("router", {})
    if router.get("ip") != "192.168.100.1":
        raise ScenarioSpecError("true_multihop provider requires router IP 192.168.100.1")
    services = _service_by_name(topology)
    if topology.get("reachability_policy") and not topology.get("network_mode"):
        topology["network_mode"] = "multi_hop"
    roles = {str(item.get("role")) for item in services.values()}
    if roles != MULTIHOP_ROLES:
        raise ScenarioSpecError(
            "true_multihop requires exactly pivot_entry, pivot_relay, pivot_vault and pivot_decoy"
        )
    by_role = {str(item["role"]): item for item in services.values()}
    expected = {
        "pivot_entry": ("192.168.100.11", None, "192.168.110.11"),
        "pivot_relay": ("192.168.110.12", "192.168.100.12", "192.168.120.12"),
        "pivot_vault": ("192.168.120.13", "192.168.100.13", None),
        "pivot_decoy": ("192.168.100.14", None, None),
    }
    for role, (ip, bootstrap_ip, secondary_ip) in expected.items():
        item = by_role[role]
        if (item.get("ip"), item.get("bootstrap_ip"), item.get("secondary_ip")) != (
            ip, bootstrap_ip, secondary_ip
        ):
            raise ScenarioSpecError(
                f"true_multihop provider has fixed VLAN addresses; {role} does not match the provider contract"
            )
    if by_role["pivot_vault"].get("simulator") != "pivot_vault":
        raise ScenarioSpecError("true_multihop requires simulator=pivot_vault on the vault")
    for role, item in by_role.items():
        if role != "pivot_vault" and item.get("simulator"):
            raise ScenarioSpecError(f"Unexpected simulator on {role}: {item['simulator']}")

    supported_vulns = {"F16-ENTRY-CREDS", "F16-RELAY-CONFIG", "F16-RELAY-CREDS", "F16-VAULT-NOAUTH"}
    supported_controls = {
        "C16-RELAY-DIRECT-ISOLATION",
        "C16-VAULT-DIRECT-ISOLATION",
        "C16-DECOY-PASSWORD-DISABLED",
    }
    actual_vulns = {str(item.get("template_key")) for item in gt.get("vulnerabilities", []) or []}
    actual_controls = {str(item.get("template_key")) for item in gt.get("controls", []) or []}
    path_semantics = {
        str(path.get("semantics"))
        for path in gt.get("attack_paths", []) or []
        if path.get("semantics")
    }
    if path_semantics and path_semantics != {"network_pivot"}:
        raise ScenarioSpecError(
            "true_multihop Ground Truth paths must use network_pivot semantics"
        )
    if actual_vulns != supported_vulns or actual_controls != supported_controls:
        raise ScenarioSpecError(
            "true_multihop Ground Truth must match the F16 provider findings and isolation controls"
        )
    fixtures = []
    for item in topology.get("services", []) or []:
        fixtures.append({
            "device": item["name"],
            "ip": item["ip"],
            "vmid_offset": int(item["vmid_offset"]),
            "role": item["role"],
            "provider": "ansible.s20_pivot",
            "security_profile": item.get("security_profile", "vulnerable"),
            "simulator": item.get("simulator"),
            "vulnerability_keys": [],
            "control_keys": [],
        })
    return fixtures


def _validate_declared_compatibility(profile: str, ground_truth: dict[str, Any], spec: dict[str, Any]) -> None:
    declared = spec.get("compatibility") if isinstance(spec.get("compatibility"), dict) else {}
    profiles = declared.get("profiles", declared.get("required_profiles", []))
    if isinstance(profiles, str):
        profiles = [profiles]
    semantics = declared.get("semantics", declared.get("required_semantics", []))
    if isinstance(semantics, str):
        semantics = [semantics]
    if profiles and profile not in {str(item) for item in profiles}:
        raise ScenarioSpecError(
            f"Scenario compatibility requires one of {', '.join(map(str, profiles))}; got {profile}"
        )
    actual_semantics = {
        str(path.get("semantics"))
        for path in ground_truth.get("attack_paths", []) or []
        if path.get("semantics")
    }
    if semantics and not actual_semantics.issubset({str(item) for item in semantics}):
        raise ScenarioSpecError("Ground Truth attack-path semantics violate scenario compatibility")
    vuln_keys = {str(item.get("template_key")) for item in ground_truth.get("vulnerabilities", []) or []}
    required_vulns = {str(item) for item in declared.get("required_vulnerability_keys", [])}
    forbidden_vulns = {str(item) for item in declared.get("forbidden_vulnerability_keys", [])}
    if not required_vulns <= vuln_keys:
        raise ScenarioSpecError("Ground Truth is missing a required compatible vulnerability")
    if forbidden_vulns & vuln_keys:
        raise ScenarioSpecError("Ground Truth contains a forbidden vulnerability for this scenario")


def _validate_runtime_compatibility(
    profile: str,
    topology: dict[str, Any],
    ground_truth: dict[str, Any],
    spec: dict[str, Any],
) -> None:
    _validate_declared_compatibility(profile, ground_truth, spec)
    if profile == "flat_roles":
        if any(
            str(path.get("semantics", "logical_chain")) == "network_pivot"
            for path in ground_truth.get("attack_paths", []) or []
        ):
            raise ScenarioSpecError(
                "A network_pivot Ground Truth requires a network-capable execution profile"
            )
    unsupported = set(PREVIEW_ONLY_ALTERATIONS) | {
        "topology_add_pivot",
        "rotate_ports",
        "service_configuration",
        "initial_access",
        "rotate_credentials",
        "credential_reuse",
        "privilege_shift",
        "control_mutation",
        "vulnerability_parameters",
        "service_availability",
        "startup_delay",
        "rate_limit",
        "observability",
    }
    requested = {
        str(item.get("type"))
        for item in spec.get("alterations", []) or []
        if isinstance(item, dict)
    }
    blocked = sorted(requested & unsupported)
    if profile == "preview":
        blocked = []
    if blocked:
        raise ScenarioSpecError(
            f"Execution provider {profile} does not implement alterations: {', '.join(blocked)}"
        )


def build_execution_plan(
    spec: dict[str, Any], topology: dict[str, Any], ground_truth: dict[str, Any]
) -> dict[str, Any]:
    """Resolve and validate the concrete runtime adapter for a manual bundle."""
    requested = spec.get("execution") if isinstance(spec.get("execution"), dict) else {}
    adapter = str(requested.get("adapter", ADAPTER_ID))
    profile = str(requested.get("profile", "auto"))
    if profile == "preview":
        adapter = "scenario-lab"
    elif adapter != ADAPTER_ID:
        raise ScenarioSpecError(f"Unsupported execution adapter: {adapter}")
    if profile == "auto":
        profile = (
            "true_multihop"
            if any(
                item.get("bootstrap_ip") is not None
                or item.get("secondary_ip") is not None
                or str(item.get("role", "")).startswith("pivot_")
                for item in topology.get("services", []) or []
            )
            else "flat_roles"
        )
    if profile not in PROFILE_DEFINITIONS:
        raise ScenarioSpecError(
            f"Unsupported execution profile {profile!r}; choose one of {', '.join(PROFILE_DEFINITIONS)}"
        )
    if profile == "preview":
        fixtures = [
            {
                "device": item["name"],
                "ip": item["ip"],
                "vmid_offset": int(item.get("vmid_offset", index + 1)),
                "role": item.get("role", "unknown"),
                "provider": "scenario_lab.preview",
                "security_profile": item.get("security_profile", "vulnerable"),
                "vulnerability_keys": [],
                "control_keys": [],
            }
            for index, item in enumerate(topology.get("services", []))
        ]
    else:
        fixtures = (
            _validate_flat(topology, ground_truth)
            if profile == "flat_roles"
            else _validate_multihop(topology, ground_truth)
        )
    _validate_runtime_compatibility(profile, topology, ground_truth, spec)
    vuln_by_device = _findings_by_device(ground_truth, "vulnerabilities")
    control_by_device = _findings_by_device(ground_truth, "controls")
    for fixture in fixtures:
        fixture["vulnerability_keys"] = sorted(
            str(item.get("template_key")) for item in vuln_by_device.get(fixture["device"], [])
        )
        fixture["control_keys"] = sorted(
            str(item.get("template_key")) for item in control_by_device.get(fixture["device"], [])
        )

    return {
        "schema_version": 1,
        "adapter": adapter,
        "status": "preview" if profile == "preview" else "ready",
        "profile": profile,
        "source_scenario_id": PROFILE_DEFINITIONS[profile]["source_scenario_id"],
        "description": PROFILE_DEFINITIONS[profile]["description"],
        "capabilities": copy.deepcopy(PROFILE_DEFINITIONS[profile].get("capabilities", [])),
        "compatibility": {
            "status": "preview" if profile == "preview" else "ready",
            "profile": profile,
            "requested_alterations": sorted(str(item.get("type")) for item in spec.get("alterations", []) if isinstance(item, dict)),
            "declared": copy.deepcopy(spec.get("compatibility", {})),
        },
        "manual_expected_control_count": len(ground_truth.get("controls", []) or []),
        "router_provider": "scenario_lab.preview" if profile == "preview" else "ansible.openwrt_template",
        "service_fixtures": fixtures,
        "supported_playbooks": [] if profile == "preview" else [
            "03_deploy_scenario.yml",
            "04_inject_vulns.yml",
            "06_verify.yml",
            "99_teardown.yml",
        ],
    }
