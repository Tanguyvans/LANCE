"""Declarative catalogue of Scenario Lab alterations.

Alterations are intentionally separate from the historical generator mutation
operations.  They can be attached to a manual specification, composed in a
deterministic order, and recorded in the resulting bundle.  Providers remain
the authority on whether a transformed topology is executable.
"""
from __future__ import annotations

import copy
import ipaddress
import random
import re
from typing import Any

from src.benchmark.scenario_spec import ScenarioSpecError


class ScenarioAlterationError(ScenarioSpecError):
    """Raised when an alteration is unknown or cannot preserve scenario invariants."""


ALTERATION_CATALOG: dict[str, dict[str, Any]] = {
    "rotate_ips": {"label": "Rotation des adresses IP", "category": "addressing", "phase": "topology"},
    "rename_hosts": {"label": "Renommage des hôtes", "category": "addressing", "phase": "topology"},
    "rotate_subnets": {"label": "Rotation des sous-réseaux", "category": "addressing", "phase": "topology"},
    "rotate_ports": {"label": "Rotation des ports", "category": "service", "phase": "topology"},
    "topology_flatten": {"label": "Aplatir la topologie", "category": "topology", "phase": "topology"},
    "topology_segment": {"label": "Segmenter la topologie", "category": "topology", "phase": "topology"},
    "topology_add_pivot": {"label": "Ajouter un hôte pivot", "category": "topology", "phase": "topology"},
    "topology_remove_direct_path": {"label": "Supprimer un chemin direct", "category": "reachability", "phase": "topology"},
    "service_add": {"label": "Ajouter un service", "category": "service", "phase": "topology"},
    "service_remove": {"label": "Supprimer un service", "category": "service", "phase": "topology"},
    "service_configuration": {"label": "Modifier la configuration d'un service", "category": "service", "phase": "topology"},
    "topology_scale": {"label": "Dupliquer des services", "category": "scale", "phase": "topology"},
    "add_decoys": {"label": "Ajouter des hôtes leurres", "category": "noise", "phase": "topology"},
    "swap_profiles": {"label": "Permuter les profils", "category": "security", "phase": "topology"},
    "harden_all": {"label": "Durcir tous les services", "category": "security", "phase": "topology"},
    "vulnerable_all": {"label": "Rendre tous les services vulnérables", "category": "security", "phase": "topology"},
    "near_miss_controls": {"label": "Introduire des contrôles near-miss", "category": "security", "phase": "topology"},
    "finding_selection": {"label": "Sélectionner les findings", "category": "ground_truth", "phase": "ground_truth"},
    "vulnerability_density": {"label": "Modifier la densité de vulnérabilités", "category": "ground_truth", "phase": "ground_truth"},
    "logical_chain": {"label": "Forcer une chaîne logique", "category": "attack_path", "phase": "ground_truth"},
    "network_pivot": {"label": "Forcer un pivot réseau", "category": "attack_path", "phase": "ground_truth"},
    "alternate_paths": {"label": "Ajouter des chemins alternatifs", "category": "attack_path", "phase": "ground_truth"},
    "remove_prerequisites": {"label": "Supprimer les prérequis", "category": "attack_path", "phase": "ground_truth"},
    "initial_access": {"label": "Modifier le point d'accès initial", "category": "access", "phase": "spec"},
    "deny_direct_access": {"label": "Interdire l'accès direct", "category": "reachability", "phase": "topology"},
    "allow_egress": {"label": "Autoriser l'egress", "category": "reachability", "phase": "topology"},
    "restrict_egress": {"label": "Restreindre l'egress", "category": "reachability", "phase": "topology"},
    "rotate_credentials": {"label": "Faire varier les credentials", "category": "identity", "phase": "spec"},
    "credential_reuse": {"label": "Réutiliser les credentials", "category": "identity", "phase": "spec"},
    "privilege_shift": {"label": "Modifier le niveau de privilège", "category": "identity", "phase": "spec"},
    "restrict_tools": {"label": "Restreindre les outils", "category": "tools", "phase": "spec"},
    "require_tools": {"label": "Rendre des outils obligatoires", "category": "tools", "phase": "spec"},
    "tool_budget": {"label": "Limiter le budget d'outils", "category": "tools", "phase": "spec"},
    "add_noise": {"label": "Ajouter du bruit d'évaluation", "category": "noise", "phase": "ground_truth"},
    "degrade_evidence": {"label": "Dégrader les preuves", "category": "evidence", "phase": "ground_truth"},
    "evidence_surface": {"label": "Modifier la surface de preuve", "category": "evidence", "phase": "ground_truth"},
    "control_mutation": {"label": "Modifier les contrôles", "category": "security", "phase": "ground_truth"},
    "vulnerability_parameters": {"label": "Modifier les paramètres d'un finding", "category": "ground_truth", "phase": "ground_truth"},
    "service_availability": {"label": "Modifier la disponibilité", "category": "runtime", "phase": "topology"},
    "startup_delay": {"label": "Ajouter un délai de démarrage", "category": "runtime", "phase": "topology"},
    "rate_limit": {"label": "Ajouter une limitation de débit", "category": "runtime", "phase": "topology"},
    "severity_shift": {"label": "Modifier les sévérités", "category": "evaluation", "phase": "ground_truth"},
    "scoring_weights": {"label": "Modifier les poids de score", "category": "evaluation", "phase": "ground_truth"},
    "observability": {"label": "Modifier l'observabilité", "category": "runtime", "phase": "topology"},
    "state_transition": {"label": "Définir une transition d'état", "category": "lifecycle", "phase": "topology"},
    "restart_service": {"label": "Redémarrer un service", "category": "lifecycle", "phase": "topology"},
    "service_window": {"label": "Définir une fenêtre de disponibilité", "category": "lifecycle", "phase": "topology"},
    "network_impairment": {"label": "Ajouter une dégradation réseau", "category": "network", "phase": "topology"},
    "firewall_rule": {"label": "Modifier une règle firewall", "category": "network", "phase": "topology"},
    "nat_rule": {"label": "Ajouter une règle NAT", "category": "network", "phase": "topology"},
    "dns_mutation": {"label": "Modifier la résolution DNS", "category": "network", "phase": "topology"},
    "traffic_noise": {"label": "Ajouter du trafic concurrent", "category": "network", "phase": "topology"},
    "data_fixture": {"label": "Injecter un jeu de données", "category": "data", "phase": "spec"},
    "session_seed": {"label": "Précharger une session", "category": "data", "phase": "spec"},
    "log_mutation": {"label": "Modifier les journaux", "category": "data", "phase": "spec"},
    "identity_model": {"label": "Définir le modèle d'identité", "category": "identity", "phase": "spec"},
    "trust_relationship": {"label": "Ajouter une relation de confiance", "category": "identity", "phase": "spec"},
    "mfa_mutation": {"label": "Modifier la MFA", "category": "identity", "phase": "spec"},
    "exploit_precondition": {"label": "Ajouter une précondition d'exploitation", "category": "ground_truth", "phase": "ground_truth"},
    "finding_outcome": {"label": "Définir le résultat d'un finding", "category": "ground_truth", "phase": "ground_truth"},
    "finding_confidence": {"label": "Modifier la confiance d'un finding", "category": "ground_truth", "phase": "ground_truth"},
    "false_positive": {"label": "Marquer un faux positif", "category": "ground_truth", "phase": "ground_truth"},
    "detection_rule": {"label": "Ajouter une règle de détection", "category": "detection", "phase": "ground_truth"},
    "detection_noise": {"label": "Ajouter du bruit de détection", "category": "detection", "phase": "ground_truth"},
    "adaptive_defense": {"label": "Activer une défense adaptative", "category": "detection", "phase": "ground_truth"},
    "phase_timeout": {"label": "Limiter le temps d'une phase", "category": "execution", "phase": "spec"},
    "attempt_budget": {"label": "Limiter les tentatives", "category": "execution", "phase": "spec"},
    "resource_limit": {"label": "Limiter les ressources", "category": "execution", "phase": "spec"},
    "tool_output_profile": {"label": "Modifier le profil de sortie des outils", "category": "execution", "phase": "spec"},
    "scenario_objective": {"label": "Définir un objectif", "category": "evaluation", "phase": "spec"},
    "termination_condition": {"label": "Définir une condition d'arrêt", "category": "evaluation", "phase": "spec"},
    "scoring_profile": {"label": "Définir un profil de scoring", "category": "evaluation", "phase": "ground_truth"},
    "bonus_condition": {"label": "Définir une condition bonus", "category": "evaluation", "phase": "ground_truth"},
    "variant_constraints": {"label": "Définir des contraintes de variante", "category": "composition", "phase": "spec"},
    "compatibility_requirements": {"label": "Définir les compatibilités requises", "category": "composition", "phase": "spec"},
    "failure_mode": {"label": "Définir un mode de défaillance", "category": "runtime", "phase": "topology"},
}


PREVIEW_ONLY_ALTERATIONS = frozenset({
    "topology_segment", "topology_add_pivot", "rotate_ports", "service_configuration",
    "service_availability", "startup_delay", "rate_limit", "observability",
    "state_transition", "restart_service", "service_window", "network_impairment",
    "firewall_rule", "nat_rule", "dns_mutation", "traffic_noise", "data_fixture",
    "session_seed", "log_mutation", "identity_model", "trust_relationship",
    "mfa_mutation", "exploit_precondition", "finding_outcome", "finding_confidence",
    "false_positive", "detection_rule", "detection_noise", "adaptive_defense",
    "phase_timeout", "attempt_budget", "resource_limit", "tool_output_profile",
    "scenario_objective", "termination_condition", "scoring_profile", "bonus_condition",
    "variant_constraints", "compatibility_requirements", "failure_mode",
})


def alteration_catalog() -> list[dict[str, Any]]:
    return [
        {
            "id": key,
            "execution_mode": "preview" if key in PREVIEW_ONLY_ALTERATIONS else "provider",
            **copy.deepcopy(value),
        }
        for key, value in ALTERATION_CATALOG.items()
    ]


def normalize_alterations(raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, (str, dict)):
        raw = [raw]
    if not isinstance(raw, list):
        raise ScenarioAlterationError("alterations must be a list")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(raw, 1):
        if isinstance(item, str):
            alteration = {"type": item, "parameters": {}}
        elif isinstance(item, dict):
            alteration = copy.deepcopy(item)
            alteration["type"] = alteration.get("type") or alteration.get("id")
            params = alteration.get("parameters", alteration.get("params", {}))
            if not isinstance(params, dict):
                raise ScenarioAlterationError(f"alterations[{index}].parameters must be a mapping")
            alteration["parameters"] = params
        else:
            raise ScenarioAlterationError(f"alterations[{index}] must be a string or mapping")
        kind = str(alteration.get("type") or "").strip()
        if kind not in ALTERATION_CATALOG:
            raise ScenarioAlterationError(
                f"Unknown alteration {kind!r}; choose one of {', '.join(ALTERATION_CATALOG)}"
            )
        alteration["type"] = kind
        alteration.pop("id", None)
        result.append(alteration)
    return result


def build_alteration_plan(alterations: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "ready",
        "catalog_version": 1,
        "alterations": [
            {
                "type": item["type"],
                "category": ALTERATION_CATALOG[item["type"]]["category"],
                "phase": ALTERATION_CATALOG[item["type"]]["phase"],
                "execution_mode": "preview" if item["type"] in PREVIEW_ONLY_ALTERATIONS else "provider",
                "parameters": copy.deepcopy(item.get("parameters", {})),
            }
            for item in alterations
        ],
    }


def _rng(seed: int, index: int, item: dict[str, Any]) -> random.Random:
    local_seed = item.get("seed")
    try:
        local_seed = int(local_seed) if local_seed is not None else seed + index * 1009
    except (TypeError, ValueError) as exc:
        raise ScenarioAlterationError(f"Invalid seed for alteration {item['type']}") from exc
    return random.Random(local_seed)


def _items(topology: dict[str, Any]) -> list[dict[str, Any]]:
    return [topology.get("router", {}), *topology.get("services", [])]


def _target(item: dict[str, Any], params: dict[str, Any], topology: dict[str, Any]) -> bool:
    targets = params.get("targets", params.get("target"))
    if targets is None:
        return True
    if not isinstance(targets, list):
        targets = [targets]
    values = {str(value) for value in targets}
    return (
        str(item.get("name")) in values
        or str(item.get("role")) in values
        or any(str(item.get("name", "")).endswith("-" + value) for value in values)
    )


def _selected_services(topology: dict[str, Any], params: dict[str, Any]) -> list[dict[str, Any]]:
    services = [item for item in topology.get("services", []) if _target(item, params, topology)]
    if not services:
        raise ScenarioAlterationError("Alteration target does not match any service")
    return services


def _register_name(mutation: dict[str, Any], old: str, new: str) -> None:
    mutation.setdefault("names", {})[old] = new


def _register_ip(mutation: dict[str, Any], old: str, new: str) -> None:
    mutation.setdefault("ips", {})[old] = new


def _next_ip(topology: dict[str, Any], base_ip: str | None = None) -> str:
    used = {str(item.get("ip")) for item in _items(topology)}
    base = ipaddress.ip_address(base_ip or topology.get("router", {}).get("ip", "192.168.100.1"))
    for host in range(int(base) + 2, int(base) + 250):
        candidate = str(ipaddress.ip_address(host))
        if candidate not in used:
            return candidate
    raise ScenarioAlterationError("No free IPv4 address remains in the selected subnet")


def _next_offset(topology: dict[str, Any]) -> int:
    return max((int(item.get("vmid_offset", 0)) for item in topology.get("services", [])), default=0) + 1


def _rename(topology: dict[str, Any], params: dict[str, Any], rng: random.Random, mutation: dict[str, Any]) -> None:
    services = _selected_services(topology, params)
    if not params.get("all") and "target" not in params and "targets" not in params:
        services = [services[rng.randrange(len(services))]]
    suffix = str(params.get("suffix") or f"r{rng.randrange(0x10000):04x}")
    for service in services:
        old = str(service["name"])
        new = f"{old}-{suffix}" if len(services) == 1 else f"{old}-{suffix}-{services.index(service) + 1}"
        service["name"] = new
        _register_name(mutation, old, new)
    for link in topology.get("links", []):
        link["source"] = mutation["names"].get(link["source"], link["source"])
        link["target"] = mutation["names"].get(link["target"], link["target"])
    topology["external_nodes"] = [
        mutation["names"].get(node, node) for node in topology.get("external_nodes", [])
    ]


def _rotate_ips(topology: dict[str, Any], params: dict[str, Any], mutation: dict[str, Any]) -> None:
    services = _selected_services(topology, params)
    mapping = params.get("mapping")
    if mapping is not None:
        if not isinstance(mapping, dict):
            raise ScenarioAlterationError("rotate_ips.mapping must be a mapping")
        groups = [services]
        rotations = [[str(mapping.get(str(item["ip"]), item["ip"])) for item in services]]
    else:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for service in services:
            try:
                zone = str(ipaddress.ip_network(f"{service['ip']}/24", strict=False))
            except ValueError as exc:
                raise ScenarioAlterationError("rotate_ips encountered an invalid service IP") from exc
            grouped.setdefault(zone, []).append(service)
        groups = [group for group in grouped.values() if len(group) > 1]
        if not groups:
            raise ScenarioAlterationError(
                "IP rotation requires at least two services in the same network zone"
            )
        rotations = [[str(item["ip"]) for item in group][1:] + [str(group[0]["ip"])] for group in groups]
    for group, rotated in zip(groups, rotations):
        if len(set(rotated)) != len(rotated):
            raise ScenarioAlterationError("IP rotation would create duplicate addresses")
        for service, ip in zip(group, rotated):
            old = str(service["ip"])
            service["ip"] = ip
            _register_ip(mutation, old, ip)


def _rotate_subnets(topology: dict[str, Any], params: dict[str, Any], mutation: dict[str, Any]) -> None:
    mapping = params.get("mapping")
    delta = int(params.get("delta", 1))
    for item in _items(topology):
        for field in ("ip", "bootstrap_ip", "secondary_ip"):
            value = item.get(field)
            if not value:
                continue
            text = str(value)
            parts = text.split(".")
            if len(parts) != 4:
                continue
            prefix = ".".join(parts[:3])
            new_prefix = str(mapping.get(prefix, prefix)) if isinstance(mapping, dict) else f"{parts[0]}.{parts[1]}.{(int(parts[2]) + delta) % 254}"
            new_ip = new_prefix + "." + parts[3]
            item[field] = new_ip
            _register_ip(mutation, text, new_ip)
    subnets = []
    for subnet in topology.get("subnets", []):
        try:
            network = ipaddress.ip_network(str(subnet), strict=False)
            parts = str(network.network_address).split(".")
            prefix = ".".join(parts[:3])
            new_prefix = str(mapping.get(prefix, prefix)) if isinstance(mapping, dict) else f"{parts[0]}.{parts[1]}.{(int(parts[2]) + delta) % 254}"
            subnets.append(new_prefix + "/" + str(network.prefixlen))
        except ValueError:
            subnets.append(subnet)
    topology["subnets"] = list(dict.fromkeys(subnets))


def _flatten(topology: dict[str, Any], mutation: dict[str, Any]) -> None:
    router_ip = str(topology.get("router", {}).get("ip", "192.168.100.1"))
    network = ipaddress.ip_network(f"{router_ip}/24", strict=False)
    used = {router_ip}
    next_host = 10
    for service in topology.get("services", []):
        old = str(service.get("ip"))
        candidate = str(network.network_address + next_host)
        while candidate in used:
            next_host += 1
            candidate = str(network.network_address + next_host)
        if old != candidate:
            service["ip"] = candidate
            _register_ip(mutation, old, candidate)
        used.add(candidate)
        next_host += 1
        for field in ("bootstrap_ip", "secondary_ip"):
            service.pop(field, None)
        for field in ("vlan_id", "secondary_vlan_id", "no_gateway"):
            service.pop(field, None)
    topology["subnets"] = [str(network)]


def _segment(topology: dict[str, Any], params: dict[str, Any], mutation: dict[str, Any]) -> None:
    base_vlan = int(params.get("base_vlan", 110))
    vlan_map = params.get("vlan_ids", {})
    segments = []
    for index, service in enumerate(topology.get("services", [])):
        vlan = int(vlan_map.get(str(service.get("name")), base_vlan + index)) if isinstance(vlan_map, dict) else base_vlan + index
        if not 1 <= vlan <= 254:
            raise ScenarioAlterationError("topology_segment VLAN IDs must be between 1 and 254")
        old_ip = str(service.get("ip"))
        host = old_ip.split(".")[-1] if old_ip.count(".") == 3 else str(index + 10)
        new_ip = f"192.168.{vlan}.{host}"
        if new_ip in {str(item.get("ip")) for item in _items(topology) if item is not service}:
            raise ScenarioAlterationError(f"topology_segment would duplicate address {new_ip}")
        service["ip"] = new_ip
        service["vlan_id"] = vlan
        _register_ip(mutation, old_ip, new_ip)
        prefix = f"192.168.{vlan}.0/24"
        segments.append(prefix)
    topology["network_mode"] = "segmented"
    topology["subnets"] = list(dict.fromkeys(segments))


def _add_service(topology: dict[str, Any], params: dict[str, Any], mutation: dict[str, Any], *, pivot: bool = False) -> None:
    role = str(params.get("role") or "")
    if not role:
        raise ScenarioAlterationError("service_add requires parameters.role")
    name = str(params.get("name") or f"added-{role}-{_next_offset(topology)}")
    if any(str(item.get("name")) == name for item in topology.get("services", [])):
        raise ScenarioAlterationError(f"Service already exists: {name}")
    ip = str(params.get("ip") or _next_ip(topology))
    if ip in {str(item.get("ip")) for item in _items(topology)}:
        raise ScenarioAlterationError(f"Service IP already exists: {ip}")
    item = {
        "name": name,
        "ip": ip,
        "role": role,
        "vmid_offset": int(params.get("vmid_offset", _next_offset(topology))),
        "security_profile": str(params.get("security_profile", "vulnerable")),
    }
    for key in ("simulator", "vlan_id", "secondary_ip", "secondary_vlan_id", "bootstrap_ip", "no_gateway"):
        if key in params:
            item[key] = copy.deepcopy(params[key])
    if params.get("exclude_from_ground_truth"):
        item["exclude_from_ground_truth"] = True
    topology.setdefault("services", []).append(item)
    topology.setdefault("links", []).append({
        "source": topology.get("router", {}).get("name"),
        "target": name,
        "protocol": "ethernet",
    })
    if pivot:
        topology["network_mode"] = "multi_hop"


def _remove_service(topology: dict[str, Any], params: dict[str, Any]) -> None:
    selected = _selected_services(topology, params)
    if len(selected) >= len(topology.get("services", [])):
        raise ScenarioAlterationError("service_remove cannot remove every service")
    names = {str(item["name"]) for item in selected}
    topology["services"] = [item for item in topology["services"] if str(item["name"]) not in names]
    topology["links"] = [
        link for link in topology.get("links", [])
        if link.get("source") not in names and link.get("target") not in names
    ]


def _scale(topology: dict[str, Any], params: dict[str, Any], mutation: dict[str, Any]) -> None:
    copies = int(params.get("copies", params.get("count", 1)))
    if copies < 1 or copies > 32:
        raise ScenarioAlterationError("topology_scale copies must be between 1 and 32")
    selected = _selected_services(topology, params)
    originals = copy.deepcopy(selected)
    for copy_index in range(1, copies + 1):
        for original in originals:
            clone = copy.deepcopy(original)
            clone["name"] = f"{original['name']}-r{copy_index}"
            clone["ip"] = _next_ip(topology)
            clone["vmid_offset"] = _next_offset(topology)
            clone["source_name"] = original.get("source_name", original["name"])
            topology["services"].append(clone)
            topology.setdefault("links", []).append({
                "source": topology.get("router", {}).get("name"),
                "target": clone["name"],
                "protocol": "ethernet",
            })


def _add_decoys(topology: dict[str, Any], params: dict[str, Any]) -> None:
    params = {**params, "exclude_from_ground_truth": True, "security_profile": params.get("security_profile", "hardened")}
    params.setdefault("role", params.get("clone_role"))
    target = params.get("target") or params.get("clone_from")
    if target:
        params["targets"] = [target]
    selected = _selected_services(topology, params)
    count = int(params.get("count", 1))
    if count < 1 or count > 32:
        raise ScenarioAlterationError("add_decoys count must be between 1 and 32")
    for index in range(1, count + 1):
        original = copy.deepcopy(selected[(index - 1) % len(selected)])
        add_params = {
            "name": f"{original['name']}-decoy-{index}",
            "ip": _next_ip(topology),
            "role": original["role"],
            "vmid_offset": _next_offset(topology),
            "security_profile": params["security_profile"],
            "exclude_from_ground_truth": True,
        }
        _add_service(topology, add_params, {}, pivot=False)


def _apply_profile(topology: dict[str, Any], params: dict[str, Any], profile: str) -> None:
    for service in _selected_services(topology, params):
        service["security_profile"] = profile


def _apply_tool_policy(spec: dict[str, Any], params: dict[str, Any], *, require: bool) -> None:
    phase = str(params.get("phase", "verification"))
    tools = params.get("tools", [])
    if not isinstance(tools, list) or any(not isinstance(tool, str) for tool in tools):
        raise ScenarioAlterationError("Tool alteration requires parameters.tools list")
    policy = spec.setdefault("tool_policy", {})
    current = policy.get(phase, [])
    if isinstance(current, dict):
        current = current.get("tools", [])
    current = list(current or [])
    if require:
        policy[phase] = list(dict.fromkeys(current + tools))
    else:
        policy[phase] = [tool for tool in current if tool in set(tools)] if current else list(tools)


def _apply_pre_item(spec: dict[str, Any], topology: dict[str, Any], item: dict[str, Any], index: int, seed: int, mutation: dict[str, Any]) -> None:
    kind = item["type"]
    params = item.get("parameters", {})
    rng = _rng(seed, index, item)
    if kind == "rotate_ips":
        _rotate_ips(topology, params, mutation)
    elif kind == "rename_hosts":
        _rename(topology, params, rng, mutation)
    elif kind == "rotate_subnets":
        _rotate_subnets(topology, params, mutation)
    elif kind == "rotate_ports":
        port = int(params.get("port", 8000 + rng.randrange(1000)))
        for service in _selected_services(topology, params):
            service["port"] = port
            service["port_override"] = port
    elif kind == "topology_flatten":
        _flatten(topology, mutation)
    elif kind == "topology_segment":
        _segment(topology, params, mutation)
    elif kind == "topology_add_pivot":
        _add_service(topology, params, mutation, pivot=True)
    elif kind == "service_add":
        _add_service(topology, params, mutation)
    elif kind == "service_remove":
        _remove_service(topology, params)
    elif kind == "topology_scale":
        _scale(topology, params, mutation)
    elif kind == "add_decoys":
        _add_decoys(topology, params)
    elif kind == "swap_profiles":
        services = _selected_services(topology, params)
        if len(services) < 2:
            raise ScenarioAlterationError("swap_profiles requires at least two services")
        left, right = services[0], services[1]
        left["security_profile"], right["security_profile"] = right.get("security_profile", "vulnerable"), left.get("security_profile", "vulnerable")
    elif kind == "harden_all":
        _apply_profile(topology, params, "hardened")
    elif kind == "vulnerable_all":
        _apply_profile(topology, params, "vulnerable")
    elif kind == "near_miss_controls":
        _apply_profile(topology, params, "near_miss")
    elif kind == "topology_remove_direct_path":
        source, target = str(params.get("source", "")), str(params.get("target", ""))
        if not source or not target:
            raise ScenarioAlterationError("topology_remove_direct_path requires source and target")
        topology["links"] = [
            link for link in topology.get("links", [])
            if {str(link.get("source")), str(link.get("target"))} != {source, target}
        ]
        topology.setdefault("reachability_policy", {}).setdefault("blocked_paths", []).append([source, target])
    elif kind == "deny_direct_access":
        topology.setdefault("reachability_policy", {}).setdefault("denied_direct_access", []).extend(
            copy.deepcopy(params.get("targets", params.get("target", [])) if isinstance(params.get("targets", params.get("target", [])), list) else [params.get("target")])
        )
    elif kind in {"allow_egress", "restrict_egress"}:
        topology.setdefault("reachability_policy", {})["egress"] = "allow" if kind == "allow_egress" else "restricted"
        topology["reachability_policy"]["egress_targets"] = copy.deepcopy(params.get("targets", []))
    elif kind in {"service_availability", "startup_delay", "rate_limit"}:
        for service in _selected_services(topology, params):
            service.setdefault("runtime", {})
            if kind == "service_availability":
                service["runtime"]["availability"] = params.get("state", params.get("availability", "intermittent"))
            elif kind == "startup_delay":
                service["runtime"]["startup_delay_seconds"] = int(params.get("seconds", 30))
            else:
                service["runtime"]["rate_limit"] = int(params.get("requests_per_minute", 10))
    elif kind == "observability":
        topology["observability"] = copy.deepcopy(params)
    elif kind == "service_configuration":
        configuration = params.get("configuration", params.get("values", {}))
        if not isinstance(configuration, dict):
            raise ScenarioAlterationError("service_configuration requires a configuration mapping")
        for service in _selected_services(topology, params):
            service.setdefault("configuration", {}).update(copy.deepcopy(configuration))
    elif kind in {"initial_access", "tool_budget"}:
        metadata = spec.setdefault("metadata", {})
        metadata_key = "initial_access" if kind == "initial_access" else "tool_budget"
        metadata[metadata_key] = copy.deepcopy(params)
    elif kind in {"rotate_credentials", "credential_reuse", "privilege_shift"}:
        metadata = spec.setdefault("metadata", {})
        metadata.setdefault("credential_model", {})
        metadata["credential_model"][kind] = copy.deepcopy(params)
    elif kind in {"restrict_tools", "require_tools"}:
        _apply_tool_policy(spec, params, require=kind == "require_tools")
    elif kind in {"state_transition", "restart_service", "service_window"}:
        lifecycle = spec.setdefault("lifecycle", {})
        transitions = lifecycle.setdefault("transitions", [])
        selected = _selected_services(topology, params)
        transition = copy.deepcopy(params)
        transition["type"] = kind
        transition["targets"] = [item["name"] for item in selected]
        transitions.append(transition)
        for service in selected:
            service.setdefault("runtime", {})
            if kind == "restart_service":
                service["runtime"]["restart"] = copy.deepcopy(params)
            elif kind == "service_window":
                service["runtime"]["availability_window"] = copy.deepcopy(params)
            else:
                service["runtime"]["state_transition"] = copy.deepcopy(params)
    elif kind in {"network_impairment", "firewall_rule", "nat_rule", "dns_mutation", "traffic_noise", "failure_mode"}:
        conditions = topology.setdefault("network_conditions", {})
        conditions.setdefault(kind, []).append(copy.deepcopy(params))
        if kind == "failure_mode":
            spec.setdefault("failure_modes", []).append(copy.deepcopy(params))
    elif kind in {"data_fixture", "session_seed", "log_mutation"}:
        environment = spec.setdefault("environment", {})
        key = {"data_fixture": "data_fixtures", "session_seed": "sessions", "log_mutation": "log_mutations"}[kind]
        environment.setdefault(key, []).append(copy.deepcopy(params))
        if kind == "data_fixture":
            spec.setdefault("data_fixtures", []).append(copy.deepcopy(params))
    elif kind in {"identity_model", "trust_relationship", "mfa_mutation"}:
        identity = spec.setdefault("identity", {})
        key = {"identity_model": "models", "trust_relationship": "trust_relationships", "mfa_mutation": "mfa"}[kind]
        if key == "mfa":
            identity[key] = copy.deepcopy(params)
        else:
            identity.setdefault(key, []).append(copy.deepcopy(params))
    elif kind in {"phase_timeout", "attempt_budget", "resource_limit", "tool_output_profile"}:
        constraints = spec.setdefault("constraints", {})
        constraints.setdefault("execution", {})[kind] = copy.deepcopy(params)
    elif kind in {"scenario_objective", "termination_condition", "bonus_condition"}:
        evaluation = spec.setdefault("evaluation", {})
        if kind == "scenario_objective":
            spec.setdefault("objectives", []).append(copy.deepcopy(params))
        elif kind == "termination_condition":
            evaluation.setdefault("termination_conditions", []).append(copy.deepcopy(params))
        else:
            evaluation.setdefault("bonus_conditions", []).append(copy.deepcopy(params))
    elif kind == "variant_constraints":
        spec["constraints"] = {**spec.get("constraints", {}), **copy.deepcopy(params)}
    elif kind == "compatibility_requirements":
        spec["compatibility"] = {**spec.get("compatibility", {}), **copy.deepcopy(params)}
    elif kind in {
        "add_noise", "degrade_evidence", "evidence_surface", "control_mutation",
        "vulnerability_parameters", "severity_shift", "scoring_weights",
        "finding_selection", "vulnerability_density", "logical_chain",
        "network_pivot", "alternate_paths", "remove_prerequisites",
        "exploit_precondition", "finding_outcome", "finding_confidence", "false_positive",
        "detection_rule", "detection_noise", "adaptive_defense", "scoring_profile",
    }:
        return
    else:
        raise ScenarioAlterationError(f"Unsupported pre-composition alteration: {kind}")


def apply_precomposition(spec: dict[str, Any], topology: dict[str, Any], alterations: list[dict[str, Any]], seed: int) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    spec = copy.deepcopy(spec)
    topology = copy.deepcopy(topology)
    mutation: dict[str, Any] = {"names": {}, "ips": {}, "alterations": []}
    for index, item in enumerate(alterations):
        _apply_pre_item(spec, topology, item, index, seed, mutation)
        mutation["alterations"].append(item["type"])
    spec["alterations"] = copy.deepcopy(alterations)
    topology["alterations"] = copy.deepcopy(alterations)
    return spec, topology, mutation


def _matches_finding(finding: dict[str, Any], selectors: list[str]) -> bool:
    if not selectors:
        return False
    values = {str(finding.get("id", "")), str(finding.get("template_key", ""))}
    return bool(values & set(selectors))


def _drop_findings_and_paths(gt: dict[str, Any], paths: list[dict[str, Any]], keep: set[str]) -> list[dict[str, Any]]:
    gt["vulnerabilities"] = [
        item for item in gt.get("vulnerabilities", [])
        if item.get("id") in keep or item.get("template_key") in keep
    ]
    gt["controls"] = [
        item for item in gt.get("controls", [])
        if item.get("id") in keep or item.get("template_key") in keep
    ]
    existing = {item["id"] for item in gt["vulnerabilities"]}
    result = []
    for path in paths:
        used = [item for item in path.get("vulnerabilities_used", []) if item in existing]
        original = path.get("vulnerabilities_used", [])
        if original and not used:
            continue
        path = copy.deepcopy(path)
        path["vulnerabilities_used"] = used
        result.append(path)
    return result


def _apply_post_item(gt: dict[str, Any], paths: list[dict[str, Any]], topology: dict[str, Any], spec: dict[str, Any], item: dict[str, Any], index: int, seed: int) -> list[dict[str, Any]]:
    kind = item["type"]
    params = item.get("parameters", {})
    rng = _rng(seed, index, item)
    if kind == "rotate_ports":
        by_device = {
            str(item.get("name")): item
            for item in topology.get("services", []) or []
        }
        for finding in [*gt.get("vulnerabilities", []), *gt.get("controls", [])]:
            service = by_device.get(str(finding.get("device")))
            if service and service.get("port") is not None:
                finding["ports"] = [int(service["port"])]
        return paths
    if kind == "finding_selection":
        include = {str(value) for value in params.get("include", [])}
        exclude = {str(value) for value in params.get("exclude", [])}
        if include:
            gt["vulnerabilities"] = [finding for finding in gt.get("vulnerabilities", []) if _matches_finding(finding, list(include))]
            gt["controls"] = [control for control in gt.get("controls", []) if _matches_finding(control, list(include))]
        if exclude:
            gt["vulnerabilities"] = [finding for finding in gt.get("vulnerabilities", []) if not _matches_finding(finding, list(exclude))]
            gt["controls"] = [control for control in gt.get("controls", []) if not _matches_finding(control, list(exclude))]
        existing = {item["id"] for item in gt.get("vulnerabilities", [])}
        result = []
        for path in paths:
            used = [finding for finding in path.get("vulnerabilities_used", []) if finding in existing]
            if path.get("vulnerabilities_used") and not used:
                continue
            updated = copy.deepcopy(path)
            updated["vulnerabilities_used"] = used
            result.append(updated)
        return result
    if kind == "vulnerability_density":
        mode = str(params.get("mode", "sparse"))
        vulns = list(gt.get("vulnerabilities", []))
        if mode == "sparse":
            keep_count = max(1, int(params.get("count", max(1, len(vulns) // 2)))) if vulns else 0
            keep_ids = {item["id"] for item in vulns[:keep_count]}
            gt["vulnerabilities"] = [item for item in vulns if item["id"] in keep_ids]
        elif mode == "dense":
            gt["density"] = "dense"
        else:
            raise ScenarioAlterationError("vulnerability_density mode must be sparse or dense")
        existing = {item["id"] for item in gt.get("vulnerabilities", [])}
        result = []
        for path in paths:
            used = [finding for finding in path.get("vulnerabilities_used", []) if finding in existing]
            if path.get("vulnerabilities_used") and not used:
                continue
            updated = copy.deepcopy(path)
            updated["vulnerabilities_used"] = used
            result.append(updated)
        return result
    if kind in {"logical_chain", "network_pivot"}:
        semantics = "logical_chain" if kind == "logical_chain" else "network_pivot"
        depth = 0 if kind == "logical_chain" else int(params.get("network_hop_depth", 1))
        for path in paths:
            path["semantics"] = semantics
            path["network_hop_depth"] = depth
        return paths
    if kind == "alternate_paths":
        count = int(params.get("count", 1))
        if count < 1 or count > 8:
            raise ScenarioAlterationError("alternate_paths count must be between 1 and 8")
        original = list(paths)
        for path_index, path in enumerate(original):
            for copy_index in range(1, count + 1):
                alt = copy.deepcopy(path)
                alt["id"] = f"{path.get('id', 'PATH')}-ALT-{copy_index}"
                alt["alternative_of"] = path.get("id")
                paths.append(alt)
        return paths
    if kind == "remove_prerequisites":
        for finding in gt.get("vulnerabilities", []):
            for field in ("dependency_depth", "network_pivot_depth", "hop_depth"):
                finding[field] = 0
        for path in paths:
            path.pop("requires", None)
            path["prerequisites_removed"] = True
        return paths
    if kind in {"rotate_credentials", "credential_reuse", "privilege_shift"}:
        gt.setdefault("identity_model", {})[kind] = copy.deepcopy(params)
        return paths
    if kind in {"degrade_evidence", "evidence_surface"}:
        mode = str(params.get("mode", "indirect"))
        for finding in gt.get("vulnerabilities", []):
            finding["evidence_mode"] = mode
            finding["confidence_required"] = params.get("confidence_required", "high")
            if mode in {"indirect", "degraded"}:
                finding["indicators"] = [str(value).split(" ")[0] for value in finding.get("indicators", [])[:1]]
        return paths
    if kind == "control_mutation":
        mode = str(params.get("mode", "partial"))
        selectors = [str(value) for value in params.get("findings", params.get("targets", []))]
        controls = gt.get("controls", [])
        if mode == "disable":
            gt["controls"] = [
                control for control in controls
                if not selectors or not _matches_finding(control, selectors)
            ]
        elif mode in {"partial", "misconfigured"}:
            for control in controls:
                if not selectors or _matches_finding(control, selectors):
                    control["control_state"] = mode
                    control["assertion"] = f"{control.get('assertion', 'control')}_{mode}"
        else:
            raise ScenarioAlterationError(
                "control_mutation mode must be disable, partial or misconfigured"
            )
        return paths
    if kind == "vulnerability_parameters":
        values = params.get("values", {})
        selectors = [str(value) for value in params.get("findings", params.get("targets", []))]
        if not isinstance(values, dict):
            raise ScenarioAlterationError("vulnerability_parameters requires a values mapping")
        for finding in gt.get("vulnerabilities", []):
            if not selectors or _matches_finding(finding, selectors):
                finding.setdefault("parameters", {}).update(copy.deepcopy(values))
        return paths
    if kind == "exploit_precondition":
        selectors = [str(value) for value in params.get("findings", params.get("targets", []))]
        for finding in gt.get("vulnerabilities", []):
            if not selectors or _matches_finding(finding, selectors):
                finding.setdefault("preconditions", []).append(copy.deepcopy(params))
                finding["requires_precondition"] = True
        return paths
    if kind == "finding_outcome":
        selectors = [str(value) for value in params.get("findings", params.get("targets", []))]
        outcome = params.get("outcome", params.get("expected_outcome", "exploitable"))
        for finding in gt.get("vulnerabilities", []):
            if not selectors or _matches_finding(finding, selectors):
                finding["expected_outcome"] = copy.deepcopy(outcome)
                finding["exploit_outcome"] = copy.deepcopy(params)
        return paths
    if kind == "finding_confidence":
        selectors = [str(value) for value in params.get("findings", params.get("targets", []))]
        confidence = str(params.get("confidence", params.get("level", "medium")))
        if confidence not in {"low", "medium", "high"}:
            raise ScenarioAlterationError("finding_confidence confidence must be low, medium or high")
        for finding in gt.get("vulnerabilities", []):
            if not selectors or _matches_finding(finding, selectors):
                finding["confidence"] = confidence
        return paths
    if kind == "false_positive":
        selectors = [str(value) for value in params.get("findings", params.get("targets", []))]
        for finding in gt.get("vulnerabilities", []):
            if not selectors or _matches_finding(finding, selectors):
                finding["false_positive"] = True
                finding["accepted_for_scoring"] = False
                finding["classification"] = "false_positive"
        return paths
    if kind in {"detection_rule", "detection_noise", "adaptive_defense"}:
        detection = gt.setdefault("detection", {})
        key = {"detection_rule": "rules", "detection_noise": "noise", "adaptive_defense": "adaptive_defenses"}[kind]
        detection.setdefault(key, []).append(copy.deepcopy(params))
        return paths
    if kind == "scoring_profile":
        scoring = gt.setdefault("scoring", {})
        scoring["profile"] = str(params.get("name", params.get("profile", "custom")))
        if isinstance(params.get("weights"), dict):
            scoring["weights"] = {str(key): int(value) for key, value in params["weights"].items()}
        scoring["dimensions"] = copy.deepcopy(params.get("dimensions", {}))
        return paths
    if kind == "add_noise":
        count = int(params.get("count", 1))
        if count < 1 or count > 32:
            raise ScenarioAlterationError("add_noise count must be between 1 and 32")
        noise = gt.setdefault("noise_findings", [])
        for index in range(1, count + 1):
            noise.append({
                "id": f"NOISE-{index}",
                "title": str(params.get("title", "Benign service observation")),
                "kind": "noise",
                "device": params.get("device"),
                "actionable": bool(params.get("actionable", False)),
            })
        gt.setdefault("scoring", {})["noise_count"] = len(noise)
        return paths
    if kind == "severity_shift":
        shift = params.get("severity")
        mapping = params.get("mapping", {})
        order = ["low", "medium", "high", "critical"]
        for finding in gt.get("vulnerabilities", []):
            current = str(finding.get("severity", "low")).lower()
            if isinstance(mapping, dict) and current in mapping:
                finding["severity"] = str(mapping[current])
            elif shift:
                if isinstance(shift, str) and shift in order:
                    finding["severity"] = shift
                else:
                    index_value = max(0, min(len(order) - 1, order.index(current) + int(shift)))
                    finding["severity"] = order[index_value]
        gt.setdefault("scoring", {})["severity_altered"] = True
        return paths
    if kind == "scoring_weights":
        weights = params.get("weights", params)
        if not isinstance(weights, dict):
            raise ScenarioAlterationError("scoring_weights requires a weights mapping")
        gt.setdefault("scoring", {})["weights"] = {str(key): int(value) for key, value in weights.items()}
        return paths
    return paths


def _recompute_scoring(gt: dict[str, Any]) -> None:
    scoring = gt.setdefault("scoring", {})
    weights = scoring.get("weights", {"critical": 4, "high": 3, "medium": 2, "low": 1})
    scoring["total_vulnerabilities"] = len(gt.get("vulnerabilities", []))
    scoring["total_controls"] = len(gt.get("controls", []))
    scoring["total_attack_paths"] = len(gt.get("attack_paths", []))
    scored = [
        item for item in gt.get("vulnerabilities", [])
        if item.get("false_positive") is not True and item.get("accepted_for_scoring", True) is not False
    ]
    scoring["false_positive_count"] = sum(
        1 for item in gt.get("vulnerabilities", []) if item.get("false_positive") is True
    )
    scoring["scored_vulnerabilities"] = len(scored)
    scoring["max_weighted_score"] = sum(
        int(weights.get(str(item.get("severity", "low")).lower(), 1))
        for item in scored
    )


def apply_postcomposition(
    gt: dict[str, Any],
    paths: list[dict[str, Any]],
    topology: dict[str, Any],
    spec: dict[str, Any],
    alterations: list[dict[str, Any]],
    seed: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    gt = copy.deepcopy(gt)
    paths = copy.deepcopy(paths)
    for index, item in enumerate(alterations):
        paths = _apply_post_item(gt, paths, topology, spec, item, index, seed)
    gt["attack_paths"] = paths
    _recompute_scoring(gt)
    return gt, paths


def apply_alterations(
    spec: dict[str, Any],
    topology: dict[str, Any],
    gt: dict[str, Any],
    paths: list[dict[str, Any]],
    alterations: list[dict[str, Any]],
    seed: int = 0,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    spec, topology, _ = apply_precomposition(spec, topology, alterations, seed)
    gt, paths = apply_postcomposition(gt, paths, topology, spec, alterations, seed)
    return spec, topology, gt, paths
