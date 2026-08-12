"""Compose manually authored Scenario Lab specifications.

This module is intentionally independent from the historical ScenarioGenerator
mutations.  It is the first shared composition path for custom scenarios and
produces the same family of artifacts as a generated bundle.
"""
from __future__ import annotations

import copy
import hashlib
import re
from pathlib import Path
from typing import Any

import yaml

from src.benchmark.scenario_spec import (
    ScenarioSpecError,
    deep_merge,
    normalize_scenario_spec,
    validate_scenario_spec,
)
from src.benchmark.strict_v3 import derive_matching_contract
from src.benchmark.manual_execution import build_execution_plan
from src.benchmark.scenario_alterations import (
    apply_postcomposition,
    apply_precomposition,
    build_alteration_plan,
    normalize_alterations,
)
from src.benchmark.tool_registry import (
    PHASES,
    service_descriptors,
    tool_policy_for_phase,
    tools_for_services,
)


SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}
META_FIELDS = {"scenarios", "applies_to", "key"}


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ScenarioSpecError(f"Invalid YAML artifact: {path}") from exc
    if not isinstance(value, dict):
        raise ScenarioSpecError(f"Expected a YAML mapping: {path}")
    return value


def _yaml_bytes(value: Any) -> bytes:
    """Serialize an artifact exactly as it is persisted in a bundle."""
    return yaml.safe_dump(value, allow_unicode=True, sort_keys=False).encode("utf-8")


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")


def _replace(value: Any, ip: str) -> Any:
    if isinstance(value, str):
        return value.replace("{ip}", ip)
    if isinstance(value, list):
        return [_replace(item, ip) for item in value]
    if isinstance(value, dict):
        return {key: _replace(item, ip) for key, item in value.items()}
    return copy.deepcopy(value)


class ScenarioComposer:
    """Compile one normalized manual specification into a validated bundle."""

    def __init__(self, repo_root: Path | None = None):
        self.repo_root = (repo_root or Path(__file__).resolve().parents[2]).resolve()
        self.benchmarks_root = self.repo_root / "benchmarks"

    def compose(
        self,
        raw_spec: dict[str, Any],
        *,
        artifact_id: str | None = None,
    ) -> dict[str, Any]:
        spec = normalize_scenario_spec(raw_spec)
        validate_scenario_spec(spec, self.repo_root)
        logical_id = spec["scenario_id"]
        scenario_id = artifact_id or logical_id
        # Render names from the human-authored logical ID.  The storage ID is
        # content-addressed and should not leak into a hand-written path.
        topology = self._resolve_topology(spec["topology"], logical_id)
        topology["id"] = scenario_id
        alterations = normalize_alterations(spec.get("alterations", []))
        spec, topology, alteration_mutation = apply_precomposition(
            spec, topology, alterations, int(spec.get("seed", 0) or 0)
        )
        packs = self._load_packs(spec["packs"])
        targets = [
            target for target in self._targets(topology)
            if not target.get("exclude_from_ground_truth", False)
        ]
        vulnerabilities: list[dict[str, Any]] = []
        controls: list[dict[str, Any]] = []

        for pack in packs:
            pack_id = str(pack["__pack_id"])
            for target in targets:
                role = target["role"]
                for template in pack.get("vulnerabilities", {}).get(role, []) or []:
                    if self._matches(template, target, logical_id):
                        vulnerabilities.append(
                            self._materialize(template, target, pack_id, "vulnerability", len(vulnerabilities))
                        )
                for template in pack.get("controls", {}).get(role, []) or []:
                    if self._matches(template, target, logical_id):
                        controls.append(
                            self._materialize(template, target, pack_id, "control", len(controls), prefix="C")
                        )

        vulnerabilities.extend(
            self._materialize_extra(item, targets, "vulnerability", len(vulnerabilities))
            for item in spec.get("extra_vulnerabilities", [])
        )
        controls.extend(
            self._materialize_extra(item, targets, "control", len(controls), prefix="C")
            for item in spec.get("extra_controls", [])
        )

        paths = self._resolve_paths(
            spec.get("attack_paths", []), vulnerabilities, targets, scenario_id
        )
        gt = self._ground_truth(spec, topology, scenario_id, vulnerabilities, controls, paths)
        gt, paths = apply_postcomposition(
            gt, paths, topology, spec, alterations, int(spec.get("seed", 0) or 0)
        )
        execution = build_execution_plan(spec, topology, gt)
        injection = self._injection_plan(scenario_id, topology, gt)
        execution_by_device = {
            item["device"]: item for item in execution["service_fixtures"]
        }
        injection["execution_adapter"] = execution["adapter"]
        injection["deployment_status"] = execution["status"]
        for fixture in injection["fixtures"]:
            if fixture["role"] == "router":
                fixture["provider"] = execution["router_provider"]
            elif fixture["device"] in execution_by_device:
                fixture["provider"] = execution_by_device[fixture["device"]]["provider"]
        verification = self._verification_plan(scenario_id, gt)
        verification["execution_adapter"] = execution["adapter"]
        verification["execution_status"] = execution["status"]
        contracts = self._contracts(scenario_id, gt)
        self._validate_bundle(spec, topology, gt, contracts, injection)
        return {
            "scenario": self._scenario_artifact(spec, scenario_id, topology),
            "topology": topology,
            "ground_truth": gt,
            "injection_plan": injection,
            "verification_plan": verification,
            "matching_contracts": contracts,
            "execution_plan": execution,
            "alteration_plan": build_alteration_plan(alterations),
            "alteration_mutation": alteration_mutation,
            "source_spec": spec,
        }

    def _load_packs(self, pack_ids: list[str]) -> list[dict[str, Any]]:
        result = []
        for pack_id in pack_ids:
            pack = _load_yaml(self.benchmarks_root / "packs" / "definitions" / f"{pack_id}.yaml")
            pack["__pack_id"] = pack_id
            result.append(pack)
        return result

    def _resolve_topology(self, topology_spec: dict[str, Any], sid: str) -> dict[str, Any]:
        if "ref" in topology_spec:
            source = _load_yaml(
                self.benchmarks_root / "topologies" / f"{topology_spec['ref']}.yaml"
            )
            source = deep_merge(source, topology_spec.get("overrides", {}))
        else:
            source = copy.deepcopy(topology_spec["inline"])

        router_source = dict(source.get("router") or {})
        if not router_source.get("ip"):
            raise ScenarioSpecError("topology.router.ip is required")
        names: dict[str, str] = {}

        def resolve_name(raw: dict[str, Any], fallback: str) -> tuple[str, dict[str, Any]]:
            template = str(raw.get("name_template") or raw.get("name") or fallback)
            concrete = template.format(sid=sid)
            names[template] = concrete
            names[template.format(sid=sid)] = concrete
            item = {**copy.deepcopy(raw), "name": concrete, "source_name": concrete}
            item.pop("name_template", None)
            return concrete, item

        router_name, router = resolve_name(router_source, f"s{sid}-router")
        services = []
        for index, raw in enumerate(source.get("services", []) or [], 1):
            name, item = resolve_name(dict(raw), f"s{sid}-device-{index}")
            if not item.get("ip"):
                raise ScenarioSpecError(f"topology service {name} is missing ip")
            item.setdefault("role", "unknown")
            services.append(item)

        known = {router_name, *(item["name"] for item in services)}
        external = set(str(item) for item in source.get("external_nodes", []) or [])
        links = []
        for raw_link in source.get("links", []) or []:
            link = copy.deepcopy(raw_link)
            left = names.get(str(link.get("source")), str(link.get("source", "")).format(sid=sid))
            right = names.get(str(link.get("target")), str(link.get("target", "")).format(sid=sid))
            if left not in known:
                external.add(left)
            if right not in known:
                external.add(right)
            link["source"], link["target"] = left, right
            links.append(link)

        # Existing flat presets omit links.  Materialize their router-centered
        # connectivity while keeping the topology's subnet semantics explicit.
        if not links:
            links = [
                {"source": router_name, "target": item["name"], "protocol": "ethernet"}
                for item in services
            ]

        subnets = list(source.get("subnets") or [])
        if not subnets:
            for item in [router, *services]:
                parts = str(item.get("ip", "")).split(".")
                if len(parts) == 4:
                    subnet = ".".join(parts[:3]) + ".0/24"
                    if subnet not in subnets:
                        subnets.append(subnet)

        return {
            "schema_version": 1,
            "id": sid,
            "name": source.get("name", sid),
            "description": source.get("description", ""),
            "deployment_status": "ready",
            "base_vmid": source.get("base_vmid"),
            "router": router,
            "services": services,
            "links": links,
            "subnets": subnets,
            "external_nodes": sorted(external),
        }

    @staticmethod
    def _targets(topology: dict[str, Any]) -> list[dict[str, Any]]:
        router = {**topology["router"], "role": "router"}
        return [router, *topology.get("services", [])]

    @staticmethod
    def _matches(template: dict[str, Any], target: dict[str, Any], scenario_id: str) -> bool:
        scenarios = template.get("scenarios")
        if scenarios and scenario_id not in {str(item) for item in scenarios}:
            return False
        selector = template.get("applies_to") or {}
        if not isinstance(selector, dict):
            raise ScenarioSpecError("pack applies_to must be a mapping")
        if selector.get("roles") and target.get("role") not in selector["roles"]:
            return False
        if selector.get("profiles") and target.get("security_profile", "vulnerable") not in selector["profiles"]:
            return False
        if selector.get("devices"):
            selected = {str(item).format(sid=scenario_id) for item in selector["devices"]}
            if target.get("name") not in selected and target.get("source_name") not in selected:
                return False
        return True

    @staticmethod
    def _materialize(
        template: dict[str, Any],
        target: dict[str, Any],
        pack_id: str,
        kind: str,
        index: int,
        *,
        prefix: str = "V",
    ) -> dict[str, Any]:
        key = str(template.get("key") or f"{pack_id}:{kind}:{index}").strip()
        item = {
            "id": f"{key}@{_slug(target['name'])}",
            "device": target["name"],
            "ip": target["ip"],
            "role": target["role"],
            "security_profile": target.get("security_profile", "vulnerable"),
            "template_key": key,
            "pack": pack_id,
        }
        if prefix == "C":
            item["id"] = f"{key}@{_slug(target['name'])}"
        for field, value in template.items():
            if field in META_FIELDS:
                continue
            item[field] = _replace(value, str(target["ip"]))
        return item

    @staticmethod
    def _find_target(raw_device: str, targets: list[dict[str, Any]]) -> dict[str, Any]:
        wanted = re.sub(r"\s+\([^)]*\)$", "", str(raw_device)).strip()
        exact = [
            target for target in targets
            if wanted in {target.get("name"), target.get("source_name")}
        ]
        if len(exact) == 1:
            return exact[0]
        # Short names such as ``web`` and ``mqtt`` are convenient in manual
        # specs, while concrete topology names remain deterministic in output.
        suffix = [target for target in targets if str(target.get("name", "")).endswith(f"-{wanted}")]
        if len(suffix) == 1:
            return suffix[0]
        raise ScenarioSpecError(f"Finding references unknown device: {raw_device}")

    def _materialize_extra(
        self,
        raw: dict[str, Any],
        targets: list[dict[str, Any]],
        kind: str,
        index: int,
        *,
        prefix: str = "V",
    ) -> dict[str, Any]:
        raw = dict(raw)
        target = self._find_target(str(raw.get("device", "")), targets)
        key = str(raw.get("key") or raw.get("template_key") or f"extra-{kind}-{index}")
        item = {
            "id": f"{key}@{_slug(target['name'])}",
            "device": target["name"],
            "ip": target["ip"],
            "role": target["role"],
            "security_profile": target.get("security_profile", "vulnerable"),
            "template_key": key,
        }
        for field, value in raw.items():
            if field not in {"id", "device", "ip", "role", "security_profile", "template_key", "key"}:
                item[field] = _replace(value, str(target["ip"]))
        return item

    @staticmethod
    def _resolve_finding(ref: str, vulnerabilities: list[dict[str, Any]]) -> str:
        ref = str(ref)
        by_id = {item["id"]: item["id"] for item in vulnerabilities}
        if ref in by_id:
            return ref
        candidates = [item["id"] for item in vulnerabilities if item.get("template_key") == ref]
        if len(candidates) == 1:
            return candidates[0]
        if "@" in ref:
            key, device = ref.split("@", 1)
            candidates = [
                item["id"] for item in vulnerabilities
                if item.get("template_key") == key and _slug(item.get("device", "")) == _slug(device)
            ]
        if len(candidates) != 1:
            raise ScenarioSpecError(f"Attack path finding does not resolve uniquely: {ref}")
        return candidates[0]

    def _resolve_paths(
        self,
        raw_paths: list[dict[str, Any]],
        vulnerabilities: list[dict[str, Any]],
        targets: list[dict[str, Any]],
        scenario_id: str,
    ) -> list[dict[str, Any]]:
        target_names = {item["name"] for item in targets}
        result = []
        for raw in raw_paths:
            path = copy.deepcopy(raw)
            steps = path.get("steps")
            if steps is not None:
                chain = []
                used = []
                for index, step in enumerate(steps, 1):
                    step = dict(step)
                    target = self._find_target(str(step.get("target") or step.get("device") or ""), targets)
                    finding = step.get("finding") or step.get("vulnerability")
                    if finding:
                        resolved = self._resolve_finding(str(finding), vulnerabilities)
                        used.append(resolved)
                        step["finding"] = resolved
                    chain.append({
                        "hop": index,
                        "device": target["name"],
                        "action": str(step.get("action") or ""),
                    })
                path["steps"] = steps
                path["chain"] = chain
                if used:
                    path["vulnerabilities_used"] = list(dict.fromkeys(used))
            else:
                chain = []
                for index, hop in enumerate(path.get("chain", []), 1):
                    hop = dict(hop)
                    target = self._find_target(str(hop.get("device", "")), targets)
                    hop["hop"] = index
                    hop["device"] = target["name"]
                    chain.append(hop)
                path["chain"] = chain
                path["vulnerabilities_used"] = [
                    self._resolve_finding(ref, vulnerabilities)
                    for ref in path.get("vulnerabilities_used", [])
                ]

            path.setdefault("semantics", "network_pivot" if path.get("network_hop_depth", 0) else "logical_chain")
            if any(hop["device"] not in target_names for hop in path["chain"]):
                raise ScenarioSpecError(f"Attack path {path.get('id')} references an unknown target")
            result.append(path)
        return result

    @staticmethod
    def _ground_truth(spec, topology, scenario_id, vulnerabilities, controls, paths):
        return {
            "schema_version": 3,
            "scenario_id": scenario_id,
            "scenario_name": spec["name"],
            "difficulty": spec["difficulty"],
            "description": spec.get("description") or topology.get("description", ""),
            "topology": {
                "deployment_status": "ready",
                "router": {key: topology["router"].get(key) for key in ("name", "ip", "type", "security_profile") if key in topology["router"]},
                "services": [
                    {key: item.get(key) for key in ("name", "ip", "role", "security_profile", "simulator", "provider", "vmid_offset") if key in item}
                    for item in topology.get("services", [])
                ],
                "links": copy.deepcopy(topology.get("links", [])),
                "external_nodes": copy.deepcopy(topology.get("external_nodes", [])),
                "subnets": copy.deepcopy(topology.get("subnets", [])),
                "network_conditions": copy.deepcopy(topology.get("network_conditions", {})),
            },
            "vulnerabilities": vulnerabilities,
            "controls": controls,
            "attack_paths": paths,
            "tool_policy": copy.deepcopy(spec.get("tool_policy", {})),
            "scoring": {
                "total_vulnerabilities": len(vulnerabilities),
                "total_controls": len(controls),
                "total_attack_paths": len(paths),
                "weights": SEVERITY_WEIGHTS,
                "max_weighted_score": sum(SEVERITY_WEIGHTS.get(str(item.get("severity", "low")).lower(), 1) for item in vulnerabilities),
            },
            "bonus_types": copy.deepcopy(spec.get("bonus_types", [])),
            "alterations": copy.deepcopy(spec.get("alterations", [])),
            "seed": int(spec.get("seed", 0) or 0),
            "lifecycle": copy.deepcopy(spec.get("lifecycle", {})),
            "environment": copy.deepcopy(spec.get("environment", {})),
            "identity": copy.deepcopy(spec.get("identity", {})),
            "detection": copy.deepcopy(spec.get("detection", {})),
            "evaluation": copy.deepcopy(spec.get("evaluation", {})),
            "objectives": copy.deepcopy(spec.get("objectives", [])),
            "constraints": copy.deepcopy(spec.get("constraints", {})),
            "compatibility": copy.deepcopy(spec.get("compatibility", {})),
            "data_fixtures": copy.deepcopy(spec.get("data_fixtures", [])),
            "failure_modes": copy.deepcopy(spec.get("failure_modes", [])),
        }

    @staticmethod
    def _scenario_artifact(spec, scenario_id, topology):
        artifact = copy.deepcopy(spec)
        artifact.update({
            "scenario_id": scenario_id,
            "logical_scenario_id": spec["scenario_id"],
            "kind": "manual-scenario",
            "topology": scenario_id,
            "topology_name": topology.get("name", scenario_id),
        })
        return artifact

    @staticmethod
    def _injection_plan(scenario_id, topology, gt):
        vuln_by_device: dict[str, list[str]] = {}
        control_by_device: dict[str, list[str]] = {}
        for item in gt["vulnerabilities"]:
            vuln_by_device.setdefault(item["device"], []).append(item["template_key"])
        for item in gt["controls"]:
            control_by_device.setdefault(item["device"], []).append(item["template_key"])
        fixtures = []
        for item in [topology["router"], *topology.get("services", [])]:
            role = item.get("role", "router")
            fixtures.append({
                "device": item["name"],
                "ip": item["ip"],
                "role": role,
                "provider": item.get("provider") or ("benchmark_simulator" if item.get("simulator") else "unresolved"),
                "mode": item.get("simulator"),
                "security_profile": item.get("security_profile", "vulnerable"),
                "vulnerability_keys": sorted(vuln_by_device.get(item["name"], [])),
                "control_keys": sorted(control_by_device.get(item["name"], [])),
            })
        return {"schema_version": 2, "scenario_id": scenario_id, "deployment_status": "preview", "fixtures": fixtures}

    @staticmethod
    def _verification_plan(scenario_id, gt):
        checks = []
        for state, collection in (("vulnerable", gt["vulnerabilities"]), ("control", gt["controls"])):
            for item in collection:
                checks.append({
                    "id": item["id"],
                    "template_key": item["template_key"],
                    "device": item["device"],
                    "ip": item["ip"],
                    "expected_state": state,
                    "probe_type": item.get("probe_type", "descriptive"),
                    "required_tools": item.get("required_tools", []),
                    "verification": item.get("verification", ""),
                })
        return {"schema_version": 2, "scenario_id": scenario_id, "execution_status": "not-executable", "checks": checks}

    @staticmethod
    def _contracts(scenario_id, gt):
        fields = ("accepted_types", "services", "ports", "protocols", "endpoints", "products", "versions")
        entries = {}
        for item in gt["vulnerabilities"]:
            contract = derive_matching_contract(item)
            acceptable = set(item.get("acceptable_tools", []))
            for phase in PHASES:
                acceptable.update(tools_for_services(contract["services"], phase))
            entries[item["id"]] = {
                **{field: contract[field] for field in fields},
                "acceptable_tools": sorted(acceptable),
                "required_tools": list(item.get("required_tools", [])),
                "contract_source": contract["contract_source"],
            }
        source_hash = hashlib.sha256(_yaml_bytes(gt)).hexdigest()
        return {
            "schema_version": "strict-v3.2",
            "source_hashes": {scenario_id: source_hash},
            "scenarios": {scenario_id: entries},
        }

    @staticmethod
    def _validate_bundle(spec, topology, gt, contracts, injection):
        targets = {topology["router"]["name"], *(item["name"] for item in topology.get("services", []))}
        ids = [item["id"] for item in [*gt["vulnerabilities"], *gt["controls"]]]
        if len(ids) != len(set(ids)):
            raise ScenarioSpecError("Ground Truth contains duplicate finding/control IDs")
        for item in [*gt["vulnerabilities"], *gt["controls"]]:
            if item["device"] not in targets:
                raise ScenarioSpecError(f"Ground Truth references unknown device: {item['device']}")
        node_names = targets | set(topology.get("external_nodes", []))
        for link in topology.get("links", []):
            if link.get("source") not in node_names or link.get("target") not in node_names:
                raise ScenarioSpecError("Topology contains a dangling link")
        vuln_ids = {item["id"] for item in gt["vulnerabilities"]}
        for path in gt["attack_paths"]:
            if not set(path.get("vulnerabilities_used", [])) <= vuln_ids:
                raise ScenarioSpecError(f"Attack path {path.get('id')} references an unknown finding")
            devices = [hop.get("device") for hop in path.get("chain", [])]
            if any(device not in node_names for device in devices):
                raise ScenarioSpecError(f"Attack path {path.get('id')} references an unknown device")

        policy = spec.get("tool_policy", {})
        allowed = set()
        for phase in PHASES:
            phase_policy = tool_policy_for_phase(policy, phase)
            if phase_policy is not None:
                allowed.update(phase_policy)
        if policy:
            for finding_id, contract in contracts["scenarios"][gt["scenario_id"]].items():
                if contract["required_tools"] and not set(contract["required_tools"]) <= allowed:
                    missing = sorted(set(contract["required_tools"]) - allowed)
                    raise ScenarioSpecError(f"{finding_id} requires disallowed tools: {', '.join(missing)}")
                if contract["acceptable_tools"] and not (set(contract["acceptable_tools"]) & allowed):
                    raise ScenarioSpecError(f"No allowed tool can produce evidence for {finding_id}")

        constraints = spec.get("constraints") if isinstance(spec.get("constraints"), dict) else {}
        services = topology.get("services", []) or []
        roles = {str(item.get("role")) for item in services}
        service_count = len(services)
        min_services = constraints.get("min_services")
        max_services = constraints.get("max_services")
        if min_services is not None and service_count < int(min_services):
            raise ScenarioSpecError("Scenario variant violates constraints.min_services")
        if max_services is not None and service_count > int(max_services):
            raise ScenarioSpecError("Scenario variant violates constraints.max_services")
        required_roles = {str(item) for item in constraints.get("required_roles", [])}
        forbidden_roles = {str(item) for item in constraints.get("forbidden_roles", [])}
        if not required_roles <= roles:
            raise ScenarioSpecError("Scenario variant is missing a required service role")
        if forbidden_roles & roles:
            raise ScenarioSpecError("Scenario variant contains a forbidden service role")
        min_vulnerabilities = constraints.get("min_vulnerabilities")
        max_vulnerabilities = constraints.get("max_vulnerabilities")
        vuln_count = len(gt.get("vulnerabilities", []))
        if min_vulnerabilities is not None and vuln_count < int(min_vulnerabilities):
            raise ScenarioSpecError("Scenario variant violates constraints.min_vulnerabilities")
        if max_vulnerabilities is not None and vuln_count > int(max_vulnerabilities):
            raise ScenarioSpecError("Scenario variant violates constraints.max_vulnerabilities")
        required_semantics = {str(item) for item in constraints.get("required_semantics", [])}
        actual_semantics = {str(path.get("semantics")) for path in gt.get("attack_paths", []) if path.get("semantics")}
        if not required_semantics <= actual_semantics:
            raise ScenarioSpecError("Scenario variant is missing a required attack-path semantic")

        planned = {key for fixture in injection["fixtures"] for key in fixture["vulnerability_keys"]}
        expected = {item["template_key"] for item in gt["vulnerabilities"]}
        if planned != expected:
            raise ScenarioSpecError("Injection plan and Ground Truth differ")


def spec_hash(spec: dict[str, Any]) -> str:
    payload = yaml.safe_dump(spec, allow_unicode=True, sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
