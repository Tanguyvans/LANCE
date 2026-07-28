"""Immutable preview bundles for generated benchmark scenarios.

Bundles live outside ``benchmarks/`` and cannot be deployed by the current
pipeline.  They keep topology, expected findings, and future injection inputs
together so generated variants cannot silently alter official presets.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
import random
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from src.benchmark.scenario_exports import ExportedScenarioStore
from src.benchmark.strict_v3 import derive_matching_contract


GENERATOR_MARKER = "lance.scenario-generator"
GENERATOR_VERSION = 2
VARIANT_ID_RE = re.compile(r"^gen-[a-z0-9]+-[a-f0-9]{10}$")
SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}
META_FIELDS = {"scenarios", "applies_to", "key"}

OPERATIONS = {
    "rotate_ips": {"id": "rotate_ips", "label": "Rotation des adresses IP"},
    "rename_hosts": {"id": "rename_hosts", "label": "Renommage faible des hôtes"},
    "swap_profiles": {"id": "swap_profiles", "label": "Permutation de profils compatibles"},
}

BLUEPRINTS = {
    "api-authorization": {
        "id": "api-authorization",
        "short_id": "api",
        "label": "API multi-tenant",
        "source_scenario_id": "15",
        "allowed_operations": ["rotate_ips", "rename_hosts", "swap_profiles"],
    },
    "ota-lifecycle": {
        "id": "ota-lifecycle",
        "short_id": "ota",
        "label": "Cycle de mise à jour OTA",
        "source_scenario_id": "17",
        "allowed_operations": ["rotate_ips", "rename_hosts"],
    },
}


class ScenarioGeneratorError(ValueError):
    """A request or stored generated bundle is invalid."""


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _yaml_bytes(value: Any) -> bytes:
    return yaml.safe_dump(value, allow_unicode=True, sort_keys=False).encode("utf-8")


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ScenarioGeneratorError(f"Invalid YAML artifact: {path.name}") from exc
    if not isinstance(value, dict):
        raise ScenarioGeneratorError(f"Expected a YAML mapping: {path.name}")
    return value


class ScenarioGenerator:
    """Generate and mutate preview bundles while preserving official inputs."""

    def __init__(
        self,
        repo_root: Path | None = None,
        storage_root: Path | None = None,
        export_root: Path | None = None,
    ):
        self.repo_root = (repo_root or Path(__file__).resolve().parents[2]).resolve()
        self.benchmarks_root = self.repo_root / "benchmarks"
        self.storage_root = (
            storage_root or self.repo_root / "output" / "generated_scenarios"
        ).resolve()
        self.export_store = ExportedScenarioStore(
            export_root or self.repo_root / "output" / "exported_scenarios"
        )
        for protected in ("scenarios", "topologies", "ground_truth", "packs"):
            path = (self.benchmarks_root / protected).resolve()
            if any(
                candidate == path or path in candidate.parents
                for candidate in (self.storage_root, self.export_store.root)
            ):
                raise ScenarioGeneratorError(
                    "Generated and exported storage must stay outside benchmarks/"
                )

    def list_blueprints(self) -> list[dict[str, Any]]:
        return [
            {
                "id": item["id"],
                "label": item["label"],
                "source_scenario_id": item["source_scenario_id"],
                "operations": [OPERATIONS[op] for op in item["allowed_operations"]],
            }
            for item in BLUEPRINTS.values()
        ]

    def list_variants(self) -> list[dict[str, Any]]:
        if not self.storage_root.exists():
            return []
        exported = {item["id"]: item for item in self.export_store.list()}
        variants = []
        for path in self.storage_root.iterdir():
            if path.is_symlink() or not path.is_dir() or not VARIANT_ID_RE.fullmatch(path.name):
                continue
            try:
                summary = self._summary(self._load_bundle(path.name))
                export = exported.get(summary["id"])
                summary["exported"] = export is not None
                summary["exported_at"] = export.get("exported_at") if export else None
                variants.append(summary)
            except ScenarioGeneratorError:
                continue
        return sorted(variants, key=lambda item: (item["created_at"], item["id"]), reverse=True)

    def export_variant(self, variant_id: str) -> dict[str, Any]:
        """Publish one trusted preview bundle for use in the dashboard."""
        return self.export_store.publish(self._load_bundle(variant_id))

    def delete_export(self, variant_id: str) -> dict[str, Any]:
        """Remove a dashboard export without deleting its Lab source variant."""
        return self.export_store.delete(variant_id)

    def delete_variant(self, variant_id: str) -> dict[str, Any]:
        """Remove one trusted Lab bundle and its dashboard export, if any."""
        bundle = self._load_bundle(variant_id)  # validate provenance before deletion
        summary = self._summary(bundle)
        exported = self.export_store.has_entry(variant_id)
        if exported:
            # Validate the export before removing either copy.  A corrupted
            # dashboard bundle must never be hidden by deleting its Lab source.
            self.export_store.load(variant_id)
            self.export_store.delete(variant_id)
        shutil.rmtree(self._variant_dir(variant_id))
        return {**summary, "export_deleted": exported}

    def generate(self, blueprint_id: str, seed: int, operation: str) -> dict[str, Any]:
        blueprint = self._blueprint(blueprint_id)
        self._validate_request(blueprint, seed, operation)
        source_scenario, source_topology, packs = self._load_blueprint(blueprint)
        blueprint = {
            **blueprint,
            "source_hash": self._blueprint_hash(source_scenario, source_topology, packs),
        }
        spec = {
            "action": "generate",
            "source_hash": blueprint["source_hash"],
            "blueprint": blueprint_id,
            "seed": seed,
            "operation": operation,
            "version": GENERATOR_VERSION,
        }
        digest = _canonical_hash(spec)
        variant_id = f"gen-{blueprint['short_id']}-{digest[:10]}"
        if self._variant_dir(variant_id).is_dir():
            return self.get_variant(variant_id)

        topology, names = self._resolve_topology(
            source_topology, blueprint["source_scenario_id"], f"g{digest[:8]}", variant_id
        )
        topology, operation_names = self._apply_operation(topology, operation, seed)
        names = {old: operation_names.get(new, new) for old, new in names.items()}
        scenario = self._new_scenario(variant_id, blueprint, source_scenario, names)
        bundle = self._compile(
            variant_id, blueprint, scenario, topology, packs, seed, operation, None, names
        )
        self._write_bundle(bundle)
        return self.get_variant(variant_id)

    def mutate(self, source_variant_id: str, seed: int, operation: str) -> dict[str, Any]:
        parent = self._load_bundle(source_variant_id)
        blueprint = self._blueprint(parent["manifest"]["blueprint_id"])
        self._validate_request(blueprint, seed, operation)
        source_scenario, source_topology, packs = self._load_blueprint(blueprint)
        source_hash = self._blueprint_hash(source_scenario, source_topology, packs)
        if source_hash != parent["manifest"].get("source_blueprint_hash"):
            raise ScenarioGeneratorError(
                "Blueprint changed since the parent variant was generated"
            )
        blueprint = {**blueprint, "source_hash": source_hash}
        spec = {
            "action": "mutate",
            "parent": source_variant_id,
            "parent_hash": parent["manifest"]["bundle_hash"],
            "seed": seed,
            "operation": operation,
            "version": GENERATOR_VERSION,
        }
        digest = _canonical_hash(spec)
        variant_id = f"gen-{blueprint['short_id']}-{digest[:10]}"
        if self._variant_dir(variant_id).is_dir():
            return self.get_variant(variant_id)

        topology, names = self._apply_operation(copy.deepcopy(parent["topology"]), operation, seed)
        topology["id"] = variant_id
        scenario = copy.deepcopy(parent["scenario"])
        scenario.update({
            "scenario_id": variant_id,
            "name": f"{blueprint['label']} / {digest[:6]}",
            "parent_variant_id": source_variant_id,
            "mutation": {"operation": operation, "seed": seed},
        })
        bundle = self._compile(
            variant_id, blueprint, scenario, topology, packs, seed, operation,
            source_variant_id, names,
        )
        self._write_bundle(bundle)
        return self.get_variant(variant_id)

    def get_variant(self, variant_id: str) -> dict[str, Any]:
        bundle = self._load_bundle(variant_id)
        gt = bundle["ground_truth"]
        blueprint = BLUEPRINTS[bundle["manifest"]["blueprint_id"]]
        return {
            **self._summary(bundle),
            "scenario": bundle["scenario"],
            "topology": {
                "name": bundle["topology"]["name"],
                "service_count": len(bundle["topology"].get("services", [])),
                "link_count": len(bundle["topology"].get("links", [])),
            },
            "ground_truth": {
                "vulnerabilities": [
                    {key: item.get(key) for key in ("id", "title", "device", "severity")}
                    for item in gt.get("vulnerabilities", [])
                ],
                "controls": [
                    {key: item.get(key) for key in ("id", "device", "assertion")}
                    for item in gt.get("controls", [])
                ],
                "attack_path_count": len(gt.get("attack_paths", [])),
            },
            "allowed_operations": [OPERATIONS[op] for op in blueprint["allowed_operations"]],
        }

    def get_topology_graph(self, variant_id: str) -> dict[str, Any]:
        bundle = self._load_bundle(variant_id)
        topology, gt = bundle["topology"], bundle["ground_truth"]
        vuln_counts: dict[str, int] = {}
        for item in gt.get("vulnerabilities", []):
            vuln_counts[item["device"]] = vuln_counts.get(item["device"], 0) + 1
        router = topology["router"]
        nodes = [{
            "id": router["name"], "label": router["name"], "ip": router["ip"],
            "type": "router", "role": "router", "services": [],
            "vuln_count": vuln_counts.get(router["name"], 0),
        }]
        for service in topology.get("services", []):
            nodes.append({
                "id": service["name"], "label": service["name"], "ip": service["ip"],
                "type": self._role_type(service["role"]), "role": service["role"],
                "services": [service["role"]],
                "security_profile": service.get("security_profile", "vulnerable"),
                "vuln_count": vuln_counts.get(service["name"], 0),
            })
        edges = [{
            "id": f"{link['source']}-{link['target']}", "source": link["source"],
            "target": link["target"], "protocol": link.get("protocol", "ethernet"),
        } for link in topology.get("links", [])]
        subnets = topology.get("subnets", [])
        return {
            "variant_id": variant_id, "generated": True, "deployable": False,
            "nodes": nodes, "edges": edges,
            "subnet": subnets[0] if subnets else "", "subnets": subnets,
        }

    def _blueprint(self, blueprint_id: str) -> dict[str, Any]:
        try:
            return BLUEPRINTS[blueprint_id]
        except KeyError as exc:
            raise ScenarioGeneratorError(f"Unknown generator blueprint: {blueprint_id}") from exc

    @staticmethod
    def _validate_request(blueprint: dict[str, Any], seed: int, operation: str) -> None:
        if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= 2**31 - 1:
            raise ScenarioGeneratorError("Seed must be between 0 and 2147483647")
        if operation not in blueprint["allowed_operations"]:
            raise ScenarioGeneratorError(f"Operation {operation!r} is not allowed for {blueprint['id']}")

    def _load_blueprint(self, blueprint: dict[str, Any]):
        sid = blueprint["source_scenario_id"]
        scenario = _load_yaml(self.benchmarks_root / "scenarios" / f"S{sid}.yaml")
        if int(scenario.get("schema_version", 1)) < 2:
            raise ScenarioGeneratorError("Generator blueprints require schema-v2 scenarios")
        topology = _load_yaml(self.benchmarks_root / "topologies" / f"{scenario['topology']}.yaml")
        packs = [
            _load_yaml(self.benchmarks_root / "packs" / "definitions" / f"{pack}.yaml")
            for pack in scenario.get("packs", [])
        ]
        return scenario, topology, packs

    @staticmethod
    def _blueprint_hash(scenario, topology, packs) -> str:
        return _canonical_hash({
            "scenario": scenario,
            "topology": topology,
            "packs": packs,
        })

    @staticmethod
    def _resolve_topology(source, sid: str, prefix: str, variant_id: str):
        names: dict[str, str] = {}

        def resolve(template: str):
            old = template.format(sid=sid)
            new = f"{prefix}-{re.sub(rf'^s{re.escape(sid)}-', '', old)}"
            names[old] = new
            return old, new

        old_router, new_router = resolve(source["router"].get("name_template", "s{sid}-router"))
        router = {**copy.deepcopy(source["router"]), "source_name": old_router, "name": new_router}
        services = []
        for raw in source.get("services", []):
            old, new = resolve(raw["name_template"])
            services.append({
                **copy.deepcopy(raw), "source_name": old,
                "source_name_template": raw["name_template"], "name": new,
            })
        links = []
        for raw in source.get("links", []):
            left, right = str(raw["source"]).format(sid=sid), str(raw["target"]).format(sid=sid)
            links.append({**copy.deepcopy(raw), "source": names.get(left, left), "target": names.get(right, right)})
        existing_edges = {(link["source"], link["target"]) for link in links}
        for service in services:
            edge = (new_router, service["name"])
            if edge not in existing_edges:
                links.append({"source": edge[0], "target": edge[1], "protocol": "ethernet"})
                existing_edges.add(edge)
        subnets = copy.deepcopy(source.get("subnets") or [])
        if not subnets:
            for item in [router, *services]:
                parts = str(item.get("ip", "")).split(".")
                subnet = ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else ""
                if subnet and subnet not in subnets:
                    subnets.append(subnet)
        return ({
            "schema_version": 1, "id": variant_id, "name": source.get("name", variant_id),
            "description": source.get("description", ""), "deployment_status": "preview",
            "base_vmid": None, "source_base_vmid": source.get("base_vmid"),
            "router": router, "services": services, "links": links, "subnets": subnets,
        }, names)

    @staticmethod
    def _apply_operation(topology, operation: str, seed: int):
        services, rng, names = topology.get("services", []), random.Random(seed), {}
        if operation == "rotate_ips":
            zones: dict[str, list[dict[str, Any]]] = {}
            for service in services:
                try:
                    zone = str(ipaddress.ip_network(f"{service['ip']}/24", strict=False))
                except ValueError as exc:
                    raise ScenarioGeneratorError("Invalid service IP address") from exc
                zones.setdefault(zone, []).append(service)
            mutable_zones = [zone for zone in zones.values() if len(zone) > 1]
            if not mutable_zones:
                raise ScenarioGeneratorError("IP rotation requires two services in the same network zone")
            for zone in mutable_zones:
                ips = [item["ip"] for item in zone]
                offset = rng.randrange(1, len(ips))
                for service, ip in zip(zone, ips[offset:] + ips[:offset]):
                    service["ip"] = ip
        elif operation == "rename_hosts":
            if not services:
                raise ScenarioGeneratorError("Host renaming requires at least one service")
            service = services[rng.randrange(len(services))]
            old = service["name"]
            token = hashlib.sha256(f"{seed}:{old}".encode()).hexdigest()[:4]
            service["name"] = f"{old}-r{token}"
            names[old] = service["name"]
            for link in topology.get("links", []):
                link["source"] = names.get(link["source"], link["source"])
                link["target"] = names.get(link["target"], link["target"])
        elif operation == "swap_profiles":
            groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
            for service in services:
                groups.setdefault((service["role"], service.get("simulator", "")), []).append(service)
            pairs = [
                (left, right) for group in groups.values() for index, left in enumerate(group)
                for right in group[index + 1:] if left.get("security_profile") != right.get("security_profile")
            ]
            if not pairs:
                raise ScenarioGeneratorError("No compatible security profiles can be swapped")
            left, right = pairs[rng.randrange(len(pairs))]
            left["security_profile"], right["security_profile"] = right["security_profile"], left["security_profile"]
            names.update({left["name"]: right["name"], right["name"]: left["name"]})
        else:
            raise ScenarioGeneratorError(f"Unknown mutation operation: {operation}")
        return topology, names

    def _new_scenario(self, variant_id, blueprint, source, names):
        return {
            "schema_version": 1, "scenario_id": variant_id, "kind": "generated-scenario",
            "name": f"{blueprint['label']} / {variant_id.rsplit('-', 1)[-1][:6]}",
            "difficulty": source.get("difficulty", "custom"), "posture": source.get("posture", "mixed"),
            "source_scenario_id": blueprint["source_scenario_id"], "blueprint_id": blueprint["id"],
            "topology_file": "topology.yaml", "packs": copy.deepcopy(source.get("packs", [])),
            "attack_paths": self._remap_devices(source.get("attack_paths", []), names),
            "bonus_types": copy.deepcopy(source.get("bonus_types", [])),
        }

    @staticmethod
    def _remap_devices(paths, names):
        result = copy.deepcopy(paths)
        for path in result:
            for hop in path.get("chain", []):
                hop["device"] = names.get(hop.get("device"), hop.get("device"))
        return result

    def _compile(self, variant_id, blueprint, scenario, topology, packs, seed, operation, parent, names):
        gt = self._compose(scenario, topology, packs, blueprint["source_scenario_id"])
        gt["attack_paths"] = self._resolve_paths(scenario.get("attack_paths", []), gt["vulnerabilities"], variant_id, names)
        gt["scoring"]["total_attack_paths"] = len(gt["attack_paths"])
        scenario["attack_paths"] = copy.deepcopy(gt["attack_paths"])
        injection = self._injection_plan(variant_id, topology, gt)
        verification = self._verification_plan(variant_id, gt)
        self._validate(scenario, topology, gt, injection)
        artifacts = {
            "scenario.yaml": scenario, "topology.yaml": topology, "ground_truth.yaml": gt,
            "injection_plan.yaml": injection, "verification_plan.yaml": verification,
        }
        gt_hash = hashlib.sha256(_yaml_bytes(gt)).hexdigest()
        contracts = self._contracts(variant_id, gt, gt_hash)
        artifacts["matching_contracts.yaml"] = contracts
        hashes = {name: hashlib.sha256(_yaml_bytes(value)).hexdigest() for name, value in artifacts.items()}
        manifest = {
            "schema_version": 1, "kind": "generated-scenario", "generated_by": GENERATOR_MARKER,
            "generator_version": GENERATOR_VERSION, "variant_id": variant_id,
            "blueprint_id": blueprint["id"], "source_scenario_id": blueprint["source_scenario_id"],
            "source_blueprint_hash": blueprint["source_hash"],
            "parent_variant_id": parent, "seed": seed, "operation": operation,
            "mutation_policy": "generated-only", "deployment_status": "preview", "deployable": False,
            "created_at": datetime.now(timezone.utc).isoformat(), "artifact_hashes": hashes,
            "topology_signature": self._topology_signature(topology),
            "bundle_hash": _canonical_hash(hashes),
        }
        return {"manifest": manifest, "scenario": scenario, "topology": topology,
                "ground_truth": gt, "injection_plan": injection,
                "verification_plan": verification, "matching_contracts": contracts}

    def _compose(self, scenario, topology, packs, source_sid: str):
        vulns, controls = [], []
        for pack in packs:
            for service in topology.get("services", []):
                for template in pack.get("vulnerabilities", {}).get(service["role"], []):
                    if self._matches(template, service, source_sid):
                        vulns.append(self._materialize(template, service))
                for template in pack.get("controls", {}).get(service["role"], []):
                    if self._matches(template, service, source_sid):
                        controls.append(self._materialize(template, service))
        services = [{key: item[key] for key in ("name", "ip", "role", "security_profile", "simulator", "vmid_offset") if key in item}
                    for item in topology.get("services", [])]
        return {
            "schema_version": 1, "scenario_id": scenario["scenario_id"], "scenario_name": scenario["name"],
            "difficulty": scenario.get("difficulty", "custom"), "description": topology.get("description", ""),
            "topology": {"deployment_status": "preview",
                         "router": {key: topology["router"].get(key) for key in ("name", "ip", "type")},
                         "services": services, "links": copy.deepcopy(topology.get("links", [])),
                         "subnets": copy.deepcopy(topology.get("subnets", []))},
            "vulnerabilities": vulns, "controls": controls, "attack_paths": [],
            "scoring": {"total_vulnerabilities": len(vulns), "total_controls": len(controls),
                        "total_attack_paths": 0, "weights": SEVERITY_WEIGHTS,
                        "max_weighted_score": sum(SEVERITY_WEIGHTS.get(v.get("severity", "low").lower(), 1) for v in vulns)},
            "bonus_types": copy.deepcopy(scenario.get("bonus_types", [])),
        }

    @staticmethod
    def _matches(template, service, sid: str):
        scenarios = template.get("scenarios")
        if scenarios and sid not in [str(item) for item in scenarios]:
            return False
        selector = template.get("applies_to") or {}
        if not isinstance(selector, dict):
            raise ScenarioGeneratorError("Pack applies_to must be a mapping")
        if selector.get("roles") and service["role"] not in selector["roles"]:
            return False
        if selector.get("profiles") and service.get("security_profile", "vulnerable") not in selector["profiles"]:
            return False
        if selector.get("devices"):
            selected = {str(item).format(sid=sid) for item in selector["devices"]}
            candidates = {service.get("source_name", ""), service.get("name", ""),
                          str(service.get("source_name_template", "")).format(sid=sid)}
            if selected.isdisjoint(candidates):
                return False
        return True

    @staticmethod
    def _materialize(template, service):
        key = str(template.get("key", "")).strip()
        if not key:
            raise ScenarioGeneratorError("Generated packs require stable template keys")
        ip = service["ip"]
        result = {"id": f"{key}@{_slug(service['name'])}", "device": service["name"],
                  "ip": ip, "role": service["role"],
                  "security_profile": service.get("security_profile", "vulnerable"), "template_key": key}
        for field, value in template.items():
            if field in META_FIELDS:
                continue
            if field == "indicators":
                result[field] = [str(item).replace("{ip}", ip) for item in value]
            elif field == "verification":
                result[field] = str(value).replace("{ip}", ip)
            else:
                result[field] = copy.deepcopy(value)
        return result

    @staticmethod
    def _resolve_paths(paths, vulns, variant_id: str, names):
        by_key: dict[str, list[dict[str, Any]]] = {}
        for vuln in vulns:
            by_key.setdefault(vuln["template_key"], []).append(vuln)
        result = copy.deepcopy(paths)
        for index, path in enumerate(result, 1):
            path["id"] = f"PGEN-{variant_id.rsplit('-', 1)[-1].upper()}-{index}"
            resolved = []
            for old_id in path.get("vulnerabilities_used", []):
                candidates = by_key.get(str(old_id).split("@", 1)[0], [])
                if len(candidates) != 1:
                    raise ScenarioGeneratorError(f"Attack-path finding does not resolve: {old_id}")
                resolved.append(candidates[0]["id"])
            path["vulnerabilities_used"] = resolved
            for hop in path.get("chain", []):
                hop["device"] = names.get(hop.get("device"), hop.get("device"))
        return result

    @staticmethod
    def _injection_plan(variant_id: str, topology, gt):
        vulnerabilities: dict[str, list[str]] = {}
        controls: dict[str, list[str]] = {}
        for item in gt["vulnerabilities"]:
            vulnerabilities.setdefault(item["device"], []).append(item["template_key"])
        for item in gt["controls"]:
            controls.setdefault(item["device"], []).append(item["template_key"])
        fixtures = [{"device": item["name"], "ip": item["ip"], "role": item["role"],
                     "provider": "benchmark_simulator" if item.get("simulator") else "unresolved",
                     "mode": item.get("simulator"), "security_profile": item.get("security_profile", "vulnerable"),
                     "vulnerability_keys": sorted(vulnerabilities.get(item["name"], [])),
                     "control_keys": sorted(controls.get(item["name"], []))}
                    for item in topology.get("services", [])]
        return {"schema_version": 1, "scenario_id": variant_id,
                "deployment_status": "preview", "fixtures": fixtures}

    @staticmethod
    def _verification_plan(variant_id: str, gt):
        checks = []
        for state, collection in (("vulnerable", gt["vulnerabilities"]), ("control", gt["controls"])):
            checks.extend({"id": item["id"], "template_key": item["template_key"],
                           "device": item["device"], "ip": item["ip"], "expected_state": state,
                           "probe_type": "descriptive", "verification": item.get("verification", "")}
                          for item in collection)
        return {"schema_version": 1, "scenario_id": variant_id,
                "execution_status": "not-executable", "checks": checks}

    @staticmethod
    def _contracts(variant_id: str, gt, source_hash: str):
        fields = ("accepted_types", "services", "ports", "protocols", "endpoints", "products", "versions")
        entries = {}
        for vuln in gt["vulnerabilities"]:
            contract = derive_matching_contract(vuln)
            entries[vuln["id"]] = {field: contract[field] for field in fields}
        return {"schema_version": "strict-v3.2", "source_hashes": {variant_id: source_hash},
                "scenarios": {variant_id: entries}}

    @staticmethod
    def _validate(scenario, topology, gt, injection):
        variant_id = scenario["scenario_id"]
        if topology["id"] != variant_id or gt["scenario_id"] != variant_id:
            raise ScenarioGeneratorError("Generated artifact IDs differ")
        router, services = topology["router"], topology.get("services", [])
        names = [router["name"], *[item["name"] for item in services]]
        ips = [router["ip"], *[item["ip"] for item in services]]
        offsets = [item.get("vmid_offset") for item in services]
        if len(names) != len(set(names)) or len(ips) != len(set(ips)) or len(offsets) != len(set(offsets)):
            raise ScenarioGeneratorError("Generated topology identifiers are not unique")
        nodes = set(names)
        if any(link["source"] not in nodes or link["target"] not in nodes for link in topology.get("links", [])):
            raise ScenarioGeneratorError("Generated topology contains a dangling link")
        target_by_name = {item["name"]: item for item in services} | {router["name"]: router}
        all_items = [*gt["vulnerabilities"], *gt["controls"]]
        ids = [item["id"] for item in all_items]
        if len(ids) != len(set(ids)):
            raise ScenarioGeneratorError("Generated ground-truth IDs are not unique")
        if any(item["device"] not in target_by_name or item["ip"] != target_by_name[item["device"]]["ip"] for item in all_items):
            raise ScenarioGeneratorError("Ground truth does not resolve against topology")
        vuln_ids = {item["id"] for item in gt["vulnerabilities"]}
        for path in gt["attack_paths"]:
            if not set(path.get("vulnerabilities_used", [])) <= vuln_ids:
                raise ScenarioGeneratorError("Attack path references an unknown finding")
            path_devices = [hop.get("device") for hop in path.get("chain", [])]
            if any(device not in nodes for device in path_devices):
                raise ScenarioGeneratorError("Attack path references an unknown device")
            if any(
                not ScenarioGenerator._is_reachable(left, right, topology.get("links", []))
                for left, right in zip(path_devices, path_devices[1:])
            ):
                raise ScenarioGeneratorError("Attack path crosses disconnected topology components")
        planned = {key for fixture in injection["fixtures"] for key in fixture["vulnerability_keys"]}
        expected = {item["template_key"] for item in gt["vulnerabilities"]}
        if planned != expected:
            raise ScenarioGeneratorError("Injection plan and ground truth differ")

    def _write_bundle(self, bundle):
        variant_id, target = bundle["manifest"]["variant_id"], self._variant_dir(bundle["manifest"]["variant_id"])
        self.storage_root.mkdir(parents=True, exist_ok=True)
        temp = Path(tempfile.mkdtemp(prefix=f".{variant_id}-", dir=self.storage_root))
        try:
            files = {"scenario.yaml": "scenario", "topology.yaml": "topology",
                     "ground_truth.yaml": "ground_truth", "injection_plan.yaml": "injection_plan",
                     "verification_plan.yaml": "verification_plan", "matching_contracts.yaml": "matching_contracts"}
            for filename, key in files.items():
                (temp / filename).write_bytes(_yaml_bytes(bundle[key]))
            (temp / "manifest.yaml").write_bytes(_yaml_bytes(bundle["manifest"]))
            if not target.exists():
                os.replace(temp, target)
        finally:
            if temp.exists():
                shutil.rmtree(temp)

    def _load_bundle(self, variant_id: str):
        path = self._variant_dir(variant_id)
        if path.is_symlink() or not path.is_dir():
            raise ScenarioGeneratorError(f"Generated scenario not found: {variant_id}")
        manifest = _load_yaml(path / "manifest.yaml")
        if (manifest.get("kind"), manifest.get("generated_by"), manifest.get("variant_id"), manifest.get("mutation_policy")) != (
            "generated-scenario", GENERATOR_MARKER, variant_id, "generated-only"
        ):
            raise ScenarioGeneratorError("Scenario is not a trusted generated bundle")
        if manifest.get("generator_version") != GENERATOR_VERSION:
            raise ScenarioGeneratorError("Generated bundle version is not supported")
        files = {"scenario": "scenario.yaml", "topology": "topology.yaml", "ground_truth": "ground_truth.yaml",
                 "injection_plan": "injection_plan.yaml", "verification_plan": "verification_plan.yaml",
                 "matching_contracts": "matching_contracts.yaml"}
        artifacts = {}
        for key, filename in files.items():
            artifact = path / filename
            if artifact.is_symlink() or not artifact.is_file():
                raise ScenarioGeneratorError(f"Missing generated artifact: {filename}")
            if hashlib.sha256(artifact.read_bytes()).hexdigest() != manifest.get("artifact_hashes", {}).get(filename):
                raise ScenarioGeneratorError(f"Generated artifact was modified: {filename}")
            artifacts[key] = _load_yaml(artifact)
        if _canonical_hash(manifest["artifact_hashes"]) != manifest.get("bundle_hash"):
            raise ScenarioGeneratorError("Generated bundle hash is invalid")
        if self._topology_signature(artifacts["topology"]) != manifest.get("topology_signature"):
            raise ScenarioGeneratorError("Generated topology structure has drifted")
        return {"manifest": manifest, **artifacts}

    def _variant_dir(self, variant_id: str) -> Path:
        if not VARIANT_ID_RE.fullmatch(str(variant_id)):
            raise ScenarioGeneratorError("Invalid generated scenario identifier")
        path = (self.storage_root / variant_id).resolve()
        if path.parent != self.storage_root:
            raise ScenarioGeneratorError("Generated scenario escapes storage")
        return path

    @staticmethod
    def _summary(bundle):
        manifest, gt = bundle["manifest"], bundle["ground_truth"]
        return {"id": manifest["variant_id"], "name": bundle["scenario"]["name"], "kind": manifest["kind"],
                "blueprint_id": manifest["blueprint_id"], "source_scenario_id": manifest["source_scenario_id"],
                "parent_variant_id": manifest.get("parent_variant_id"), "seed": manifest["seed"],
                "operation": manifest["operation"], "created_at": manifest["created_at"],
                "deployment_status": manifest["deployment_status"], "deployable": manifest["deployable"],
                "vulnerability_count": len(gt["vulnerabilities"]), "control_count": len(gt["controls"]),
                "attack_path_count": len(gt["attack_paths"])}

    @staticmethod
    def _is_reachable(source: str, target: str, links) -> bool:
        if source == target:
            return True
        adjacency: dict[str, set[str]] = {}
        for link in links:
            left, right = link["source"], link["target"]
            adjacency.setdefault(left, set()).add(right)
            adjacency.setdefault(right, set()).add(left)
        pending, visited = [source], {source}
        while pending:
            current = pending.pop()
            for neighbor in adjacency.get(current, set()):
                if neighbor == target:
                    return True
                if neighbor not in visited:
                    visited.add(neighbor)
                    pending.append(neighbor)
        return False

    @staticmethod
    def _topology_signature(topology):
        roles: dict[str, int] = {}
        simulators: dict[str, int] = {}
        protocols: dict[str, int] = {}
        for service in topology.get("services", []):
            role = str(service.get("role", ""))
            simulator = str(service.get("simulator", ""))
            roles[role] = roles.get(role, 0) + 1
            simulators[simulator] = simulators.get(simulator, 0) + 1
        for link in topology.get("links", []):
            protocol = str(link.get("protocol", "ethernet"))
            protocols[protocol] = protocols.get(protocol, 0) + 1
        return {
            "router_type": topology.get("router", {}).get("type"),
            "service_count": len(topology.get("services", [])),
            "roles": dict(sorted(roles.items())),
            "simulators": dict(sorted(simulators.items())),
            "link_count": len(topology.get("links", [])),
            "protocols": dict(sorted(protocols.items())),
            "subnets": sorted(topology.get("subnets", [])),
        }

    @staticmethod
    def _role_type(role: str) -> str:
        if role in {"router", "gateway", "mqtt_broker", "mqtt_broker_v2"}:
            return "gateway"
        if role in {"camera", "camera_server", "nvr_server"}:
            return "camera"
        if role in {"modbus_server", "coap_server", "snmp_server", "ota_device"}:
            return "sensor"
        return "compute"
