"""Topology-aware Scenario Lab composition helpers.

The builder exposes a deliberately small, server-side catalogue of valid
node/finding combinations.  The browser only sends opaque candidate IDs; the
authoritative pack templates are resolved and checked again before a bundle is
written.
"""
from __future__ import annotations

import copy
import random
import re
from pathlib import Path
from typing import Any

import yaml

from src.benchmark.manual_execution import FLAT_ROLE_PROVIDERS
from src.benchmark.tool_registry import service_descriptors


class ScenarioBuilderError(ValueError):
    """Raised when a manual or random Scenario Lab request is incoherent."""


def _slug(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")
    return value or "scenario"


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ScenarioBuilderError(f"Invalid Scenario Lab source: {path.name}") from exc
    if not isinstance(value, dict):
        raise ScenarioBuilderError(f"Scenario Lab source must be a mapping: {path.name}")
    return value


class ScenarioBuilder:
    """Build validated custom scenario specifications from topology primitives."""

    def __init__(self, repo_root: Path | None = None):
        self.repo_root = (repo_root or Path(__file__).resolve().parents[2]).resolve()
        self.benchmarks_root = self.repo_root / "benchmarks"

    def _ensure_catalog_sources(self) -> None:
        missing = []
        topologies_dir = self.benchmarks_root / "topologies"
        packs_dir = self.benchmarks_root / "packs" / "definitions"
        if not topologies_dir.is_dir() or not any(topologies_dir.glob("*.yaml")):
            missing.append("benchmarks/topologies")
        if not packs_dir.is_dir() or not any(packs_dir.glob("*.yaml")):
            missing.append("benchmarks/packs/definitions")
        if missing:
            raise ScenarioBuilderError(
                "Scenario Lab catalogue unavailable; missing "
                + ", ".join(missing)
            )

    def list_topologies(self) -> list[dict[str, Any]]:
        self._ensure_catalog_sources()
        result = []
        for path in sorted((self.benchmarks_root / "topologies").glob("*.yaml")):
            topology = _load_yaml(path)
            topology_id = str(topology.get("id") or path.stem)
            nodes = self._nodes(topology)
            candidate_sets = [
                (node, self._candidates_for_node(node, topology_id))
                for node in nodes
            ]
            candidates = sum(len(items) for _, items in candidate_sets)
            executable_candidates = sum(
                len(items)
                for node, items in candidate_sets
                if not node["router"]
                and not node.get("simulator")
                and node["role"] in FLAT_ROLE_PROVIDERS
                and self._flat_runtime_topology(topology)
            )
            result.append({
                "id": topology_id,
                "name": str(topology.get("name") or topology_id),
                "description": str(topology.get("description") or ""),
                "node_count": max(0, len(nodes) - 1),
                "candidate_count": candidates,
                "executable_candidate_count": executable_candidates,
                "has_links": bool(topology.get("links")),
            })
        return result

    def catalog(self, topology_id: str) -> dict[str, Any]:
        topology = self._topology(topology_id)
        nodes = []
        for node in self._nodes(topology):
            candidates = self._candidates_for_node(node, topology_id)
            nodes.append({
                **{key: node.get(key) for key in (
                    "id", "name", "source_name", "role", "ip", "security_profile",
                    "simulator", "vmid_offset", "router",
                )},
                "services": copy.deepcopy(node["services"]),
                "candidate_count": len(candidates),
                "candidates": [
                    {key: value for key, value in candidate.items() if key != "_template"}
                    for candidate in candidates
                ],
            })
        return {
            "topology": {
                "id": topology_id,
                "name": str(topology.get("name") or topology_id),
                "description": str(topology.get("description") or ""),
                "subnets": copy.deepcopy(topology.get("subnets") or []),
                "link_count": len(topology.get("links") or []),
            },
            "nodes": nodes,
        }

    def build_spec(
        self,
        *,
        topology_id: str,
        selected_nodes: list[str],
        findings: list[dict[str, str]],
        name: str | None = None,
        description: str | None = None,
        seed: int = 0,
        execution_profile: str = "auto",
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        topology = self._topology(topology_id)
        nodes = {node["id"]: node for node in self._nodes(topology)}
        selected = list(dict.fromkeys(str(item) for item in selected_nodes))
        unknown = sorted(set(selected) - set(nodes))
        if unknown:
            raise ScenarioBuilderError(
                f"Unknown topology node(s): {', '.join(unknown)}"
            )
        services = [node for node in nodes.values() if not node["router"]]
        selected_services = [node for node in services if node["id"] in selected]
        if not selected_services:
            raise ScenarioBuilderError("Select at least one service node")

        candidate_index = {
            (node["id"], candidate["candidate_id"]): (node, candidate)
            for node in nodes.values()
            for candidate in self._candidates_for_node(node, topology_id)
        }
        extra_vulnerabilities = []
        logical_id = self._logical_id(topology_id, name, seed)
        selected_finding_keys = []
        seen_findings: set[tuple[str, str]] = set()
        for index, raw_finding in enumerate(findings, 1):
            node_id = str(raw_finding.get("node_id") or "")
            candidate_id = str(raw_finding.get("candidate_id") or "")
            lookup = (node_id, candidate_id)
            if lookup in seen_findings:
                raise ScenarioBuilderError(
                    f"Finding {candidate_id} is selected more than once on {node_id}"
                )
            seen_findings.add(lookup)
            if node_id not in selected:
                raise ScenarioBuilderError(
                    f"Finding {candidate_id} targets a node that was not selected"
                )
            entry = candidate_index.get(lookup)
            if entry is None:
                raise ScenarioBuilderError(
                    f"Finding {candidate_id} is not compatible with node {node_id}"
                )
            node, candidate = entry
            template = copy.deepcopy(candidate["_template"])
            template["key"] = candidate["template_key"]
            template["device"] = node["source_name"].format(sid=logical_id)
            # Selection metadata is for the catalogue only.  It must not leak
            # into the materialized finding or make it scenario-ID-specific.
            template.pop("applies_to", None)
            template.pop("scenarios", None)
            extra_vulnerabilities.append(template)
            selected_finding_keys.append({
                "node_id": node_id,
                "candidate_id": candidate_id,
                "template_key": candidate["template_key"],
                "device": node["source_name"].format(sid=logical_id),
            })

        selected_raw = [copy.deepcopy(node["_raw"]) for node in selected_services]
        selected_source_names = {
            str(item.get("name_template") or item.get("name") or "")
            for item in selected_raw
        }
        router_raw = copy.deepcopy(topology.get("router") or {})
        router_source_name = str(
            router_raw.get("name_template") or router_raw.get("name") or "router"
        )
        allowed_names = selected_source_names | {router_source_name}
        external_nodes = set(str(item) for item in topology.get("external_nodes") or [])
        links = []
        for raw_link in topology.get("links") or []:
            source = str(raw_link.get("source") or "")
            target = str(raw_link.get("target") or "")
            if source in (allowed_names | external_nodes) and target in (allowed_names | external_nodes):
                links.append(copy.deepcopy(raw_link))

        overrides = {
            "services": selected_raw,
            "links": links,
            "external_nodes": sorted(external_nodes),
        }
        spec = {
            "schema_version": 4,
            "scenario_id": logical_id,
            "name": str(name or f"Scenario Lab · {topology.get('name', topology_id)}"),
            "difficulty": "custom",
            "posture": "vulnerable" if extra_vulnerabilities else "mixed",
            "description": str(description or topology.get("description") or ""),
            "seed": int(seed),
            "topology": {"ref": topology_id, "overrides": overrides},
            "execution": {"profile": str(execution_profile or "auto")},
            "packs": [],
            "extra_vulnerabilities": extra_vulnerabilities,
            "metadata": {
                "scenario_lab_builder": {
                    "topology_id": topology_id,
                    "selected_nodes": selected,
                    "findings": selected_finding_keys,
                }
            },
        }
        return spec, {
            "topology_id": topology_id,
            "selected_nodes": selected,
            "findings": selected_finding_keys,
            "execution_profile": str(execution_profile or "auto"),
        }


    @staticmethod
    def _flat_runtime_topology(topology: dict[str, Any]) -> bool:
        router = topology.get("router") or {}
        return (
            str(router.get("type", "openwrt")) == "openwrt"
            and router.get("ip") == "192.168.100.1"
            and topology.get("network_mode") in {None, "flat"}
            and not topology.get("reachability_policy")
            and not topology.get("observability")
        )

    def _random_eligible_nodes(
        self,
        topology: dict[str, Any],
        topology_id: str,
        execution_profile: str,
    ) -> list[dict[str, Any]]:
        eligible = [
            node
            for node in self._nodes(topology)
            if not node["router"] and self._candidates_for_node(node, topology_id)
        ]
        if execution_profile == "preview":
            return eligible
        if execution_profile in {"auto", "flat_roles"}:
            if not self._flat_runtime_topology(topology):
                return []
            return [
                node
                for node in eligible
                if not node.get("simulator")
                and node["role"] in FLAT_ROLE_PROVIDERS
            ]
        return eligible

    def random_spec(
        self,
        *,
        topology_id: str | None = None,
        seed: int = 0,
        min_nodes: int = 2,
        max_nodes: int = 5,
        min_vulnerabilities: int = 2,
        max_vulnerabilities: int = 6,
        execution_profile: str = "auto",
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        rng = random.Random(int(seed))
        execution_profile = str(execution_profile or "auto")
        topologies = self.list_topologies() if not topology_id else []
        if topology_id:
            chosen_topology_id = str(topology_id)
        else:
            if execution_profile == "preview":
                viable = [
                    item["id"] for item in topologies
                    if item["candidate_count"] > 0
                ]
            elif execution_profile in {"auto", "flat_roles"}:
                viable = [
                    item["id"] for item in topologies
                    if item.get("executable_candidate_count", 0) > 0
                ]
            else:
                viable = [
                    item["id"] for item in topologies
                    if item["candidate_count"] > 0
                ]
            if not viable:
                if execution_profile == "preview":
                    raise ScenarioBuilderError("No topology has compatible vulnerability candidates")
                raise ScenarioBuilderError(
                    f"No topology has compatible executable vulnerability candidates for {execution_profile}"
                )
            chosen_topology_id = rng.choice(viable)
        topology = self._topology(chosen_topology_id)
        eligible = self._random_eligible_nodes(
            topology,
            chosen_topology_id,
            execution_profile,
        )
        if not eligible:
            if execution_profile != "preview":
                raise ScenarioBuilderError(
                    f"Topology {chosen_topology_id} has no compatible executable vulnerable service node for {execution_profile}"
                )
            raise ScenarioBuilderError(
                f"Topology {chosen_topology_id} has no compatible vulnerable service node"
            )

        components = self._eligible_components(topology, eligible)
        component = rng.choice(components)
        min_nodes = max(1, int(min_nodes))
        max_nodes = max(min_nodes, int(max_nodes))
        min_vulnerabilities = max(1, int(min_vulnerabilities))
        max_vulnerabilities = max(min_vulnerabilities, int(max_vulnerabilities))
        max_nodes = min(max_nodes, len(component), max_vulnerabilities)
        if max_nodes < 1:
            raise ScenarioBuilderError("Random limits cannot select a service node")
        min_nodes = min(min_nodes, max_nodes)
        node_count = rng.randint(min_nodes, max_nodes)
        selected_nodes = rng.sample(sorted(node["id"] for node in component), node_count)

        per_node: dict[str, list[dict[str, Any]]] = {
            node["id"]: self._candidates_for_node(node, chosen_topology_id)
            for node in component if node["id"] in selected_nodes
        }
        selected_findings = []
        for node_id in selected_nodes:
            selected_findings.append({
                "node_id": node_id,
                "candidate_id": rng.choice(per_node[node_id])["candidate_id"],
            })
        pool = [
            (node_id, candidate)
            for node_id, candidates in per_node.items()
            for candidate in candidates
            if (node_id, candidate["candidate_id"]) not in {
                (item["node_id"], item["candidate_id"]) for item in selected_findings
            }
        ]
        target_count = min(
            len(selected_findings) + len(pool),
            max(len(selected_findings), rng.randint(min_vulnerabilities, max_vulnerabilities)),
        )
        if target_count > len(selected_findings):
            for node_id, candidate in rng.sample(pool, target_count - len(selected_findings)):
                selected_findings.append({
                    "node_id": node_id,
                    "candidate_id": candidate["candidate_id"],
                })
        spec, summary = self.build_spec(
            topology_id=chosen_topology_id,
            selected_nodes=selected_nodes,
            findings=selected_findings,
            name=f"Random Scenario Lab · {chosen_topology_id}",
            description="Deterministically generated from topology-compatible node/finding candidates.",
            seed=int(seed),
            execution_profile=execution_profile,
        )
        summary["random"] = {
            "seed": int(seed),
            "topology_id": chosen_topology_id,
            "node_count": len(selected_nodes),
            "vulnerability_count": len(selected_findings),
        }
        return spec, summary

    def _topology(self, topology_id: str) -> dict[str, Any]:
        wanted = str(topology_id).strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", wanted):
            raise ScenarioBuilderError("Invalid topology identifier")
        for path in (self.benchmarks_root / "topologies").glob("*.yaml"):
            topology = _load_yaml(path)
            if str(topology.get("id") or path.stem) == wanted:
                topology["_builder_source_path"] = str(path)
                return topology
        raise ScenarioBuilderError(f"Unknown topology: {wanted}")

    @staticmethod
    def _nodes(topology: dict[str, Any]) -> list[dict[str, Any]]:
        router = copy.deepcopy(topology.get("router") or {})
        router_name = str(router.get("name_template") or router.get("name") or "router")
        result = [{
            "id": "router",
            "name": router_name,
            "source_name": router_name,
            "role": "router",
            "ip": router.get("ip"),
            "security_profile": router.get("security_profile", "vulnerable"),
            "simulator": router.get("simulator"),
            "vmid_offset": 0,
            "router": True,
            "services": [
                str(item.get("name")) for item in service_descriptors(
                    "router", router.get("services")
                )
            ],
            "_raw": router,
        }]
        for index, raw in enumerate(topology.get("services") or [], 1):
            item = copy.deepcopy(raw)
            source_name = str(item.get("name_template") or item.get("name") or f"service-{index}")
            role = str(item.get("role") or "unknown")
            descriptors = service_descriptors(role, item.get("services"))
            result.append({
                "id": f"service-{index}",
                "name": source_name,
                "source_name": source_name,
                "role": role,
                "ip": item.get("ip"),
                "security_profile": item.get("security_profile", "vulnerable"),
                "simulator": item.get("simulator"),
                "vmid_offset": item.get("vmid_offset"),
                "router": False,
                "services": [str(service.get("name")) for service in descriptors],
                "_raw": item,
            })
        return result

    def _candidates_for_node(
        self, node: dict[str, Any], topology_id: str
    ) -> list[dict[str, Any]]:
        result = []
        packs_dir = self.benchmarks_root / "packs" / "definitions"
        for path in sorted(packs_dir.glob("*.yaml")):
            pack = _load_yaml(path)
            pack_id = str(pack.get("id") or path.stem)
            templates = (pack.get("vulnerabilities") or {}).get(node["role"], []) or []
            for index, template in enumerate(templates):
                if not isinstance(template, dict) or not self._template_matches(template, node):
                    continue
                key = str(
                    template.get("key")
                    or f"BUILDER-{_slug(pack_id)}-{_slug(node['role'])}-{index + 1}"
                )
                result.append({
                    "candidate_id": f"{pack_id}:{node['role']}:{index}",
                    "pack": pack_id,
                    "role": node["role"],
                    "template_key": key,
                    "title": str(template.get("title") or key),
                    "severity": str(template.get("severity") or "medium"),
                    "category": str(template.get("category") or "unknown"),
                    "description": str(template.get("description") or ""),
                    "verification": str(template.get("verification") or ""),
                    "required_tools": list(template.get("required_tools") or []),
                    "services": list(template.get("services") or node["services"]),
                    "ports": list(template.get("ports") or []),
                    "protocols": list(template.get("protocols") or []),
                    "scenario_scope": list(template.get("scenarios") or []),
                    "_template": copy.deepcopy(template),
                })
        return result

    @staticmethod
    def _template_matches(template: dict[str, Any], node: dict[str, Any]) -> bool:
        selector = template.get("applies_to") or {}
        if not isinstance(selector, dict):
            return False
        profiles = selector.get("profiles") or []
        if profiles and node["security_profile"] not in {str(item) for item in profiles}:
            return False
        devices = selector.get("devices") or []
        if devices:
            normalized = {str(item).replace("{sid}", "builder") for item in devices}
            source = str(node["source_name"]).replace("{sid}", "builder")
            if source not in normalized:
                return False
        node_services = {str(item).casefold() for item in node["services"]}
        requested_services = {str(item).casefold() for item in template.get("services") or []}
        if requested_services and not node_services.intersection(requested_services):
            return False
        node_ports = {
            int(item.get("port")) for item in service_descriptors(
                node["role"]
            ) if str(item.get("port", "")).isdigit()
        }
        requested_ports = {
            int(item) for item in template.get("ports") or [] if str(item).isdigit()
        }
        if requested_ports and not node_ports.intersection(requested_ports):
            return False
        node_protocols = {
            str(item.get("protocol", "")).casefold()
            for item in service_descriptors(node["role"])
        }
        requested_protocols = {
            str(item).casefold() for item in template.get("protocols") or []
        }
        return not requested_protocols or node_protocols.intersection(requested_protocols)

    @staticmethod
    def _eligible_components(
        topology: dict[str, Any], eligible: list[dict[str, Any]]
    ) -> list[list[dict[str, Any]]]:
        eligible_by_name = {
            str(node["source_name"]): node for node in eligible
        }
        if not topology.get("links"):
            return [eligible]
        adjacency: dict[str, set[str]] = {node["id"]: set() for node in eligible}
        for link in topology.get("links") or []:
            left = eligible_by_name.get(str(link.get("source")))
            right = eligible_by_name.get(str(link.get("target")))
            if left and right:
                adjacency[left["id"]].add(right["id"])
                adjacency[right["id"]].add(left["id"])
        remaining = set(adjacency)
        components = []
        while remaining:
            start = next(iter(remaining))
            stack = [start]
            component_ids = set()
            while stack:
                current = stack.pop()
                if current in component_ids:
                    continue
                component_ids.add(current)
                remaining.discard(current)
                stack.extend(adjacency[current] - component_ids)
            components.append([node for node in eligible if node["id"] in component_ids])
        return [component for component in components if component]

    @staticmethod
    def _logical_id(topology_id: str, name: str | None, seed: int) -> str:
        base = _slug(name or f"{topology_id}-{seed}")
        return f"builder-{base}"[:64]
