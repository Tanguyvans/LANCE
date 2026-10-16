"""Reproduce a definition-only coverage snapshot; never deploy or audit a host.

Run from the repository root:
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python benchmarks/experiments/research-review/coverage_snapshot.py
The JSON goes to stdout. Classifications are proxies, not measured capabilities.
"""
from __future__ import annotations

from collections import Counter
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import re
import runpy
import subprocess

import yaml


ROOT = Path(__file__).resolve().parents[3]


def snapshot(base_commit: str | None = None) -> dict:
    # Reuse the existing inventory, including its matching-sidecar SHA checks.
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        runpy.run_path(str(ROOT / "benchmarks/experiments/research-review/inventory.py"))
    inventory = json.loads(buffer.getvalue())
    catalog = yaml.safe_load((ROOT / "benchmarks/catalog.yaml").read_text())
    source_paths = {
        ROOT / "benchmarks/catalog.yaml",
        ROOT / "benchmarks/ground_truth/matching_contracts.yaml",
        ROOT / "src/benchmark/derived_index.py",
        ROOT / "src/benchmark/strict_v3.py",
        ROOT / "src/benchmark/scenario_alterations.py",
        ROOT / "src/benchmark/manual_execution.py",
        ROOT / "src/agent/scanner.py",
        ROOT / "src/agent/pipeline.py",
        ROOT / "src/agent/audit_experiment.py",
        ROOT / "src/agent/phases/intrusion/observations.py",
        ROOT / "src/agent/core/executor.py",
        ROOT / "benchmarks/ansible/playbooks/03_deploy_scenario.yml",
        ROOT / "benchmarks/ansible/playbooks/04_inject_vulns.yml",
        ROOT / "benchmarks/ansible/playbooks/06_verify.yml",
        ROOT / "benchmarks/ansible/files/benchmark_simulator.py",
        ROOT / "benchmarks/topologies/true_multihop.yaml",
        ROOT / "docs/benchmark/agent-vs-automation-cli.md",
        ROOT / "benchmarks/experiments/ssh_reference.py",
        ROOT / "benchmarks/experiments/ssh_reference_live.py",
        ROOT / "benchmarks/experiments/ssh_reference_llm.py",
        ROOT / "benchmarks/experiments/ssh_reference_proxmox.py",
        ROOT / "benchmarks/ansible/files/ssh_reference_proxmox.py",
        ROOT / "benchmarks/ansible/playbooks/ssh_reference.yml",
        ROOT / "research/2026-10-12-recentrage-corpus/coverage-plan.json",
        ROOT / "research/2026-10-12-recentrage-corpus/structuration-corpus.tex",
        ROOT / "research/2026-10-12-recentrage-corpus/revue-iot-ctf.json",
        ROOT / "research/2026-10-12-recentrage-corpus/revue-iot-ctf.tex",
        ROOT / "research/2026-10-12-recentrage-corpus/revue-iot-ctf.pdf",
        ROOT / "research/2026-09-27-agent-vs-automation/protocol.md",
        ROOT / "objectifs/asiaccs-2027/README.md",
        ROOT / "objectifs/asiaccs-2027/plan-soumission.md",
        ROOT / "benchmarks/experiments/research-review/inventory.py",
        Path(__file__).resolve(),
    }
    logic_scenarios: dict[str, list[str]] = {}
    templates = Counter()
    missing_templates = 0
    for scenario in catalog["scenarios"]:
        identifier = scenario["id"]
        split = scenario["split"].split("-")[0]
        gt_path = ROOT / f"benchmarks/ground_truth/{split}/scenario_{identifier}.yaml"
        scenario_path = ROOT / f"benchmarks/scenarios/{split}/S{identifier}.yaml"
        source_paths.update((gt_path, scenario_path))
        truth = yaml.safe_load(gt_path.read_text())
        for vulnerability in truth.get("vulnerabilities", []):
            category = vulnerability.get("category")
            if category in {"broken_access_control", "auth_bypass"}:
                logic_scenarios.setdefault(identifier, []).append(category)
            template = vulnerability.get("template_key")
            if template:
                templates[template] += 1
            else:
                missing_templates += 1
    defined_packs = []
    for path in sorted((ROOT / "benchmarks/packs/definitions").glob("*.yaml")):
        source_paths.add(path)
        defined_packs.append(yaml.safe_load(path.read_text())["id"])
    healthy = []
    for path in sorted((ROOT / "benchmarks/ground_truth/dev").glob("scenario_*h.yaml")):
        source_paths.add(path)
        truth = yaml.safe_load(path.read_text())
        healthy.append({"scenario_id": truth["scenario_id"], "vulnerabilities": len(truth.get("vulnerabilities", []))})
    categories = Counter()
    for group in inventory["groups"].values():
        categories.update(group["category"])
    routine_categories = ("misconfiguration", "data_exposure", "no_authentication", "default_credentials")
    referenced = {pack for row in inventory["rows"] for pack in row["packs"]}
    design = json.loads((ROOT / "research/2026-10-12-recentrage-corpus/coverage-plan.json").read_text())
    proposed = [cell["scenario"] for cell in design["cells"] + design["extension_scenarios"]]
    fixture_types = [fixture for scenario in proposed for fixture in scenario["selected_fixture_types"]]
    comparison_sets = design["scenario_plan"]["comparison_sets"]
    identifiers = [scenario["id"] for scenario in proposed]
    grouped = [identifier for group in comparison_sets for identifier in group["scenario_ids"]]
    if len(set(identifiers)) != len(identifiers) or sorted(grouped) != sorted(identifiers):
        raise ValueError("Proposed comparison sets must partition the stable scenario IDs exactly once")
    if len({fixture["id"] for fixture in fixture_types}) != len(fixture_types):
        raise ValueError("Proposed fixture type IDs must be unique")
    question_organization = design["scenario_plan"]["question_organization"]
    questions = question_organization["questions"]
    question_members = [identifier for question in questions for identifier in question["scenario_ids"]]
    question_by_scenario = {identifier: question["id"] for question in questions for identifier in question["scenario_ids"]}
    if len({question["id"] for question in questions}) != len(questions) or sorted(question_members) != sorted(identifiers):
        raise ValueError("Reading questions must partition the scenario registry exactly once")
    for question in questions:
        if not set(question["examples"]) <= set(question["scenario_ids"]):
            raise ValueError("Examples must belong to their reading question")
    if any(scenario["reading_question"] != question_by_scenario[scenario["id"]] for scenario in proposed):
        raise ValueError("Scenario reading question must match the single navigation registry")
    crossing = []
    for comparison in comparison_sets:
        involved = sorted({question_by_scenario[identifier] for identifier in comparison["scenario_ids"]})
        if len(involved) > 1:
            crossing.append({"comparison_set": comparison["id"], "questions": involved})
    if crossing != question_organization["cross_question_comparisons"]:
        raise ValueError("Cross-question comparison links must preserve the technical registry")
    integration = design["scenario_plan"]["iot_review_integration"]
    review = json.loads((ROOT / "research/2026-10-12-recentrage-corpus/revue-iot-ctf.json").read_text())
    expected_review_ids = {item["id"] for item in review["gap_proposals"] + review["edge_case_review"]["candidates"]}
    mappings = integration["mappings"]
    mapped_ids = [item["review_id"] for item in mappings]
    if len(mapped_ids) != len(set(mapped_ids)) or set(mapped_ids) != expected_review_ids:
        raise ValueError("Every frozen IoT review item must have exactly one planning disposition")
    stage_records = {stage["id"]: stage for stage in integration["construction_stages"]}
    stages = set(stage_records)
    organization = integration["implementation_organization"]
    roles = {
        "prerequisite": [organization["preparation"]],
        "main_step": organization["main_steps"],
        "parallel_workstream": organization["parallel_workstreams"],
        "optional_extension": organization["optional_extensions"],
        "separate_study": organization["separate_studies"],
    }
    organized = [identifier for members in roles.values() for identifier in members]
    if len(organized) != len(set(organized)) or set(organized) != stages:
        raise ValueError("Every implementation work item must have exactly one organizational role")
    for role, members in roles.items():
        for index, identifier in enumerate(members, 1):
            stage = stage_records[identifier]
            number = index if role == "main_step" else None
            if stage["role"] != role or stage["sequence_number"] != number:
                raise ValueError("Only the ordered main steps may have a sequence number")
            if not set(stage["dependencies"]) <= stages - {identifier}:
                raise ValueError("Implementation dependencies must reference another named work item")
    dispositions = set(integration["dispositions"])
    gates = {gate["id"]: gate for gate in integration["admission_gates"]}
    for item in mappings:
        referenced_scenarios = set(item["related_scenarios"])
        if item["anchor_scenario"]:
            referenced_scenarios.add(item["anchor_scenario"])
        if not referenced_scenarios <= set(identifiers) or item["construction_stage"] not in stages:
            raise ValueError(f"Unknown scenario or construction stage for {item['review_id']}")
        if item["disposition"] not in dispositions or item["selected_type_ids_added"] or item["runtime_admission"] is not None:
            raise ValueError("Research integration cannot silently admit new scored types or runtime evidence")
    for scenario in proposed:
        sid = scenario["id"]
        backlinks = scenario["iot_review_integration"]
        expected_primary = {item["review_id"] for item in mappings if item["anchor_scenario"] == sid}
        expected_related = {item["review_id"] for item in mappings if sid in item["related_scenarios"] and item["anchor_scenario"] != sid}
        if set(backlinks["primary_review_ids"]) != expected_primary or set(backlinks["related_review_ids"]) != expected_related:
            raise ValueError(f"IoT planning backlinks do not match the single mapping registry for {sid}")
        if set(backlinks["gate_ids"]) != {key for key, gate in gates.items() if sid in gate["applies_to"]}:
            raise ValueError(f"Conditional admissions do not match the registry for {sid}")
        if scenario["priority"] != scenario["implementation_priority"]["stage"] or scenario["priority"] not in stages:
            raise ValueError(f"Inconsistent implementation priority for {sid}")
        stage = stage_records[scenario["priority"]]
        if any(scenario["implementation_priority"][key] != stage[key] for key in ("display_label", "role", "sequence_number")):
            raise ValueError(f"Implementation label or organizational role disagrees with the registry for {sid}")
    selection = [{"id": scenario["id"], "selected_fixture_types": scenario["selected_fixture_types"]} for scenario in proposed]
    selection_sha = hashlib.sha256(json.dumps(selection, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if selection_sha != integration["selection_preservation"]["selection_sha256"]:
        raise ValueError("Selected experiment contracts changed without updating the explicit selection amendment")
    naming = design["scenario_plan"]["scenario_naming"]
    scenario_aliases = naming["scenario_aliases"]
    type_aliases = naming["fixture_type_aliases"]
    if len(scenario_aliases) != len(identifiers) or set(scenario_aliases.values()) != set(identifiers):
        raise ValueError("Scenario renaming must be a bijection onto the current scenario registry")
    if any(re.fullmatch(r"s_[a-z0-9]+(?:_[a-z0-9]+)+", identifier) is None for identifier in identifiers):
        raise ValueError("Canonical scenario names must use descriptive ASCII s_ identifiers")
    if len(type_aliases) != len(fixture_types) or set(type_aliases.values()) != {fixture["id"] for fixture in fixture_types}:
        raise ValueError("Fixture type renaming must preserve every selected type exactly once")
    inverse = {new: old for old, new in (scenario_aliases | type_aliases).items()}
    def restore_identifiers(value):
        if isinstance(value, dict):
            return {key: restore_identifiers(item) for key, item in value.items()}
        if isinstance(value, list):
            return [restore_identifiers(item) for item in value]
        return inverse.get(value, value) if isinstance(value, str) else value
    restored_sha = hashlib.sha256(json.dumps(restore_identifiers(selection), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if restored_sha != integration["selection_preservation"]["pre_rename_selection_sha256"]:
        raise ValueError("Renaming must preserve the complete prior experiment selection after inverse translation")
    return {
        "schema_version": 1,
        "scope": "static_definitions_only_not_deployed_or_experimental_coverage",
        "generated_by": "benchmarks/experiments/research-review/coverage_snapshot.py",
        "git_commit": base_commit or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "sources_sha256": {
            path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(source_paths)
        },
        "official_scenarios": len(catalog["scenarios"]),
        "defined_pack_count": len(defined_packs),
        "referenced_pack_count": len(referenced),
        "defined_packs_not_referenced": sorted(set(defined_packs) - referenced),
        "packs_shared_across_current_splits": sorted(set(inventory["groups"]["dev"]["packs"]) & set(inventory["groups"]["test"]["packs"])),
        "categories": dict(sorted(categories.items())),
        "routine_category_proxy": {
            "categories": list(routine_categories),
            "count": sum(categories[category] for category in routine_categories),
            "warning": "Author-defined grouping of categories; not proof of signature detection or absence of reasoning.",
        },
        "logic_category_proxy_scenarios": logic_scenarios,
        "template_keys_present": dict(sorted(templates.items())),
        "vulnerabilities_without_template_key": missing_templates,
        "healthy_definitions_outside_official_catalog": healthy,
        "proposed_v2_design": {
            "scope": "design_only_not_runtime_coverage_or_independent_sample_size",
            "revision": design["revision"],
            "stable_scenario_specs": len(proposed),
            "editorial_comparison_sets": len(comparison_sets),
            "editorial_reading_question_counts": {question["id"]: len(question["scenario_ids"]) for question in questions},
            "technical_comparisons_crossing_reading_questions": len(crossing),
            "selected_fixture_types": len(fixture_types),
            "conditional_arm_runs_per_common_instance_and_repetition": sum(len(fixture["arms"]) for fixture in fixture_types),
            "additional_frozen_plan_types": sum("A0" in fixture["arms"] for fixture in fixture_types),
            "direct_only_specs": sum({fixture["required_network_transitions"] for fixture in scenario["selected_fixture_types"]} == {0} for scenario in proposed),
            "full_map_only_specs": sum({fixture["knowledge"] for fixture in scenario["selected_fixture_types"]} == {"K2"} for scenario in proposed),
            "specs_with_complexity_and_measurement_contracts": sum(bool(scenario.get("complexity_profile")) and bool(scenario.get("measurement_contract")) for scenario in proposed),
            "specs_with_iot_integration_and_priority": sum(bool(scenario.get("iot_review_integration")) and bool(scenario.get("implementation_priority")) for scenario in proposed),
            "iot_review_items_with_disposition": len(mappings),
            "iot_disposition_counts": dict(sorted(Counter(item["disposition"] for item in mappings).items())),
            "priority_stage_counts": dict(sorted(Counter(scenario["priority"] for scenario in proposed).items())),
            "implementation_main_steps": organization["main_steps"],
            "implementation_work_roles": {key: stage["role"] for key, stage in stage_records.items()},
            "selected_experiment_contracts_sha256": selection_sha,
            "pre_rename_experiment_contracts_sha256": restored_sha,
            "descriptive_scenario_names": len(scenario_aliases),
            "renamed_fixture_types": len(type_aliases),
            "new_scored_types_from_iot_review": sum(len(item["selected_type_ids_added"]) for item in mappings),
            "task_counts": dict(sorted(Counter(scenario["task"] for scenario in proposed).items())),
        },
        "inventory": inventory,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", type=Path, help="Verify a saved snapshot using its recorded base commit")
    args = parser.parse_args()
    if args.check:
        expected = json.loads(args.check.read_text())
        actual = snapshot(base_commit=expected["git_commit"])
        if actual != expected:
            raise SystemExit("Snapshot differs: regenerate after checking source and design changes")
        print("Snapshot verified: source hashes and static design counts match")
    else:
        print(json.dumps(snapshot(), indent=2, ensure_ascii=False))
