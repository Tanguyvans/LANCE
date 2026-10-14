"""Deployment overlays and complete evidence bundles for the pilot controller.

This script stays outside src/: it must not change the frozen audit resource hash.
It never executes a network command or changes the campaign manifest.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

import yaml


RUN_NAME = re.compile(r"20\d{2}-\d{2}-\d{2}_\d{6}")
POLICIES = ("rules", "llm")


def deployment_overlay(repo_root: Path, scenario_id: str) -> dict:
    if scenario_id not in {"1", "14", "15", "1h"}:
        raise ValueError(f"Not a pilot scenario: {scenario_id}")
    variables = []
    for filename in ("main.yml", "scenarios_v2.yml"):
        variables.append(yaml.safe_load(
            (repo_root / "benchmarks/ansible/group_vars/all" / filename).read_text()
        ))
    ranges = {**variables[0]["scenario_vmid_ranges"], **variables[1]["scenario_vmid_ranges_v2"]}
    scenarios = {**variables[0]["scenarios"], **variables[1]["scenarios_v2"]}
    topology_source = "1" if scenario_id == "1h" else scenario_id
    scenario = copy.deepcopy(scenarios[topology_source])
    source = scenario_id
    if scenario_id == "1h":
        # Reuse S14's existing hardening and negative checks for MQTT/web/SSH.
        # S1's vulnerable population is skipped by the hardened profiles.
        source = "14"
        scenario["name"] = "Reseau plat (hardened)"
        scenario["router_vulns"] = []
        roles = {service["role"] for service in scenario["services"]}
        if roles != {"mqtt_broker", "web_server", "ssh_server"}:
            raise ValueError("S1h requires the supported S1 MQTT/web/SSH topology")
        for service in scenario["services"]:
            service["security_profile"] = "hardened"
    # Extra vars replace these mappings in Ansible. Preserve the native
    # catalogue so 03_deploy_scenario can detect another active scenario.
    ranges[scenario_id] = ranges[topology_source]
    scenarios[scenario_id] = scenario
    return {
        "scenario_id": scenario_id,
        "source_scenario_id": source,
        "pilot_topology_source_scenario_id": topology_source,
        "router_name": f"s{scenario_id}-router",
        "benchmark_scenario_vmid_ranges": ranges,
        "benchmark_scenarios": scenarios,
    }


def capture_run(trial_dir: Path, runs_root: Path, policy: str, trial_id: str) -> Path | None:
    """Find this arm, including a killed run with no readable run_meta.json."""
    marker = trial_dir / f".marker-{policy}"
    if not marker.is_file() or not runs_root.is_dir():
        return None
    since = marker.stat().st_mtime_ns
    candidates = []
    for run in runs_root.iterdir():
        if run.is_symlink() or not run.is_dir() or not RUN_NAME.fullmatch(run.name):
            continue
        if run.stat().st_mtime_ns < since:
            continue
        meta_path = run / "run_meta.json"
        if meta_path.is_file():
            try:
                meta = json.loads(meta_path.read_text())
            except (ValueError, OSError):
                meta = None  # Preserve damaged/incomplete runs as evidence too.
            if meta is not None and (
                meta.get("decision_policy") != policy
                or meta.get("experiment", {}).get("trial_id") != trial_id
            ):
                continue
        candidates.append(run.resolve())
    if len(candidates) > 1:
        raise ValueError(f"Ambiguous {policy} run selection: {len(candidates)} candidates")
    if not candidates:
        return None
    selected = candidates[0]
    (trial_dir / f"{policy}_dir.txt").write_text(str(selected) + "\n")
    return selected


def _files(directory: Path, prefix: str):
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"Evidence contains a symlink: {path}")
        if path.is_file():
            yield path, f"{prefix}/{path.relative_to(directory).as_posix()}"
        elif not path.is_dir():
            raise ValueError(f"Evidence contains a special file: {path}")


def archive_trial(trial_dir: Path, runs_root: Path, destination: Path, trial_id: str) -> Path:
    """Bundle only this attempt and its two full run directories, with hashes."""
    trial_dir, runs_root, destination = (p.resolve() for p in (trial_dir, runs_root, destination))
    if destination == trial_dir or destination.is_relative_to(trial_dir):
        raise ValueError("Archive destination must be outside the trial directory")
    sources = list(_files(trial_dir, "trial"))
    roots = [(trial_dir, "trial")]
    runs = {}
    for policy in POLICIES:
        reference = trial_dir / f"{policy}_dir.txt"
        run = Path(reference.read_text().strip()) if reference.is_file() else capture_run(
            trial_dir, runs_root, policy, trial_id,
        )
        if run is None:
            runs[policy] = None
            continue
        if not run.is_absolute():
            raise ValueError(f"{policy} run reference must be absolute")
        run = run.resolve()
        if run.parent != runs_root or not RUN_NAME.fullmatch(run.name) or not run.is_dir():
            raise ValueError(f"{policy} run is outside the run store")
        runs[policy] = f"runs/{run.name}"
        if runs[policy] in {v for key, v in runs.items() if key != policy}:
            raise ValueError("Both policies reference the same run")
        sources.extend(_files(run, runs[policy]))
        roots.append((run, runs[policy]))
    # capture_run may have just written missing reference files.
    sources = list(_files(trial_dir, "trial")) + [s for s in sources if s[1].startswith("runs/")]
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    archive = destination / "evidence.tar.gz"
    manifest = {"schema_version": 1, "trial_id": trial_id, "runs": runs, "files": {}}
    with tarfile.open(archive, "w:gz", dereference=False) as bundle:
        for root, prefix in roots:
            for directory in [root, *(p for p in sorted(root.rglob("*")) if p.is_dir())]:
                info = bundle.gettarinfo(str(directory), arcname=f"{prefix}/{directory.relative_to(root).as_posix()}".rstrip("/.") )
                bundle.addfile(info)
        for path, name in sources:
            # Hash the bytes actually placed in the archive, not a second read.
            data = path.read_bytes()
            info = bundle.gettarinfo(str(path), arcname=name)
            info.size = len(data)
            bundle.addfile(info, io.BytesIO(data))
            manifest["files"][name] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    with archive.open("rb") as handle:
        manifest["archive_sha256"] = hashlib.file_digest(handle, "sha256").hexdigest()
    archive.chmod(0o600)
    (destination / "evidence-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (destination / "evidence-manifest.json").chmod(0o600)
    # Keep the comparison immediately readable beside the complete bundle.
    for comparison in trial_dir.glob("comparison-*.json"):
        (destination / comparison.name).write_bytes(comparison.read_bytes())
    return archive


def export_summary(archive: Path, summary_directory: Path, runs_root: Path) -> None:
    """Export only the metadata/comparison already published by the workflow."""
    manifest_path = archive.parent / "evidence-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    summary_directory.mkdir(parents=True, exist_ok=True)
    (summary_directory / manifest_path.name).write_bytes(manifest_path.read_bytes())
    for comparison in archive.parent.glob("comparison-*.json"):
        (summary_directory / comparison.name).write_bytes(comparison.read_bytes())
    for relative in manifest["runs"].values():
        if relative is None:
            continue
        name = Path(relative).name
        target = summary_directory / "runs" / name
        target.mkdir(parents=True, exist_ok=True)
        for filename in ("run_meta.json", "audit_inventory.json", "cost_summary.json"):
            source = runs_root / name / filename
            if source.is_file():
                (target / filename).write_bytes(source.read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--repo-root", type=Path, required=True)
    prepare.add_argument("--scenario-id", required=True)
    prepare.add_argument("--output", type=Path, required=True)
    for command in ("capture", "archive"):
        sub = commands.add_parser(command)
        sub.add_argument("--trial-dir", type=Path, required=True)
        sub.add_argument("--runs-root", type=Path, required=True)
        sub.add_argument("--trial-id", required=True)
        if command == "capture":
            sub.add_argument("--policy", choices=POLICIES, required=True)
        else:
            sub.add_argument("--destination", type=Path, required=True)
            sub.add_argument("--summary-directory", type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        overlay = deployment_overlay(args.repo_root, args.scenario_id)
        args.output.write_text(json.dumps(overlay, indent=2) + "\n")
    elif args.command == "capture":
        capture_run(args.trial_dir, args.runs_root, args.policy, args.trial_id)
    else:
        archive = archive_trial(args.trial_dir, args.runs_root, args.destination, args.trial_id)
        if args.summary_directory:
            export_summary(archive, args.summary_directory, args.runs_root)
        print(archive)


if __name__ == "__main__":
    main()
