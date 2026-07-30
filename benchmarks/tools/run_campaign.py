#!/usr/bin/env python3
"""Serial, manifest-driven runner for the paper v3.4 IoT campaign.

The controller is the only process allowed to manage Proxmox. Agent workers
receive one already-prepared scenario at a time and always run with scenario
management disabled. This intentionally favours isolation over throughput: a
mutable scenario is reset and verified between every condition.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "benchmarks" / "campaigns" / "paper_v3_4.yaml"
DEFAULT_INVENTORY = ROOT / "benchmarks" / "ansible" / "inventory.yml"
PLAYBOOK_DIR = ROOT / "benchmarks" / "ansible" / "playbooks"


@dataclass(frozen=True)
class Condition:
    scenario: str
    system: str
    mode: str
    role: str

    @property
    def id(self) -> str:
        return f"S{self.scenario}:{self.system}:{self.mode}"


def _load_manifest(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if data.get("schema_version") != 2:
        raise ValueError("campaign manifest must use schema_version 2")
    if data.get("execution", {}).get("reset_between_conditions") is not True:
        raise ValueError("campaign must require reset_between_conditions")
    return data


def _conditions(manifest: dict[str, Any]) -> list[Condition]:
    by_scenario: dict[int, list[Condition]] = {}

    def add(group: dict[str, Any]) -> None:
        repetitions = int(group.get("repetitions", 1))
        if repetitions != 1:
            raise ValueError("v3.4 runner currently requires one precommitted run per condition")
        systems = [str(item) for item in group.get("systems", [])]
        modes = group.get("modes") or [group.get("mode")]
        modes = [str(item) for item in modes if item]
        for raw_sid in group.get("scenarios", []):
            sid = int(raw_sid)
            for mode in modes:
                if mode not in {"blind", "informed"}:
                    raise ValueError(f"unsupported campaign mode: {mode}")
                for system in systems:
                    by_scenario.setdefault(sid, []).append(Condition(
                        scenario=str(sid),
                        system=system,
                        mode=mode,
                        role=str(group.get("role", "unspecified")),
                    ))

    # Within S20-S29, blind confirmatory systems always run before the informed
    # LANCE diagnostic. Across scenarios, the manifest fixes ascending order.
    add(manifest["development_diagnostics"])
    add(manifest["confirmatory"])
    add(manifest["public_held_out_informed_diagnostic"])

    conditions: list[Condition] = []
    base_system_order = ["lance", "cai", "vulnbot"]
    for sid in sorted(by_scenario):
        items = by_scenario[sid]
        if sid >= 20:
            rotation = (sid - 20) % len(base_system_order)
            rotated = base_system_order[rotation:] + base_system_order[:rotation]
            rank = {system: index for index, system in enumerate(rotated)}
            blind = sorted(
                (item for item in items if item.mode == "blind"),
                key=lambda item: rank.get(item.system, len(rank)),
            )
            informed = [item for item in items if item.mode != "blind"]
            items = [*blind, *informed]
        conditions.extend(items)
    expected = int(manifest.get("planned_published_runs", -1))
    if len(conditions) != expected:
        raise ValueError(f"manifest declares {expected} runs but expands to {len(conditions)}")
    if len({item.id for item in conditions}) != len(conditions):
        raise ValueError("campaign expands to duplicate condition identifiers")
    return conditions


class CampaignRunner:
    def __init__(self, args: argparse.Namespace, manifest: dict[str, Any]):
        self.args = args
        self.manifest = manifest
        campaign_id = str(manifest["campaign_id"])
        self.state_path = args.state or ROOT / "output" / "campaigns" / campaign_id / "state.json"
        self.state = self._read_state()
        self.workers = args.worker or ["local"]
        self.worker_index = 0

    def _read_state(self) -> dict[str, Any]:
        if self.state_path.exists():
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            if data.get("campaign_id") != self.manifest.get("campaign_id"):
                raise ValueError("state file belongs to a different campaign")
            return data
        return {
            "campaign_id": self.manifest["campaign_id"],
            "manifest": str(self.args.manifest),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "conditions": {},
        }

    def _save_state(self) -> None:
        if self.args.dry_run:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.state, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(self.state_path)

    def _run(self, command: list[str], *, cwd: Path = ROOT) -> None:
        print("+", shlex.join(command), flush=True)
        if self.args.dry_run:
            return
        subprocess.run(command, cwd=cwd, check=True)

    def _playbook(self, name: str, scenario: str) -> None:
        command = [
            "ansible-playbook",
            "-i", str(self.args.inventory),
            str(PLAYBOOK_DIR / name),
            "--extra-vars", f"scenario_id={scenario}",
        ]
        if self.args.vault_password_file:
            command[1:1] = ["--vault-password-file", str(self.args.vault_password_file)]
        else:
            command.insert(1, "--ask-vault-pass")
        self._run(command)

    def _deploy(self, scenario: str) -> None:
        # Start from a fresh scenario if benchmark-owned objects already exist.
        self._playbook("99_teardown.yml", scenario)
        for playbook in (
            "03_deploy_scenario.yml",
            "04_inject_vulns.yml",
            "05_populate_services.yml",
            "06_verify.yml",
        ):
            self._playbook(playbook, scenario)

    def _reset(self, scenario: str) -> None:
        self._playbook("08_reset_scenario.yml", scenario)
        self._playbook("06_verify.yml", scenario)

    def _next_worker(self) -> str:
        worker = self.workers[self.worker_index % len(self.workers)]
        self.worker_index += 1
        return worker

    def _agent_command(self, condition: Condition) -> list[str]:
        common = [
            "--scenario", condition.scenario,
            "--no-manage-scenario",
        ]
        if condition.mode == "blind":
            common.append("--blind")
        if condition.system == "lance":
            command = [self.args.python_executable, "-m", "src.agent", *common]
            if self.args.provider:
                command.extend(["--provider", self.args.provider])
            if self.args.model:
                command.extend(["--model", self.args.model])
            if self.args.execution_profile:
                command.extend(["--execution-profile", self.args.execution_profile])
            return command
        if condition.system in {"cai", "vulnbot"}:
            command = [
                self.args.python_executable, "-m", "src.baselines", "run-local",
                "--tool", condition.system,
                "--scenario", condition.scenario,
                "--mode", condition.mode,
                "--scope", self.args.scope,
            ]
            baseline_model = self.args.baseline_model or self.args.model
            if baseline_model:
                command.extend(["--model", baseline_model])
            return command
        raise ValueError(f"unsupported campaign system: {condition.system}")

    def _run_condition(self, condition: Condition) -> None:
        worker = self._next_worker()
        command = self._agent_command(condition)
        if worker == "local":
            self._run(command)
        else:
            remote = f"cd {shlex.quote(self.args.remote_workdir)} && {shlex.join(command)}"
            self._run(["ssh", worker, remote])

        self.state["conditions"][condition.id] = {
            **asdict(condition),
            "worker": worker,
            "status": "completed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save_state()

    def run(self, conditions: list[Condition]) -> None:
        selected = [item for item in conditions if self._selected(item)]
        by_scenario: dict[str, list[Condition]] = {}
        for item in selected:
            if self.state["conditions"].get(item.id, {}).get("status") == "completed":
                continue
            by_scenario.setdefault(item.scenario, []).append(item)

        for scenario, scenario_conditions in by_scenario.items():
            self._deploy(scenario)
            try:
                for index, condition in enumerate(scenario_conditions):
                    if index:
                        self._reset(scenario)
                    self._run_condition(condition)
            finally:
                self._playbook("99_teardown.yml", scenario)

    def _selected(self, condition: Condition) -> bool:
        if self.args.only_scenario and condition.scenario not in self.args.only_scenario:
            return False
        if self.args.only_system and condition.system not in self.args.only_system:
            return False
        return True


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the frozen paper-v3.4 campaign")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--vault-password-file", type=Path)
    parser.add_argument("--worker", action="append", help="SSH host; repeat for a fleet. Default: local")
    parser.add_argument("--remote-workdir", default="/opt/nato-smartcity-iot")
    parser.add_argument("--python-executable", default="python3")
    parser.add_argument("--scope", default="192.168.100.0/24")
    parser.add_argument("--provider")
    parser.add_argument("--model")
    parser.add_argument(
        "--baseline-model",
        help="Model identifier used by CAI/VulnBot adapters (for example openai/MiniMax-M2.7).",
    )
    parser.add_argument("--execution-profile", choices=["auto", "compact", "full"], default="auto")
    parser.add_argument("--only-scenario", action="append")
    parser.add_argument("--only-system", action="append", choices=["lance", "cai", "vulnbot"])
    parser.add_argument("--state", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--authorize",
        action="store_true",
        help="Explicitly authorize real Proxmox and worker execution.",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()
    args.manifest = args.manifest.resolve()
    args.inventory = args.inventory.resolve()
    if not args.dry_run and not args.authorize:
        raise SystemExit("Refusing real execution without --authorize; use --dry-run to inspect commands")
    manifest = _load_manifest(args.manifest)
    if not args.dry_run and manifest.get("status") != "frozen-authorized":
        raise SystemExit(
            f"Refusing official execution while manifest status is {manifest.get('status')!r}; "
            "complete the lab smoke test and freeze the campaign first"
        )
    runner = CampaignRunner(args, manifest)
    runner.run(_conditions(manifest))


if __name__ == "__main__":
    main()
