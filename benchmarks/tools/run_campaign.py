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
import re
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from itertools import groupby
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "benchmarks" / "campaigns" / "paper_v3_4.yaml"
DEFAULT_INVENTORY = ROOT / "benchmarks" / "ansible" / "inventory.yml"
PLAYBOOK_DIR = ROOT / "benchmarks" / "ansible" / "playbooks"
SCENARIO_DIR = ROOT / "benchmarks" / "scenarios"
LANCE_REQUIRED_ARTIFACTS = (
    "run_meta.json",
    "scenario_meta.json",
    "cost_summary.json",
    "tool_calls.jsonl",
    "01_graph_analysis.md",
    "02_recon.md",
    "06_report.md",
)
LANCE_REQUIRED_PHASES = ("graph_analysis", "recon", "report")


@dataclass(frozen=True)
class Condition:
    scenario: str
    system: str
    mode: str
    role: str
    repetition: int

    @property
    def id(self) -> str:
        return f"S{self.scenario}:{self.system}:{self.mode}:r{self.repetition}"

    @property
    def slug(self) -> str:
        return f"S{self.scenario}_{self.system}_{self.mode}_r{self.repetition}"


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
        if repetitions < 1:
            raise ValueError("campaign repetitions must be at least one")
        systems = [str(item) for item in group.get("systems", [])]
        modes = group.get("modes") or [group.get("mode")]
        modes = [str(item) for item in modes if item]
        for raw_sid in group.get("scenarios", []):
            sid = int(raw_sid)
            for mode in modes:
                if mode not in {"blind", "informed"}:
                    raise ValueError(f"unsupported campaign mode: {mode}")
                for system in systems:
                    for repetition in range(1, repetitions + 1):
                        by_scenario.setdefault(sid, []).append(Condition(
                            scenario=str(sid),
                            system=system,
                            mode=mode,
                            role=str(group.get("role", "unspecified")),
                            repetition=repetition,
                        ))

    # Within S20-S29, blind confirmatory systems always run before the informed
    # LANCE diagnostic. Across scenarios, the manifest fixes ascending order.
    add(manifest["development_diagnostics"])
    add(manifest["confirmatory"])
    add(manifest["public_held_out_informed_diagnostic"])

    blind_conditions: list[Condition] = []
    informed_conditions: list[Condition] = []
    base_system_order = ["lance", "cai", "vulnbot"]
    for sid in sorted(by_scenario):
        items = by_scenario[sid]
        rotation = (sid - 20) % len(base_system_order) if sid >= 20 else 0
        rotated = base_system_order[rotation:] + base_system_order[:rotation]
        rank = {system: index for index, system in enumerate(rotated)}
        blind_conditions.extend(sorted(
            (item for item in items if item.mode == "blind"),
            key=lambda item: (rank.get(item.system, len(rank)), item.repetition),
        ))
        informed_conditions.extend(
            item for item in items if item.mode == "informed"
        )
    # No informed run is allowed to precede a blind run. This keeps later
    # oracle-visible diagnostics from influencing the primary blind phase.
    conditions = [*blind_conditions, *informed_conditions]
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

    def _run(
        self,
        command: list[str],
        *,
        cwd: Path = ROOT,
        log_path: Path | None = None,
    ) -> None:
        print("+", shlex.join(command), flush=True)
        if self.args.dry_run:
            return
        if log_path is None:
            subprocess.run(command, cwd=cwd, check=True)
            return
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as log_handle:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            assert process.stdout is not None
            for line in process.stdout:
                print(line, end="", flush=True)
                log_handle.write(line)
                log_handle.flush()
            return_code = process.wait()
        if return_code:
            raise subprocess.CalledProcessError(return_code, command)

    def _set_operation(self, operation: str, scenario: str | None = None) -> None:
        self.state["current_operation"] = {
            "operation": operation,
            "scenario": scenario,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save_state()

    def _playbook(self, name: str, scenario: str) -> None:
        command = [
            "ansible-playbook",
            "-i", str(self.args.inventory),
            str(PLAYBOOK_DIR / name),
            "--extra-vars", f"scenario_id={scenario}",
        ]
        if self.args.vault_password_file:
            command[1:1] = ["--vault-password-file", str(self.args.vault_password_file)]
        elif self.args.ask_vault_pass:
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

    def _preflight_workers(self, conditions: list[Condition]) -> None:
        """Validate every remote blind LANCE worker before Proxmox is touched."""
        if not any(
            item.system == "lance" and item.mode == "blind"
            for item in conditions
        ):
            return
        for worker in dict.fromkeys(self.workers):
            if worker == "local":
                continue
            remote = (
                f"cd {shlex.quote(self.args.remote_workdir)} && "
                f"{shlex.quote(self.args.blind_worker_launcher)} --preflight"
            )
            self._run(["ssh", worker, remote])

    @staticmethod
    def _validate_collected_run(
        condition: Condition, run_dir: Path, meta: dict[str, Any]
    ) -> None:
        """Reject incomplete LANCE artifacts even if the process exited zero."""
        if condition.system != "lance":
            return
        if meta.get("run_status") != "completed":
            raise RuntimeError(
                f"collected LANCE run is not completed: {meta.get('run_status')!r}"
            )
        phase_statuses = meta.get("phase_statuses")
        if not isinstance(phase_statuses, dict):
            raise RuntimeError("collected LANCE run has no phase_statuses contract")
        bad_phases = {
            name: phase_statuses.get(name)
            for name in LANCE_REQUIRED_PHASES
            if not str(phase_statuses.get(name, "")).startswith("completed")
        }
        if bad_phases:
            raise RuntimeError(f"required LANCE phases are incomplete: {bad_phases}")
        missing = [name for name in LANCE_REQUIRED_ARTIFACTS if not (run_dir / name).is_file()]
        if missing:
            raise RuntimeError(f"collected LANCE run is missing artifacts: {', '.join(missing)}")

    @staticmethod
    def _initial_credentials(scenario: str) -> list[dict[str, Any]]:
        path = SCENARIO_DIR / f"S{scenario}.yaml"
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        credentials = data.get("initial_credentials") or []
        if not isinstance(credentials, list) or not all(
            isinstance(item, dict) for item in credentials
        ):
            raise ValueError(f"S{scenario} initial_credentials must be a list of objects")
        return credentials

    def _agent_command(
        self,
        condition: Condition,
        *,
        output_dir: str | None = None,
        remote: bool = False,
    ) -> list[str]:
        common = [
            "--scenario", condition.scenario,
            "--no-manage-scenario",
        ]
        if condition.mode == "blind":
            common.extend(["--blind", "--target-network", self.args.scope])
        credentials = self._initial_credentials(condition.scenario)
        if credentials:
            common.extend([
                "--initial-credentials",
                json.dumps(credentials, ensure_ascii=False, separators=(",", ":")),
            ])
        if output_dir:
            common.extend(["--output-dir", output_dir])
        if condition.system == "lance":
            if remote and condition.mode == "blind":
                command = [self.args.blind_worker_launcher, *common]
            else:
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
            if output_dir:
                command.extend(["--output-dir", output_dir])
            baseline_model = self.args.baseline_model or self.args.model
            if baseline_model:
                command.extend(["--model", baseline_model])
            return command
        raise ValueError(f"unsupported campaign system: {condition.system}")

    def _run_condition(self, condition: Condition) -> None:
        worker = self._next_worker()
        attempt_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        campaign_slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(self.manifest["campaign_id"]))
        result_parent = self.state_path.parent / "results" / condition.slug
        if worker == "local":
            output_root = result_parent / attempt_id
            command = self._agent_command(condition, output_dir=str(output_root))
        else:
            remote_output = PurePosixPath(self.args.remote_output_root) / campaign_slug / condition.slug / attempt_id
            command = self._agent_command(condition, output_dir=str(remote_output), remote=True)
        log_path = result_parent / f"{attempt_id}.log"
        started_at = datetime.now(timezone.utc).isoformat()
        self.state["conditions"][condition.id] = {
            **asdict(condition),
            "worker": worker,
            "status": "running",
            "started_at": started_at,
            "log_path": str(log_path),
        }
        self._set_operation(f"run:{condition.id}", condition.scenario)

        run_dir: Path | None = None
        remote_result_dir: str | None = None
        try:
            if worker == "local":
                self._run(command, log_path=log_path)
            else:
                remote = f"cd {shlex.quote(self.args.remote_workdir)} && {shlex.join(command)}"
                self._run(["ssh", worker, remote], log_path=log_path)

            if not self.args.dry_run:
                if worker == "local":
                    fetched_root = output_root
                else:
                    self._set_operation(f"collect:{condition.id}", condition.scenario)
                    result_parent.mkdir(parents=True, exist_ok=True)
                    remote_result = PurePosixPath(self.args.remote_workdir) / remote_output
                    self._run(["scp", "-r", f"{worker}:{remote_result}", str(result_parent)])
                    fetched_root = result_parent / attempt_id
                    remote_result_dir = str(remote_result)
                meta_files = sorted(fetched_root.rglob("run_meta.json"))
                if len(meta_files) != 1:
                    raise RuntimeError(
                        f"expected exactly one collected run_meta.json for {condition.id}, "
                        f"found {len(meta_files)} under {fetched_root}"
                    )
                run_dir = meta_files[0].parent
                meta = json.loads(meta_files[0].read_text(encoding="utf-8"))
                if meta.get("mode") != condition.mode:
                    raise RuntimeError(
                        f"collected mode mismatch for {condition.id}: {meta.get('mode')!r}"
                    )
                self._validate_collected_run(condition, run_dir, meta)
                if (run_dir / "ground_truth.yaml").exists():
                    raise RuntimeError(
                        f"blind worker leaked ground_truth.yaml into {condition.id} artifacts"
                    )
        except Exception as exc:
            self.state["conditions"][condition.id].update({
                "status": "failed",
                "failed_at": datetime.now(timezone.utc).isoformat(),
                "error": str(exc),
            })
            self._save_state()
            raise

        self.state["conditions"][condition.id].update({
            "status": "completed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "run_dir": str(run_dir) if run_dir else None,
            "remote_result_dir": remote_result_dir,
        })
        self._save_state()

    def run(self, conditions: list[Condition]) -> None:
        selected = [item for item in conditions if self._selected(item)]
        pending = [
            item for item in selected
            if self.state["conditions"].get(item.id, {}).get("status") != "completed"
        ]
        self._preflight_workers(pending)
        # groupby deliberately preserves phase order from _conditions. The same
        # scenario may therefore form one blind block and a later informed block.
        for scenario, grouped in groupby(pending, key=lambda item: item.scenario):
            scenario_conditions = list(grouped)
            try:
                self._set_operation("deploy", scenario)
                self._deploy(scenario)
                for index, condition in enumerate(scenario_conditions):
                    if index:
                        self._set_operation("reset-and-verify", scenario)
                        self._reset(scenario)
                    self._run_condition(condition)
            finally:
                self._set_operation("teardown", scenario)
                self._playbook("99_teardown.yml", scenario)
        self._set_operation("idle")

    def print_status(self, conditions: list[Condition]) -> None:
        selected = [item for item in conditions if self._selected(item)]
        entries = self.state.get("conditions", {})
        counts = {"pending": 0, "running": 0, "completed": 0, "failed": 0}
        for item in selected:
            status = str(entries.get(item.id, {}).get("status", "pending"))
            counts[status if status in counts else "pending"] += 1
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        print(
            f"[{now}] {self.manifest['campaign_id']} — "
            f"{counts['completed']}/{len(selected)} terminés, "
            f"{counts['running']} en cours, {counts['failed']} échec(s), "
            f"{counts['pending']} en attente"
        )
        current = self.state.get("current_operation") or {}
        if current:
            print(
                f"Opération : {current.get('operation', 'unknown')} "
                f"S{current.get('scenario') or '-'} — {current.get('updated_at', '')}"
            )
        active = [
            (item, entries.get(item.id, {})) for item in selected
            if entries.get(item.id, {}).get("status") in {"running", "failed"}
        ]
        for item, entry in active:
            print(
                f"{entry.get('status', '').upper():7} {item.id} "
                f"worker={entry.get('worker', '-')} log={entry.get('log_path', '-')}"
            )

    def _selected(self, condition: Condition) -> bool:
        if self.args.only_scenario and condition.scenario not in self.args.only_scenario:
            return False
        if self.args.only_system and condition.system not in self.args.only_system:
            return False
        if self.args.only_mode and condition.mode not in self.args.only_mode:
            return False
        if self.args.only_repetition and condition.repetition not in self.args.only_repetition:
            return False
        return True


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the frozen paper-v3.4 campaign")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--vault-password-file", type=Path)
    parser.add_argument("--ask-vault-pass", action="store_true")
    parser.add_argument("--worker", action="append", help="SSH host; repeat for a fleet. Default: local")
    parser.add_argument("--remote-workdir", default="/opt/nato-smartcity-iot-v3.4")
    parser.add_argument("--remote-output-root", default="output/campaigns")
    parser.add_argument("--python-executable", default=".venv/bin/python")
    parser.add_argument(
        "--blind-worker-launcher",
        default="benchmarks/tools/run_blind_worker.sh",
        help="Root launcher that drops privileges and hides oracle files on remote blind workers.",
    )
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
    parser.add_argument("--only-mode", action="append", choices=["blind", "informed"])
    parser.add_argument("--only-repetition", action="append", type=int, choices=[1, 2])
    parser.add_argument("--state", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--pilot",
        action="store_true",
        help="Run one excluded LANCE-blind repetition on a declared pilot scenario.",
    )
    parser.add_argument("--status", action="store_true", help="Print campaign progress without executing anything")
    parser.add_argument(
        "--watch-status",
        type=int,
        metavar="SECONDS",
        help="Continuously print campaign progress every 1-60 seconds",
    )
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
    if args.vault_password_file and args.ask_vault_pass:
        raise SystemExit("choose either --vault-password-file or --ask-vault-pass, not both")
    manifest = _load_manifest(args.manifest)
    if args.pilot and args.state is None:
        args.state = (
            ROOT / "output" / "campaigns" / str(manifest["campaign_id"]) / "pilot-state.json"
        )
    if args.watch_status is not None and not 1 <= args.watch_status <= 60:
        raise SystemExit("--watch-status must be between 1 and 60 seconds")
    if args.status or args.watch_status is not None:
        runner = CampaignRunner(args, manifest)
        conditions = _conditions(manifest)
        try:
            while True:
                runner.state = runner._read_state()
                runner.print_status(conditions)
                if args.watch_status is None:
                    return
                time.sleep(args.watch_status)
        except KeyboardInterrupt:
            return
    if not args.dry_run and not args.authorize:
        raise SystemExit("Refusing real execution without --authorize; use --dry-run to inspect commands")
    if args.pilot:
        pilot_scenarios = {str(item) for item in manifest.get("pilot", {}).get("scenarios", [])}
        valid_pilot = (
            args.only_scenario is not None
            and len(args.only_scenario) == 1
            and args.only_scenario[0] in pilot_scenarios
            and args.only_system == ["lance"]
            and args.only_mode == ["blind"]
            and args.only_repetition == [1]
        )
        if not valid_pilot:
            raise SystemExit(
                "--pilot requires one declared pilot scenario plus "
                "--only-system lance --only-mode blind --only-repetition 1"
            )
    if not args.dry_run and not args.pilot and manifest.get("status") != "frozen-authorized":
        raise SystemExit(
            f"Refusing official execution while manifest status is {manifest.get('status')!r}; "
            "complete the lab smoke test and freeze the campaign first"
        )
    runner = CampaignRunner(args, manifest)
    runner.run(_conditions(manifest))


if __name__ == "__main__":
    main()
