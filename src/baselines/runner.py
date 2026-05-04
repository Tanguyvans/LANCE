"""Run external baseline tools and evaluate their scenario-level output."""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from src.benchmark.evaluator import evaluate
from src.baselines.config import DEFAULT_CONFIG, ToolConfig, load_tool_config
from src.baselines.normalizer import normalize_tool_outputs, write_exploitation_results, write_vuln_analysis
from src.baselines.scenarios import BaselineTarget, load_ground_truth_targets, load_scenario_targets


DEFAULT_OUTPUT_DIR = Path("output/baselines")
HEARTBEAT_SECONDS = 30


def _log(message: str) -> None:
    print(f"[baseline] {message}", flush=True)


def _render(
    template: str,
    tool: str,
    scenario_id: str,
    target: BaselineTarget,
    remote_output: str,
    variant: str,
    scope: str,
    max_turns: int,
    model: str,
) -> str:
    return template.format(
        tool=tool,
        scenario=scenario_id,
        scenario_id=scenario_id,
        variant=variant,
        ip=target.ip,
        target=target.ip,
        role=target.role,
        name=target.name,
        output=remote_output,
        scope=scope,
        max_turns=max_turns,
        model=model,
    )


def _remote_output_name(
    config: ToolConfig,
    scenario_id: str,
    target: BaselineTarget,
    variant: str,
    scope: str,
    max_turns: int,
    model: str,
) -> str:
    rendered = _render(config.output_glob, config.name, scenario_id, target, "", variant, scope, max_turns, model)
    return rendered.replace("/", "_").replace(":", "_")


def _run_remote_target(
    baseline_host: str,
    config: ToolConfig,
    scenario_id: str,
    target: BaselineTarget,
    local_raw_dir: Path,
    variant: str,
    scope: str,
    max_turns: int,
    model: str,
    dry_run: bool = False,
) -> Path:
    output_name = _remote_output_name(config, scenario_id, target, variant, scope, max_turns, model)
    remote_output = f"{config.remote_workdir.rstrip('/')}/results/{output_name}"
    command = _render(config.command, config.name, scenario_id, target, remote_output, variant, scope, max_turns, model)
    wrapped = (
        f"mkdir -p {shlex.quote(config.remote_workdir)}/results "
        f"&& cd {shlex.quote(config.remote_workdir)} "
        f"&& timeout {int(config.timeout_seconds)}s {command}"
    )
    local_output = local_raw_dir / output_name
    if dry_run:
        _log(f"dry-run target {target.ip} ({target.name}) -> {local_output}")
        local_output.write_text(
            json.dumps({"dry_run_command": wrapped, "target": asdict(target)}, indent=2),
            encoding="utf-8",
        )
        return local_output

    _log(f"start {config.name} target {target.ip} ({target.name})")
    _log(f"remote output: {remote_output}")
    started = time.monotonic()
    process = subprocess.Popen(["ssh", baseline_host, wrapped])
    last_heartbeat = started
    while True:
        rc = process.poll()
        now = time.monotonic()
        if rc is not None:
            break
        if now - last_heartbeat >= HEARTBEAT_SECONDS:
            elapsed = int(now - started)
            _log(f"still running target {target.ip} after {elapsed}s")
            last_heartbeat = now
        time.sleep(1)

    elapsed = round(time.monotonic() - started, 1)
    if rc != 0:
        _log(f"failed target {target.ip} after {elapsed}s (ssh exit {rc})")
        raise subprocess.CalledProcessError(rc, ["ssh", baseline_host, wrapped])

    _log(f"finished target {target.ip} in {elapsed}s; fetching result")
    local_raw_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["scp", f"{baseline_host}:{remote_output}", str(local_output)], check=True)
    _log(f"saved raw result: {local_output}")
    return local_output


def run_baseline(
    tool: str,
    scenario_id: str,
    baseline_host: str,
    variant: str = "A",
    scope: str = "192.168.100.0/24",
    max_turns: int = 200,
    model: str = "MiniMax-M2.7",
    target_source: str = "ground_truth",
    config_file: Path = DEFAULT_CONFIG,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    include_router: bool = True,
    dry_run: bool = False,
) -> Path:
    config = load_tool_config(tool, config_file)
    if target_source == "ground_truth":
        targets = load_ground_truth_targets(scenario_id)
    elif target_source == "inventory":
        targets = load_scenario_targets(scenario_id, include_router=include_router)
    else:
        raise ValueError("--target-source must be 'ground_truth' or 'inventory'")

    if variant.upper() == "B":
        targets = [
            BaselineTarget(
                ip=scope,
                name=f"S{scenario_id}-scope",
                role="cidr_scope",
                device_id=f"S{scenario_id}-scope",
                source="scope",
            )
        ]

    run_dir = output_dir / tool / f"scenario_{scenario_id}" / variant.upper()
    raw_dir = run_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    _log(
        f"run tool={tool} scenario={scenario_id} variant={variant.upper()} "
        f"targets={len(targets)} host={baseline_host}"
    )
    _log(f"output dir: {run_dir}")

    started_at = datetime.now()
    target_outputs: list[tuple[BaselineTarget, Path]] = []
    for index, target in enumerate(targets, 1):
        _log(f"target {index}/{len(targets)}: {target.ip} ({target.name}, {target.source})")
        local_output = _run_remote_target(
            baseline_host=baseline_host,
            config=config,
            scenario_id=scenario_id,
            target=target,
            local_raw_dir=raw_dir,
            variant=variant.upper(),
            scope=scope,
            max_turns=max_turns,
            model=model,
            dry_run=dry_run,
        )
        target_outputs.append((target, local_output))

    _log("normalizing findings")
    findings = [] if dry_run else normalize_tool_outputs(tool, target_outputs)
    write_exploitation_results(tool, scenario_id, findings, run_dir)
    write_vuln_analysis(tool, scenario_id, findings, run_dir)
    (run_dir / "targets.json").write_text(
        json.dumps([asdict(t) for t in targets], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    finished_at = datetime.now()
    (run_dir / "metadata.json").write_text(
        json.dumps(
            {
                "tool": tool,
                "scenario_id": scenario_id,
                "variant": variant.upper(),
                "scope": scope,
                "model": model,
                "max_turns": max_turns,
                "target_source": target_source,
                "baseline_host": baseline_host,
                "target_count": len(targets),
                "finding_count": len(findings),
                "dry_run": dry_run,
                "started_at": started_at.isoformat(timespec="seconds"),
                "finished_at": finished_at.isoformat(timespec="seconds"),
                "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (run_dir / "run_meta.json").write_text((run_dir / "metadata.json").read_text(encoding="utf-8"), encoding="utf-8")

    gt_file = Path("benchmarks/ground_truth") / f"scenario_{scenario_id}.yaml"
    if gt_file.exists():
        _log(f"evaluating against {gt_file}")
        score = evaluate(run_dir, gt_file)
        (run_dir / "evaluator_score.json").write_text(
            json.dumps(asdict(score), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        _log(
            f"score recall={score.recall:.3f} precision={score.precision:.3f} "
            f"f1={score.f1_score:.3f} score={score.score_pct:.1f}%"
        )
    _log(f"done: {run_dir}")
    return run_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Run an external baseline pentest tool per scenario target")
    parser.add_argument("--tool", required=True, help="Tool name from benchmarks/baselines/tools.example.yml")
    parser.add_argument("--scenario", required=True, help="Scenario id, e.g. 1, 3, 13")
    parser.add_argument("--baseline-host", required=True, help="SSH host for the isolated baseline VM")
    parser.add_argument("--variant", default="A", choices=["A", "B"], help="A=per-IP, B=single CIDR session")
    parser.add_argument("--scope", default="192.168.100.0/24", help="CIDR scope passed to the baseline tool")
    parser.add_argument("--max-turns", type=int, default=200, help="Total turn/step budget for this baseline run")
    parser.add_argument("--model", default="MiniMax-M2.7", help="LLM model passed to the baseline adapter")
    parser.add_argument("--target-source", default="ground_truth", choices=["ground_truth", "inventory"])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--no-router", action="store_true", help="Do not include the benchmark router target")
    parser.add_argument("--dry-run", action="store_true", help="Write planned commands instead of SSH execution")
    args = parser.parse_args()

    run_dir = run_baseline(
        tool=args.tool,
        scenario_id=args.scenario,
        baseline_host=args.baseline_host,
        variant=args.variant,
        scope=args.scope,
        max_turns=args.max_turns,
        model=args.model,
        target_source=args.target_source,
        config_file=args.config,
        output_dir=args.output_dir,
        include_router=not args.no_router,
        dry_run=args.dry_run,
    )
    print(run_dir)


if __name__ == "__main__":
    main()
