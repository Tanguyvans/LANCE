"""Run external baseline tools and evaluate their scenario-level output."""
from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Callable, Any

from src.benchmark.evaluator import evaluate
from src.baselines.config import DEFAULT_CONFIG, ToolConfig, load_tool_config
from src.baselines.install_tools import DEFAULT_MODEL, deploy_all_adapters
from src.baselines.normalizer import normalize_tool_outputs, write_exploitation_results, write_vuln_analysis
from src.baselines.scenarios import BaselineTarget, load_ground_truth_targets, load_scenario_targets


DEFAULT_OUTPUT_DIR = Path("output/baselines")
HEARTBEAT_SECONDS = 30
DEFAULT_SUITE_TOOLS = ("cai", "pentgpt", "vulnbot")
EventCallback = Callable[[dict[str, Any]], None]


def _log(message: str) -> None:
    print(f"[baseline] {message}", flush=True)


def _emit(callback: EventCallback | None, event: str, **payload: Any) -> None:
    if callback:
        callback({"event": event, **payload})


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


def _remote_adapter_path(command_template: str, remote_workdir: str) -> str | None:
    match = re.search(r"(\./adapters/[^\s]+|/opt/baseline-tools/adapters/[^\s]+)", command_template)
    if not match:
        return None
    adapter = match.group(1)
    if adapter.startswith("./"):
        return f"{remote_workdir.rstrip('/')}/{adapter[2:]}"
    return adapter


def _ensure_remote_adapter_ready(baseline_host: str, config: ToolConfig) -> None:
    adapter = _remote_adapter_path(config.command, config.remote_workdir)
    if not adapter:
        return
    check = (
        f"test -x {shlex.quote(adapter)} "
        f"&& ! grep -qi 'placeholder' {shlex.quote(adapter)}"
    )
    result = subprocess.run(["ssh", baseline_host, check], text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Remote adapter for {config.name} is missing or still a placeholder: {adapter}. "
            "Run: python3 -m src.baselines setup-baselines "
            f"--baseline-host {baseline_host} --preserve-remote-env"
        )


def _fetch_remote_log(
    baseline_host: str,
    local_output: Path,
    local_logs_dir: Path,
    event_callback: EventCallback | None = None,
    quiet: bool = False,
) -> Path | None:
    try:
        data = json.loads(local_output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    raw_log = data.get("raw_log")
    if not isinstance(raw_log, str) or not raw_log.startswith("/"):
        return None

    local_logs_dir.mkdir(parents=True, exist_ok=True)
    local_log = local_logs_dir / f"{local_output.stem}{Path(raw_log).suffix or '.log'}"
    try:
        subprocess.run(
            ["scp", f"{baseline_host}:{raw_log}", str(local_log)],
            check=True,
            stdout=subprocess.DEVNULL if quiet else None,
            stderr=subprocess.DEVNULL if quiet else None,
        )
    except subprocess.CalledProcessError:
        _emit(event_callback, "remote_log_fetch_failed", output=str(local_output), remote_log=raw_log)
        return None

    data["local_raw_log"] = str(local_log)
    local_output.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    _emit(event_callback, "remote_log_saved", output=str(local_output), remote_log=raw_log, local_log=str(local_log))
    return local_log


def _run_remote_target(
    baseline_host: str,
    config: ToolConfig,
    scenario_id: str,
    target: BaselineTarget,
    local_raw_dir: Path,
    local_logs_dir: Path,
    variant: str,
    scope: str,
    max_turns: int,
    model: str,
    dry_run: bool = False,
    event_callback: EventCallback | None = None,
    quiet: bool = False,
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
        if not quiet:
            _log(f"dry-run target {target.ip} ({target.name}) -> {local_output}")
        _emit(event_callback, "target_dry_run", target=asdict(target), output=str(local_output))
        local_output.write_text(
            json.dumps({"dry_run_command": wrapped, "target": asdict(target)}, indent=2),
            encoding="utf-8",
        )
        return local_output

    if not quiet:
        _log(f"start {config.name} target {target.ip} ({target.name})")
        _log(f"remote output: {remote_output}")
    _emit(
        event_callback,
        "target_start",
        tool=config.name,
        target=asdict(target),
        remote_output=remote_output,
    )
    started = time.monotonic()
    process = subprocess.Popen(
        ["ssh", baseline_host, wrapped],
        stdout=subprocess.DEVNULL if quiet else None,
        stderr=subprocess.DEVNULL if quiet else None,
    )
    last_heartbeat = started
    while True:
        rc = process.poll()
        now = time.monotonic()
        if rc is not None:
            break
        if now - last_heartbeat >= HEARTBEAT_SECONDS:
            elapsed = int(now - started)
            if not quiet:
                _log(f"still running target {target.ip} after {elapsed}s")
            _emit(event_callback, "target_heartbeat", target=asdict(target), elapsed=elapsed)
            last_heartbeat = now
        time.sleep(1)

    elapsed = round(time.monotonic() - started, 1)
    if rc != 0:
        if not quiet:
            _log(f"failed target {target.ip} after {elapsed}s (ssh exit {rc})")
        _emit(event_callback, "target_failed", target=asdict(target), elapsed=elapsed, returncode=rc)
        local_raw_dir.mkdir(parents=True, exist_ok=True)
        local_output.write_text(
            json.dumps(
                {
                    "tool": config.name,
                    "target": target.ip,
                    "scenario": scenario_id,
                    "findings": [],
                    "adapter_status": "ssh_or_remote_error",
                    "summary": f"Remote baseline command failed with exit code {rc}",
                    "exit_code": rc,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        _emit(event_callback, "target_result_saved", target=asdict(target), output=str(local_output))
        return local_output

    if not quiet:
        _log(f"finished target {target.ip} in {elapsed}s; fetching result")
    _emit(event_callback, "target_finished", target=asdict(target), elapsed=elapsed)
    local_raw_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["scp", f"{baseline_host}:{remote_output}", str(local_output)],
        check=True,
        stdout=subprocess.DEVNULL if quiet else None,
        stderr=subprocess.DEVNULL if quiet else None,
    )
    _fetch_remote_log(baseline_host, local_output, local_logs_dir, event_callback, quiet=quiet)
    if not quiet:
        _log(f"saved raw result: {local_output}")
    _emit(event_callback, "target_result_saved", target=asdict(target), output=str(local_output))
    return local_output


def run_baseline(
    tool: str,
    scenario_id: str,
    baseline_host: str,
    variant: str = "A",
    scope: str = "192.168.100.0/24",
    max_turns: int = 200,
    model: str = DEFAULT_MODEL,
    target_source: str = "ground_truth",
    config_file: Path = DEFAULT_CONFIG,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    include_router: bool = True,
    dry_run: bool = False,
    event_callback: EventCallback | None = None,
    quiet: bool = False,
) -> Path:
    config = load_tool_config(tool, config_file)
    if not dry_run:
        _ensure_remote_adapter_ready(baseline_host, config)
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
    logs_dir = run_dir / "logs"
    raw_dir.mkdir(parents=True, exist_ok=True)

    if not quiet:
        _log(
            f"run tool={tool} scenario={scenario_id} variant={variant.upper()} "
            f"targets={len(targets)} host={baseline_host}"
        )
        _log(f"output dir: {run_dir}")
    _emit(
        event_callback,
        "run_start",
        tool=tool,
        scenario_id=str(scenario_id),
        variant=variant.upper(),
        target_count=len(targets),
        baseline_host=baseline_host,
        run_dir=str(run_dir),
    )

    started_at = datetime.now()
    target_outputs: list[tuple[BaselineTarget, Path]] = []
    for index, target in enumerate(targets, 1):
        if not quiet:
            _log(f"target {index}/{len(targets)}: {target.ip} ({target.name}, {target.source})")
        _emit(event_callback, "target_selected", index=index, total=len(targets), target=asdict(target))
        local_output = _run_remote_target(
            baseline_host=baseline_host,
            config=config,
            scenario_id=scenario_id,
            target=target,
            local_raw_dir=raw_dir,
            local_logs_dir=logs_dir,
            variant=variant.upper(),
            scope=scope,
            max_turns=max_turns,
            model=model,
            dry_run=dry_run,
            event_callback=event_callback,
            quiet=quiet,
        )
        target_outputs.append((target, local_output))

    if not quiet:
        _log("normalizing findings")
    _emit(event_callback, "normalizing")
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
        if not quiet:
            _log(f"evaluating against {gt_file}")
        _emit(event_callback, "evaluating", ground_truth=str(gt_file))
        score = evaluate(run_dir, gt_file)
        (run_dir / "evaluator_score.json").write_text(
            json.dumps(asdict(score), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        if not quiet:
            _log(
                f"score recall={score.recall:.3f} precision={score.precision:.3f} "
                f"f1={score.f1_score:.3f} score={score.score_pct:.1f}%"
            )
        _emit(
            event_callback,
            "score",
            recall=score.recall,
            precision=score.precision,
            f1=score.f1_score,
            score_pct=score.score_pct,
            true_positives=score.true_positives,
            false_positives=score.false_positives,
            false_negatives=score.false_negatives,
        )
    if not quiet:
        _log(f"done: {run_dir}")
    _emit(event_callback, "run_done", run_dir=str(run_dir), finding_count=len(findings))
    return run_dir


def run_suite(
    scenario_id: str,
    baseline_host: str,
    tools: tuple[str, ...] | list[str] = DEFAULT_SUITE_TOOLS,
    variant: str = "A",
    scope: str = "192.168.100.0/24",
    max_turns: int = 200,
    model: str = DEFAULT_MODEL,
    target_source: str = "ground_truth",
    config_file: Path = DEFAULT_CONFIG,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    include_router: bool = True,
    dry_run: bool = False,
    event_callback: EventCallback | None = None,
    quiet: bool = False,
    refresh_adapters: bool = True,
) -> Path:
    suite_name = f"scenario_{scenario_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    suite_dir = output_dir / "suites" / suite_name
    suite_dir.mkdir(parents=True, exist_ok=True)
    selected_tools = tuple(tools)

    if refresh_adapters and not dry_run:
        _emit(event_callback, "suite_adapters_refresh_start", baseline_host=baseline_host)
        if not quiet:
            _log(f"refresh baseline adapters on {baseline_host}")
        deploy_all_adapters(baseline_host)
        _emit(event_callback, "suite_adapters_refresh_done", baseline_host=baseline_host)

    _emit(
        event_callback,
        "suite_start",
        scenario_id=str(scenario_id),
        tools=list(selected_tools),
        suite_dir=str(suite_dir),
    )
    if not quiet:
        _log(f"suite scenario={scenario_id} tools={','.join(selected_tools)} -> {suite_dir}")

    run_dirs: list[Path] = []
    for index, tool in enumerate(selected_tools, 1):
        _emit(event_callback, "suite_tool_start", tool=tool, index=index, total=len(selected_tools))
        run_dir = run_baseline(
            tool=tool,
            scenario_id=scenario_id,
            baseline_host=baseline_host,
            variant=variant,
            scope=scope,
            max_turns=max_turns,
            model=model,
            target_source=target_source,
            config_file=config_file,
            output_dir=suite_dir,
            include_router=include_router,
            dry_run=dry_run,
            event_callback=event_callback,
            quiet=quiet,
        )
        run_dirs.append(run_dir)
        _emit(event_callback, "suite_tool_done", tool=tool, run_dir=str(run_dir), index=index, total=len(selected_tools))

    scores = []
    for run_dir in run_dirs:
        score_file = run_dir / "evaluator_score.json"
        metadata_file = run_dir / "metadata.json"
        if not score_file.exists():
            continue
        score = json.loads(score_file.read_text(encoding="utf-8"))
        metadata = json.loads(metadata_file.read_text(encoding="utf-8")) if metadata_file.exists() else {}
        scores.append(
            {
                "tool": metadata.get("tool", run_dir.parts[-3] if len(run_dir.parts) >= 3 else run_dir.name),
                "run_dir": str(run_dir),
                "recall": score.get("recall", 0),
                "precision": score.get("precision", 0),
                "f1_score": score.get("f1_score", 0),
                "score_pct": score.get("score_pct", 0),
                "true_positives": score.get("true_positives", 0),
                "false_positives": score.get("false_positives", 0),
                "false_negatives": score.get("false_negatives", 0),
            }
        )

    summary = {
        "scenario_id": str(scenario_id),
        "variant": variant.upper(),
        "scope": scope,
        "model": model,
        "baseline_host": baseline_host,
        "tools": list(selected_tools),
        "dry_run": dry_run,
        "suite_dir": str(suite_dir),
        "run_dirs": [str(path) for path in run_dirs],
        "scores": scores,
    }
    (suite_dir / "suite_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    _emit(event_callback, "suite_done", suite_dir=str(suite_dir), run_dirs=[str(path) for path in run_dirs], scores=scores)
    return suite_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Run an external baseline pentest tool per scenario target")
    parser.add_argument("--tool", default="cai", help="Tool name from benchmarks/baselines/tools.example.yml")
    parser.add_argument("--scenario", required=True, help="Scenario id, e.g. 1, 3, 13")
    parser.add_argument("--baseline-host", required=True, help="SSH host for the isolated baseline VM")
    parser.add_argument("--variant", default="A", choices=["A", "B"], help="A=per-IP, B=single CIDR session")
    parser.add_argument("--scope", default="192.168.100.0/24", help="CIDR scope passed to the baseline tool")
    parser.add_argument("--max-turns", type=int, default=200, help="Total turn/step budget for this baseline run")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="LLM model passed to the baseline adapter")
    parser.add_argument("--target-source", default="ground_truth", choices=["ground_truth", "inventory"])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--no-router", action="store_true", help="Do not include the benchmark router target")
    parser.add_argument("--dry-run", action="store_true", help="Write planned commands instead of SSH execution")
    parser.add_argument("--suite", action="store_true", help="Run CAI, PentestGPT and VulnBot sequentially")
    parser.add_argument("--tools", default=",".join(DEFAULT_SUITE_TOOLS), help="Comma-separated tools for --suite")
    parser.add_argument("--no-refresh-adapters", action="store_true", help="Do not refresh remote adapters before --suite")
    args = parser.parse_args()

    if args.suite:
        suite_dir = run_suite(
            scenario_id=args.scenario,
            baseline_host=args.baseline_host,
            tools=tuple(tool.strip() for tool in args.tools.split(",") if tool.strip()),
            variant=args.variant,
            scope=args.scope,
            max_turns=args.max_turns,
            model=args.model,
            target_source=args.target_source,
            config_file=args.config,
            output_dir=args.output_dir,
            include_router=not args.no_router,
            dry_run=args.dry_run,
            refresh_adapters=not args.no_refresh_adapters,
        )
        print(suite_dir)
    else:
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
