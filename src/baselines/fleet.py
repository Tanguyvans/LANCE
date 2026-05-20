"""Multi-VM benchmark fleet orchestration.

Sharding, parallel dispatch, and aggregation on top of the existing single-VM
detached job lifecycle in `src.baselines.external_benchmarks`.
"""
from __future__ import annotations

import json
import re
import subprocess
from collections import Counter
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from time import sleep, time
from typing import Any

from src.baselines.external_benchmarks import (
    DEFAULT_OUTPUT_DIR,
    DEFAULT_REMOTE_BENCHMARK_DIR,
    DEFAULT_REMOTE_JOB_DIR,
    DEFAULT_REMOTE_OUTPUT_DIR,
    DEFAULT_REMOTE_PROJECT_DIR,
    autopenbench_case_id,
    detached_job_status,
    ensure_remote_benchmark_repo,
    ensure_remote_docker,
    fetch_detached_job,
    organize_fetched_job,
    prepare_remote_external_environment,
    resume_detached_job,
    start_detached_job,
    stop_detached_job,
    sync_project_to_remote,
)
from src.baselines import store as _store


from src.baselines.paths import under_root as _under_root

DEFAULT_FLEET_HOSTS: tuple[str, ...] = ()
DEFAULT_FLEET_OUTPUT = DEFAULT_OUTPUT_DIR / "distributed"
FLEET_HOSTS_FILE = _under_root("output", "baselines", "fleet_hosts.json")
SHARD_STRATEGIES = ("round-robin", "load-aware")
USEFUL_OUTCOMES = {
    "confirmed_exploit",
    "probable_vulnerability",
    "blocked_missing_tool",
    "blocked_missing_credentials",
}


@dataclass
class HostJob:
    baseline_host: str
    cases: list[str]
    job_id: str = ""
    session: str = ""
    job_dir: str = ""
    status: str = "pending"
    last_status_payload: dict[str, Any] = field(default_factory=dict)
    last_seen_at: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HostJob":
        return cls(**data)


@dataclass
class DistributedJob:
    distributed_job_id: str
    suite: str
    created_at: str
    shard_strategy: str
    host_jobs: list[HostJob]
    local_dir: Path
    cases_total: int
    repo: str = ""
    agent_command: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "distributed_job_id": self.distributed_job_id,
            "suite": self.suite,
            "created_at": self.created_at,
            "shard_strategy": self.shard_strategy,
            "host_jobs": [hj.to_dict() for hj in self.host_jobs],
            "local_dir": str(self.local_dir),
            "cases_total": self.cases_total,
            "repo": self.repo,
            "agent_command": self.agent_command,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DistributedJob":
        return cls(
            distributed_job_id=data["distributed_job_id"],
            suite=data["suite"],
            created_at=data["created_at"],
            shard_strategy=data["shard_strategy"],
            host_jobs=[HostJob.from_dict(hj) for hj in data.get("host_jobs", [])],
            local_dir=Path(data["local_dir"]),
            cases_total=int(data.get("cases_total", 0)),
            repo=str(data.get("repo", "")),
            agent_command=data.get("agent_command"),
        )


@dataclass
class FleetStatus:
    distributed_job_id: str
    hosts: list[HostJob]
    aggregate: dict[str, Any]
    refreshed_at: float


def _load_case_durations(durations_path: Path | None) -> dict[str, float]:
    if not durations_path or not durations_path.exists():
        return {}
    try:
        data = json.loads(durations_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): float(v) for k, v in data.items() if isinstance(v, (int, float))}


def shard_cases(
    cases: Iterable[str],
    hosts: Iterable[str],
    strategy: str = "round-robin",
    durations_path: Path | None = None,
) -> dict[str, list[str]]:
    """Split a case list across hosts.

    Strategies:
      - "round-robin": cases[i] -> hosts[i % N].
      - "load-aware": LPT greedy bin-packing using a `case -> duration_seconds`
        map at `durations_path`. Unknown cases get the median duration. Falls
        back to round-robin when no duration data is available.
    """
    host_list = [h for h in hosts if h]
    case_list = list(cases)
    if not host_list:
        raise ValueError("shard_cases requires at least one host")
    if strategy not in SHARD_STRATEGIES:
        raise ValueError(f"Unsupported shard strategy: {strategy}")

    shards: dict[str, list[str]] = {h: [] for h in host_list}
    if not case_list:
        return shards

    if strategy == "round-robin":
        for index, case_id in enumerate(case_list):
            shards[host_list[index % len(host_list)]].append(case_id)
        return shards

    durations = _load_case_durations(durations_path)
    if not durations:
        return shard_cases(case_list, host_list, strategy="round-robin")

    sorted_values = sorted(durations.values())
    median = sorted_values[len(sorted_values) // 2] if sorted_values else 60.0
    weighted = sorted(
        ((case_id, float(durations.get(case_id, median))) for case_id in case_list),
        key=lambda item: item[1],
        reverse=True,
    )
    loads: dict[str, float] = {h: 0.0 for h in host_list}
    for case_id, weight in weighted:
        target = min(host_list, key=lambda h: (loads[h], host_list.index(h)))
        shards[target].append(case_id)
        loads[target] += weight
    return shards


def _parallel_ssh(
    targets: list[Any],
    fn: Callable[[Any], Any],
    *,
    max_workers: int = 4,
) -> list[tuple[Any, Any | None, Exception | None]]:
    """Run `fn(target)` over `targets` in a thread pool.

    Returns `[(target, result, exception)]` preserving input order. Caller
    decides how to interpret exceptions.
    """
    results: list[tuple[Any, Any | None, Exception | None]] = [(t, None, None) for t in targets]
    if not targets:
        return results
    workers = max(1, min(max_workers, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fn, target): index for index, target in enumerate(targets)}
        for future in as_completed(futures):
            index = futures[future]
            target = targets[index]
            try:
                results[index] = (target, future.result(), None)
            except Exception as exc:
                results[index] = (target, None, exc)
    return results


def _distributed_job_dir(distributed_job_id: str, output_dir: Path = DEFAULT_FLEET_OUTPUT) -> Path:
    return output_dir / distributed_job_id


def _distributed_job_path(distributed_job_id: str, output_dir: Path = DEFAULT_FLEET_OUTPUT) -> Path:
    return _distributed_job_dir(distributed_job_id, output_dir) / "distributed_job.json"


def save_distributed_job(job: DistributedJob) -> Path:
    job.local_dir.mkdir(parents=True, exist_ok=True)
    path = job.local_dir / "distributed_job.json"
    path.write_text(json.dumps(job.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def load_distributed_job(
    distributed_job_id: str,
    output_dir: Path = DEFAULT_FLEET_OUTPUT,
) -> DistributedJob:
    path = _distributed_job_path(distributed_job_id, output_dir)
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        return DistributedJob.from_dict(data)
    # SQLite fallback: reconstruct from the store if the JSON sidecar is missing.
    try:
        from src.baselines import store as _store

        rows = _store.run_sql(
            "SELECT * FROM distributed_jobs WHERE distributed_job_id = ?",
            (distributed_job_id,),
        )
        if not rows:
            raise FileNotFoundError(f"No distributed job at {path} and none in store")
        dj_row = rows[0]
        host_rows = _store.run_sql(
            "SELECT * FROM host_jobs WHERE distributed_job_id = ?",
            (distributed_job_id,),
        )
        job = DistributedJob(
            distributed_job_id=dj_row["distributed_job_id"],
            suite=dj_row["suite"],
            created_at=dj_row["created_at"],
            shard_strategy=dj_row["shard_strategy"],
            host_jobs=[
                HostJob(
                    baseline_host=hr["baseline_host"],
                    cases=[],
                    job_id=hr.get("job_id") or "",
                    session=hr.get("session") or "",
                    job_dir=hr.get("job_dir") or "",
                    status=hr.get("status") or "pending",
                    error=hr.get("error"),
                )
                for hr in host_rows
            ],
            local_dir=Path(dj_row.get("local_dir") or str(output_dir / distributed_job_id)),
            cases_total=int(dj_row.get("cases_total") or 0),
            repo=dj_row.get("repo") or "",
            agent_command=dj_row.get("agent_command"),
        )
        # Best-effort: persist the reconstructed JSON for next time.
        try:
            save_distributed_job(job)
        except Exception:
            pass
        return job
    except FileNotFoundError:
        raise
    except Exception as exc:
        raise FileNotFoundError(f"No distributed job metadata at {path}: {exc}")


def list_distributed_jobs(output_dir: Path = DEFAULT_FLEET_OUTPUT) -> list[dict[str, Any]]:
    if not output_dir.exists():
        return []
    summaries: list[dict[str, Any]] = []
    for path in sorted(output_dir.glob("*/distributed_job.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        summaries.append(
            {
                "distributed_job_id": data.get("distributed_job_id"),
                "suite": data.get("suite"),
                "created_at": data.get("created_at"),
                "hosts": [hj.get("baseline_host") for hj in data.get("host_jobs", [])],
                "cases_total": data.get("cases_total"),
                "local_dir": data.get("local_dir"),
            }
        )
    return summaries


def deploy_env_on_fleet(
    hosts: list[str],
    api_key: str,
    *,
    max_workers: int = 4,
) -> dict[str, str]:
    """Push `/opt/baseline-tools/.env` on every fleet host in parallel."""
    from src.baselines import install_tools

    def _deploy(host: str) -> str:
        install_tools.deploy_minimax_env(host, api_key=api_key)
        return "ok"

    outcomes: dict[str, str] = {}
    for host, _result, exc in _parallel_ssh(hosts, _deploy, max_workers=max_workers):
        outcomes[host] = "ok" if exc is None else f"error: {exc}"
    return outcomes


def fleet_prepare(
    hosts: list[str],
    project_dir: Path = DEFAULT_REMOTE_PROJECT_DIR,
    *,
    install_deps: bool = True,
    max_workers: int = 4,
    suites: tuple[str, ...] = ("vulhub",),
    benchmark_root: Path = DEFAULT_REMOTE_BENCHMARK_DIR,
) -> dict[str, str]:
    """Sync the project, ensure Docker, and clone benchmark suites on each host in parallel.

    `suites` is the tuple of suite ids whose upstream repo should be cloned on
    each host (defaults to just "vulhub"). Other supported values:
    "autopenbench". Pass () to skip suite cloning entirely.
    """

    def _prepare(host: str) -> str:
        sync_project_to_remote(host, project_dir=project_dir, install_deps=install_deps)
        try:
            ensure_remote_docker(host)
        except Exception as exc:  # docker setup best-effort; continue to clone
            return f"ok (docker warning: {exc})"
        for suite in suites:
            try:
                ensure_remote_benchmark_repo(host, suite, benchmark_root=benchmark_root)
            except Exception as exc:
                return f"ok (suite {suite} clone failed: {exc})"
        return "ok"

    outcomes: dict[str, str] = {}
    for host, result, exc in _parallel_ssh(hosts, _prepare, max_workers=max_workers):
        outcomes[host] = (result if isinstance(result, str) else "ok") if exc is None else f"error: {exc}"
    return outcomes


def _make_distributed_job_id(suite: str) -> str:
    return f"dist-{suite}-{datetime.now().strftime('%Y%m%d_%H%M%S')}"


def _normalize_model_for_minimax_api(model: str) -> str:
    """Strip the LiteLLM-style 'openai/' prefix that CAI requires but MiniMax rejects.

    CAI runs through LiteLLM and needs `openai/MiniMax-M2.7` to select the
    OpenAI-compatible provider. Our `src.agent_external` talks to MiniMax
    directly via the openai Python client, which forwards the model string
    verbatim. MiniMax's `/v1/chat/completions` rejects unknown ids (case-
    sensitive, no provider prefix). Strip the prefix only for fleet-driven
    runs.
    """
    if model.startswith("openai/"):
        return model[len("openai/"):]
    return model


def start_distributed_job(
    hosts: list[str],
    suite: str,
    cases: list[str],
    repo: Path,
    *,
    shard_strategy: str = "round-robin",
    durations_path: Path | None = None,
    stagger_seconds: float = 0.0,
    output_dir: Path = DEFAULT_FLEET_OUTPUT,
    agent_command: str | None = None,
    model: str = "MiniMax-M2.7",
    max_turns: int = 40,
    context_mode: str = "informed",
    timeout_seconds: int = 3600,
    sync_project: bool = True,
    dry_run: bool = False,
    keep_running: bool = False,
    docker_cleanup: bool = True,
    min_free_gb: float = 15.0,
    remote_output_dir: Path = DEFAULT_REMOTE_OUTPUT_DIR,
    remote_job_dir: Path = DEFAULT_REMOTE_JOB_DIR,
    starter: Callable[..., dict[str, Any]] = start_detached_job,
) -> DistributedJob:
    """Shard `cases` across `hosts` and launch a detached job per host in parallel."""
    if not hosts:
        raise ValueError("start_distributed_job requires at least one host")
    if not cases:
        raise ValueError("start_distributed_job requires at least one case")

    shards = shard_cases(cases, hosts, strategy=shard_strategy, durations_path=durations_path)
    distributed_job_id = _make_distributed_job_id(suite)
    local_dir = _distributed_job_dir(distributed_job_id, output_dir)
    # Strip LiteLLM-style prefix because fleet jobs invoke src.agent_external,
    # which talks to MiniMax directly (provider prefix is rejected there).
    model = _normalize_model_for_minimax_api(model)

    host_jobs = [HostJob(baseline_host=h, cases=shards[h]) for h in hosts]
    job = DistributedJob(
        distributed_job_id=distributed_job_id,
        suite=suite,
        created_at=datetime.now().isoformat(timespec="seconds"),
        shard_strategy=shard_strategy,
        host_jobs=host_jobs,
        local_dir=local_dir,
        cases_total=sum(len(s) for s in shards.values()),
        repo=str(repo),
        agent_command=agent_command,
    )
    save_distributed_job(job)

    if dry_run:
        for hj in host_jobs:
            hj.status = "dry_run"
            hj.job_id = f"dryrun-{hj.baseline_host}"
        save_distributed_job(job)
        return job

    def _launch(hj: HostJob) -> dict[str, Any]:
        if not hj.cases:
            return {"skipped": True, "reason": "empty_shard"}
        return starter(
            baseline_host=hj.baseline_host,
            suite=suite,
            cases=hj.cases,
            repo=repo,
            agent_command=agent_command,
            project_dir=DEFAULT_REMOTE_PROJECT_DIR,
            remote_output_dir=remote_output_dir,
            remote_job_dir=remote_job_dir,
            timeout_seconds=timeout_seconds,
            dry_run=dry_run,
            keep_running=keep_running,
            sync_project=sync_project,
            model=model,
            max_turns=max_turns,
            context_mode=context_mode,
            docker_cleanup=docker_cleanup,
            min_free_gb=min_free_gb,
        )

    if stagger_seconds > 0 and len(host_jobs) > 1:
        # Serial launch with delay between calls.
        for index, hj in enumerate(host_jobs):
            try:
                payload = _launch(hj)
                _apply_launch_payload(hj, payload)
            except Exception as exc:
                hj.status = "failed"
                hj.error = f"start: {exc}"
            if index + 1 < len(host_jobs):
                sleep(stagger_seconds)
    else:
        for host, payload, exc in _parallel_ssh(host_jobs, _launch, max_workers=len(host_jobs)):
            if exc is not None:
                host.status = "failed"
                host.error = f"start: {exc}"
                continue
            _apply_launch_payload(host, payload or {})

    save_distributed_job(job)
    try:
        _store.record_distributed_job(job)
    except Exception:  # store is best-effort; never block dispatch
        pass
    return job


def _apply_launch_payload(hj: HostJob, payload: dict[str, Any]) -> None:
    if payload.get("skipped"):
        hj.status = "skipped"
        return
    hj.job_id = str(payload.get("job_id") or hj.job_id)
    hj.session = str(payload.get("session") or hj.session)
    hj.job_dir = str(payload.get("job_dir") or hj.job_dir)
    hj.status = "running"


def fleet_status(
    distributed_job_id: str,
    output_dir: Path = DEFAULT_FLEET_OUTPUT,
    *,
    status_fn: Callable[[str, str], dict[str, Any]] = detached_job_status,
) -> FleetStatus:
    """Poll the per-host status for a distributed job and aggregate."""
    job = load_distributed_job(distributed_job_id, output_dir=output_dir)

    def _read(hj: HostJob) -> dict[str, Any]:
        if not hj.job_id or hj.status in {"dry_run", "skipped"}:
            return {}
        return status_fn(hj.baseline_host, hj.job_id)

    now = time()
    for host, payload, exc in _parallel_ssh(job.host_jobs, _read, max_workers=max(1, len(job.host_jobs))):
        if exc is not None:
            host.status = "unreachable"
            host.error = f"status: {exc}"
            continue
        if payload:
            host.last_status_payload = payload
            host.last_seen_at = now
            new_status = str(payload.get("status") or host.status)
            host.status = new_status
            host.error = None

    save_distributed_job(job)
    try:
        _store.record_host_status(distributed_job_id, job.host_jobs)
    except Exception:
        pass
    return FleetStatus(
        distributed_job_id=distributed_job_id,
        hosts=job.host_jobs,
        aggregate=_aggregate_fleet(job),
        refreshed_at=now,
    )


def _aggregate_fleet(job: DistributedJob) -> dict[str, Any]:
    completed_total = 0
    failed_total = 0
    useful_total = 0
    estimated_cost = 0.0
    total_tokens = 0
    outcome_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    host_statuses: Counter[str] = Counter()
    for hj in job.host_jobs:
        host_statuses[hj.status] += 1
        payload = hj.last_status_payload or {}
        completed_total += int(payload.get("completed") or 0)
        failed_total += int(payload.get("failed") or 0)
        useful_total += int(payload.get("useful_findings") or 0)
        estimated_cost += float(payload.get("estimated_cost_usd") or 0.0)
        total_tokens += int(payload.get("total_tokens") or 0)
        outcome_counts.update(dict(payload.get("outcome_counts") or {}))
        status_counts.update(dict(payload.get("status_counts") or {}))
    return {
        "cases_total": job.cases_total,
        "cases_completed": completed_total,
        "cases_failed": failed_total,
        "useful_findings": useful_total,
        "estimated_cost_usd": round(estimated_cost, 6),
        "total_tokens": total_tokens,
        "outcome_counts": dict(outcome_counts),
        "status_counts": dict(status_counts),
        "host_statuses": dict(host_statuses),
    }


def fleet_stop(
    distributed_job_id: str,
    output_dir: Path = DEFAULT_FLEET_OUTPUT,
    *,
    stop_fn: Callable[[str, str], None] = stop_detached_job,
) -> dict[str, str]:
    job = load_distributed_job(distributed_job_id, output_dir=output_dir)

    def _stop(hj: HostJob) -> str:
        if not hj.job_id:
            return "skipped"
        stop_fn(hj.baseline_host, hj.job_id)
        hj.status = "stopped"
        return "stopped"

    outcomes: dict[str, str] = {}
    for host, result, exc in _parallel_ssh(job.host_jobs, _stop, max_workers=max(1, len(job.host_jobs))):
        outcomes[host.baseline_host] = "stopped" if exc is None else f"error: {exc}"
        if exc is not None:
            host.error = f"stop: {exc}"
    save_distributed_job(job)
    return outcomes


def fleet_resume(
    distributed_job_id: str,
    output_dir: Path = DEFAULT_FLEET_OUTPUT,
    *,
    resume_fn: Callable[..., dict[str, Any]] = resume_detached_job,
    sync_project: bool = True,
) -> dict[str, dict[str, Any]]:
    job = load_distributed_job(distributed_job_id, output_dir=output_dir)

    def _resume(hj: HostJob) -> dict[str, Any]:
        if not hj.job_id:
            return {"status": "skipped"}
        return resume_fn(
            baseline_host=hj.baseline_host,
            job_id=hj.job_id,
            sync_project=sync_project,
            include_failed=True,
        )

    outcomes: dict[str, dict[str, Any]] = {}
    for host, payload, exc in _parallel_ssh(job.host_jobs, _resume, max_workers=max(1, len(job.host_jobs))):
        if exc is not None:
            outcomes[host.baseline_host] = {"status": "error", "error": str(exc)}
            continue
        outcomes[host.baseline_host] = payload or {}
        if isinstance(payload, dict) and payload.get("job_id"):
            host.job_id = str(payload["job_id"])
            host.session = str(payload.get("session") or host.session)
            host.status = "running"
    save_distributed_job(job)
    return outcomes


def fleet_fetch(
    distributed_job_id: str,
    output_dir: Path = DEFAULT_FLEET_OUTPUT,
    *,
    fetch_fn: Callable[..., Path] = fetch_detached_job,
    parallel: int = 4,
    base_results_dir: Path = DEFAULT_OUTPUT_DIR,
) -> Path:
    """Pull per-host artifacts and merge them into distributed_summary.json."""
    job = load_distributed_job(distributed_job_id, output_dir=output_dir)
    host_artifacts: list[dict[str, Any]] = []

    def _fetch(hj: HostJob) -> Path:
        return fetch_fn(hj.baseline_host, hj.job_id, host_subdir=True)

    for host, fetched_path, exc in _parallel_ssh(job.host_jobs, _fetch, max_workers=parallel):
        host_artifacts.append(
            {
                "baseline_host": host.baseline_host,
                "job_id": host.job_id,
                "status": host.status,
                "fetched": exc is None,
                "fetched_path": str(fetched_path) if fetched_path else "",
                "error": str(exc) if exc else "",
            }
        )

    manifest_path = job.local_dir / "distributed_fetch_manifest.json"
    job.local_dir.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(
            {
                "distributed_job_id": distributed_job_id,
                "fetched_at": datetime.now().isoformat(timespec="seconds"),
                "hosts": host_artifacts,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return merge_distributed_results(
        distributed_job_id,
        output_dir=output_dir,
        base_results_dir=base_results_dir,
    )


def merge_distributed_results(
    distributed_job_id: str,
    output_dir: Path = DEFAULT_FLEET_OUTPUT,
    *,
    base_results_dir: Path = DEFAULT_OUTPUT_DIR,
) -> Path:
    """Aggregate per-host summary.json into a single distributed_summary.json."""
    job = load_distributed_job(distributed_job_id, output_dir=output_dir)
    hosts_summary: list[dict[str, Any]] = []
    totals_outcomes: Counter[str] = Counter()
    totals_statuses: Counter[str] = Counter()
    items_concat: list[dict[str, Any]] = []
    total_completed = 0
    total_useful = 0
    estimated_cost = 0.0
    total_tokens = 0

    for hj in job.host_jobs:
        summary = _load_host_summary(hj, base_results_dir)
        outcomes = Counter(dict(summary.get("outcome_counts") or {}))
        statuses = Counter(dict(summary.get("status_counts") or {}))
        items = list(summary.get("items") or [])
        completed = int(summary.get("completed") or len(items))
        useful = int(summary.get("useful_findings") or sum(1 for i in items if str(i.get("outcome")) in USEFUL_OUTCOMES))
        cost = float(summary.get("estimated_cost_usd") or 0.0)
        tokens = int(summary.get("total_tokens") or 0)
        hosts_summary.append(
            {
                "baseline_host": hj.baseline_host,
                "job_id": hj.job_id,
                "status": hj.status,
                "cases_total": len(hj.cases),
                "cases_completed": completed,
                "useful_findings": useful,
                "estimated_cost_usd": round(cost, 6),
                "total_tokens": tokens,
                "outcome_counts": dict(outcomes),
                "status_counts": dict(statuses),
            }
        )
        totals_outcomes.update(outcomes)
        totals_statuses.update(statuses)
        for item in items:
            stamped = dict(item)
            stamped.setdefault("source_host", hj.baseline_host)
            items_concat.append(stamped)
        total_completed += completed
        total_useful += useful
        estimated_cost += cost
        total_tokens += tokens

    merged = {
        "distributed_job_id": distributed_job_id,
        "suite": job.suite,
        "shard_strategy": job.shard_strategy,
        "created_at": job.created_at,
        "merged_at": datetime.now().isoformat(timespec="seconds"),
        "hosts": hosts_summary,
        "totals": {
            "cases_total": job.cases_total,
            "cases_completed": total_completed,
            "useful_findings": total_useful,
            "estimated_cost_usd": round(estimated_cost, 6),
            "total_tokens": total_tokens,
            "outcome_counts": dict(totals_outcomes),
            "status_counts": dict(totals_statuses),
        },
        "items": items_concat,
    }
    job.local_dir.mkdir(parents=True, exist_ok=True)
    target = job.local_dir / "distributed_summary.json"
    target.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        _store.record_runs_from_merge(distributed_job_id, merged)
    except Exception:
        pass
    return target


def _load_host_summary(hj: HostJob, base_results_dir: Path) -> dict[str, Any]:
    """Find the per-host summary.json after `fetch_detached_job` copied it locally.

    Prefer the host-isolated layout (`jobs/<host_safe>/<job_id>/summary.json`)
    written by the patched fetcher; fall back to the legacy shared path for
    backwards compatibility with old fetches.
    """
    if not hj.job_id:
        return {}
    host_safe = re.sub(r"[^A-Za-z0-9.-]+", "_", hj.baseline_host).strip("_") or "host"
    candidates = [
        base_results_dir / "jobs" / host_safe / hj.job_id / "summary.json",
        base_results_dir / "jobs" / hj.job_id / "summary.json",
        base_results_dir / "batches" / hj.job_id / "summary.json",
    ]
    for path in candidates:
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
    return {}


def _discover_autopenbench_remote(host: str, remote_repo: str) -> list[str]:
    """SSH to `host`, read `data/games.json`, return AutoPenBench case_id strings.

    Case ids mirror `discover_autopenbench` via the shared
    `autopenbench_case_id` helper; target falls back to `vm{index}` when absent.
    """
    games_path = f"{remote_repo}/data/games.json"
    script = (
        f"if [ ! -f {games_path} ]; then echo __MISSING_REPO__ 1>&2; exit 2; fi; "
        f"cat {games_path}"
    )
    result = subprocess.run(
        ["ssh", "-o", "ConnectTimeout=10", host, script],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 2 or "__MISSING_REPO__" in result.stderr:
        raise RuntimeError(
            f"autopenbench repo not present at {host}:{remote_repo} (no data/games.json). "
            "Run 'Sync project + prepare environment on all fleet hosts' first to clone it."
        )
    if result.returncode != 0:
        raise RuntimeError(f"Remote discovery failed on {host}: {result.stderr.strip() or 'no output'}")
    try:
        games = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Could not parse {games_path} from {host}: {exc}")
    cases: list[str] = []
    for level, categories in (games.items() if isinstance(games, dict) else []):
        if not isinstance(categories, dict):
            continue
        for category, tasks in categories.items():
            if not isinstance(tasks, list):
                continue
            for index, item in enumerate(tasks):
                if not isinstance(item, dict):
                    continue
                target = str(item.get("target") or f"vm{index}")
                cases.append(autopenbench_case_id(str(level), str(category), target))
    return list(dict.fromkeys(cases))


def discover_cases_remote(
    host: str,
    suite: str = "vulhub",
    remote_repo: str = "/opt/external-benchmarks/vulhub",
) -> list[str]:
    """SSH to `host`, walk the suite repo, return the list of case_id strings.

    Vulhub: each subdir with a docker-compose.yml is a case. We exclude `.git`
    and `base`. AutoPenBench: enumerated from `data/games.json`. Other suites
    can be added when needed.
    """
    if suite == "autopenbench":
        return _discover_autopenbench_remote(host, remote_repo)
    if suite != "vulhub":
        raise NotImplementedError(f"Remote discovery for suite {suite!r} not implemented yet")
    script = (
        f"if [ ! -d {remote_repo} ]; then echo __MISSING_REPO__ 1>&2; exit 2; fi; "
        f"find {remote_repo} -name docker-compose.yml -not -path '*/.git/*' "
        f"-not -path '*/base/*' | sed 's|{remote_repo}/||; s|/docker-compose.yml||' | sort -u"
    )
    result = subprocess.run(
        ["ssh", "-o", "ConnectTimeout=10", host, script],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 2 or "__MISSING_REPO__" in result.stderr:
        raise RuntimeError(
            f"{suite} repo not present at {host}:{remote_repo}. "
            "Run 'Sync project + prepare environment on all fleet hosts' first to clone it."
        )
    if result.returncode != 0:
        raise RuntimeError(f"Remote discovery failed on {host}: {result.stderr.strip() or 'no output'}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def write_cases_file(cases: list[str], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(cases) + "\n", encoding="utf-8")
    return path


def load_provisioned_hosts(path: Path = FLEET_HOSTS_FILE) -> list[str]:
    """Return the SSH hosts persisted by `deploy_fleet.yml` (or [] if missing).

    The playbook writes `output/baselines/fleet_hosts.json` after provisioning,
    with one entry per VM: `{hostname, vmid, benchmark_ip, mgmt_host}`. We
    return the `mgmt_host` list, filtering out unresolved entries.
    """
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    raw_hosts = data.get("hosts") if isinstance(data, dict) else None
    if not isinstance(raw_hosts, list):
        return []
    hosts = []
    for entry in raw_hosts:
        if not isinstance(entry, dict):
            continue
        mgmt = str(entry.get("mgmt_host") or "").strip()
        if not mgmt or "UNKNOWN" in mgmt:
            continue
        hosts.append(mgmt)
    return hosts


def parse_hosts_arg(value: str) -> list[str]:
    """Parse a comma-separated hosts string ("h1,h2,h3") into a clean list."""
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def load_cases_from_file(path: Path) -> list[str]:
    """Read newline-delimited case ids from a text file; ignore blanks/comments."""
    cases: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cases.append(line)
    return cases
