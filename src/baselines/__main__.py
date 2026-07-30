from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from src.baselines.runner import run_local_baseline


def _external_manifest() -> dict:
    import yaml
    path = Path("benchmarks/external/manifest.yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "external":
        from src.baselines.external_benchmarks import main as external_main
        external_main(sys.argv[2:])
        return
    parser = argparse.ArgumentParser(description="Run paper baseline harnesses")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run-local", help="Run one real harness once against a scenario CIDR")
    run.add_argument("--tool", required=True, choices=["cai", "vulnbot"])
    run.add_argument("--scenario", required=True)
    run.add_argument("--mode", required=True, choices=["blind", "informed"])
    run.add_argument("--scope", default="192.168.100.0/24")
    run.add_argument("--model", default=os.environ.get("AGENT_MODEL", ""))
    run.add_argument("--max-turns", type=int, default=200)
    run.add_argument("--output-dir", type=Path, default=Path("output/baselines"))
    run.add_argument("--command-template")
    run.add_argument("--dry-run", action="store_true")

    prepare = sub.add_parser("fleet-prepare", help="Sync project and pinned suites to external workers")
    prepare.add_argument("--host", action="append", required=True)
    prepare.add_argument("--suite", action="append", choices=["autopenbench", "vulhub"], default=[])

    start = sub.add_parser("fleet-start", help="Shard a pinned external runlist across workers")
    start.add_argument("--host", action="append", required=True)
    start.add_argument("--suite", required=True, choices=["autopenbench", "vulhub"])
    start.add_argument("--cases-file", required=True, type=Path)
    start.add_argument("--repo", required=True, type=Path)
    start.add_argument("--context-mode", choices=["blind", "informed"], default="blind")
    start.add_argument("--model", default=os.environ.get("AGENT_MODEL", "MiniMax-M2.7"))
    start.add_argument("--max-turns", type=int, default=40)
    start.add_argument("--dry-run", action="store_true")
    start.add_argument("--no-sync", action="store_true")

    for name in ("fleet-status", "fleet-resume", "fleet-fetch", "fleet-stop"):
        command = sub.add_parser(name)
        command.add_argument("distributed_job_id")
    args = parser.parse_args()

    if args.command == "run-local":
        print(run_local_baseline(
            tool=args.tool,
            scenario_id=args.scenario,
            mode=args.mode,
            scope=args.scope,
            model=args.model,
            max_turns=args.max_turns,
            output_root=args.output_dir,
            command_template=args.command_template,
            dry_run=args.dry_run,
        ))
    elif args.command == "fleet-prepare":
        from src.baselines.fleet import fleet_prepare
        suites = tuple(args.suite or ["autopenbench", "vulhub"])
        manifest = _external_manifest()
        commits = {
            suite: str(manifest["suites"][suite]["commit"])
            for suite in suites
        }
        print(json.dumps(fleet_prepare(args.host, suites=suites, pinned_commits=commits), indent=2))
    elif args.command == "fleet-start":
        from src.baselines.fleet import load_cases_from_file, start_distributed_job, verify_fleet_commit
        manifest = _external_manifest()
        expected_commit = str(manifest["suites"][args.suite]["commit"])
        if not args.dry_run:
            audit = verify_fleet_commit(args.host, args.repo, expected_commit)
            failures = {host: value for host, value in audit.items() if value != expected_commit}
            if failures:
                raise SystemExit("remote suite commit mismatch: " + json.dumps(failures))
        job = start_distributed_job(
            hosts=args.host,
            suite=args.suite,
            cases=load_cases_from_file(args.cases_file),
            repo=args.repo,
            context_mode=args.context_mode,
            model=args.model,
            max_turns=args.max_turns,
            sync_project=not args.no_sync,
            dry_run=args.dry_run,
        )
        print(json.dumps(job.to_dict(), indent=2, ensure_ascii=False))
    elif args.command == "fleet-status":
        from src.baselines.fleet import fleet_status
        status = fleet_status(args.distributed_job_id)
        print(json.dumps({
            "distributed_job_id": status.distributed_job_id,
            "aggregate": status.aggregate,
            "hosts": [host.to_dict() for host in status.hosts],
        }, indent=2, ensure_ascii=False))
    elif args.command == "fleet-resume":
        from src.baselines.fleet import fleet_resume
        print(json.dumps(fleet_resume(args.distributed_job_id), indent=2, ensure_ascii=False))
    elif args.command == "fleet-fetch":
        from src.baselines.fleet import fleet_fetch
        print(fleet_fetch(args.distributed_job_id))
    elif args.command == "fleet-stop":
        from src.baselines.fleet import fleet_stop
        print(json.dumps(fleet_stop(args.distributed_job_id), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
