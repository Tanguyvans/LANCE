"""CLI entry point for baseline utilities."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.baselines import compare, deploy, runner
from src.baselines.scenarios import load_scenario_targets


def main() -> None:
    parser = argparse.ArgumentParser(prog="python3 -m src.baselines")
    sub = parser.add_subparsers(dest="command", required=True)

    deploy_vm = sub.add_parser("deploy-vm", help="Deploy the isolated baseline VM with Ansible")
    deploy_vm.add_argument("--inventory", default=str(deploy.DEFAULT_INVENTORY))
    deploy_vm.add_argument("--playbook", default=str(deploy.DEFAULT_PLAYBOOK))
    deploy_vm.add_argument("--vault-password-file", default=str(deploy.DEFAULT_VAULT_PASSWORD))
    deploy_vm.add_argument("--check", action="store_true")
    deploy_vm.add_argument("--extra-vars", action="append", default=[])

    targets = sub.add_parser("targets", help="Print scenario targets as JSON")
    targets.add_argument("--scenario", required=True)
    targets.add_argument("--no-router", action="store_true")
    targets.add_argument("--target-source", default="ground_truth", choices=["ground_truth", "inventory"])

    run = sub.add_parser("run", help="Run one baseline tool through SSH")
    run.add_argument("--tool", required=True)
    run.add_argument("--scenario", required=True)
    run.add_argument("--baseline-host", required=True)
    run.add_argument("--variant", default="A", choices=["A", "B"])
    run.add_argument("--scope", default="192.168.100.0/24")
    run.add_argument("--max-turns", default="200")
    run.add_argument("--model", default="MiniMax-M2.7")
    run.add_argument("--target-source", default="ground_truth", choices=["ground_truth", "inventory"])
    run.add_argument("--config", default=str(runner.DEFAULT_CONFIG))
    run.add_argument("--output-dir", default=str(runner.DEFAULT_OUTPUT_DIR))
    run.add_argument("--no-router", action="store_true")
    run.add_argument("--dry-run", action="store_true")

    ev = sub.add_parser("compare", help="Evaluate baseline run directories")
    ev.add_argument("run_dirs", nargs="+")
    ev.add_argument("--output", default=None)

    pilot = sub.add_parser("pilot-cai", help="Shortcut for the scenario_3 CAI pilot from the paper plan")
    pilot.add_argument("--baseline-host", required=True)
    pilot.add_argument("--variant", default="A", choices=["A", "B"])
    pilot.add_argument("--scenario", default="3")
    pilot.add_argument("--scope", default="192.168.100.0/24")
    pilot.add_argument("--max-turns", default="40")
    pilot.add_argument("--model", default="MiniMax-M2.7")
    pilot.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()
    if args.command == "deploy-vm":
        deploy.deploy_baseline_vm(
            inventory=Path(args.inventory),
            playbook=Path(args.playbook),
            vault_password_file=Path(args.vault_password_file).expanduser(),
            check=args.check,
            extra_vars=args.extra_vars,
        )
    elif args.command == "targets":
        import json
        from src.baselines.scenarios import load_ground_truth_targets

        if args.target_source == "ground_truth":
            selected = load_ground_truth_targets(args.scenario)
        else:
            selected = load_scenario_targets(args.scenario, include_router=not args.no_router)
        print(json.dumps([t.to_dict() for t in selected], indent=2))
    elif args.command == "run":
        sys.argv = [
            "src.baselines.runner",
            "--tool", args.tool,
            "--scenario", args.scenario,
            "--baseline-host", args.baseline_host,
            "--variant", args.variant,
            "--scope", args.scope,
            "--max-turns", args.max_turns,
            "--model", args.model,
            "--target-source", args.target_source,
            "--config", args.config,
            "--output-dir", args.output_dir,
        ]
        if args.no_router:
            sys.argv.append("--no-router")
        if args.dry_run:
            sys.argv.append("--dry-run")
        runner.main()
    elif args.command == "compare":
        sys.argv = ["src.baselines.compare", *args.run_dirs]
        if args.output:
            sys.argv.extend(["--output", args.output])
        compare.main()
    elif args.command == "pilot-cai":
        run_dir = runner.run_baseline(
            tool="cai",
            scenario_id=args.scenario,
            baseline_host=args.baseline_host,
            variant=args.variant,
            scope=args.scope,
            max_turns=int(args.max_turns),
            model=args.model,
            dry_run=args.dry_run,
        )
        print(run_dir)


if __name__ == "__main__":
    main()
