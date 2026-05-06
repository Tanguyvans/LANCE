"""CLI entry point for baseline utilities."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.baselines import compare, deploy, install_tools, runner, ui, wizard
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

    deploy_scenario = sub.add_parser("deploy-scenario", help="Deploy and prepare a benchmark scenario")
    deploy_scenario.add_argument("--scenario", required=True)
    deploy_scenario.add_argument("--inventory", default=str(deploy.DEFAULT_INVENTORY))
    deploy_scenario.add_argument("--vault-password-file", default=str(deploy.DEFAULT_VAULT_PASSWORD))
    deploy_scenario.add_argument("--no-populate", action="store_true")
    deploy_scenario.add_argument("--verify", action="store_true")

    inject = sub.add_parser("inject-vulns", help="Inject vulnerabilities into an already deployed scenario")
    inject.add_argument("--scenario", required=True)
    inject.add_argument("--inventory", default=str(deploy.DEFAULT_INVENTORY))
    inject.add_argument("--vault-password-file", default=str(deploy.DEFAULT_VAULT_PASSWORD))
    inject.add_argument("--populate", action="store_true")
    inject.add_argument("--verify", action="store_true")

    populate = sub.add_parser("populate-services", help="Populate benchmark services after vulnerability injection")
    populate.add_argument("--scenario", required=True)
    populate.add_argument("--inventory", default=str(deploy.DEFAULT_INVENTORY))
    populate.add_argument("--vault-password-file", default=str(deploy.DEFAULT_VAULT_PASSWORD))
    populate.add_argument("--verify", action="store_true")

    verify_scenario = sub.add_parser("verify-scenario", help="Verify expected scenario vulnerabilities")
    verify_scenario.add_argument("--scenario", required=True)
    verify_scenario.add_argument("--inventory", default=str(deploy.DEFAULT_INVENTORY))
    verify_scenario.add_argument("--vault-password-file", default=str(deploy.DEFAULT_VAULT_PASSWORD))

    reset = sub.add_parser("reset-scenario", help="Reset a deployed scenario back to vulnerable state")
    reset.add_argument("--scenario", required=True)
    reset.add_argument("--inventory", default=str(deploy.DEFAULT_INVENTORY))
    reset.add_argument("--vault-password-file", default=str(deploy.DEFAULT_VAULT_PASSWORD))
    reset.add_argument("--verify", action="store_true")

    teardown = sub.add_parser("teardown-scenario", help="Destroy a benchmark scenario")
    teardown.add_argument("--scenario", required=True)
    teardown.add_argument("--inventory", default=str(deploy.DEFAULT_INVENTORY))
    teardown.add_argument("--vault-password-file", default=str(deploy.DEFAULT_VAULT_PASSWORD))

    setup_cai = sub.add_parser("setup-cai", help="Install CAI and deploy the CAI adapter on the baseline VM")
    setup_cai.add_argument("--baseline-host", required=True)
    setup_cai.add_argument("--remote-dir", default=install_tools.DEFAULT_REMOTE_DIR)
    setup_cai.add_argument("--model", default=install_tools.DEFAULT_MODEL)
    setup_cai.add_argument("--api-key-env", default=install_tools.DEFAULT_API_KEY_ENV)
    setup_cai.add_argument("--minimax-api-key-env", default=None)
    setup_cai.add_argument("--openai-api-key", default=None)
    setup_cai.add_argument("--install-command", default="pip install cai-framework")
    setup_cai.add_argument("--preserve-remote-env", action="store_true")

    setup_tools = sub.add_parser(
        "setup-baselines",
        help="Install/deploy CAI, PentestGPT and VulnBot adapters on the baseline VM",
    )
    setup_tools.add_argument("--baseline-host", required=True)
    setup_tools.add_argument("--remote-dir", default=install_tools.DEFAULT_REMOTE_DIR)
    setup_tools.add_argument("--model", default=install_tools.DEFAULT_MODEL)
    setup_tools.add_argument("--api-key-env", default=install_tools.DEFAULT_API_KEY_ENV)
    setup_tools.add_argument("--minimax-api-key-env", default=None)
    setup_tools.add_argument("--openai-api-key", default=None)
    setup_tools.add_argument("--install-cai-command", default="pip install cai-framework")
    setup_tools.add_argument("--preserve-remote-env", action="store_true")

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
    run.add_argument("--model", default=install_tools.DEFAULT_MODEL)
    run.add_argument("--target-source", default="ground_truth", choices=["ground_truth", "inventory"])
    run.add_argument("--config", default=str(runner.DEFAULT_CONFIG))
    run.add_argument("--output-dir", default=str(runner.DEFAULT_OUTPUT_DIR))
    run.add_argument("--no-router", action="store_true")
    run.add_argument("--dry-run", action="store_true")

    suite = sub.add_parser("suite", help="Run CAI, PentestGPT and VulnBot sequentially for one scenario")
    suite.add_argument("--scenario", required=True)
    suite.add_argument("--baseline-host", required=True)
    suite.add_argument("--tools", default=",".join(runner.DEFAULT_SUITE_TOOLS))
    suite.add_argument("--variant", default="A", choices=["A", "B"])
    suite.add_argument("--scope", default="192.168.100.0/24")
    suite.add_argument("--max-turns", default="40")
    suite.add_argument("--model", default=install_tools.DEFAULT_MODEL)
    suite.add_argument("--target-source", default="ground_truth", choices=["ground_truth", "inventory"])
    suite.add_argument("--config", default=str(runner.DEFAULT_CONFIG))
    suite.add_argument("--output-dir", default=str(runner.DEFAULT_OUTPUT_DIR))
    suite.add_argument("--no-router", action="store_true")
    suite.add_argument("--dry-run", action="store_true")
    suite.add_argument("--no-refresh-adapters", action="store_true")

    ev = sub.add_parser("compare", help="Evaluate baseline run directories")
    ev.add_argument("run_dirs", nargs="+")
    ev.add_argument("--output", default=None)

    pilot = sub.add_parser("pilot-cai", help="Shortcut for the scenario_3 CAI pilot from the paper plan")
    pilot.add_argument("--baseline-host", required=True)
    pilot.add_argument("--variant", default="A", choices=["A", "B"])
    pilot.add_argument("--scenario", default="3")
    pilot.add_argument("--scope", default="192.168.100.0/24")
    pilot.add_argument("--max-turns", default="40")
    pilot.add_argument("--model", default=install_tools.DEFAULT_MODEL)
    pilot.add_argument("--dry-run", action="store_true")

    sub.add_parser("wizard", help="Open the interactive terminal interface")
    sub.add_parser("dashboard", help="Open the rich real-time terminal dashboard")

    args = parser.parse_args()
    if args.command == "deploy-vm":
        deploy.deploy_baseline_vm(
            inventory=Path(args.inventory),
            playbook=Path(args.playbook),
            vault_password_file=Path(args.vault_password_file).expanduser(),
            check=args.check,
            extra_vars=args.extra_vars,
        )
    elif args.command == "deploy-scenario":
        deploy.deploy_scenario(
            scenario_id=args.scenario,
            inventory=Path(args.inventory),
            vault_password_file=Path(args.vault_password_file).expanduser(),
            populate=not args.no_populate,
            verify=args.verify,
        )
    elif args.command == "inject-vulns":
        deploy.inject_vulnerabilities(
            scenario_id=args.scenario,
            inventory=Path(args.inventory),
            vault_password_file=Path(args.vault_password_file).expanduser(),
        )
        if args.populate:
            deploy.populate_services(
                scenario_id=args.scenario,
                inventory=Path(args.inventory),
                vault_password_file=Path(args.vault_password_file).expanduser(),
            )
        if args.verify:
            deploy.verify_scenario(
                scenario_id=args.scenario,
                inventory=Path(args.inventory),
                vault_password_file=Path(args.vault_password_file).expanduser(),
            )
    elif args.command == "populate-services":
        deploy.populate_services(
            scenario_id=args.scenario,
            inventory=Path(args.inventory),
            vault_password_file=Path(args.vault_password_file).expanduser(),
        )
        if args.verify:
            deploy.verify_scenario(
                scenario_id=args.scenario,
                inventory=Path(args.inventory),
                vault_password_file=Path(args.vault_password_file).expanduser(),
            )
    elif args.command == "verify-scenario":
        deploy.verify_scenario(
            scenario_id=args.scenario,
            inventory=Path(args.inventory),
            vault_password_file=Path(args.vault_password_file).expanduser(),
        )
    elif args.command == "reset-scenario":
        deploy.reset_scenario(
            scenario_id=args.scenario,
            inventory=Path(args.inventory),
            vault_password_file=Path(args.vault_password_file).expanduser(),
        )
        if args.verify:
            deploy.verify_scenario(
                scenario_id=args.scenario,
                inventory=Path(args.inventory),
                vault_password_file=Path(args.vault_password_file).expanduser(),
            )
    elif args.command == "teardown-scenario":
        deploy.teardown_scenario(
            scenario_id=args.scenario,
            inventory=Path(args.inventory),
            vault_password_file=Path(args.vault_password_file).expanduser(),
        )
    elif args.command == "setup-cai":
        import os

        if args.preserve_remote_env:
            install_tools.deploy_cai_adapter(args.baseline_host, args.remote_dir)
            return
        key_env = args.minimax_api_key_env or args.api_key_env
        api_key = os.environ.get(key_env)
        if not api_key:
            raise SystemExit(
                f"Missing {key_env}. Export it locally first, "
                f"or choose another env var with --api-key-env."
            )
        install_tools.setup_cai(
            baseline_host=args.baseline_host,
            api_key=api_key,
            remote_dir=args.remote_dir,
            model=args.model,
            install_command=args.install_command,
            openai_api_key=args.openai_api_key,
        )
    elif args.command == "setup-baselines":
        import os

        if args.preserve_remote_env:
            install_tools.deploy_all_adapters(args.baseline_host, args.remote_dir)
            return
        key_env = args.minimax_api_key_env or args.api_key_env
        api_key = os.environ.get(key_env)
        if not api_key:
            raise SystemExit(
                f"Missing {key_env}. Export it locally first, "
                f"or choose another env var with --api-key-env."
            )
        install_tools.setup_baseline_adapters(
            baseline_host=args.baseline_host,
            api_key=api_key,
            remote_dir=args.remote_dir,
            model=args.model,
            install_cai_command=args.install_cai_command,
            openai_api_key=args.openai_api_key,
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
    elif args.command == "suite":
        suite_dir = runner.run_suite(
            scenario_id=args.scenario,
            baseline_host=args.baseline_host,
            tools=tuple(tool.strip() for tool in args.tools.split(",") if tool.strip()),
            variant=args.variant,
            scope=args.scope,
            max_turns=int(args.max_turns),
            model=args.model,
            target_source=args.target_source,
            config_file=Path(args.config),
            output_dir=Path(args.output_dir),
            include_router=not args.no_router,
            dry_run=args.dry_run,
            refresh_adapters=not args.no_refresh_adapters,
        )
        print(suite_dir)
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
    elif args.command == "wizard":
        wizard.run_wizard()
    elif args.command == "dashboard":
        ui.run_dashboard()


if __name__ == "__main__":
    main()
