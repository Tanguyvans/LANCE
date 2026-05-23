"""CLI entry point for baseline utilities."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.baselines import compare, deploy, external_benchmarks, fleet, install_tools, runner, store, ui, wizard
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

    switch = sub.add_parser(
        "switch-scenario",
        help="Teardown one scenario, then deploy, inject, populate and verify another one",
    )
    switch.add_argument("--current-scenario", required=True)
    switch.add_argument("--next-scenario", required=True)
    switch.add_argument("--inventory", default=str(deploy.DEFAULT_INVENTORY))
    switch.add_argument("--vault-password-file", default=str(deploy.DEFAULT_VAULT_PASSWORD))
    switch.add_argument("--no-populate", action="store_true")
    switch.add_argument("--no-verify", action="store_true")

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
    run.add_argument("--jobs", default=1, type=int, help="Number of targets to run in parallel")

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
    suite.add_argument("--jobs", default=1, type=int, help="Number of targets to run in parallel per tool")

    ev = sub.add_parser("compare", help="Evaluate baseline run directories")
    ev.add_argument("run_dirs", nargs="+")
    ev.add_argument("--output", default=None)

    external = sub.add_parser("external", help="Run our agent against third-party benchmark suites")
    external_sub = external.add_subparsers(dest="external_command", required=True)
    external_list = external_sub.add_parser("list", help="List cases from a local benchmark repo")
    external_list.add_argument("--suite", required=True, choices=external_benchmarks.SUPPORTED_SUITES)
    external_list.add_argument("--repo", required=True)
    external_list.add_argument("--remote-host", default=None)
    external_list.add_argument("--no-sync", action="store_true")
    external_list.add_argument("--json", action="store_true")
    external_manifest = external_sub.add_parser("manifest", help="Write a JSON manifest for a benchmark repo")
    external_manifest.add_argument("--suite", required=True, choices=external_benchmarks.SUPPORTED_SUITES)
    external_manifest.add_argument("--repo", required=True)
    external_manifest.add_argument("--output", required=True)
    external_run = external_sub.add_parser("run", help="Run one external benchmark case")
    external_run.add_argument("--suite", required=True, choices=external_benchmarks.SUPPORTED_SUITES)
    external_run.add_argument("--repo", required=True)
    external_run.add_argument("--case", required=True)
    external_run.add_argument("--agent-command", default=None)
    external_run.add_argument("--baseline-tool", choices=external_benchmarks.BASELINE_TOOLS, default=None)
    external_run.add_argument("--baseline-model", default="openai/MiniMax-M2.7")
    external_run.add_argument("--baseline-max-turns", default=40, type=int)
    external_run.add_argument("--baseline-adapter-dir", default="/opt/baseline-tools/adapters")
    external_run.add_argument("--output-dir", default=str(external_benchmarks.DEFAULT_OUTPUT_DIR))
    external_run.add_argument("--remote-host", default=None)
    external_run.add_argument("--remote-output-dir", default=str(external_benchmarks.DEFAULT_REMOTE_OUTPUT_DIR))
    external_run.add_argument("--no-sync", action="store_true")
    external_run.add_argument("--flag", default=None)
    external_run.add_argument("--timeout", default=1800, type=int)
    external_run.add_argument("--dry-run", action="store_true")
    external_run.add_argument("--keep-running", action="store_true")
    external_run.add_argument("--docker-cleanup", dest="docker_cleanup", action="store_true", default=False)
    external_run.add_argument("--no-docker-cleanup", dest="docker_cleanup", action="store_false")
    external_run.add_argument("--min-free-gb", default=external_benchmarks.DEFAULT_DOCKER_MIN_FREE_GB, type=float)
    external_detached = external_sub.add_parser("start-detached", help="Start a long-running external benchmark job on the baseline VM")
    external_detached.add_argument("--suite", required=True, choices=external_benchmarks.SUPPORTED_SUITES)
    external_detached.add_argument("--repo", required=True)
    external_detached.add_argument("--case", required=True, action="append", dest="cases")
    external_detached.add_argument("--remote-host", required=True)
    external_detached.add_argument("--agent-command", default=None)
    external_detached.add_argument("--baseline-tool", choices=external_benchmarks.BASELINE_TOOLS, default=None)
    external_detached.add_argument("--baseline-model", default="openai/MiniMax-M2.7")
    external_detached.add_argument("--baseline-max-turns", default=40, type=int)
    external_detached.add_argument("--baseline-adapter-dir", default="/opt/baseline-tools/adapters")
    external_detached.add_argument("--remote-output-dir", default=str(external_benchmarks.DEFAULT_REMOTE_OUTPUT_DIR))
    external_detached.add_argument("--remote-job-dir", default=str(external_benchmarks.DEFAULT_REMOTE_JOB_DIR))
    external_detached.add_argument("--timeout", default=3600, type=int)
    external_detached.add_argument("--model", default="MiniMax-M2.7")
    external_detached.add_argument("--max-turns", default=40, type=int)
    external_detached.add_argument("--context-mode", default="informed", choices=external_benchmarks.CONTEXT_MODES)
    external_detached.add_argument("--dry-run", action="store_true")
    external_detached.add_argument("--keep-running", action="store_true")
    external_detached.add_argument("--docker-cleanup", dest="docker_cleanup", action="store_true", default=True)
    external_detached.add_argument("--no-docker-cleanup", dest="docker_cleanup", action="store_false")
    external_detached.add_argument("--min-free-gb", default=external_benchmarks.DEFAULT_DOCKER_MIN_FREE_GB, type=float)
    external_detached.add_argument("--no-sync", action="store_true")
    external_resume = external_sub.add_parser("resume-detached", help="Start a new detached job for cases missing from a previous job")
    external_resume.add_argument("--remote-host", required=True)
    external_resume.add_argument("--job-id", required=True)
    external_resume.add_argument("--remote-job-dir", default=str(external_benchmarks.DEFAULT_REMOTE_JOB_DIR))
    external_resume.add_argument("--no-sync", action="store_true")
    external_prune = external_sub.add_parser("docker-prune", help="Prune unused Docker data on the baseline VM")
    external_prune.add_argument("--remote-host", required=True)
    external_jobs = external_sub.add_parser("jobs", help="List detached external jobs")
    external_jobs.add_argument("--remote-host", required=True)
    external_jobs.add_argument("--remote-job-dir", default=str(external_benchmarks.DEFAULT_REMOTE_JOB_DIR))
    external_status = external_sub.add_parser("status", help="Show detached external job status")
    external_status.add_argument("--remote-host", required=True)
    external_status.add_argument("--job-id", required=True)
    external_status.add_argument("--remote-job-dir", default=str(external_benchmarks.DEFAULT_REMOTE_JOB_DIR))
    external_logs = external_sub.add_parser("logs", help="Show detached external job logs")
    external_logs.add_argument("--remote-host", required=True)
    external_logs.add_argument("--job-id", required=True)
    external_logs.add_argument("--tail", default=100, type=int)
    external_logs.add_argument("--remote-job-dir", default=str(external_benchmarks.DEFAULT_REMOTE_JOB_DIR))
    external_stop = external_sub.add_parser("stop", help="Stop a detached external job")
    external_stop.add_argument("--remote-host", required=True)
    external_stop.add_argument("--job-id", required=True)
    external_stop.add_argument("--remote-job-dir", default=str(external_benchmarks.DEFAULT_REMOTE_JOB_DIR))
    external_attach = external_sub.add_parser("attach", help="Attach to a detached external job tmux session")
    external_attach.add_argument("--remote-host", required=True)
    external_attach.add_argument("--job-id", required=True)
    external_fetch = external_sub.add_parser("fetch", help="Fetch detached external job results")
    external_fetch.add_argument("--remote-host", required=True)
    external_fetch.add_argument("--job-id", required=True)
    external_fetch.add_argument("--output-dir", default=str(external_benchmarks.DEFAULT_OUTPUT_DIR))
    external_fetch.add_argument("--remote-job-dir", default=str(external_benchmarks.DEFAULT_REMOTE_JOB_DIR))
    external_fetch.add_argument("--remote-output-dir", default=str(external_benchmarks.DEFAULT_REMOTE_OUTPUT_DIR))
    external_organize = external_sub.add_parser("organize-job", help="Create a single local batch folder for a fetched detached job")
    external_organize.add_argument("--job-id", required=True)
    external_organize.add_argument("--output-dir", default=str(external_benchmarks.DEFAULT_OUTPUT_DIR))
    external_organize.add_argument("--move", action="store_true")
    external_report = external_sub.add_parser("report", help="Aggregate external benchmark result stats and costs")
    external_report.add_argument("--root", default=str(external_benchmarks.DEFAULT_OUTPUT_DIR))
    external_report.add_argument("--output", default=None)
    external_report.add_argument("--markdown", default=None)

    fleet_start = external_sub.add_parser("start-distributed", help="Launch a benchmark batch sharded across multiple baseline VMs")
    fleet_start.add_argument("--remote-hosts", required=True, help="Comma-separated SSH hosts (e.g. root@h1,root@h2)")
    fleet_start.add_argument("--suite", required=True, choices=external_benchmarks.SUPPORTED_SUITES)
    fleet_start.add_argument("--repo", required=True)
    fleet_start.add_argument("--cases-file", default=None, help="Newline-delimited cases file (one case_id per line)")
    fleet_start.add_argument("--case", action="append", dest="cases", default=[], help="Repeat to add cases inline")
    fleet_start.add_argument("--shard-strategy", default="round-robin", choices=list(fleet.SHARD_STRATEGIES))
    fleet_start.add_argument("--durations-file", default=None)
    fleet_start.add_argument("--stagger-seconds", default=0.0, type=float)
    fleet_start.add_argument("--agent-command", default=None)
    fleet_start.add_argument("--model", default="MiniMax-M2.7")
    fleet_start.add_argument("--max-turns", default=40, type=int)
    fleet_start.add_argument("--context-mode", default="informed", choices=external_benchmarks.CONTEXT_MODES)
    fleet_start.add_argument("--timeout", default=3600, type=int)
    fleet_start.add_argument("--output-dir", default=str(fleet.DEFAULT_FLEET_OUTPUT))
    fleet_start.add_argument("--remote-output-dir", default=str(external_benchmarks.DEFAULT_REMOTE_OUTPUT_DIR))
    fleet_start.add_argument("--remote-job-dir", default=str(external_benchmarks.DEFAULT_REMOTE_JOB_DIR))
    fleet_start.add_argument("--no-sync", action="store_true")
    fleet_start.add_argument("--dry-run", action="store_true")
    fleet_start.add_argument("--keep-running", action="store_true")
    fleet_start.add_argument("--docker-cleanup", dest="docker_cleanup", action="store_true", default=True)
    fleet_start.add_argument("--no-docker-cleanup", dest="docker_cleanup", action="store_false")
    fleet_start.add_argument("--min-free-gb", default=external_benchmarks.DEFAULT_DOCKER_MIN_FREE_GB, type=float)

    fleet_status_cmd = external_sub.add_parser("fleet-status", help="Aggregate live status across all fleet hosts")
    fleet_status_cmd.add_argument("--distributed-job-id", required=True)
    fleet_status_cmd.add_argument("--output-dir", default=str(fleet.DEFAULT_FLEET_OUTPUT))
    fleet_status_cmd.add_argument("--watch", action="store_true", help="Poll every 5s until interrupted")

    fleet_logs_cmd = external_sub.add_parser("fleet-logs", help="Show per-host detached job logs for a distributed job")
    fleet_logs_cmd.add_argument("--distributed-job-id", required=True)
    fleet_logs_cmd.add_argument("--host", required=True, help="Baseline host (must match one of the host_jobs)")
    fleet_logs_cmd.add_argument("--tail", default=100, type=int)
    fleet_logs_cmd.add_argument("--output-dir", default=str(fleet.DEFAULT_FLEET_OUTPUT))
    fleet_logs_cmd.add_argument("--remote-job-dir", default=str(external_benchmarks.DEFAULT_REMOTE_JOB_DIR))

    fleet_stop_cmd = external_sub.add_parser("fleet-stop", help="Stop all detached jobs of a distributed job")
    fleet_stop_cmd.add_argument("--distributed-job-id", required=True)
    fleet_stop_cmd.add_argument("--output-dir", default=str(fleet.DEFAULT_FLEET_OUTPUT))

    fleet_resume_cmd = external_sub.add_parser("fleet-resume", help="Resume remaining cases on each host of a distributed job")
    fleet_resume_cmd.add_argument("--distributed-job-id", required=True)
    fleet_resume_cmd.add_argument("--output-dir", default=str(fleet.DEFAULT_FLEET_OUTPUT))
    fleet_resume_cmd.add_argument("--no-sync", action="store_true")

    fleet_fetch_cmd = external_sub.add_parser("fetch-all", help="Fetch per-host results then write distributed_summary.json")
    fleet_fetch_cmd.add_argument("--distributed-job-id", required=True)
    fleet_fetch_cmd.add_argument("--output-dir", default=str(fleet.DEFAULT_FLEET_OUTPUT))
    fleet_fetch_cmd.add_argument("--base-results-dir", default=str(external_benchmarks.DEFAULT_OUTPUT_DIR))
    fleet_fetch_cmd.add_argument("--parallel", default=4, type=int)

    fleet_list_cmd = external_sub.add_parser("fleet-list", help="List local distributed-job metadata")
    fleet_list_cmd.add_argument("--output-dir", default=str(fleet.DEFAULT_FLEET_OUTPUT))

    fleet_prepare_cmd = external_sub.add_parser("fleet-prepare", help="Sync project + prepare environment on multiple baseline VMs")
    fleet_prepare_cmd.add_argument("--remote-hosts", required=True)
    fleet_prepare_cmd.add_argument("--project-dir", default=str(external_benchmarks.DEFAULT_REMOTE_PROJECT_DIR))
    fleet_prepare_cmd.add_argument("--no-install-deps", action="store_true")
    fleet_prepare_cmd.add_argument("--max-workers", default=4, type=int)

    db_init_cmd = external_sub.add_parser("db-init", help="Initialize the SQLite store (schema only)")
    db_init_cmd.add_argument("--db", default=str(store.DEFAULT_DB_PATH))
    db_list_cmd = external_sub.add_parser("db-list", help="List distributed jobs from the SQLite store")
    db_list_cmd.add_argument("--db", default=str(store.DEFAULT_DB_PATH))
    db_runs_cmd = external_sub.add_parser("db-runs", help="List runs (rows) from the SQLite store")
    db_runs_cmd.add_argument("--db", default=str(store.DEFAULT_DB_PATH))
    db_runs_cmd.add_argument("--distributed-job-id", default=None)
    db_runs_cmd.add_argument("--outcome", default=None)
    db_runs_cmd.add_argument("--case-id", default=None)
    db_runs_cmd.add_argument("--limit", type=int, default=200)
    db_breakdown_cmd = external_sub.add_parser("db-breakdown", help="Outcome breakdown (counts, cost, tokens)")
    db_breakdown_cmd.add_argument("--db", default=str(store.DEFAULT_DB_PATH))
    db_breakdown_cmd.add_argument("--distributed-job-id", default=None)
    db_durations_cmd = external_sub.add_parser("db-case-durations", help="Per-case average duration (for load-aware sharding)")
    db_durations_cmd.add_argument("--db", default=str(store.DEFAULT_DB_PATH))
    db_durations_cmd.add_argument("--output", default=None, help="Write JSON to this path (default: stdout)")
    db_query_cmd = external_sub.add_parser("db-query", help="Run an ad-hoc SELECT against the SQLite store")
    db_query_cmd.add_argument("--db", default=str(store.DEFAULT_DB_PATH))
    db_query_cmd.add_argument("--sql", required=True)
    db_import_cmd = external_sub.add_parser("db-import-existing", help="One-shot import of an existing external_benchmarks/ tree")
    db_import_cmd.add_argument("--root", default=str(external_benchmarks.DEFAULT_OUTPUT_DIR))
    db_import_cmd.add_argument("--db", default=str(store.DEFAULT_DB_PATH))
    db_import_cmd.add_argument("--distributed-job-id", default="legacy-import")

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
    elif args.command == "switch-scenario":
        def on_event(event: dict) -> None:
            name = event["event"]
            step = event.get("step")
            scenario_id = event.get("scenario_id")
            if name == "switch_start":
                print(f"Switching S{event['current_scenario_id']} -> S{event['next_scenario_id']}")
            elif name == "switch_step_start":
                print(f"{step} S{scenario_id}...")
            elif name == "switch_step_done":
                print(f"{step} S{scenario_id}: done")
            elif name == "switch_done":
                print(f"S{event['next_scenario_id']} ready")

        deploy.switch_scenario(
            current_scenario_id=args.current_scenario,
            next_scenario_id=args.next_scenario,
            inventory=Path(args.inventory),
            vault_password_file=Path(args.vault_password_file).expanduser(),
            populate=not args.no_populate,
            verify=not args.no_verify,
            event_callback=on_event,
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
            "--jobs", str(args.jobs),
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
            jobs=args.jobs,
        )
        print(suite_dir)
    elif args.command == "compare":
        sys.argv = ["src.baselines.compare", *args.run_dirs]
        if args.output:
            sys.argv.extend(["--output", args.output])
        compare.main()
    elif args.command == "external":
        if args.external_command == "list":
            if args.remote_host:
                cases = external_benchmarks.discover_remote_cases(
                    baseline_host=args.remote_host,
                    suite=args.suite,
                    repo=Path(args.repo),
                    sync_project=not args.no_sync,
                )
            else:
                cases = external_benchmarks.discover_cases(args.suite, Path(args.repo))
            if args.json:
                import json

                print(json.dumps([case.to_dict() for case in cases], indent=2, ensure_ascii=False))
            else:
                for case in cases:
                    target = case.target_url or "-"
                    level = f"L{case.level}" if case.level else "-"
                    marker = "run" if case.runnable else "manual"
                    print(f"{case.case_id}\t{level}\t{marker}\t{target}\t{case.description}")
        elif args.external_command == "manifest":
            print(
                external_benchmarks.write_manifest(
                    suite=args.suite,
                    repo=Path(args.repo),
                    output=Path(args.output),
                )
            )
        elif args.external_command == "run":
            command = external_benchmarks.resolve_external_command(
                agent_command=args.agent_command,
                baseline_tool=args.baseline_tool,
                baseline_model=args.baseline_model,
                baseline_max_turns=args.baseline_max_turns,
                baseline_adapter_dir=args.baseline_adapter_dir,
            )
            if args.remote_host:
                run_dir = external_benchmarks.run_remote_case(
                    baseline_host=args.remote_host,
                    suite=args.suite,
                    repo=Path(args.repo),
                    case_id=args.case,
                    agent_command=command,
                    output_dir=Path(args.output_dir),
                    remote_output_dir=Path(args.remote_output_dir),
                    flag=args.flag,
                    dry_run=args.dry_run,
                    keep_running=args.keep_running,
                    timeout_seconds=args.timeout,
                    sync_project=not args.no_sync,
                    docker_cleanup=args.docker_cleanup,
                    min_free_gb=args.min_free_gb,
                )
            else:
                run_dir = external_benchmarks.run_case(
                    suite=args.suite,
                    repo=Path(args.repo),
                    case_id=args.case,
                    agent_command=command,
                    output_dir=Path(args.output_dir),
                    flag=args.flag,
                    dry_run=args.dry_run,
                    keep_running=args.keep_running,
                    timeout_seconds=args.timeout,
                    docker_cleanup=args.docker_cleanup,
                    min_free_gb=args.min_free_gb,
                )
            print(run_dir)
        elif args.external_command == "start-detached":
            import json
            command = (
                external_benchmarks.resolve_external_command(
                    agent_command=args.agent_command,
                    baseline_tool=args.baseline_tool,
                    baseline_model=args.baseline_model,
                    baseline_max_turns=args.baseline_max_turns,
                    baseline_adapter_dir=args.baseline_adapter_dir,
                )
                if args.baseline_tool
                else args.agent_command
            )
            job = external_benchmarks.start_detached_job(
                baseline_host=args.remote_host,
                suite=args.suite,
                cases=args.cases,
                repo=Path(args.repo),
                agent_command=command,
                remote_output_dir=Path(args.remote_output_dir),
                remote_job_dir=Path(args.remote_job_dir),
                timeout_seconds=args.timeout,
                dry_run=args.dry_run,
                keep_running=args.keep_running,
                sync_project=not args.no_sync,
                model=args.model,
                max_turns=args.max_turns,
                context_mode=args.context_mode,
                docker_cleanup=args.docker_cleanup,
                min_free_gb=args.min_free_gb,
            )
            print(json.dumps(job, indent=2, ensure_ascii=False))
        elif args.external_command == "resume-detached":
            import json
            print(json.dumps(
                external_benchmarks.resume_detached_job(
                    baseline_host=args.remote_host,
                    job_id=args.job_id,
                    remote_job_dir=Path(args.remote_job_dir),
                    sync_project=not args.no_sync,
                ),
                indent=2,
                ensure_ascii=False,
            ))
        elif args.external_command == "docker-prune":
            print(external_benchmarks.prune_remote_docker(args.remote_host))
        elif args.external_command == "jobs":
            import json
            print(json.dumps(
                external_benchmarks.list_detached_jobs(args.remote_host, Path(args.remote_job_dir)),
                indent=2,
                ensure_ascii=False,
            ))
        elif args.external_command == "status":
            import json
            print(json.dumps(
                external_benchmarks.detached_job_status(args.remote_host, args.job_id, Path(args.remote_job_dir)),
                indent=2,
                ensure_ascii=False,
            ))
        elif args.external_command == "logs":
            print(external_benchmarks.detached_job_logs(
                args.remote_host,
                args.job_id,
                args.tail,
                Path(args.remote_job_dir),
            ), end="")
        elif args.external_command == "stop":
            external_benchmarks.stop_detached_job(args.remote_host, args.job_id, Path(args.remote_job_dir))
            print(f"stopped {args.job_id}")
        elif args.external_command == "attach":
            external_benchmarks.attach_detached_job(args.remote_host, args.job_id)
        elif args.external_command == "fetch":
            print(external_benchmarks.fetch_detached_job(
                args.remote_host,
                args.job_id,
                Path(args.output_dir),
                Path(args.remote_job_dir),
                Path(args.remote_output_dir),
            ))
        elif args.external_command == "organize-job":
            print(external_benchmarks.organize_fetched_job(
                args.job_id,
                Path(args.output_dir),
                move=args.move,
            ))
        elif args.external_command == "report":
            import json
            print(json.dumps(
                external_benchmarks.generate_report(
                    Path(args.root),
                    Path(args.output) if args.output else None,
                    Path(args.markdown) if args.markdown else None,
                ),
                indent=2,
                ensure_ascii=False,
            ))
        elif args.external_command == "start-distributed":
            import json
            hosts = fleet.parse_hosts_arg(args.remote_hosts)
            if not hosts:
                raise SystemExit("--remote-hosts requires at least one host")
            cases: list[str] = list(args.cases)
            if args.cases_file:
                cases.extend(fleet.load_cases_from_file(Path(args.cases_file)))
            if not cases:
                raise SystemExit("Provide cases via --case (repeatable) or --cases-file")
            durations_path = Path(args.durations_file) if args.durations_file else None
            job = fleet.start_distributed_job(
                hosts=hosts,
                suite=args.suite,
                cases=cases,
                repo=Path(args.repo),
                shard_strategy=args.shard_strategy,
                durations_path=durations_path,
                stagger_seconds=args.stagger_seconds,
                output_dir=Path(args.output_dir),
                agent_command=args.agent_command,
                model=args.model,
                max_turns=args.max_turns,
                context_mode=args.context_mode,
                timeout_seconds=args.timeout,
                sync_project=not args.no_sync,
                dry_run=args.dry_run,
                keep_running=args.keep_running,
                docker_cleanup=args.docker_cleanup,
                min_free_gb=args.min_free_gb,
                remote_output_dir=Path(args.remote_output_dir),
                remote_job_dir=Path(args.remote_job_dir),
            )
            print(json.dumps(job.to_dict(), indent=2, ensure_ascii=False, default=str))
        elif args.external_command == "fleet-status":
            import json
            import time
            output_dir = Path(args.output_dir)
            while True:
                status = fleet.fleet_status(args.distributed_job_id, output_dir=output_dir)
                payload = {
                    "distributed_job_id": status.distributed_job_id,
                    "refreshed_at": status.refreshed_at,
                    "aggregate": status.aggregate,
                    "hosts": [
                        {
                            "baseline_host": h.baseline_host,
                            "job_id": h.job_id,
                            "status": h.status,
                            "cases": len(h.cases),
                            "completed": h.last_status_payload.get("completed"),
                            "current_case": h.last_status_payload.get("current_case"),
                            "error": h.error,
                        }
                        for h in status.hosts
                    ],
                }
                print(json.dumps(payload, indent=2, ensure_ascii=False))
                if not args.watch:
                    break
                print("---", flush=True)
                try:
                    time.sleep(5)
                except KeyboardInterrupt:
                    break
        elif args.external_command == "fleet-logs":
            job = fleet.load_distributed_job(args.distributed_job_id, output_dir=Path(args.output_dir))
            host_jobs = {hj.baseline_host: hj for hj in job.host_jobs}
            if args.host not in host_jobs:
                raise SystemExit(f"Host {args.host!r} not in distributed job. Hosts: {list(host_jobs)}")
            hj = host_jobs[args.host]
            print(external_benchmarks.detached_job_logs(
                hj.baseline_host,
                hj.job_id,
                args.tail,
                Path(args.remote_job_dir),
            ), end="")
        elif args.external_command == "fleet-stop":
            import json
            outcomes = fleet.fleet_stop(args.distributed_job_id, output_dir=Path(args.output_dir))
            print(json.dumps(outcomes, indent=2, ensure_ascii=False))
        elif args.external_command == "fleet-resume":
            import json
            outcomes = fleet.fleet_resume(
                args.distributed_job_id,
                output_dir=Path(args.output_dir),
                sync_project=not args.no_sync,
            )
            print(json.dumps(outcomes, indent=2, ensure_ascii=False, default=str))
        elif args.external_command == "fetch-all":
            merged = fleet.fleet_fetch(
                args.distributed_job_id,
                output_dir=Path(args.output_dir),
                parallel=args.parallel,
                base_results_dir=Path(args.base_results_dir),
            )
            print(merged)
        elif args.external_command == "fleet-list":
            import json
            print(json.dumps(
                fleet.list_distributed_jobs(output_dir=Path(args.output_dir)),
                indent=2,
                ensure_ascii=False,
            ))
        elif args.external_command == "fleet-prepare":
            import json
            hosts = fleet.parse_hosts_arg(args.remote_hosts)
            if not hosts:
                raise SystemExit("--remote-hosts requires at least one host")
            outcomes = fleet.fleet_prepare(
                hosts=hosts,
                project_dir=Path(args.project_dir),
                install_deps=not args.no_install_deps,
                max_workers=args.max_workers,
            )
            print(json.dumps(outcomes, indent=2, ensure_ascii=False))
        elif args.external_command == "db-init":
            print(store.init_db(Path(args.db)))
        elif args.external_command == "db-list":
            import json
            print(json.dumps(store.list_distributed_jobs(Path(args.db)), indent=2, ensure_ascii=False, default=str))
        elif args.external_command == "db-runs":
            import json
            rows = store.list_runs(
                distributed_job_id=args.distributed_job_id,
                outcome=args.outcome,
                case_id=args.case_id,
                limit=args.limit,
                path=Path(args.db),
            )
            print(json.dumps(rows, indent=2, ensure_ascii=False, default=str))
        elif args.external_command == "db-breakdown":
            import json
            print(json.dumps(
                store.outcome_breakdown(args.distributed_job_id, path=Path(args.db)),
                indent=2,
                ensure_ascii=False,
                default=str,
            ))
        elif args.external_command == "db-case-durations":
            import json
            data = store.case_durations(path=Path(args.db))
            if args.output:
                Path(args.output).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
                print(args.output)
            else:
                print(json.dumps(data, indent=2, ensure_ascii=False))
        elif args.external_command == "db-query":
            import json
            print(json.dumps(store.run_sql(args.sql, path=Path(args.db)), indent=2, ensure_ascii=False, default=str))
        elif args.external_command == "db-import-existing":
            count = store.import_existing_external_runs(
                Path(args.root),
                distributed_job_id=args.distributed_job_id,
                path=Path(args.db),
            )
            print(f"imported {count} runs into {args.db}")
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
            jobs=1,
        )
        print(run_dir)
    elif args.command == "wizard":
        wizard.run_wizard()
    elif args.command == "dashboard":
        ui.run_dashboard()


if __name__ == "__main__":
    main()
