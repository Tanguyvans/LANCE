"""Allow running as: python3 -m src.agent"""
from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

from dotenv import load_dotenv

_DOTENV_PATH = Path(".env")
if os.access(_DOTENV_PATH, os.R_OK):
    load_dotenv(_DOTENV_PATH)

from src.agent.provider import LLMProvider
from src.agent.pipeline import Pipeline


def _scrub_sensitive_environment_for_tools() -> None:
    """Remove credentials after the provider client has captured its API key.

    Agent tools execute child processes. Those children need PATH and locale,
    but never provider keys, auth sockets, passwords, tokens, or proxy secrets.
    """
    markers = ("API_KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
    exact = {"SSH_AUTH_SOCK", "AWS_PROFILE", "NETRC"}
    for name in list(os.environ):
        upper = name.upper()
        if upper in exact or upper.endswith("_PROXY") or any(marker in upper for marker in markers):
            os.environ.pop(name, None)


def _parse_initial_credentials(args, parser) -> list[dict] | None:
    """Parse --initial-credentials into a list of foothold dicts.

    Accepts an inline JSON array or @path/to/file.json. Structural validation
    (literal IPs, allowed services, port ranges) happens in
    Pipeline._sanitize_initial_credentials; here we only guarantee a list of
    objects so invalid input fails before any provider is constructed.
    """
    raw = args.initial_credentials
    if raw is None:
        return None
    if args.batch is not None:
        parser.error(
            "--initial-credentials cannot be combined with --batch; declare "
            'per-scenario "initial_credentials" in the scenario YAML instead'
        )
    import json as _json

    text = raw
    if raw.startswith("@"):
        from pathlib import Path as _Path

        try:
            text = _Path(raw[1:]).read_text()
        except OSError as exc:
            parser.error(f"cannot read initial credentials file: {exc}")
    try:
        parsed = _json.loads(text)
    except _json.JSONDecodeError as exc:
        parser.error(f"--initial-credentials is not valid JSON: {exc}")
    if not isinstance(parsed, list) or not all(isinstance(item, dict) for item in parsed):
        parser.error("--initial-credentials must be a JSON array of objects")
    return parsed


def main():
    parser = argparse.ArgumentParser(
        description="NATO Smart City IoT — Pentest Agent Pipeline"
    )
    parser.add_argument(
        "--provider",
        default=os.environ.get("AGENT_PROVIDER", "anthropic"),
        choices=["anthropic", "openrouter", "minimax", "glm", "qwen", "local"],
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("AGENT_MODEL"),
    )
    parser.add_argument(
        "--execution-profile",
        choices=["auto", "compact", "full"],
        default=os.environ.get("AGENT_EXECUTION_PROFILE", "auto"),
        help="Tool orchestration profile (default: auto).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Graph tools only, no network recon tools",
    )
    parser.add_argument(
        "--phases",
        nargs="+",
        type=int,
        help="Run specific phases only (e.g. --phases 1 2)",
    )
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--scenario",
        type=str,
        default=None,
        help=(
            "Benchmark scenario ID. S1-S19 are public development scenarios, "
            "and S20-S29 are public held-out tests."
        ),
    )
    parser.add_argument(
        "--batch",
        default=None,
        metavar="IDS",
        help=(
            "Run multiple scenarios sequentially and aggregate metrics. "
            "Accepts comma-separated IDs, 'dev', 'test', 'public', or 'all'; "
            "the current 'eval' selector is empty."
        ),
    )
    parser.add_argument(
        "--blind",
        action="store_true",
        help="Hide the public topology and force active discovery.",
    )
    parser.add_argument(
        "--no-manage-scenario",
        action="store_true",
        help=(
            "Run the agent against an already prepared scenario; do not call "
            "Proxmox deployment or teardown playbooks."
        ),
    )
    parser.add_argument(
        "--no-auto-teardown",
        action="store_true",
        help="Keep a locally managed scenario deployed after the run.",
    )
    parser.add_argument(
        "--target-network",
        default=None,
        metavar="CIDR",
        help="Discovery scope, for example 192.168.100.0/24.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Root directory for this run's timestamped artifacts.",
    )
    parser.add_argument(
        "--split",
        choices=["auto", "dev-public", "test-public", "eval-sealed"],
        default="auto",
        help="Benchmark split policy. No current 3.2 scenario uses eval-sealed.",
    )
    parser.add_argument(
        "--initial-credentials",
        default=None,
        metavar="JSON|@FILE",
        help=(
            "Explicit foothold credentials for Phase 5, as a JSON array or "
            "@path/to/file.json. Each entry needs ip, user, password and "
            "optionally service/port/device_id. Single-scenario runs only."
        ),
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    resolved_split = None if args.split == "auto" else args.split
    if args.scenario is not None and args.batch is not None:
        parser.error("--scenario and --batch are mutually exclusive")
    if args.batch is not None and args.target_network is not None:
        parser.error("--target-network cannot be combined with --batch")
    if args.no_manage_scenario and args.scenario is None and args.batch is None:
        parser.error("--no-manage-scenario requires --scenario or --batch")
    if args.split == "eval-sealed":
        parser.error(
            "eval-sealed runs must be launched through the sealed controller; "
            "the regular CLI has no oracle or deployment access"
        )

    initial_credentials = _parse_initial_credentials(args, parser)

    if args.output_dir is not None:
        import src.agent.pipeline as pipeline_module
        pipeline_module.OUTPUT_DIR = args.output_dir

    normalized_batch: str | None = None
    if args.batch is not None:
        from src.agent.batch import _parse_scenario_ids, _public_scenario_split
        try:
            batch_ids = _parse_scenario_ids(args.batch)
            normalized_batch = ",".join(batch_ids)
        except ValueError as exc:
            parser.error(str(exc))
        batch_splits = {_public_scenario_split(sid) for sid in batch_ids}
        if args.no_manage_scenario and len(batch_ids) != 1:
            parser.error(
                "--no-manage-scenario accepts exactly one scenario per worker invocation; "
                "the central campaign runner must prepare/reset scenarios between runs"
            )
        if resolved_split is not None and batch_splits != {resolved_split}:
            parser.error(
                f"batch belongs to {', '.join(sorted(batch_splits))}, not {resolved_split}"
            )
        resolved_split = next(iter(batch_splits)) if len(batch_splits) == 1 else None
    elif args.scenario is not None:
        from src.agent.batch import _parse_single_scenario_id, _public_scenario_split
        try:
            args.scenario = _parse_single_scenario_id(args.scenario)
        except ValueError as exc:
            parser.error(str(exc))
        scenario_split = _public_scenario_split(args.scenario)
        if resolved_split not in (None, scenario_split):
            parser.error(f"S{args.scenario} belongs to {scenario_split}, not {resolved_split}")
        resolved_split = scenario_split

    # Resolve all local-only validation before constructing a provider. This
    # keeps invalid/sealed invocations free of credentials and network setup.
    provider = LLMProvider(provider=args.provider, model=args.model)
    if args.blind:
        _scrub_sensitive_environment_for_tools()

    # Batch mode: sequential multi-scenario run
    if args.batch is not None:
        from src.agent.batch import run_batch
        run_batch(
            batch_arg=normalized_batch or args.batch,
            provider=provider,
            dry_run=args.dry_run,
            phases=args.phases,
            blind=args.blind,
            execution_profile=args.execution_profile,
            manage_scenario=not args.no_manage_scenario,
            auto_teardown=not args.no_auto_teardown and not args.no_manage_scenario,
        )
        return

    pipeline = Pipeline(
        provider=provider, dry_run=args.dry_run, phases=args.phases,
        scenario_id=args.scenario,
        blind=args.blind,
        manage_scenario=not args.no_manage_scenario,
        auto_teardown=not args.no_auto_teardown and not args.no_manage_scenario,
        target_network=args.target_network,
        benchmark_split=resolved_split,
        execution_profile=args.execution_profile,
        initial_credentials=initial_credentials,
    )
    results = pipeline.run()

    print(f"\n{'=' * 60}")
    print("PIPELINE COMPLETE")
    print(f"{'=' * 60}")
    for name, status in results.items():
        icon = "v" if status == "completed" else "x" if "failed" in status else "-"
        print(f"  [{icon}] {name}: {status}")


if __name__ == "__main__":
    main()
