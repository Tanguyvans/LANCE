"""Isolated entry point for an evaluator-issued sealed challenge.

This module is intentionally worker-only: it accepts a strict challenge
contract, runs the normal pipeline in blind discovery mode, and emits an
allowlisted submission bundle.  It has no controller credentials and performs
no deployment, teardown, or local evaluation.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from src.agent.provider import LLMProvider
from src.benchmark.artifacts import create_submission_bundle
from src.benchmark.contracts import ChallengeContract, ContractError


def _load_contract(path: Path) -> ChallengeContract:
    if not path.is_file() or path.is_symlink():
        raise ContractError("challenge contract must be a regular non-symlink file")
    contract = ChallengeContract.from_json(path.read_bytes())
    expiry = datetime.fromisoformat(contract.limits.expires_at.replace("Z", "+00:00"))
    if expiry <= datetime.now(timezone.utc):
        raise ContractError("challenge contract has expired")
    return contract


def main() -> None:
    parser = argparse.ArgumentParser(description="Run an isolated sealed benchmark worker")
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--provider", default=os.environ.get("AGENT_PROVIDER", "openrouter"))
    parser.add_argument("--model", default=os.environ.get("AGENT_MODEL"))
    parser.add_argument("--phases", nargs="+", type=int)
    parser.add_argument("--output-dir", type=Path, default=Path(os.environ.get("WORKER_OUTPUT_DIR", "/work/output")))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    # The controller credential must stay in the trusted control plane.
    leaked_controller_vars = [
        name for name in ("SEALED_CONTROLLER_TOKEN", "SEALED_CONTROLLER_URL")
        if os.environ.get(name)
    ]
    if leaked_controller_vars:
        parser.error(
            "controller configuration leaked into worker environment: "
            + ", ".join(leaked_controller_vars)
        )
    if Path("benchmarks").exists():
        parser.error("sealed worker image must not contain the benchmarks directory")

    try:
        contract = _load_contract(args.contract)
    except ContractError as exc:
        parser.error(str(exc))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    import src.agent.pipeline as pipeline_module

    pipeline_module.OUTPUT_DIR = args.output_dir
    provider = LLMProvider(provider=args.provider, model=args.model)
    pipeline = pipeline_module.Pipeline(
        provider=provider,
        dry_run=args.dry_run,
        phases=args.phases,
        scenario_id=contract.scenario_id,
        execution_context=contract,
        benchmark_split=contract.split,
        manage_scenario=False,
        auto_teardown=False,
    )
    results = pipeline.run()

    bundle_path = args.output_dir / f"submission-{contract.session_id}.zip"
    bundle, manifest, manifest_hash = create_submission_bundle(
        pipeline.run_dir,
        contract,
        run_id=pipeline.run_dir.name,
        output_path=bundle_path,
    )
    print(json.dumps({
        "status": "complete",
        "scenario_id": contract.scenario_id,
        "session_id": contract.session_id,
        "run_dir": str(pipeline.run_dir),
        "bundle": str(bundle),
        "manifest_sha256": manifest_hash,
        "artifact_count": len(manifest.artifacts),
        "pipeline_results": results,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
