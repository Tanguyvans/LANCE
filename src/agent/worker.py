"""Isolated entry point for an evaluator-issued sealed challenge.

This module is intentionally worker-only: it accepts a strict challenge
contract, runs the normal pipeline in blind discovery mode, and emits an
allowlisted submission bundle.  It has no controller credentials and performs
no deployment, teardown, or local evaluation.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

from src.agent.provider import LLMProvider
from src.benchmark.artifacts import create_submission_bundle
from src.benchmark.contracts import ChallengeContract, ContractError


_WORKER_ENV_ALLOWLIST = frozenset(
    {
        "AGENT_MODEL",
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONHASHSEED",
        "PYTHONIOENCODING",
        "PYTHONPATH",
        "PYTHONUNBUFFERED",
        "REQUESTS_CA_BUNDLE",
        "SEALED_INFERENCE_BASE_URL",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "TZ",
        "WORKER_OUTPUT_DIR",
    }
)
_SECRET_NAME_MARKERS = (
    "API_KEY",
    "ACCESS_KEY",
    "CREDENTIAL",
    "PASSWORD",
    "PRIVATE_KEY",
    "SECRET",
    "TOKEN",
)


class _WorkerDeadlineExceeded(BaseException):
    """Escape pipeline-level ``except Exception`` handlers at contract expiry."""


def _sanitize_environment(
    parser: argparse.ArgumentParser,
    work_root: Path,
) -> dict[str, str]:
    """Reject recognizable secrets, then discard every non-allowlisted var."""

    leaked = sorted(
        name
        for name in os.environ
        if name not in _WORKER_ENV_ALLOWLIST
        and (
            name.startswith(("AWS_", "AZURE_", "GOOGLE_", "GITHUB_", "SEALED_"))
            or any(marker in name.upper() for marker in _SECRET_NAME_MARKERS)
        )
    )
    if leaked:
        parser.error(
            "secret or control-plane variables leaked into worker environment: "
            + ", ".join(leaked)
        )

    original = dict(os.environ)
    retained = {
        name: value
        for name, value in os.environ.items()
        if name in _WORKER_ENV_ALLOWLIST
    }
    # All writable caches and home state belong under the runtime-provided
    # /work tmpfs, never in an image layer or persistent home directory.
    retained.update(
        {
            "HOME": str(work_root / "home"),
            "TMPDIR": str(work_root / "tmp"),
            "XDG_CACHE_HOME": str(work_root / "cache"),
        }
    )
    os.environ.clear()
    os.environ.update(retained)
    return original


def _arm_contract_deadline(contract: ChallengeContract) -> None:
    expiry = datetime.fromisoformat(contract.limits.expires_at.replace("Z", "+00:00"))
    remaining = max(1, math.ceil((expiry - datetime.now(timezone.utc)).total_seconds()))
    remaining = min(remaining, 2_147_483_647)

    def _deadline_handler(_signum, _frame):
        raise _WorkerDeadlineExceeded()

    signal.signal(signal.SIGALRM, _deadline_handler)
    signal.alarm(remaining)


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
    # Never inherit AGENT_PROVIDER from a generic runner environment.  A sealed
    # worker has exactly one admissible transport: the credential-free gateway.
    parser.add_argument("--provider", default="sealed-gateway")
    parser.add_argument("--model", default=os.environ.get("AGENT_MODEL"))
    parser.add_argument("--phases", nargs="+", type=int)
    parser.add_argument("--output-dir", type=Path, default=Path(os.environ.get("WORKER_OUTPUT_DIR", "/work/output")))
    parser.add_argument(
        "--receipt",
        type=Path,
        help="Machine-readable completion receipt (defaults to <output-dir>/worker-receipt.json)",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.provider != "sealed-gateway":
        parser.error("sealed worker requires the evaluator-owned sealed-gateway provider")
    if not args.model:
        parser.error("--model is required")
    if Path("benchmarks").exists():
        parser.error("sealed worker image must not contain the benchmarks directory")

    try:
        contract = _load_contract(args.contract)
    except ContractError as exc:
        parser.error(str(exc))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = args.receipt or (args.output_dir / "worker-receipt.json")
    if receipt_path.exists() and receipt_path.is_symlink():
        parser.error("receipt path must not be a symlink")
    receipt_path.parent.mkdir(parents=True, exist_ok=True)

    # The worker is hostile by design: reject recognizable credentials and
    # remove every environment variable outside a minimal runtime allowlist
    # before importing the pipeline or starting subprocess tools.
    original_environment = _sanitize_environment(parser, args.output_dir.parent)
    Path(os.environ["HOME"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["XDG_CACHE_HOME"]).mkdir(parents=True, exist_ok=True)

    # Pipeline output contains discoveries, tool arguments/results and partial
    # findings.  It must never reach Docker logs or the public control plane.
    # The private controller reads only the allowlisted receipt below.  The
    # container runtime must additionally use a disabled log driver and a tmpfs
    # for /work so abrupt process termination cannot persist raw output.
    try:
        _arm_contract_deadline(contract)
        with open(os.devnull, "w", encoding="utf-8") as sink, \
             contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
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
            pipeline.run()

            bundle_path = args.output_dir / f"submission-{contract.session_id}.zip"
            bundle, manifest, manifest_hash = create_submission_bundle(
                pipeline.run_dir,
                contract,
                run_id=pipeline.run_dir.name,
                output_path=bundle_path,
            )
        receipt = {
            "status": "complete",
            "session_id": contract.session_id,
            "bundle": str(bundle),
            "manifest_sha256": manifest_hash,
            "artifact_count": len(manifest.artifacts),
        }
    except (Exception, _WorkerDeadlineExceeded):
        # Never serialize exception text: provider/tool exceptions may embed
        # prompts, responses, IPs, headers or other adaptive feedback.
        receipt = {"status": "failed", "session_id": contract.session_id}
    finally:
        signal.alarm(0)

    try:
        temporary_receipt = receipt_path.with_name(receipt_path.name + ".tmp")
        temporary_receipt.write_text(
            json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        temporary_receipt.chmod(0o600)
        temporary_receipt.replace(receipt_path)
    finally:
        # A production worker exits immediately. Restoring here keeps
        # in-process tests from inheriting the deliberately stripped env.
        os.environ.clear()
        os.environ.update(original_environment)
    if receipt["status"] != "complete":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
