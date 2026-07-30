"""Run the full six-phase LANCE pipeline against one external target."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()

from src.agent.provider import LLMProvider
import src.agent.pipeline as pipeline_module


def _network_target(value: str) -> str:
    value = value.strip()
    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)
        if not parsed.hostname:
            raise ValueError(f"invalid target URL: {value}")
        return parsed.hostname
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            return host
    return value


def _answer_text(run_dir: Path) -> str:
    fragments: list[str] = []
    for name in (
        "06_final_report.md",
        "05_intrusion_results.json",
        "04_exploitation.json",
        "03_vuln_analysis.json",
    ):
        path = run_dir / name
        if not path.is_file():
            continue
        try:
            fragments.append(path.read_text(encoding="utf-8"))
        except OSError:
            continue
    return "\n\n".join(fragments)


def main() -> None:
    parser = argparse.ArgumentParser(description="Full LANCE external benchmark profile")
    parser.add_argument("--target", required=True)
    parser.add_argument("--hint", default="")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--provider", default=os.environ.get("AGENT_PROVIDER", "minimax"))
    parser.add_argument("--model", default=os.environ.get("AGENT_MODEL"))
    parser.add_argument("--execution-profile", choices=["auto", "compact", "full"], default="auto")
    parser.add_argument("--max-turns", type=int, default=40)
    parser.add_argument("--max-cost-usd", type=float)
    parser.add_argument("--phases", nargs="+", type=int)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    pipeline_module.OUTPUT_DIR = args.output_dir
    provider = LLMProvider(provider=args.provider, model=args.model)
    hint = args.hint.strip()
    if args.target.startswith(("http://", "https://")):
        hint = f"Target endpoint: {args.target}\n{hint}".strip()
    pipeline = pipeline_module.Pipeline(
        provider=provider,
        dry_run=args.dry_run,
        phases=args.phases,
        scenario_id=None,
        target_network=_network_target(args.target),
        blind=True,
        manage_scenario=False,
        auto_teardown=False,
        max_cost_usd=args.max_cost_usd,
        execution_profile=args.execution_profile,
        external_task_hint=hint,
    )
    # Preserve the historical external CLI while interpreting max-turns as a
    # global native-tool-call ceiling for the full multi-phase profile.
    pipeline.max_tool_calls = args.max_turns
    results = pipeline.run()
    answer = _answer_text(pipeline.run_dir)
    (pipeline.run_dir / "external_agent_answer.txt").write_text(answer, encoding="utf-8")
    print(answer)
    print(json.dumps({
        "status": "completed",
        "profile": "lance-external-full",
        "target": args.target,
        "run_dir": str(pipeline.run_dir),
        "pipeline_results": results,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
