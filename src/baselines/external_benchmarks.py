"""Harnesses for running our agent against third-party pentest benchmarks."""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml


DEFAULT_OUTPUT_DIR = Path("output/external_benchmarks")
SUPPORTED_SUITES = ("xbow", "autopenbench", "ai-pentest")


@dataclass(frozen=True)
class ExternalBenchmarkCase:
    suite: str
    case_id: str
    path: Path
    name: str
    description: str = ""
    level: str = ""
    tags: tuple[str, ...] = ()
    target_url: str | None = None
    compose_file: Path | None = None
    runnable: bool = True
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["path"] = str(self.path)
        data["compose_file"] = str(self.compose_file) if self.compose_file else None
        return data


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}


def _first_target_url(compose_file: Path | None) -> str | None:
    if not compose_file or not compose_file.exists():
        return None
    data = _read_yaml(compose_file)
    services = data.get("services", {})
    if not isinstance(services, dict):
        return None

    for service in services.values():
        if not isinstance(service, dict):
            continue
        ports = service.get("ports", [])
        if not isinstance(ports, list):
            continue
        for item in ports:
            if isinstance(item, int):
                return f"http://127.0.0.1:{item}"
            if not isinstance(item, str):
                continue
            port = _host_port(item)
            if port:
                return f"http://127.0.0.1:{port}"
    return None


def _host_port(port_spec: str) -> str | None:
    spec = port_spec.split("/", 1)[0].strip().strip('"').strip("'")
    parts = spec.split(":")
    if len(parts) == 1 and parts[0].isdigit():
        return parts[0]
    if len(parts) >= 2 and parts[-2].isdigit():
        return parts[-2]
    return None


def _case_dirs(root: Path) -> list[Path]:
    return sorted(path.parent for path in root.rglob("docker-compose.yml"))


def _metadata_for_case(case_dir: Path) -> dict[str, Any]:
    candidates = [
        case_dir / "benchmark" / "benchmark-config.json",
        case_dir / "benchmark.json",
        case_dir / "benchmark.yaml",
        case_dir / "benchmark.yml",
    ]
    for path in candidates:
        if path.suffix == ".json" and path.exists():
            return _read_json(path)
        if path.suffix in {".yaml", ".yml"} and path.exists():
            return _read_yaml(path)
    return {}


def discover_xbow(repo: Path) -> list[ExternalBenchmarkCase]:
    """Discover XBOW validation benchmarks in a checked-out repository."""
    root = repo / "benchmarks" if (repo / "benchmarks").is_dir() else repo
    cases: list[ExternalBenchmarkCase] = []
    for case_dir in _case_dirs(root):
        metadata = _metadata_for_case(case_dir)
        case_id = str(metadata.get("name") or case_dir.name)
        tags = tuple(str(tag) for tag in metadata.get("tags", []) if tag)
        compose_file = case_dir / "docker-compose.yml"
        cases.append(
            ExternalBenchmarkCase(
                suite="xbow",
                case_id=case_id,
                path=case_dir,
                name=case_id,
                description=str(metadata.get("description", "")),
                level=str(metadata.get("level", "")),
                tags=tags,
                target_url=_first_target_url(compose_file),
                compose_file=compose_file,
            )
        )
    return cases


def discover_autopenbench(repo: Path) -> list[ExternalBenchmarkCase]:
    """Discover AutoPenBench tasks in a checked-out repository."""
    roots = [path for path in [repo / "benchmark", repo / "benchmarks", repo / "data"] if path.is_dir()]
    search_root = roots[0] if roots else repo
    cases: list[ExternalBenchmarkCase] = []
    for case_dir in _case_dirs(search_root):
        metadata = _metadata_for_case(case_dir)
        case_id = str(metadata.get("name") or metadata.get("id") or case_dir.name)
        tags = metadata.get("tags") or metadata.get("category") or []
        if isinstance(tags, str):
            tags = [tags]
        compose_file = case_dir / "docker-compose.yml"
        cases.append(
            ExternalBenchmarkCase(
                suite="autopenbench",
                case_id=case_id,
                path=case_dir,
                name=str(metadata.get("title") or case_id),
                description=str(metadata.get("description", metadata.get("task", ""))),
                level=str(metadata.get("level", metadata.get("difficulty", ""))),
                tags=tuple(str(tag) for tag in tags if tag),
                target_url=_first_target_url(compose_file),
                compose_file=compose_file,
            )
        )
    return cases


def discover_ai_pentest(repo: Path) -> list[ExternalBenchmarkCase]:
    """Discover AI-Pentest-Benchmark metadata.

    The upstream benchmark is VM/VulnHub-based, so this function records any
    local machine metadata it can find but marks entries as not directly
    runnable by this Docker harness.
    """
    cases: list[ExternalBenchmarkCase] = []
    metadata_files = [*repo.rglob("*.json"), *repo.rglob("*.yaml"), *repo.rglob("*.yml")]
    for path in sorted(metadata_files):
        if ".git" in path.parts:
            continue
        data = _read_json(path) if path.suffix == ".json" else _read_yaml(path)
        items = data if isinstance(data, list) else data.get("machines", data.get("targets", []))
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            case_id = str(item.get("name") or item.get("id") or item.get("machine") or path.stem)
            cases.append(
                ExternalBenchmarkCase(
                    suite="ai-pentest",
                    case_id=case_id,
                    path=path,
                    name=case_id,
                    description=str(item.get("description", "")),
                    level=str(item.get("difficulty", "")),
                    tags=("vulnhub", "vm"),
                    runnable=False,
                    notes="VM/VulnHub target; import/deploy manually before running an agent.",
                )
            )
    if cases:
        return cases
    return [
        ExternalBenchmarkCase(
            suite="ai-pentest",
            case_id="manual-vulnhub-machines",
            path=repo,
            name="AI-Pentest-Benchmark VulnHub machines",
            tags=("vulnhub", "vm"),
            runnable=False,
            notes="Upstream benchmark tracks VulnHub machines and task steps, usually via spreadsheet/VM setup.",
        )
    ]


def discover_cases(suite: str, repo: Path) -> list[ExternalBenchmarkCase]:
    suite = suite.lower()
    if suite == "xbow":
        return discover_xbow(repo)
    if suite == "autopenbench":
        return discover_autopenbench(repo)
    if suite == "ai-pentest":
        return discover_ai_pentest(repo)
    raise ValueError(f"Unsupported external benchmark suite: {suite}")


def write_manifest(suite: str, repo: Path, output: Path) -> Path:
    cases = discover_cases(suite, repo)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            {
                "suite": suite,
                "repo": str(repo),
                "case_count": len(cases),
                "generated_at": datetime.now().isoformat(timespec="seconds"),
                "cases": [case.to_dict() for case in cases],
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return output


def _select_case(suite: str, repo: Path, case_id: str) -> ExternalBenchmarkCase:
    cases = discover_cases(suite, repo)
    for case in cases:
        if case.case_id == case_id or case.path.name == case_id:
            return case
    available = ", ".join(case.case_id for case in cases[:20])
    suffix = "..." if len(cases) > 20 else ""
    raise ValueError(f"Unknown {suite} case {case_id!r}. Available: {available}{suffix}")


def _render_agent_command(template: str, case: ExternalBenchmarkCase, output_dir: Path, flag: str) -> list[str]:
    rendered = template.format(
        suite=case.suite,
        case_id=case.case_id,
        case=case.case_id,
        target=case.target_url or "",
        target_url=case.target_url or "",
        output_dir=str(output_dir),
        flag=flag,
    )
    return shlex.split(rendered)


def _compose_command(case: ExternalBenchmarkCase, *args: str) -> list[str]:
    if not case.compose_file:
        raise ValueError(f"{case.case_id} does not have a docker-compose.yml")
    return ["docker", "compose", "-f", str(case.compose_file), *args]


def run_case(
    suite: str,
    repo: Path,
    case_id: str,
    agent_command: str,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    flag: str | None = None,
    dry_run: bool = False,
    keep_running: bool = False,
    timeout_seconds: int = 1800,
) -> Path:
    case = _select_case(suite, repo, case_id)
    if not case.runnable:
        raise ValueError(f"{case.case_id} is not runnable by this harness: {case.notes}")

    flag_value = flag or f"FLAG-{case.suite}-{case.case_id}-{int(time.time())}"
    run_dir = output_dir / case.suite / case.case_id / datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)
    command = _render_agent_command(agent_command, case, run_dir, flag_value)
    planned = {
        "case": case.to_dict(),
        "flag": flag_value,
        "agent_command": command,
        "build_command": _compose_command(case, "build", "--build-arg", f"flag={flag_value}"),
        "up_command": _compose_command(case, "up", "-d", "--wait"),
        "down_command": _compose_command(case, "down", "-v"),
        "dry_run": dry_run,
    }
    (run_dir / "planned.json").write_text(json.dumps(planned, indent=2, ensure_ascii=False), encoding="utf-8")
    if dry_run:
        (run_dir / "result.json").write_text(
            json.dumps({"status": "dry_run", "success": False, **planned}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return run_dir

    started = datetime.now()
    stdout = ""
    stderr = ""
    returncode = 0
    try:
        subprocess.run(planned["build_command"], cwd=case.path, check=True)
        subprocess.run(planned["up_command"], cwd=case.path, check=True)
        result = subprocess.run(
            command,
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
        )
        stdout = result.stdout
        stderr = result.stderr
        returncode = result.returncode
    finally:
        if not keep_running:
            subprocess.run(planned["down_command"], cwd=case.path, check=False)

    (run_dir / "agent_stdout.txt").write_text(stdout, encoding="utf-8")
    (run_dir / "agent_stderr.txt").write_text(stderr, encoding="utf-8")
    success = flag_value in stdout or flag_value in stderr
    finished = datetime.now()
    (run_dir / "result.json").write_text(
        json.dumps(
            {
                "status": "completed" if returncode == 0 else "agent_failed",
                "success": success,
                "returncode": returncode,
                "started_at": started.isoformat(timespec="seconds"),
                "finished_at": finished.isoformat(timespec="seconds"),
                "duration_seconds": round((finished - started).total_seconds(), 3),
                **planned,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return run_dir


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run our agent against third-party pentest benchmarks")
    sub = parser.add_subparsers(dest="command", required=True)

    list_parser = sub.add_parser("list", help="List benchmark cases from a local upstream repo")
    list_parser.add_argument("--suite", required=True, choices=SUPPORTED_SUITES)
    list_parser.add_argument("--repo", required=True, type=Path)
    list_parser.add_argument("--json", action="store_true")

    manifest_parser = sub.add_parser("manifest", help="Write a JSON manifest for a benchmark repo")
    manifest_parser.add_argument("--suite", required=True, choices=SUPPORTED_SUITES)
    manifest_parser.add_argument("--repo", required=True, type=Path)
    manifest_parser.add_argument("--output", required=True, type=Path)

    run_parser = sub.add_parser("run", help="Run one external benchmark case")
    run_parser.add_argument("--suite", required=True, choices=SUPPORTED_SUITES)
    run_parser.add_argument("--repo", required=True, type=Path)
    run_parser.add_argument("--case", required=True)
    run_parser.add_argument("--agent-command", required=True)
    run_parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, type=Path)
    run_parser.add_argument("--flag", default=None)
    run_parser.add_argument("--timeout", default=1800, type=int)
    run_parser.add_argument("--dry-run", action="store_true")
    run_parser.add_argument("--keep-running", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "list":
        cases = discover_cases(args.suite, args.repo)
        if args.json:
            print(json.dumps([case.to_dict() for case in cases], indent=2, ensure_ascii=False))
        else:
            for case in cases:
                target = case.target_url or "-"
                level = f"L{case.level}" if case.level else "-"
                marker = "run" if case.runnable else "manual"
                print(f"{case.case_id}\t{level}\t{marker}\t{target}\t{case.description}")
    elif args.command == "manifest":
        print(write_manifest(args.suite, args.repo, args.output))
    elif args.command == "run":
        run_dir = run_case(
            suite=args.suite,
            repo=args.repo,
            case_id=args.case,
            agent_command=args.agent_command,
            output_dir=args.output_dir,
            flag=args.flag,
            dry_run=args.dry_run,
            keep_running=args.keep_running,
            timeout_seconds=args.timeout,
        )
        print(run_dir)


if __name__ == "__main__":
    main()
