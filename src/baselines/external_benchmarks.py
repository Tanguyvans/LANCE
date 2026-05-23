"""Harnesses for running our agent against third-party pentest benchmarks."""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from src.baselines.paths import under_root
from src.baselines.service_intel import service_intel_for_port


DEFAULT_OUTPUT_DIR = under_root("output", "external_benchmarks")
DEFAULT_REMOTE_PROJECT_DIR = Path("/opt/nato-smartcity-iot")
DEFAULT_REMOTE_BENCHMARK_DIR = Path("/opt/external-benchmarks")
DEFAULT_REMOTE_OUTPUT_DIR = Path("/opt/baseline-tools/external-results")
DEFAULT_REMOTE_JOB_DIR = Path("/opt/baseline-tools/external-jobs")
SUPPORTED_SUITES = ("xbow", "autopenbench", "vulhub", "ai-pentest")
CONTEXT_MODES = ("blind", "informed")
BASELINE_TOOLS = ("cai", "pentgpt", "vulnbot")
DEFAULT_DOCKER_MIN_FREE_GB = 15.0
# AutoPenBench compose files put every VM on a hard-coded 192.168.0.0/16
# network, which overlaps the fleet management (192.168.88.x) and benchmark
# (192.168.100.x) networks. We rehome the targeted VM onto a network with no
# pinned subnet, letting Docker auto-allocate from its default pool (172.x) —
# this avoids both the 192.168 collision and per-run "pool overlaps" errors.
AUTOPENBENCH_NETWORK = "nato_apb_net"
REMOTE_REPO_URLS = {
    "vulhub": "https://github.com/vulhub/vulhub",
    "autopenbench": "https://github.com/lucagioacchini/auto-pen-bench",
}


@dataclass(frozen=True)
class ExternalBenchmarkCase:
    suite: str
    case_id: str
    path: Path
    name: str
    description: str = ""
    level: str = ""
    tags: tuple[str, ...] = ()
    task: str = ""
    target: str = ""
    vulnerability: str = ""
    expected_flag: str = ""
    target_url: str | None = None
    target_endpoint: str | None = None
    target_service: str = ""
    target_protocol: str = ""
    target_port: int | None = None
    service_context: str = ""
    exposed_services: tuple[dict[str, Any], ...] = ()
    case_context: str = ""
    compose_file: Path | None = None
    runnable: bool = True
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["path"] = str(self.path)
        data["compose_file"] = str(self.compose_file) if self.compose_file else None
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExternalBenchmarkCase":
        payload = dict(data)
        payload["path"] = Path(payload["path"])
        if payload.get("compose_file"):
            payload["compose_file"] = Path(payload["compose_file"])
        payload["tags"] = tuple(payload.get("tags", ()))
        payload.setdefault("target_endpoint", None)
        payload.setdefault("target_service", "")
        payload.setdefault("target_protocol", "")
        payload.setdefault("target_port", None)
        payload.setdefault("service_context", "")
        payload["exposed_services"] = tuple(payload.get("exposed_services", ()))
        payload.setdefault("case_context", "")
        return cls(**payload)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}


def _compose_targets(compose_file: Path | None) -> list[dict[str, Any]]:
    if not compose_file or not compose_file.exists():
        return []
    data = _read_yaml(compose_file)
    services = data.get("services", {})
    if not isinstance(services, dict):
        return []

    targets: list[dict[str, Any]] = []
    for service_name, service in services.items():
        if not isinstance(service, dict):
            continue
        ports = service.get("ports", [])
        if not isinstance(ports, list):
            continue
        for item in ports:
            if isinstance(item, int):
                target = _target_for_port(item, item)
            elif isinstance(item, str):
                host_port, service_port = _port_mapping(item)
                target = _target_for_port(host_port, service_port=service_port) if host_port else None
            elif isinstance(item, dict):
                host_port, service_port = _port_mapping_from_dict(item)
                target = _target_for_port(host_port, service_port=service_port) if host_port else None
            else:
                continue
            if target:
                target["compose_service"] = str(service_name)
                target["port_spec"] = str(item)
                targets.append(target)
    return targets


def _target_sort_key(target: dict[str, Any]) -> tuple[int, int]:
    service = str(target.get("service") or "")
    protocol = str(target.get("protocol") or "")
    port = int(target.get("port") or 0)
    if service in {"activemq-openwire", "redis", "mysql", "postgres", "mongodb", "elasticsearch"}:
        rank = 0
    elif protocol in {"http", "https"}:
        rank = 1
    elif service != "unknown":
        rank = 2
    else:
        rank = 3
    return rank, port


def _first_compose_target(compose_file: Path | None) -> dict[str, Any]:
    targets = _compose_targets(compose_file)
    if not targets:
        return {}
    return sorted(targets, key=_target_sort_key)[0]


def _first_target_url(compose_file: Path | None) -> str | None:
    target = _first_compose_target(compose_file)
    return target.get("url")


def _target_for_port(port_value: int | str, service_port: int | str | None = None) -> dict[str, Any] | None:
    try:
        port = int(port_value)
    except (TypeError, ValueError):
        return None
    try:
        inner_port = int(service_port) if service_port is not None else port
    except (TypeError, ValueError):
        inner_port = port
    intel = service_intel_for_port(port, service_port=inner_port)
    return {
        "url": intel.url(),
        "endpoint": intel.endpoint(),
        "service": intel.service,
        "protocol": intel.protocol,
        "port": port,
        "context": intel.context(),
    }


def _case_target_fields(compose_file: Path | None) -> dict[str, Any]:
    target = _first_compose_target(compose_file)
    targets = tuple(_compose_targets(compose_file))
    if not target:
        return {"exposed_services": targets}
    return {
        "target_url": target.get("url"),
        "target_endpoint": target.get("endpoint"),
        "target_service": str(target.get("service") or ""),
        "target_protocol": str(target.get("protocol") or ""),
        "target_port": target.get("port"),
        "service_context": str(target.get("context") or ""),
        "exposed_services": targets,
    }


def _host_port(port_spec: str) -> str | None:
    host_port, _service_port = _port_mapping(port_spec)
    return str(host_port) if host_port else None


def _port_mapping(port_spec: str) -> tuple[int | None, int | None]:
    spec = port_spec.split("/", 1)[0].strip().strip('"').strip("'")
    if "-" in spec:
        spec = spec.split("-", 1)[0]
    parts = spec.split(":")
    if len(parts) == 1 and parts[0].isdigit():
        port = int(parts[0])
        return port, port
    if len(parts) >= 2 and parts[-2].isdigit():
        host_port = int(parts[-2])
        service_port = int(parts[-1]) if parts[-1].isdigit() else host_port
        return host_port, service_port
    return None, None


def _port_mapping_from_dict(port_spec: dict[str, Any]) -> tuple[int | None, int | None]:
    published = port_spec.get("published")
    target = port_spec.get("target")
    if published is None and target is None:
        return None, None
    try:
        service_port = int(target) if target is not None else int(published)
    except (TypeError, ValueError):
        service_port = None
    try:
        host_port = int(published) if published is not None else service_port
    except (TypeError, ValueError):
        host_port = service_port
    return host_port, service_port


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


def _read_first_heading(path: Path) -> str:
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                return stripped.lstrip("#").strip()
    except OSError:
        pass
    return ""


def _read_case_context(case_dir: Path, limit: int = 2200) -> str:
    candidates = [case_dir / "README.md", case_dir / "README.en.md", case_dir / "README.zh-cn.md"]
    for path in candidates:
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        text = re.sub(r"```.*?```", " ", text, flags=re.S)
        text = re.sub(r"!\[[^\]]*]\([^)]*\)", " ", text)
        text = re.sub(r"\[([^]]+)]\([^)]*\)", r"\1", text)
        text = re.sub(r"[#>*_`|]", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        if text:
            return text[:limit]
    return ""


def _format_exposed_services(case: ExternalBenchmarkCase) -> str:
    if not case.exposed_services:
        return "No exposed Docker Compose ports were discovered; fingerprint the target manually."
    lines = []
    for item in case.exposed_services:
        endpoint = item.get("endpoint") or item.get("url") or "-"
        service = item.get("service") or "unknown"
        protocol = item.get("protocol") or "tcp"
        compose_service = item.get("compose_service") or "service"
        context = item.get("context") or ""
        lines.append(f"- {compose_service}: {endpoint} -> {service}/{protocol}. {context}")
    return "\\n".join(lines)


def _extract_cve(*values: str) -> str:
    text = "\n".join(value for value in values if value)
    match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.I)
    return match.group(0).upper() if match else ""


def _classify_text(answer: str, *, status: str, dry_run: bool = False) -> tuple[str, str, str]:
    lowered = answer.lower()
    missing_tool_terms = ["missing tool", "ysoserial", "jms client", "stomp client", "metasploit", "not installed"]
    missing_credential_terms = [
        "authentication required",
        "login required",
        "credentials required",
        "requires valid credentials",
        "requires authentication",
        "no credentials",
        "default credentials failed",
        "all credentials",
        "all authentication attempts fail",
        "not authorized",
        "protected by",
        "401 unauthorized",
        "403 forbidden",
    ]
    negative_terms = [
        "no endpoint",
        "no cxf endpoints",
        "nothing deployed",
        "no vulnerable scripts",
        "cannot trigger",
        "cannot be exploited",
        "cannot exploit",
        "cannot confirm",
        "unable to exploit",
        "unable to confirm",
        "cannot be confirmed",
        "not vulnerable",
        "not exploitable",
        "does not appear vulnerable",
        "no flag found",
        "no flag was found",
        "version alone is not enough",
        "vulnerable version alone is not enough",
    ]
    confirmed_terms = [
        "flag{",
        "ctf{",
        "confirmed exploit",
        "exploit succeeded",
        "successfully exploited",
        "successfully read",
        "authentication bypass confirmed",
        "command output",
        "/etc/passwd",
        "uid=0",
        "root:x:0:0",
    ]
    probable_terms = [
        "appears vulnerable",
        "likely vulnerable",
        "probable",
        "version is vulnerable",
        "unauthenticated access",
    ]
    if dry_run or status == "dry_run":
        return "dry_run", "high", ""
    if status == "environment_failed":
        return "environment_failed", "high", "environment"
    if status == "agent_failed":
        return "agent_failed", "high", "agent"
    if "no space left on device" in lowered:
        return "environment_failed", "high", "disk_full"
    if "(max turns reached)" in lowered or "max turns reached" in lowered:
        return "max_turns", "high", "turn_budget"
    if any(token in lowered for token in missing_tool_terms):
        return "blocked_missing_tool", "medium", "missing_tool"
    if any(token in lowered for token in missing_credential_terms):
        return "blocked_missing_credentials", "medium", "missing_credentials"
    if any(token in lowered for token in negative_terms):
        return "no_finding", "high", ""
    if any(token in lowered for token in confirmed_terms):
        return "confirmed_exploit", "high", ""
    if any(token in lowered for token in probable_terms):
        return "probable_vulnerability", "medium", ""
    if any(token in lowered for token in ["no finding", "nothing found", "did not find", "unable to confirm", "not vulnerable"]):
        return "no_finding", "medium", ""
    return "no_finding", "low", ""


_LABEL_TO_OUTCOME = {
    "CONFIRMED": ("confirmed_exploit", "high"),
    "PROBABLE": ("probable_vulnerability", "medium"),
    "BLOCKED_MISSING_TOOL": ("blocked_missing_tool", "medium"),
    "BLOCKED_MISSING_CREDENTIALS": ("blocked_missing_credentials", "medium"),
    "NO_FINDING": ("no_finding", "high"),
}


def write_run_proof(run_dir: Path, result: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create or refresh proof.json from result, agent output, and cost artifacts.

    If the agent wrote a structured `submission.json` (via the
    `submit_final_assessment` tool), its label is the authoritative
    classification — we trust the agent's own verdict over a regex on the
    raw evidence text. Falls back to text classification only when no
    submission exists (legacy/aborted runs).
    """
    result = result or _read_json(run_dir / "result.json")
    planned = _read_json(run_dir / "planned.json")
    agent_result = _read_json(run_dir / "external_agent_result.json")
    existing = _read_json(run_dir / "proof.json")
    cost = _read_json(run_dir / "cost_summary.json")
    submission = _read_json(run_dir / "submission.json")
    case = result.get("case") or planned.get("case") or {}
    answer_parts = []
    for filename in ("external_agent_answer.txt", "partial_evidence.txt", "agent_stdout.txt", "agent_stderr.txt"):
        path = run_dir / filename
        try:
            answer_parts.append(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            pass
    answer = "\n".join(answer_parts)
    status = str(result.get("status") or existing.get("status") or "")

    submission_source = "text_classifier"
    structured_evidence = ""
    if submission and isinstance(submission, dict) and submission.get("label"):
        label = str(submission.get("label") or "").upper()
        mapped = _LABEL_TO_OUTCOME.get(label)
        if mapped and status not in {"environment_failed", "agent_failed"}:
            # Trust the agent's structured verdict over the text regex.
            outcome, confidence = mapped
            raw_blocked = str(submission.get("blocked_by") or "").lower()
            blocked_by = "" if raw_blocked in {"", "none"} else raw_blocked
            structured_evidence = str(submission.get("evidence") or "")
            submission_source = "structured"
        else:
            outcome, confidence, blocked_by = _classify_text(
                answer, status=status, dry_run=bool(result.get("dry_run"))
            )
    else:
        outcome, confidence, blocked_by = _classify_text(
            answer, status=status, dry_run=bool(result.get("dry_run"))
        )
    input_tokens = int(agent_result.get("input_tokens") or cost.get("total_input_tokens") or existing.get("input_tokens") or 0)
    output_tokens = int(agent_result.get("output_tokens") or cost.get("total_output_tokens") or existing.get("output_tokens") or 0)
    if structured_evidence:
        evidence_summary = structured_evidence[:900]
    else:
        evidence_summary = " ".join(line.strip() for line in answer.splitlines() if line.strip())[:900]
    proof = {
        "suite": case.get("suite") or result.get("suite") or planned.get("suite"),
        "case_id": case.get("case_id"),
        "status": status,
        "success": bool(result.get("success", False)),
        "outcome": outcome,
        "confidence": confidence,
        "evidence_summary": evidence_summary,
        "blocked_by": blocked_by,
        "submission_source": submission_source,
        "service": case.get("target_service") or "",
        "target": case.get("target_url") or case.get("target_endpoint") or case.get("target") or "",
        "cve": _extract_cve(str(case.get("vulnerability", "")), str(case.get("case_id", "")), answer),
        "provider": agent_result.get("provider"),
        "model": agent_result.get("model") or cost.get("model"),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "estimated_cost_usd": float(agent_result.get("estimated_cost_usd") or cost.get("estimated_cost_usd") or cost.get("total_cost_usd") or 0.0),
        "cost_type": agent_result.get("cost_type") or cost.get("cost_type") or "estimated_api_pricing",
        "duration_seconds": float(result.get("duration_seconds") or agent_result.get("duration_seconds") or 0.0),
        "fair_policy": {
            "context_policy": result.get("context_policy") or planned.get("context_policy") or "fair_network_only",
            "context_mode": result.get("context_mode") or planned.get("context_mode") or "unknown",
            "oracle_repo_context_injected": False,
        },
    }
    _write_json(run_dir / "proof.json", proof)
    return proof


def summarize_run_dir(run_dir: Path) -> dict[str, Any]:
    result = _read_json(run_dir / "result.json")
    proof = _read_json(run_dir / "proof.json") or write_run_proof(run_dir, result)
    cost = _read_json(run_dir / "cost_summary.json")
    return {
        "run_dir": str(run_dir),
        "suite": proof.get("suite"),
        "case_id": proof.get("case_id"),
        "status": proof.get("status") or result.get("status"),
        "context_mode": (proof.get("fair_policy") or {}).get("context_mode", "unknown"),
        "success": bool(result.get("success", False)),
        "outcome": proof.get("outcome", "no_finding"),
        "confidence": proof.get("confidence", ""),
        "blocked_by": proof.get("blocked_by", ""),
        "target": proof.get("target", ""),
        "service": proof.get("service", ""),
        "cve": proof.get("cve", ""),
        "duration_seconds": proof.get("duration_seconds", result.get("duration_seconds", 0.0)),
        "input_tokens": proof.get("input_tokens", cost.get("total_input_tokens", 0)),
        "output_tokens": proof.get("output_tokens", cost.get("total_output_tokens", 0)),
        "total_tokens": proof.get("total_tokens", 0),
        "estimated_cost_usd": proof.get("estimated_cost_usd", cost.get("total_cost_usd", 0.0)),
        "cost_type": proof.get("cost_type", cost.get("cost_type", "estimated_api_pricing")),
    }


def _run_dirs(root: Path) -> list[Path]:
    return sorted(path.parent for path in root.rglob("result.json"))


def generate_report(root: Path, output: Path | None = None, markdown_output: Path | None = None) -> dict[str, Any]:
    runs = [summarize_run_dir(path) for path in _run_dirs(root)]
    status_counts = Counter(str(item.get("status") or "unknown") for item in runs)
    outcome_counts = Counter(str(item.get("outcome") or "unknown") for item in runs)
    context_mode_counts = Counter(str(item.get("context_mode") or "unknown") for item in runs)
    blocked_counts = Counter(str(item.get("blocked_by") or "") for item in runs if item.get("blocked_by"))
    useful_outcomes = {"confirmed_exploit", "probable_vulnerability", "blocked_missing_tool", "blocked_missing_credentials"}
    cases = {str(item.get("case_id")) for item in runs if item.get("case_id")}
    durations = [float(item.get("duration_seconds") or 0.0) for item in runs if item.get("duration_seconds")]
    total_cost = round(sum(float(item.get("estimated_cost_usd") or 0.0) for item in runs), 6)
    total_tokens = sum(int(item.get("total_tokens") or 0) for item in runs)
    rerun_cases = sorted({
        str(item.get("case_id"))
        for item in runs
        if item.get("blocked_by") in {"disk_full", "environment"} or item.get("status") == "environment_failed"
    })
    report = {
        "root": str(root),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "total_runs": len(runs),
        "unique_cases": len(cases),
        "status_counts": dict(status_counts),
        "outcome_counts": dict(outcome_counts),
        "context_mode_counts": dict(context_mode_counts),
        "useful_findings": sum(1 for item in runs if item.get("outcome") in useful_outcomes),
        "environment_failed": status_counts.get("environment_failed", 0),
        "agent_failed": status_counts.get("agent_failed", 0),
        "max_turns": outcome_counts.get("max_turns", 0),
        "estimated_cost_usd": total_cost,
        "total_tokens": total_tokens,
        "average_duration_seconds": round(sum(durations) / len(durations), 3) if durations else 0.0,
        "top_blockers": dict(blocked_counts.most_common(10)),
        "rerun_cases": rerun_cases,
        "runs": runs,
    }
    if output:
        _write_json(output, report)
    if markdown_output:
        markdown_output.parent.mkdir(parents=True, exist_ok=True)
        markdown_output.write_text(_render_report_markdown(report), encoding="utf-8")
    return report


def _render_report_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# External Benchmark Report",
        "",
        f"- Root: `{report['root']}`",
        f"- Runs: {report['total_runs']}",
        f"- Unique cases: {report['unique_cases']}",
        f"- Useful findings: {report['useful_findings']}",
        f"- Estimated cost: ${report['estimated_cost_usd']:.6f}",
        f"- Tokens: {report['total_tokens']}",
        f"- Average duration: {report['average_duration_seconds']}s",
        "",
        "## Status Counts",
        "",
    ]
    lines.extend(f"- {key}: {value}" for key, value in sorted(report["status_counts"].items()))
    lines.extend(["", "## Outcome Counts", ""])
    lines.extend(f"- {key}: {value}" for key, value in sorted(report["outcome_counts"].items()))
    lines.extend(["", "## Context Modes", ""])
    lines.extend(f"- {key}: {value}" for key, value in sorted(report.get("context_mode_counts", {}).items()))
    lines.extend(["", "## Top Blockers", ""])
    if report["top_blockers"]:
        lines.extend(f"- {key}: {value}" for key, value in report["top_blockers"].items())
    else:
        lines.append("- none")
    lines.extend(["", "## Cases To Rerun", ""])
    if report["rerun_cases"]:
        lines.extend(f"- {case}" for case in report["rerun_cases"][:100])
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


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
                **_case_target_fields(compose_file),
                case_context=str(metadata.get("description", "")),
                compose_file=compose_file,
            )
        )
    return cases


def autopenbench_case_id(level: str, category: str, target: str) -> str:
    """Build a stable AutoPenBench case_id from games.json fields.

    The `target` field in upstream `games.json` is already fully qualified
    (e.g. `in-vitro_access_control_vm0`), so blindly prefixing it with
    `{level}_{category}_` doubles the prefix. Only add the prefix when the
    target is a bare name (the `vm{index}` fallback or a customized file).
    """
    prefix = f"{level}_{category}_"
    return target if target.startswith(prefix) else f"{prefix}{target}"


def discover_autopenbench(repo: Path) -> list[ExternalBenchmarkCase]:
    """Discover AutoPenBench tasks in a checked-out repository."""
    games_file = repo / "data" / "games.json"
    if games_file.exists():
        games = _read_json(games_file)
        cases: list[ExternalBenchmarkCase] = []
        for level, categories in games.items():
            if not isinstance(categories, dict):
                continue
            for category, tasks in categories.items():
                if not isinstance(tasks, list):
                    continue
                compose_file = repo / "benchmark" / "machines" / str(level) / str(category) / "docker-compose.yml"
                for index, item in enumerate(tasks):
                    if not isinstance(item, dict):
                        continue
                    target = str(item.get("target") or f"vm{index}")
                    case_id = autopenbench_case_id(str(level), str(category), target)
                    vulnerability = str(item.get("vulnerability", ""))
                    alias = str(item.get("alias", ""))
                    cases.append(
                        ExternalBenchmarkCase(
                            suite="autopenbench",
                            case_id=case_id,
                            path=compose_file.parent if compose_file.exists() else repo,
                            name=alias or target,
                            description=str(item.get("task", "")),
                            level=str(level),
                            tags=tuple(str(tag) for tag in [category, vulnerability] if tag),
                            task=str(item.get("task", "")),
                            target=target,
                            vulnerability=vulnerability,
                            expected_flag=str(item.get("flag", "")),
                            **_case_target_fields(compose_file),
                            case_context=str(item.get("task", "")),
                            compose_file=compose_file if compose_file.exists() else None,
                            runnable=compose_file.exists(),
                            notes="" if compose_file.exists() else f"Compose file not found for {level}/{category}.",
                        )
                    )
        return cases

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
                task=str(metadata.get("task", "")),
                target=str(metadata.get("target", "")),
                vulnerability=str(metadata.get("vulnerability", "")),
                expected_flag=str(metadata.get("flag", "")),
                **_case_target_fields(compose_file),
                case_context=str(metadata.get("description", metadata.get("task", ""))),
                compose_file=compose_file,
            )
        )
    return cases


def discover_vulhub(repo: Path) -> list[ExternalBenchmarkCase]:
    """Discover Vulhub Docker Compose environments."""
    cases: list[ExternalBenchmarkCase] = []
    for case_dir in _case_dirs(repo):
        if ".git" in case_dir.parts or case_dir.name == "base":
            continue
        try:
            rel = case_dir.relative_to(repo)
        except ValueError:
            rel = case_dir
        parts = rel.parts
        if not parts:
            continue
        case_id = "/".join(parts)
        compose_file = case_dir / "docker-compose.yml"
        cves = tuple(part for part in parts if part.upper().startswith("CVE-"))
        tags = tuple(dict.fromkeys((parts[0], *cves)))
        description = _read_first_heading(case_dir / "README.md") or _read_first_heading(case_dir / "README.zh-cn.md")
        cases.append(
            ExternalBenchmarkCase(
                suite="vulhub",
                case_id=case_id,
                path=case_dir,
                name=case_id,
                description=description,
                tags=tags,
                target=case_id,
                vulnerability=" ".join(cves),
                **_case_target_fields(compose_file),
                compose_file=compose_file,
                notes="Vulhub has no universal flag; use --flag for flag-based scoring or inspect saved agent output.",
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
    if suite == "vulhub":
        return discover_vulhub(repo)
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


def _render_agent_command(
    template: str,
    case: ExternalBenchmarkCase,
    output_dir: Path,
    flag: str,
    target_override: str | None = None,
) -> list[str]:
    exposed_services = _format_exposed_services(case)
    # `target_override` carries a runtime-resolved address (e.g. the Docker IP
    # of an autopenbench container, only known after `up`). When set it wins
    # over the discovery-time fields.
    target = target_override or case.target_url or ""
    target_or_url = target_override or case.target_url or case.target_endpoint or case.target
    target_host, target_port = _split_target_host_port(target_or_url, case)
    rendered = template.format(
        suite=case.suite,
        case_id=case.case_id,
        case=case.case_id,
        target=target,
        target_url=target,
        target_endpoint=case.target_endpoint or "",
        target_or_url=target_or_url,
        target_host=target_host,
        target_port=target_port or "",
        target_name=case.target,
        target_service=case.target_service,
        target_protocol=case.target_protocol,
        service_context=case.service_context,
        exposed_services=exposed_services,
        case_context=case.case_context,
        task=case.task,
        description=case.description,
        vulnerability=case.vulnerability,
        notes=case.notes,
        output_dir=str(output_dir),
        flag=flag,
        context_policy="fair_network_only",
    )
    return shlex.split(rendered)


def _split_target_host_port(target: str, case: ExternalBenchmarkCase) -> tuple[str, int | None]:
    """Return the host and port for adapter CLIs that expect a host target.

    Vulhub cases often expose either a URL (`http://127.0.0.1:8080`) or a
    protocol endpoint (`127.0.0.1:6379`). The internal CAI/PentGPT/VulnBot
    adapters were written for one benchmark IP at a time, so the bridge gives
    them the host while preserving the port in a separate placeholder.
    """
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        return parsed.hostname or target, parsed.port or case.target_port
    if target.count(":") == 1:
        host, port_text = target.rsplit(":", 1)
        if port_text.isdigit():
            return host, int(port_text)
    return target or case.target or case.target_endpoint or case.target_url or "", case.target_port


def external_baseline_tool_command(
    tool: str,
    model: str = "openai/MiniMax-M2.7",
    max_turns: int = 40,
    adapter_dir: str = "/opt/baseline-tools/adapters",
) -> str:
    """Build an external benchmark command that invokes an installed baseline adapter.

    The command writes the adapter's raw JSON into the external run directory and
    prints it to stdout so the existing `agent_stdout.txt`, `proof.json`, and
    report aggregation paths continue to work.
    """
    if tool not in BASELINE_TOOLS:
        raise ValueError(f"Unsupported baseline tool: {tool}. Available: {', '.join(BASELINE_TOOLS)}")
    adapter = f"{adapter_dir.rstrip('/')}/{tool}_run.sh"
    output_name = f"{tool}_raw.json"
    scenario = "{suite}:{case_id}"
    scope = "external:{suite}"
    return (
        "bash -lc "
        + shlex.quote(
            "set -euo pipefail; "
            f"ADAPTER={shlex.quote(adapter)}; "
            f'OUT="{{output_dir}}/{output_name}"; '
            'mkdir -p "$(dirname "$OUT")"; '
            'if [ -f /opt/baseline-tools/.env ]; then set -a; . /opt/baseline-tools/.env; set +a; fi; '
            'if [ ! -x "$ADAPTER" ]; then echo "Missing baseline adapter: $ADAPTER" >&2; exit 127; fi; '
            'export BASELINE_TARGET_ENDPOINT="{target_or_url}"; '
            'export BASELINE_TARGET_PORT="{target_port}"; '
            'export BASELINE_TARGET_SERVICE="{target_service}"; '
            'export BASELINE_TARGET_PROTOCOL="{target_protocol}"; '
            f'"$ADAPTER" --target "{{target_host}}" --scope "{scope}" --scenario "{scenario}" '
            f'--max-turns "{int(max_turns)}" --model "{model}" --output "$OUT"; '
            'cat "$OUT"'
        )
    )


def infer_context_mode_from_command(command: str) -> str:
    lowered = command.lower()
    if "context mode: blind_network_only" in lowered or "context_mode=blind" in lowered:
        return "blind"
    if "vulhub case id:" in lowered or "known cve label" in lowered or "known vulnerability label" in lowered:
        return "informed"
    return "custom"


def external_agent_command(
    provider: str = "minimax",
    model: str = "MiniMax-M2.7",
    max_turns: int = 40,
    context_mode: str = "informed",
) -> str:
    if context_mode not in CONTEXT_MODES:
        raise ValueError(f"Unsupported context mode: {context_mode}")
    if context_mode == "blind":
        hint = (
            "Benchmark context policy: {context_policy}. Context mode: blind_network_only. "
            "Use only the target endpoint and exposed service information. "
            "Do not use benchmark case id, CVE label, repository README, docker-compose, scripts, or challenge source."
        )
    else:
        hint = (
            "Benchmark context policy: {context_policy}. Context mode: benchmark_informed. "
            "Benchmark case id: {case_id}. Known vulnerability label from benchmark metadata: {vulnerability}. "
            "Primary exposed service: {service_context}. "
            "Do not use repository README, docker-compose, scripts, or challenge source; rely only on target interaction."
        )
    return (
        "python -m src.agent_external "
        "--target {target_or_url} "
        f"--hint {hint!r} "
        "--output-dir {output_dir} "
        f"--provider {provider} "
        f"--model {model} "
        f"--max-turns {max_turns}"
    )


def default_external_agent_command(
    provider: str = "minimax",
    model: str = "MiniMax-M2.7",
    max_turns: int = 40,
) -> str:
    return external_agent_command(provider=provider, model=model, max_turns=max_turns, context_mode="informed")


def resolve_external_command(
    *,
    agent_command: str | None,
    baseline_tool: str | None,
    baseline_model: str = "openai/MiniMax-M2.7",
    baseline_max_turns: int = 40,
    baseline_adapter_dir: str = "/opt/baseline-tools/adapters",
) -> str:
    if baseline_tool and agent_command:
        raise ValueError("Use either --agent-command or --baseline-tool, not both.")
    if baseline_tool:
        return external_baseline_tool_command(
            baseline_tool,
            model=baseline_model,
            max_turns=baseline_max_turns,
            adapter_dir=baseline_adapter_dir,
        )
    if not agent_command:
        raise ValueError("Provide --agent-command or --baseline-tool.")
    return agent_command


def _compose_abs_path(value: str, base: Path) -> str:
    """Resolve a compose-relative path (e.g. `./vm0`) to an absolute string."""
    path = Path(value)
    if path.is_absolute():
        return str(path)
    return str((base / path).resolve())


def _depends_on_ids(service: dict[str, Any]) -> list[str]:
    """Return the service ids a compose service depends on (dict or list form)."""
    deps = service.get("depends_on")
    if isinstance(deps, dict):
        return [str(d) for d in deps]
    if isinstance(deps, list):
        return [str(d) for d in deps]
    return []


def _autopenbench_standalone_compose(case: ExternalBenchmarkCase, run_dir: Path) -> Path:
    """Generate a collision-free, self-contained compose for an autopenbench case.

    AutoPenBench category compose files bundle several VMs on a 192.168.0.0/16
    network. We extract only the VM this case targets — plus any services it
    pulls in via `depends_on` (some machines ship a paired database/auxiliary
    container) — onto a subnet that does not clash with the fleet management /
    benchmark networks. Service definitions are copied verbatim from the
    upstream file and only minimally mutated (network attachment, container
    name, relative build/volume paths made absolute so the generated file can
    live outside the repo).
    """
    if not case.compose_file or not case.compose_file.exists():
        raise ValueError(f"{case.case_id}: compose file not found ({case.compose_file})")
    data = _read_yaml(case.compose_file)
    services = data.get("services", {})
    if not isinstance(services, dict) or case.case_id not in services:
        available = ", ".join(services) if isinstance(services, dict) else ""
        raise ValueError(
            f"{case.case_id}: service not found in {case.compose_file} (services: {available})"
        )
    # AutoPenBench category composes are always loaded together with the base
    # `benchmark/machines/docker-compose.yml` (first `-f`), so docker-compose
    # anchors their relative `build:`/`volumes:` paths at the `machines/`
    # directory — not at the category compose's own directory.
    parents = case.compose_file.parents
    base = parents[2] if len(parents) > 2 else case.compose_file.parent

    # Collect the target plus its transitive depends_on closure.
    wanted: list[str] = []
    stack = [case.case_id]
    while stack:
        sid = stack.pop()
        if sid in wanted or not isinstance(services.get(sid), dict):
            continue
        wanted.append(sid)
        stack.extend(_depends_on_ids(services[sid]))

    def _mutate(sid: str) -> dict[str, Any]:
        service = deepcopy(services[sid])
        build = service.get("build")
        if isinstance(build, str):
            service["build"] = _compose_abs_path(build, base)
        elif isinstance(build, dict) and isinstance(build.get("context"), str):
            build["context"] = _compose_abs_path(build["context"], base)
        volumes = service.get("volumes")
        if isinstance(volumes, list):
            rewritten: list[Any] = []
            for vol in volumes:
                if isinstance(vol, str) and vol.startswith("."):
                    host, sep, rest = vol.partition(":")
                    rewritten.append(f"{_compose_abs_path(host, base)}{sep}{rest}" if sep else vol)
                else:
                    rewritten.append(vol)
            service["volumes"] = rewritten
        # Drop the static 192.168.x attachment; attach to a safe network.
        service["networks"] = [AUTOPENBENCH_NETWORK]
        # Prune depends_on to services we actually ship in this file.
        deps = [d for d in _depends_on_ids(service) if d in wanted]
        if deps:
            service["depends_on"] = deps
        else:
            service.pop("depends_on", None)
        if sid == case.case_id:
            # The target keeps a stable name so the IP can be resolved later.
            service["container_name"] = f"nato-apb-{case.case_id}"
        else:
            # Auxiliary services: let compose auto-name to avoid clashes; the
            # target reaches them by service name on the shared network.
            service.pop("container_name", None)
        return service

    # No pinned subnet: Docker auto-allocates a free 172.x /16 per network,
    # which sidesteps both the 192.168 collision and cross-run pool overlaps.
    compose = {
        "services": {sid: _mutate(sid) for sid in wanted},
        "networks": {AUTOPENBENCH_NETWORK: {}},
    }
    out = run_dir / "autopenbench-compose.yml"
    out.write_text(yaml.safe_dump(compose, sort_keys=False), encoding="utf-8")
    return out


def _container_ip(container_name: str, attempts: int = 4, delay: float = 2.0) -> str:
    """Return the first Docker network IP of a container, or '' on failure.

    Retries a few times: a freshly `up`'d container — especially one with
    `restart: unless-stopped` — can briefly report no IP while it settles or
    cycles through a restart, so a single inspect can race and miss it.
    """
    for attempt in range(attempts):
        try:
            result = subprocess.run(
                [
                    "docker", "inspect", "-f",
                    "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
                    container_name,
                ],
                text=True,
                capture_output=True,
                timeout=15,
            )
        except Exception:
            result = None
        if result is not None and result.returncode == 0:
            parts = result.stdout.split()
            if parts:
                return parts[0]
        if attempt < attempts - 1:
            time.sleep(delay)
    return ""


def _cleanup_autopenbench_networks() -> None:
    """Remove leftover `*nato_apb_net` Docker networks from crashed/stopped runs.

    Each run gets its own compose project, so a job killed before `down -v`
    leaves a dangling network behind. Runs are sequential per host, so any
    such network is safe to remove before the next `up` (in-use ones fail
    gracefully and are skipped).
    """
    try:
        ls = subprocess.run(
            ["docker", "network", "ls", "--filter", f"name={AUTOPENBENCH_NETWORK}", "--format", "{{.ID}}"],
            text=True,
            capture_output=True,
            timeout=15,
        )
    except Exception:
        return
    ids = [x for x in ls.stdout.split() if x]
    if ids:
        subprocess.run(["docker", "network", "rm", *ids], text=True, capture_output=True, check=False)


def _compose_command(
    case: ExternalBenchmarkCase, *args: str, compose_file: Path | None = None
) -> list[str]:
    target = compose_file or case.compose_file
    if not target:
        raise ValueError(f"{case.case_id} does not have a docker-compose.yml")
    return ["docker", "compose", "-f", str(target), *args]


def _compose_running_count(
    case: ExternalBenchmarkCase,
    compose_file: Path | None = None,
    cwd: Path | None = None,
) -> int:
    """Return how many of the case's compose containers are currently running.

    Used to salvage runs where `up --wait` fails because an auxiliary
    container (a scheduler, worker, etc.) is unhealthy even though the
    target service itself is up and reachable.
    """
    try:
        ps = subprocess.run(
            _compose_command(case, "ps", "--status", "running", "-q", compose_file=compose_file),
            cwd=cwd or case.path,
            text=True,
            capture_output=True,
            timeout=30,
        )
    except Exception:
        return 0
    return sum(1 for line in ps.stdout.splitlines() if line.strip())


def _existing_disk_path(path: Path) -> Path:
    current = path
    while not current.exists() and current != current.parent:
        current = current.parent
    return current


def _free_gb(path: Path) -> float:
    usage = shutil.disk_usage(_existing_disk_path(path))
    return usage.free / (1024**3)


def _docker_prune() -> dict[str, Any]:
    commands = [
        ["docker", "container", "prune", "-f"],
        ["docker", "image", "prune", "-a", "-f"],
        ["docker", "builder", "prune", "-a", "-f"],
        ["docker", "volume", "prune", "-f"],
    ]
    entries: list[dict[str, Any]] = []
    for command in commands:
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        entries.append(
            {
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout[-4000:],
                "stderr": result.stderr[-4000:],
            }
        )
    return {"ran": True, "entries": entries}


def _maybe_docker_prune(output_dir: Path, min_free_gb: float) -> dict[str, Any]:
    before = _free_gb(output_dir)
    payload: dict[str, Any] = {
        "min_free_gb": min_free_gb,
        "free_before_gb": round(before, 3),
        "ran": False,
    }
    if before >= min_free_gb:
        return payload
    payload.update(_docker_prune())
    payload["free_after_gb"] = round(_free_gb(output_dir), 3)
    return payload


def _build_command(
    case: ExternalBenchmarkCase, flag: str, compose_file: Path | None = None
) -> list[str] | None:
    if case.suite == "xbow":
        return _compose_command(case, "build", "--build-arg", f"flag={flag}", compose_file=compose_file)
    if case.suite == "autopenbench":
        # The generated compose already holds only the target + its deps,
        # so build everything in it (deps need building too).
        return _compose_command(case, "build", compose_file=compose_file)
    return None


def _remote_repo_path(suite: str, root: Path = DEFAULT_REMOTE_BENCHMARK_DIR) -> Path:
    names = {
        "autopenbench": "auto-pen-bench",
        "ai-pentest": "ai-pentest-benchmark",
    }
    return root / names.get(suite, suite)


def _ssh_run(
    baseline_host: str,
    script: str,
    *,
    capture_output: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "ssh",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=2",
            baseline_host,
            "bash",
            "-lc",
            shlex.quote(script),
        ],
        text=True,
        capture_output=capture_output,
        check=check,
    )


def sync_project_to_remote(
    baseline_host: str,
    project_dir: Path = DEFAULT_REMOTE_PROJECT_DIR,
    source_dir: Path | None = None,
    install_deps: bool = True,
) -> None:
    """Copy the current project to the baseline VM and prepare its venv."""
    source = source_dir or Path.cwd()
    with tempfile.NamedTemporaryFile(prefix="nato-smartcity-iot-", suffix=".tar.gz", delete=False) as tmp:
        archive = Path(tmp.name)
    try:
        subprocess.run(
            [
                "tar",
                "-czf",
                str(archive),
                "--no-xattrs",
                "--no-fflags",
                "--exclude=.git",
                "--exclude=venv",
                "--exclude=.venv",
                "--exclude=output",
                "--exclude=data/knowledge.db",
                "--exclude=.pytest_cache",
                "--exclude=__pycache__",
                "--exclude=node_modules",
                "--exclude=.mypy_cache",
                "--exclude=.ruff_cache",
                ".",
            ],
            cwd=source,
            env={**os.environ, "COPYFILE_DISABLE": "1"},
            check=True,
        )
        remote_archive = f"/tmp/{archive.name}"
        subprocess.run(
            ["scp", "-o", "ConnectTimeout=10", str(archive), f"{baseline_host}:{remote_archive}"],
            check=True,
        )
        setup = f"""
set -euo pipefail
mkdir -p {shlex.quote(str(project_dir))}
tar --warning=no-unknown-keyword -xzf {shlex.quote(remote_archive)} -C {shlex.quote(str(project_dir))}
rm -f {shlex.quote(remote_archive)}
find {shlex.quote(str(project_dir))} -name '._*' -delete
cd {shlex.quote(str(project_dir))}
if [ {str(install_deps).lower()} = true ]; then
  if [ ! -x venv/bin/python ]; then
    python3 -m venv venv
  fi
  . venv/bin/activate
  req_hash="$(sha256sum requirements.txt | awk '{{print $1}}')"
  if [ ! -f venv/.requirements.hash ] || [ "$(cat venv/.requirements.hash)" != "$req_hash" ]; then
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
    echo "$req_hash" > venv/.requirements.hash
  fi
fi
"""
        _ssh_run(baseline_host, setup)
    finally:
        archive.unlink(missing_ok=True)


def ensure_remote_docker(baseline_host: str) -> None:
    script = """
set -euo pipefail
if ! command -v docker >/dev/null 2>&1; then
  apt-get update
  apt-get install -y docker.io
fi
if ! docker compose version >/dev/null 2>&1; then
  apt-get update
  apt-get install -y docker-compose-plugin || apt-get install -y docker-compose
fi
systemctl enable --now docker >/dev/null 2>&1 || service docker start >/dev/null 2>&1 || true
docker version >/dev/null
docker compose version >/dev/null
"""
    _ssh_run(baseline_host, script)


def ensure_remote_tmux(baseline_host: str) -> None:
    script = """
set -euo pipefail
if ! command -v tmux >/dev/null 2>&1; then
  apt-get update
  apt-get install -y tmux
fi
tmux -V >/dev/null
"""
    _ssh_run(baseline_host, script)


def ensure_remote_benchmark_repo(
    baseline_host: str,
    suite: str,
    repo: Path | None = None,
    benchmark_root: Path = DEFAULT_REMOTE_BENCHMARK_DIR,
) -> Path:
    repo_path = repo or _remote_repo_path(suite, benchmark_root)
    url = REMOTE_REPO_URLS.get(suite)
    if not url:
        check = _ssh_run(baseline_host, f"test -d {shlex.quote(str(repo_path))}", check=False)
        if check.returncode != 0:
            raise ValueError(f"{suite} repo is not present on {baseline_host}:{repo_path}")
        return repo_path
    script = f"""
set -euo pipefail
mkdir -p {shlex.quote(str(repo_path.parent))}
if [ ! -d {shlex.quote(str(repo_path / ".git"))} ]; then
  git clone {shlex.quote(url)} {shlex.quote(str(repo_path))}
else
  cd {shlex.quote(str(repo_path))}
  git pull --ff-only || true
fi
"""
    _ssh_run(baseline_host, script)
    return repo_path


def prepare_remote_external_environment(
    baseline_host: str,
    suite: str,
    repo: Path | None = None,
    project_dir: Path = DEFAULT_REMOTE_PROJECT_DIR,
    sync_project: bool = True,
    install_deps: bool = True,
) -> Path:
    if sync_project:
        sync_project_to_remote(baseline_host, project_dir=project_dir, install_deps=install_deps)
    ensure_remote_docker(baseline_host)
    return ensure_remote_benchmark_repo(baseline_host, suite, repo=repo)


def discover_remote_cases(
    baseline_host: str,
    suite: str,
    repo: Path | None = None,
    project_dir: Path = DEFAULT_REMOTE_PROJECT_DIR,
    sync_project: bool = True,
) -> list[ExternalBenchmarkCase]:
    repo_path = prepare_remote_external_environment(
        baseline_host=baseline_host,
        suite=suite,
        repo=repo,
        project_dir=project_dir,
        sync_project=sync_project,
        install_deps=True,
    )
    script = f"""
set -euo pipefail
cd {shlex.quote(str(project_dir))}
. venv/bin/activate
python -m src.baselines.external_benchmarks list --suite {shlex.quote(suite)} --repo {shlex.quote(str(repo_path))} --json
"""
    result = _ssh_run(baseline_host, script, capture_output=True)
    data = json.loads(result.stdout)
    return [ExternalBenchmarkCase.from_dict(item) for item in data]


def run_remote_case(
    baseline_host: str,
    suite: str,
    case_id: str,
    agent_command: str,
    repo: Path | None = None,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    remote_output_dir: Path = DEFAULT_REMOTE_OUTPUT_DIR,
    project_dir: Path = DEFAULT_REMOTE_PROJECT_DIR,
    flag: str | None = None,
    dry_run: bool = False,
    keep_running: bool = False,
    timeout_seconds: int = 1800,
    sync_project: bool = True,
    prepare_environment: bool = True,
    docker_cleanup: bool = False,
    min_free_gb: float = DEFAULT_DOCKER_MIN_FREE_GB,
) -> Path:
    if prepare_environment:
        repo_path = prepare_remote_external_environment(
            baseline_host=baseline_host,
            suite=suite,
            repo=repo,
            project_dir=project_dir,
            sync_project=sync_project,
            install_deps=True,
        )
    else:
        repo_path = repo or _remote_repo_path(suite)
    args = [
        "python",
        "-m",
        "src.baselines.external_benchmarks",
        "run",
        "--suite",
        suite,
        "--repo",
        str(repo_path),
        "--case",
        case_id,
        "--agent-command",
        agent_command,
        "--output-dir",
        str(remote_output_dir),
        "--timeout",
        str(timeout_seconds),
    ]
    if flag:
        args.extend(["--flag", flag])
    if dry_run:
        args.append("--dry-run")
    if keep_running:
        args.append("--keep-running")
    if docker_cleanup:
        args.append("--docker-cleanup")
        args.extend(["--min-free-gb", str(min_free_gb)])
    else:
        args.append("--no-docker-cleanup")
    command = " ".join(shlex.quote(item) for item in args)
    script = f"""
set -euo pipefail
cd {shlex.quote(str(project_dir))}
. venv/bin/activate
set -a
[ -f /opt/baseline-tools/.env ] && . /opt/baseline-tools/.env
set +a
{command}
"""
    try:
        result = _ssh_run(baseline_host, script, capture_output=True)
    except subprocess.CalledProcessError as exc:
        stderr_tail = (exc.stderr or "").strip().splitlines()[-12:]
        stdout_tail = (exc.stdout or "").strip().splitlines()[-12:]
        detail = "\n".join([*stdout_tail, *stderr_tail]).strip()
        if detail:
            raise RuntimeError(f"Remote external run failed for {suite}/{case_id}:\n{detail}") from exc
        raise
    remote_run_dir = Path(result.stdout.strip().splitlines()[-1])
    try:
        rel = remote_run_dir.relative_to(remote_output_dir)
    except ValueError:
        rel = Path(remote_run_dir.name)
    local_run_dir = output_dir / rel
    local_run_dir.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["scp", "-o", "ConnectTimeout=10", "-r", f"{baseline_host}:{remote_run_dir}", str(local_run_dir.parent)],
        check=True,
    )
    return local_run_dir


def _job_id(suite: str) -> str:
    return f"{suite}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"


def load_cases_from_file(path: Path) -> list[str]:
    """Read case ids from a newline-delimited file.

    Empty lines and comments beginning with `#` are ignored. Inline comments are
    also supported so small run lists can document why a case was selected.
    """
    cases: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line:
            cases.append(line)
    return cases


def merge_case_args(cases: list[str] | None, cases_file: Path | None) -> list[str]:
    merged = list(cases or [])
    if cases_file:
        merged.extend(load_cases_from_file(cases_file))
    seen: set[str] = set()
    deduped: list[str] = []
    for case_id in merged:
        if case_id not in seen:
            seen.add(case_id)
            deduped.append(case_id)
    if not deduped:
        raise ValueError("Provide cases via --case (repeatable) or --cases-file.")
    return deduped


def _remote_write_file_script(path: Path, content: str) -> str:
    return (
        f"mkdir -p {shlex.quote(str(path.parent))}\n"
        f"cat > {shlex.quote(str(path))} <<'NATO_EXTERNAL_JOB_EOF'\n"
        f"{content}\n"
        "NATO_EXTERNAL_JOB_EOF\n"
    )


def build_detached_job_payload(
    *,
    job_id: str,
    suite: str,
    repo: Path,
    cases: list[str],
    agent_command: str,
    project_dir: Path = DEFAULT_REMOTE_PROJECT_DIR,
    remote_output_dir: Path = DEFAULT_REMOTE_OUTPUT_DIR,
    remote_job_dir: Path = DEFAULT_REMOTE_JOB_DIR,
    timeout_seconds: int = 3600,
    dry_run: bool = False,
    keep_running: bool = False,
    context_mode: str = "informed",
    docker_cleanup: bool = True,
    min_free_gb: float = DEFAULT_DOCKER_MIN_FREE_GB,
    rate_limit_breaker_enabled: bool = True,
    rate_limit_breaker_threshold: int = 3,
) -> dict[str, Any]:
    job_dir = remote_job_dir / job_id
    return {
        "job_id": job_id,
        "session": f"nato-ext-{job_id}",
        "status": "pending",
        "context_policy": "fair_network_only",
        "context_mode": context_mode,
        "oracle_repo_context_injected": False,
        "suite": suite,
        "repo": str(repo),
        "cases": cases,
        "agent_command": agent_command,
        "project_dir": str(project_dir),
        "remote_output_dir": str(remote_output_dir),
        "job_dir": str(job_dir),
        "job_log": str(job_dir / "job.log"),
        "status_file": str(job_dir / "status.json"),
        "summary_file": str(job_dir / "summary.json"),
        "timeout_seconds": timeout_seconds,
        "dry_run": dry_run,
        "keep_running": keep_running,
        "docker_cleanup": docker_cleanup,
        "min_free_gb": min_free_gb,
        "rate_limit_breaker": {
            "enabled": rate_limit_breaker_enabled,
            "threshold": rate_limit_breaker_threshold,
        },
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }


def build_detached_job_runner() -> str:
    return r'''#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


job_path = Path(__file__).with_name("job.json")
job = json.loads(job_path.read_text(encoding="utf-8"))
job_dir = Path(job["job_dir"])
status_file = Path(job["status_file"])
summary_file = Path(job["summary_file"])
project_dir = Path(job["project_dir"])
sys.path.insert(0, str(project_dir))

from src.baselines.external_benchmarks import summarize_run_dir


def write_status(status: str, **extra: object) -> None:
    payload = {
        "job_id": job["job_id"],
        "session": job["session"],
        "status": status,
        "updated_at": datetime.now().isoformat(timespec="seconds"),
        **extra,
    }
    status_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


_RATE_LIMIT_MARKERS = ("rate_limit_error", "Too Many Requests", "usage limit exceeded", "429")


def _detect_rate_limit(run_dir: str, stdout_text: str) -> bool:
    if stdout_text and any(m in stdout_text for m in _RATE_LIMIT_MARKERS):
        return True
    if not run_dir:
        return False
    err_file = Path(run_dir) / "agent_stderr.txt"
    if not err_file.exists():
        return False
    try:
        with err_file.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 8192))
            tail = f.read().decode("utf-8", errors="replace")
    except Exception:
        return False
    return any(m in tail for m in _RATE_LIMIT_MARKERS)


def main() -> int:
    cases = list(job["cases"])
    summary: list[dict[str, object]] = []
    totals: Counter[str] = Counter()
    outcome_totals: Counter[str] = Counter()
    cost_total = 0.0
    token_total = 0
    breaker_cfg = job.get("rate_limit_breaker") or {}
    breaker_enabled = bool(breaker_cfg.get("enabled", True))
    breaker_threshold = int(breaker_cfg.get("threshold", 3))
    consecutive_rl_failures = 0
    breaker_tripped = False
    write_status("running", total=len(cases), completed=0, current_case=None)
    print(f"[job] started {job['job_id']} with {len(cases)} case(s)", flush=True)
    for index, case_id in enumerate(cases, start=1):
        if breaker_tripped:
            item = {
                "case_id": case_id,
                "status": "skipped_rate_limited",
                "outcome": "skipped_rate_limited",
                "returncode": None,
                "run_dir": "",
                "useful": False,
                "estimated_cost_usd": 0.0,
                "total_tokens": 0,
            }
            print(f"[job] {index}/{len(cases)} SKIPPED {job['suite']}/{case_id} (rate limit breaker tripped)", flush=True)
            summary.append(item)
            totals["skipped_rate_limited"] += 1
            outcome_totals["skipped_rate_limited"] += 1
            rollup = {
                "job_id": job["job_id"],
                "items": summary,
                "status_counts": dict(totals),
                "outcome_counts": dict(outcome_totals),
                "useful_findings": sum(1 for entry in summary if entry.get("useful")),
                "estimated_cost_usd": round(cost_total, 6),
                "total_tokens": token_total,
                "rate_limit_breaker_tripped": True,
            }
            summary_file.write_text(json.dumps(rollup, indent=2, ensure_ascii=False), encoding="utf-8")
            write_status("running", total=len(cases), completed=index, current_case=case_id, rate_limit_breaker_tripped=True, **{k: rollup[k] for k in ("status_counts", "outcome_counts", "useful_findings", "estimated_cost_usd", "total_tokens")})
            continue
        write_status("running", total=len(cases), completed=index - 1, current_case=case_id)
        cmd = [
            "python",
            "-m",
            "src.baselines.external_benchmarks",
            "run",
            "--suite",
            job["suite"],
            "--repo",
            job["repo"],
            "--case",
            case_id,
            "--agent-command",
            job["agent_command"],
            "--output-dir",
            job["remote_output_dir"],
            "--timeout",
            str(job["timeout_seconds"]),
        ]
        if job.get("dry_run"):
            cmd.append("--dry-run")
        if job.get("keep_running"):
            cmd.append("--keep-running")
        if job.get("docker_cleanup", True):
            cmd.append("--docker-cleanup")
            cmd.extend(["--min-free-gb", str(job.get("min_free_gb", 15.0))])
        else:
            cmd.append("--no-docker-cleanup")
        print(f"[job] {index}/{len(cases)} running {job['suite']}/{case_id}", flush=True)
        try:
            result = subprocess.run(
                cmd,
                cwd=job["project_dir"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=int(job["timeout_seconds"]) + 120,
            )
            if result.stdout:
                print(result.stdout, end="" if result.stdout.endswith("\n") else "\n", flush=True)
            run_dir = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
            run_summary = summarize_run_dir(Path(run_dir)) if run_dir else {}
            item = {
                "case_id": case_id,
                "status": run_summary.get("status") or ("command_ok" if result.returncode == 0 else "command_failed"),
                "outcome": run_summary.get("outcome"),
                "returncode": result.returncode,
                "run_dir": run_dir,
                "useful": run_summary.get("outcome") in {"confirmed_exploit", "probable_vulnerability", "blocked_missing_tool", "blocked_missing_credentials"},
                "estimated_cost_usd": run_summary.get("estimated_cost_usd", 0.0),
                "total_tokens": run_summary.get("total_tokens", 0),
            }
            item_stdout = result.stdout or ""
        except Exception as exc:
            print(f"[job] {case_id} failed: {exc}", flush=True)
            item = {"case_id": case_id, "status": "failed", "error": str(exc)}
            item_stdout = str(exc)
        summary.append(item)
        totals[str(item.get("status") or "unknown")] += 1
        if item.get("outcome"):
            outcome_totals[str(item["outcome"])] += 1
        cost_total += float(item.get("estimated_cost_usd") or 0.0)
        token_total += int(item.get("total_tokens") or 0)
        status_str = str(item.get("status") or "")
        tokens_int = int(item.get("total_tokens") or 0)
        looks_like_rate_limit = (
            status_str in {"agent_failed", "command_failed", "failed"}
            and tokens_int == 0
            and _detect_rate_limit(str(item.get("run_dir") or ""), item_stdout)
        )
        if looks_like_rate_limit:
            consecutive_rl_failures += 1
            item["rate_limited"] = True
            print(f"[job] rate-limit signature detected ({consecutive_rl_failures}/{breaker_threshold})", flush=True)
        else:
            consecutive_rl_failures = 0
        if breaker_enabled and consecutive_rl_failures >= breaker_threshold:
            breaker_tripped = True
            print(f"[job] rate-limit circuit breaker TRIPPED after {consecutive_rl_failures} consecutive failures — skipping remaining cases", flush=True)
        rollup = {
            "job_id": job["job_id"],
            "items": summary,
            "status_counts": dict(totals),
            "outcome_counts": dict(outcome_totals),
            "useful_findings": sum(1 for entry in summary if entry.get("useful")),
            "estimated_cost_usd": round(cost_total, 6),
            "total_tokens": token_total,
            "rate_limit_breaker_tripped": breaker_tripped,
        }
        summary_file.write_text(json.dumps(rollup, indent=2, ensure_ascii=False), encoding="utf-8")
        write_status("running", total=len(cases), completed=index, current_case=case_id, rate_limit_breaker_tripped=breaker_tripped, **{k: rollup[k] for k in ("status_counts", "outcome_counts", "useful_findings", "estimated_cost_usd", "total_tokens")})
    failed = sum(1 for item in summary if item.get("status") in {"failed", "agent_failed", "environment_failed", "command_failed", "skipped_rate_limited"})
    final_status = "completed" if failed == 0 else "failed"
    write_status(final_status, total=len(cases), completed=len(cases), failed=failed, current_case=None, status_counts=dict(totals), outcome_counts=dict(outcome_totals), useful_findings=sum(1 for entry in summary if entry.get("useful")), estimated_cost_usd=round(cost_total, 6), total_tokens=token_total, rate_limit_breaker_tripped=breaker_tripped)
    print(f"[job] {final_status} failed={failed} useful={sum(1 for entry in summary if entry.get('useful'))} cost=${cost_total:.6f} tokens={token_total} breaker_tripped={breaker_tripped}", flush=True)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


def build_detached_shell_runner(job: dict[str, Any]) -> str:
    project_dir = shlex.quote(str(job["project_dir"]))
    runner = shlex.quote(str(Path(job["job_dir"]) / "runner.py"))
    status_file = shlex.quote(str(job["status_file"]))
    return f"""#!/usr/bin/env bash
set -u
cd {project_dir}
. venv/bin/activate
set -a
[ -f /opt/baseline-tools/.env ] && . /opt/baseline-tools/.env
set +a
python {runner}
rc=$?
if [ "$rc" -ne 0 ]; then
  python - <<'PY'
import json
from datetime import datetime
from pathlib import Path
path = Path({status_file!r})
data = json.loads(path.read_text()) if path.exists() else {{}}
if data.get("status") == "running":
    data["status"] = "failed"
    data["updated_at"] = datetime.now().isoformat(timespec="seconds")
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
PY
fi
exit "$rc"
"""


def start_detached_job(
    *,
    baseline_host: str,
    suite: str,
    cases: list[str],
    repo: Path | None = None,
    agent_command: str | None = None,
    project_dir: Path = DEFAULT_REMOTE_PROJECT_DIR,
    remote_output_dir: Path = DEFAULT_REMOTE_OUTPUT_DIR,
    remote_job_dir: Path = DEFAULT_REMOTE_JOB_DIR,
    timeout_seconds: int = 3600,
    dry_run: bool = False,
    keep_running: bool = False,
    sync_project: bool = True,
    model: str = "MiniMax-M2.7",
    max_turns: int = 40,
    context_mode: str = "informed",
    docker_cleanup: bool = True,
    min_free_gb: float = DEFAULT_DOCKER_MIN_FREE_GB,
    rate_limit_breaker_enabled: bool = True,
    rate_limit_breaker_threshold: int = 3,
) -> dict[str, Any]:
    repo_path = prepare_remote_external_environment(
        baseline_host=baseline_host,
        suite=suite,
        repo=repo,
        project_dir=project_dir,
        sync_project=sync_project,
        install_deps=True,
    )
    ensure_remote_tmux(baseline_host)
    job_id = _job_id(suite)
    command = agent_command or external_agent_command(model=model, max_turns=max_turns, context_mode=context_mode)
    job = build_detached_job_payload(
        job_id=job_id,
        suite=suite,
        repo=repo_path,
        cases=cases,
        agent_command=command,
        project_dir=project_dir,
        remote_output_dir=remote_output_dir,
        remote_job_dir=remote_job_dir,
        timeout_seconds=timeout_seconds,
        dry_run=dry_run,
        keep_running=keep_running,
        context_mode=context_mode,
        docker_cleanup=docker_cleanup,
        min_free_gb=min_free_gb,
        rate_limit_breaker_enabled=rate_limit_breaker_enabled,
        rate_limit_breaker_threshold=rate_limit_breaker_threshold,
    )
    job_dir = Path(job["job_dir"])
    job_json = json.dumps(job, indent=2, ensure_ascii=False)
    runner_py = build_detached_job_runner()
    runner_sh = build_detached_shell_runner(job)
    script = f"""
set -euo pipefail
mkdir -p {shlex.quote(str(job_dir))}
{_remote_write_file_script(job_dir / "job.json", job_json)}
{_remote_write_file_script(job_dir / "runner.py", runner_py)}
{_remote_write_file_script(job_dir / "runner.sh", runner_sh)}
chmod +x {shlex.quote(str(job_dir / "runner.py"))} {shlex.quote(str(job_dir / "runner.sh"))}
cp {shlex.quote(str(job_dir / "job.json"))} {shlex.quote(str(job_dir / "status.json"))}
tmux new-session -d -s {shlex.quote(job["session"])} "bash {shlex.quote(str(job_dir / "runner.sh"))} >> {shlex.quote(str(job_dir / "job.log"))} 2>&1"
"""
    _ssh_run(baseline_host, script)
    return job


def prune_remote_docker(baseline_host: str) -> str:
    script = """
set -euo pipefail
docker container prune -f || true
docker image prune -a -f || true
docker builder prune -a -f || true
docker volume prune -f || true
docker system df || true
df -h / /var/lib/docker /opt 2>/dev/null || df -h
"""
    result = _ssh_run(baseline_host, script, capture_output=True, check=False)
    return (result.stdout or "") + (result.stderr or "")


def _failure_statuses_for_resume() -> set[str]:
    return {"failed", "agent_failed", "environment_failed", "command_failed", "skipped_rate_limited"}


def resume_detached_job(
    *,
    baseline_host: str,
    job_id: str,
    remote_job_dir: Path = DEFAULT_REMOTE_JOB_DIR,
    sync_project: bool = True,
    include_failed: bool = True,
) -> dict[str, Any]:
    script = f"""
set -euo pipefail
cat {shlex.quote(str(remote_job_dir / job_id / "job.json"))}
printf '\\n---SUMMARY---\\n'
cat {shlex.quote(str(remote_job_dir / job_id / "summary.json"))} 2>/dev/null || true
"""
    result = _ssh_run(baseline_host, script, capture_output=True)
    job_raw, _, summary_raw = result.stdout.partition("\n---SUMMARY---\n")
    previous_job = json.loads(job_raw)
    summary_data = json.loads(summary_raw) if summary_raw.strip() else {"items": []}
    items = summary_data.get("items", summary_data) if isinstance(summary_data, dict) else summary_data
    bad_statuses = _failure_statuses_for_resume()
    done_cases = {
        str(item.get("case_id"))
        for item in items
        if item.get("case_id") and (include_failed is False or str(item.get("status")) not in bad_statuses)
    }
    if include_failed:
        done_cases = {
            str(item.get("case_id"))
            for item in items
            if item.get("case_id") and str(item.get("status")) not in bad_statuses
        }
    remaining = [case for case in previous_job.get("cases", []) if case not in done_cases]
    if not remaining:
        return {
            "job_id": job_id,
            "status": "nothing_to_resume",
            "remaining_cases": [],
            "completed_or_kept": len(done_cases),
        }
    return start_detached_job(
        baseline_host=baseline_host,
        suite=previous_job["suite"],
        cases=remaining,
        repo=Path(previous_job["repo"]),
        agent_command=previous_job.get("agent_command"),
        project_dir=Path(previous_job.get("project_dir", DEFAULT_REMOTE_PROJECT_DIR)),
        remote_output_dir=Path(previous_job.get("remote_output_dir", DEFAULT_REMOTE_OUTPUT_DIR)),
        remote_job_dir=remote_job_dir,
        timeout_seconds=int(previous_job.get("timeout_seconds", 3600)),
        dry_run=bool(previous_job.get("dry_run", False)),
        keep_running=bool(previous_job.get("keep_running", False)),
        sync_project=sync_project,
        context_mode=str(previous_job.get("context_mode", "informed")),
        docker_cleanup=bool(previous_job.get("docker_cleanup", True)),
        min_free_gb=float(previous_job.get("min_free_gb", DEFAULT_DOCKER_MIN_FREE_GB)),
        rate_limit_breaker_enabled=bool((previous_job.get("rate_limit_breaker") or {}).get("enabled", True)),
        rate_limit_breaker_threshold=int((previous_job.get("rate_limit_breaker") or {}).get("threshold", 3)),
    )


def list_detached_jobs(
    baseline_host: str,
    remote_job_dir: Path = DEFAULT_REMOTE_JOB_DIR,
) -> list[dict[str, Any]]:
    script = f"""
set -euo pipefail
python3 - <<'PY'
import glob, json
for path in sorted(glob.glob({str(remote_job_dir / "*" / "status.json")!r})):
    try:
        with open(path, encoding="utf-8") as fh:
            print(json.dumps(json.load(fh), ensure_ascii=False))
    except Exception:
        pass
PY
"""
    result = _ssh_run(baseline_host, script, capture_output=True, check=False)
    jobs = []
    for chunk in result.stdout.splitlines():
        if not chunk.strip():
            continue
        try:
            jobs.append(json.loads(chunk))
        except json.JSONDecodeError:
            continue
    return jobs


def detached_job_status(
    baseline_host: str,
    job_id: str,
    remote_job_dir: Path = DEFAULT_REMOTE_JOB_DIR,
) -> dict[str, Any]:
    path = remote_job_dir / job_id / "status.json"
    result = _ssh_run(baseline_host, f"cat {shlex.quote(str(path))}", capture_output=True)
    return json.loads(result.stdout)


def detached_job_logs(
    baseline_host: str,
    job_id: str,
    tail: int = 100,
    remote_job_dir: Path = DEFAULT_REMOTE_JOB_DIR,
) -> str:
    path = remote_job_dir / job_id / "job.log"
    result = _ssh_run(
        baseline_host,
        f"tail -n {int(tail)} {shlex.quote(str(path))}",
        capture_output=True,
        check=False,
    )
    return result.stdout


def stop_detached_job(
    baseline_host: str,
    job_id: str,
    remote_job_dir: Path = DEFAULT_REMOTE_JOB_DIR,
) -> None:
    session = f"nato-ext-{job_id}"
    status_path = remote_job_dir / job_id / "status.json"
    script = f"""
set -euo pipefail
tmux kill-session -t {shlex.quote(session)} 2>/dev/null || true
python3 - <<'PY'
import json
from datetime import datetime
from pathlib import Path
path = Path({str(status_path)!r})
data = json.loads(path.read_text()) if path.exists() else {{"job_id": {job_id!r}}}
data["status"] = "stopped"
data["updated_at"] = datetime.now().isoformat(timespec="seconds")
path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
PY
"""
    _ssh_run(baseline_host, script)


def attach_detached_job(baseline_host: str, job_id: str) -> None:
    subprocess.run(["ssh", "-t", baseline_host, "tmux", "attach", "-t", f"nato-ext-{job_id}"], check=True)


def _safe_host_dir(baseline_host: str) -> str:
    """Sanitize an SSH target (e.g. `root@192.168.88.184`) into a path component."""
    return re.sub(r"[^A-Za-z0-9.-]+", "_", baseline_host).strip("_") or "host"


def fetch_detached_job(
    baseline_host: str,
    job_id: str,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    remote_job_dir: Path = DEFAULT_REMOTE_JOB_DIR,
    remote_output_dir: Path = DEFAULT_REMOTE_OUTPUT_DIR,
    host_subdir: bool = False,
) -> Path:
    local_jobs = output_dir / "jobs"
    if host_subdir:
        local_jobs = local_jobs / _safe_host_dir(baseline_host)
    local_jobs.mkdir(parents=True, exist_ok=True)
    local_job_dir = local_jobs / job_id
    if local_job_dir.exists():
        shutil.rmtree(local_job_dir)
    remote_job = remote_job_dir / job_id
    subprocess.run(
        ["scp", "-o", "ConnectTimeout=10", "-r", f"{baseline_host}:{remote_job}", str(local_jobs)],
        check=True,
    )
    summary_path = local_jobs / job_id / "summary.json"
    if summary_path.exists():
        summary_data = json.loads(summary_path.read_text(encoding="utf-8"))
        items = summary_data.get("items", summary_data) if isinstance(summary_data, dict) else summary_data
        for item in items:
            run_dir = item.get("run_dir")
            if not run_dir:
                continue
            remote_run = Path(str(run_dir))
            try:
                rel = remote_run.relative_to(remote_output_dir)
            except ValueError:
                continue
            if host_subdir:
                local_parent = output_dir / "results_by_host" / _safe_host_dir(baseline_host) / rel.parent
            else:
                local_parent = output_dir / rel.parent
            local_parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["scp", "-o", "ConnectTimeout=10", "-r", f"{baseline_host}:{remote_run}", str(local_parent)],
                check=False,
            )
    fetch_manifest = {
        "job_id": job_id,
        "fetched_at": datetime.now().isoformat(timespec="seconds"),
        "remote_host": baseline_host,
        "remote_job_dir": str(remote_job),
        "remote_output_dir": str(remote_output_dir),
        "local_job_dir": str(local_job_dir),
        "local_results_root": str(output_dir),
        "host_subdir": host_subdir,
        "layout": {
            "job_metadata": str(local_job_dir),
            "run_results": str(output_dir / "<suite>/<case_id>/<timestamp>"),
        },
    }
    _write_json(local_job_dir / "fetch_manifest.json", fetch_manifest)
    if not host_subdir:
        organize_fetched_job(job_id, output_dir=output_dir)
    return local_job_dir


def _safe_batch_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "__", value.strip("/"))
    return cleaned[:180] or "case"


def organize_fetched_job(job_id: str, output_dir: Path = DEFAULT_OUTPUT_DIR, move: bool = False) -> Path:
    local_job_dir = output_dir / "jobs" / job_id
    summary_path = local_job_dir / "summary.json"
    if not summary_path.exists():
        raise FileNotFoundError(f"No fetched summary found for {job_id}: {summary_path}")
    batch_dir = output_dir / "batches" / job_id
    runs_dir = batch_dir / "runs"
    batch_dir.mkdir(parents=True, exist_ok=True)
    runs_dir.mkdir(parents=True, exist_ok=True)

    for name in ("job.json", "status.json", "summary.json", "fetch_manifest.json"):
        source = local_job_dir / name
        if source.exists():
            shutil.copy2(source, batch_dir / name)

    summary_data = json.loads(summary_path.read_text(encoding="utf-8"))
    items = summary_data.get("items", summary_data) if isinstance(summary_data, dict) else summary_data
    manifest_items = []
    for index, item in enumerate(items, start=1):
        run_dir_value = item.get("run_dir") if isinstance(item, dict) else None
        if not run_dir_value:
            continue
        remote_run = Path(str(run_dir_value))
        try:
            rel = remote_run.relative_to(DEFAULT_REMOTE_OUTPUT_DIR)
        except ValueError:
            rel = Path(str(run_dir_value).lstrip("/"))
        local_run = output_dir / rel
        if not local_run.exists():
            manifest_items.append({"case_id": item.get("case_id"), "status": "missing_local_copy", "source": str(local_run)})
            continue
        target = runs_dir / f"{index:03d}_{_safe_batch_name(str(item.get('case_id') or rel.parent))}_{local_run.name}"
        if target.exists():
            shutil.rmtree(target)
        if move:
            shutil.move(str(local_run), str(target))
        else:
            shutil.copytree(local_run, target)
        manifest_items.append(
            {
                "case_id": item.get("case_id"),
                "status": item.get("status"),
                "outcome": item.get("outcome"),
                "source": str(local_run),
                "batch_path": str(target),
            }
        )

    _write_json(
        batch_dir / "batch_manifest.json",
        {
            "job_id": job_id,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "mode": "move" if move else "copy",
            "source_job_dir": str(local_job_dir),
            "runs_dir": str(runs_dir),
            "items": manifest_items,
        },
    )
    return batch_dir


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
    docker_cleanup: bool = False,
    min_free_gb: float = DEFAULT_DOCKER_MIN_FREE_GB,
) -> Path:
    case = _select_case(suite, repo, case_id)
    if not case.runnable:
        raise ValueError(f"{case.case_id} is not runnable by this harness: {case.notes}")

    preflight_cleanup: dict[str, Any] | None = None
    if docker_cleanup:
        preflight_cleanup = _maybe_docker_prune(output_dir, min_free_gb)
    flag_value = flag or case.expected_flag
    if not flag_value and case.suite == "xbow":
        flag_value = f"FLAG-{case.suite}-{case.case_id}-{int(time.time())}"
    run_dir = output_dir / case.suite / case.case_id / datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)

    # AutoPenBench: run a generated single-service compose on a safe subnet
    # instead of the upstream multi-VM / 192.168.0.0/16 file.
    active_compose = case.compose_file
    compose_cwd = case.path
    if case.suite == "autopenbench":
        active_compose = _autopenbench_standalone_compose(case, run_dir)
        compose_cwd = run_dir
    # The generated autopenbench compose only holds the target + its deps, so
    # an unscoped `up` brings up exactly what the case needs.
    up_args = ["up", "-d", "--wait"]

    command = _render_agent_command(agent_command, case, run_dir, flag_value)
    context_mode = infer_context_mode_from_command(agent_command)
    planned = {
        "case": case.to_dict(),
        "context_policy": "fair_network_only",
        "context_mode": context_mode,
        "agent_context_inputs": {
            "target": case.target_url or case.target_endpoint or case.target,
            "case_id": case.case_id if context_mode != "blind" else "",
            "vulnerability": case.vulnerability if context_mode != "blind" else "",
            "service_context": case.service_context,
            "flag_provided": bool(flag_value),
            "oracle_repo_context_injected": False,
        },
        "flag": flag_value,
        "agent_command": command,
        "build_command": _build_command(case, flag_value, compose_file=active_compose),
        "up_command": _compose_command(case, *up_args, compose_file=active_compose),
        "down_command": _compose_command(case, "down", "-v", compose_file=active_compose),
        "compose_file": str(active_compose) if active_compose else None,
        "dry_run": dry_run,
        "docker_cleanup": {
            "enabled": docker_cleanup,
            "min_free_gb": min_free_gb,
            "preflight": preflight_cleanup,
        },
    }
    (run_dir / "planned.json").write_text(json.dumps(planned, indent=2, ensure_ascii=False), encoding="utf-8")
    if dry_run:
        result_payload = {"status": "dry_run", "success": False, **planned}
        _write_json(run_dir / "result.json", result_payload)
        write_run_proof(run_dir, result_payload)
        return run_dir

    started = datetime.now()
    stdout = ""
    stderr = ""
    returncode = 0
    status = "completed"
    should_run_agent = True
    try:
        if case.suite == "autopenbench":
            # The per-run `down -v` only knows this run's compose project; a
            # crashed prior run could leave the fixed-name container or a
            # dangling network behind.
            subprocess.run(
                ["docker", "rm", "-f", f"nato-apb-{case.case_id}"],
                text=True, capture_output=True, check=False,
            )
            _cleanup_autopenbench_networks()
        subprocess.run(planned["down_command"], cwd=compose_cwd, text=True, capture_output=True, check=False)
        if planned["build_command"]:
            build = subprocess.run(planned["build_command"], cwd=compose_cwd, text=True, capture_output=True)
            if build.returncode != 0:
                status = "environment_failed"
                returncode = build.returncode
                stdout = build.stdout
                stderr = build.stderr
                should_run_agent = False
        if should_run_agent:
            up = subprocess.run(planned["up_command"], cwd=compose_cwd, text=True, capture_output=True)
            if up.returncode != 0:
                # `up --wait` fails if ANY container is unhealthy/exited, even
                # an auxiliary one (scheduler, worker). For a security
                # benchmark we only need the target service reachable, so
                # salvage the run when at least one container is still up.
                running = _compose_running_count(case, compose_file=active_compose, cwd=compose_cwd)
                if running > 0:
                    planned["environment_degraded"] = {
                        "up_returncode": up.returncode,
                        "running_containers": running,
                    }
                    stdout = up.stdout
                    stderr = (
                        f"{up.stderr}\n\n[env degraded] up --wait rc={up.returncode} "
                        f"but {running} container(s) running — proceeding with agent"
                    ).strip()
                else:
                    status = "environment_failed"
                    returncode = up.returncode
                    stdout = up.stdout
                    stderr = up.stderr
                    should_run_agent = False
        if should_run_agent and case.suite == "autopenbench":
            # The target IP only exists once the container is up. Resolve it
            # and re-render the agent command so the agent gets a reachable
            # address instead of the bare service name.
            target_ip = _container_ip(f"nato-apb-{case.case_id}")
            if not target_ip:
                status = "environment_failed"
                stderr = f"{stderr}\n\n[autopenbench] could not resolve target container IP".strip()
                should_run_agent = False
            else:
                planned["target_ip"] = target_ip
                planned["agent_context_inputs"]["target"] = target_ip
                command = _render_agent_command(
                    agent_command, case, run_dir, flag_value, target_override=target_ip
                )
                planned["agent_command"] = command
        if should_run_agent:
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
            if returncode != 0:
                status = "agent_failed"
    finally:
        if not keep_running:
            down = subprocess.run(planned["down_command"], cwd=compose_cwd, text=True, capture_output=True, check=False)
            if down.stderr:
                stderr = f"{stderr}\n\n[compose down stderr]\n{down.stderr}".strip()
            if docker_cleanup:
                planned["docker_cleanup"]["post_case"] = _docker_prune()
                planned["docker_cleanup"]["free_after_gb"] = round(_free_gb(output_dir), 3)

    (run_dir / "agent_stdout.txt").write_text(stdout, encoding="utf-8")
    (run_dir / "agent_stderr.txt").write_text(stderr, encoding="utf-8")
    success = bool(flag_value) and (flag_value in stdout or flag_value in stderr)
    finished = datetime.now()
    result_payload = {
        "status": status,
        "success": success,
        "returncode": returncode,
        "started_at": started.isoformat(timespec="seconds"),
        "finished_at": finished.isoformat(timespec="seconds"),
        "duration_seconds": round((finished - started).total_seconds(), 3),
        **planned,
    }
    _write_json(run_dir / "result.json", result_payload)
    write_run_proof(run_dir, result_payload)
    return run_dir


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run our agent against third-party pentest benchmarks")
    sub = parser.add_subparsers(dest="command", required=True)

    list_parser = sub.add_parser("list", help="List benchmark cases from a local upstream repo")
    list_parser.add_argument("--suite", required=True, choices=SUPPORTED_SUITES)
    list_parser.add_argument("--repo", required=True, type=Path)
    list_parser.add_argument("--remote-host", default=None, help="Run discovery on the baseline VM over SSH")
    list_parser.add_argument("--no-sync", action="store_true", help="Do not sync the local project before remote execution")
    list_parser.add_argument("--json", action="store_true")

    manifest_parser = sub.add_parser("manifest", help="Write a JSON manifest for a benchmark repo")
    manifest_parser.add_argument("--suite", required=True, choices=SUPPORTED_SUITES)
    manifest_parser.add_argument("--repo", required=True, type=Path)
    manifest_parser.add_argument("--output", required=True, type=Path)

    run_parser = sub.add_parser("run", help="Run one external benchmark case")
    run_parser.add_argument("--suite", required=True, choices=SUPPORTED_SUITES)
    run_parser.add_argument("--repo", required=True, type=Path)
    run_parser.add_argument("--case", required=True)
    run_parser.add_argument("--agent-command", default=None)
    run_parser.add_argument("--baseline-tool", choices=BASELINE_TOOLS, default=None)
    run_parser.add_argument("--baseline-model", default="openai/MiniMax-M2.7")
    run_parser.add_argument("--baseline-max-turns", default=40, type=int)
    run_parser.add_argument("--baseline-adapter-dir", default="/opt/baseline-tools/adapters")
    run_parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, type=Path)
    run_parser.add_argument("--remote-host", default=None, help="Run Docker and the agent on the baseline VM over SSH")
    run_parser.add_argument("--remote-output-dir", default=DEFAULT_REMOTE_OUTPUT_DIR, type=Path)
    run_parser.add_argument("--no-sync", action="store_true", help="Do not sync the local project before remote execution")
    run_parser.add_argument("--flag", default=None)
    run_parser.add_argument("--timeout", default=1800, type=int)
    run_parser.add_argument("--dry-run", action="store_true")
    run_parser.add_argument("--keep-running", action="store_true")
    run_parser.add_argument("--docker-cleanup", dest="docker_cleanup", action="store_true", default=False)
    run_parser.add_argument("--no-docker-cleanup", dest="docker_cleanup", action="store_false")
    run_parser.add_argument("--min-free-gb", default=DEFAULT_DOCKER_MIN_FREE_GB, type=float)

    detached_parser = sub.add_parser("start-detached", help="Start a long-running external benchmark job on the baseline VM")
    detached_parser.add_argument("--suite", required=True, choices=SUPPORTED_SUITES)
    detached_parser.add_argument("--repo", required=True, type=Path)
    detached_parser.add_argument("--case", action="append", dest="cases", default=[])
    detached_parser.add_argument("--cases-file", type=Path, default=None)
    detached_parser.add_argument("--remote-host", required=True)
    detached_parser.add_argument("--agent-command", default=None)
    detached_parser.add_argument("--baseline-tool", choices=BASELINE_TOOLS, default=None)
    detached_parser.add_argument("--baseline-model", default="openai/MiniMax-M2.7")
    detached_parser.add_argument("--baseline-max-turns", default=40, type=int)
    detached_parser.add_argument("--baseline-adapter-dir", default="/opt/baseline-tools/adapters")
    detached_parser.add_argument("--remote-output-dir", default=DEFAULT_REMOTE_OUTPUT_DIR, type=Path)
    detached_parser.add_argument("--remote-job-dir", default=DEFAULT_REMOTE_JOB_DIR, type=Path)
    detached_parser.add_argument("--timeout", default=3600, type=int)
    detached_parser.add_argument("--model", default="MiniMax-M2.7")
    detached_parser.add_argument("--max-turns", default=40, type=int)
    detached_parser.add_argument("--context-mode", default="informed", choices=CONTEXT_MODES)
    detached_parser.add_argument("--dry-run", action="store_true")
    detached_parser.add_argument("--keep-running", action="store_true")
    detached_parser.add_argument("--docker-cleanup", dest="docker_cleanup", action="store_true", default=True)
    detached_parser.add_argument("--no-docker-cleanup", dest="docker_cleanup", action="store_false")
    detached_parser.add_argument("--min-free-gb", default=DEFAULT_DOCKER_MIN_FREE_GB, type=float)
    detached_parser.add_argument("--no-sync", action="store_true")
    detached_parser.add_argument("--rate-limit-breaker", dest="rate_limit_breaker_enabled", action="store_true", default=True, help="Stop the batch after N consecutive rate-limited failures (default: enabled)")
    detached_parser.add_argument("--no-rate-limit-breaker", dest="rate_limit_breaker_enabled", action="store_false")
    detached_parser.add_argument("--rate-limit-breaker-threshold", default=3, type=int, help="Number of consecutive rate-limited failures before tripping the breaker (default: 3)")

    resume_parser = sub.add_parser("resume-detached", help="Start a new detached job for cases missing from a previous job")
    resume_parser.add_argument("--remote-host", required=True)
    resume_parser.add_argument("--job-id", required=True)
    resume_parser.add_argument("--remote-job-dir", default=DEFAULT_REMOTE_JOB_DIR, type=Path)
    resume_parser.add_argument("--no-sync", action="store_true")

    prune_parser = sub.add_parser("docker-prune", help="Prune unused Docker data on the baseline VM")
    prune_parser.add_argument("--remote-host", required=True)

    jobs_parser = sub.add_parser("jobs", help="List detached external jobs on the baseline VM")
    jobs_parser.add_argument("--remote-host", required=True)
    jobs_parser.add_argument("--remote-job-dir", default=DEFAULT_REMOTE_JOB_DIR, type=Path)

    status_parser = sub.add_parser("status", help="Show detached job status")
    status_parser.add_argument("--remote-host", required=True)
    status_parser.add_argument("--job-id", required=True)
    status_parser.add_argument("--remote-job-dir", default=DEFAULT_REMOTE_JOB_DIR, type=Path)

    logs_parser = sub.add_parser("logs", help="Show detached job logs")
    logs_parser.add_argument("--remote-host", required=True)
    logs_parser.add_argument("--job-id", required=True)
    logs_parser.add_argument("--tail", default=100, type=int)
    logs_parser.add_argument("--remote-job-dir", default=DEFAULT_REMOTE_JOB_DIR, type=Path)

    stop_parser = sub.add_parser("stop", help="Stop a detached job")
    stop_parser.add_argument("--remote-host", required=True)
    stop_parser.add_argument("--job-id", required=True)
    stop_parser.add_argument("--remote-job-dir", default=DEFAULT_REMOTE_JOB_DIR, type=Path)

    attach_parser = sub.add_parser("attach", help="Attach to a detached job tmux session")
    attach_parser.add_argument("--remote-host", required=True)
    attach_parser.add_argument("--job-id", required=True)

    fetch_parser = sub.add_parser("fetch", help="Fetch detached job metadata and run results")
    fetch_parser.add_argument("--remote-host", required=True)
    fetch_parser.add_argument("--job-id", required=True)
    fetch_parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, type=Path)
    fetch_parser.add_argument("--remote-job-dir", default=DEFAULT_REMOTE_JOB_DIR, type=Path)
    fetch_parser.add_argument("--remote-output-dir", default=DEFAULT_REMOTE_OUTPUT_DIR, type=Path)

    organize_parser = sub.add_parser("organize-job", help="Create a single local batch folder for a fetched detached job")
    organize_parser.add_argument("--job-id", required=True)
    organize_parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, type=Path)
    organize_parser.add_argument("--move", action="store_true", help="Move run folders instead of copying them")

    report_parser = sub.add_parser("report", help="Aggregate external benchmark results into JSON/Markdown")
    report_parser.add_argument("--root", default=DEFAULT_OUTPUT_DIR, type=Path)
    report_parser.add_argument("--output", default=None, type=Path)
    report_parser.add_argument("--markdown", default=None, type=Path)

    args = parser.parse_args(argv)
    if args.command == "list":
        if args.remote_host:
            cases = discover_remote_cases(
                baseline_host=args.remote_host,
                suite=args.suite,
                repo=args.repo,
                sync_project=not args.no_sync,
            )
        else:
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
        command = resolve_external_command(
            agent_command=args.agent_command,
            baseline_tool=args.baseline_tool,
            baseline_model=args.baseline_model,
            baseline_max_turns=args.baseline_max_turns,
            baseline_adapter_dir=args.baseline_adapter_dir,
        )
        if args.remote_host:
            run_dir = run_remote_case(
                baseline_host=args.remote_host,
                suite=args.suite,
                repo=args.repo,
                case_id=args.case,
                agent_command=command,
                output_dir=args.output_dir,
                remote_output_dir=args.remote_output_dir,
                flag=args.flag,
                dry_run=args.dry_run,
                keep_running=args.keep_running,
                timeout_seconds=args.timeout,
                sync_project=not args.no_sync,
                docker_cleanup=args.docker_cleanup,
                min_free_gb=args.min_free_gb,
            )
        else:
            run_dir = run_case(
                suite=args.suite,
                repo=args.repo,
                case_id=args.case,
                agent_command=command,
                output_dir=args.output_dir,
                flag=args.flag,
                dry_run=args.dry_run,
                keep_running=args.keep_running,
                timeout_seconds=args.timeout,
                docker_cleanup=args.docker_cleanup,
                min_free_gb=args.min_free_gb,
            )
        print(run_dir)
    elif args.command == "start-detached":
        command = resolve_external_command(
            agent_command=args.agent_command,
            baseline_tool=args.baseline_tool,
            baseline_model=args.baseline_model,
            baseline_max_turns=args.baseline_max_turns,
            baseline_adapter_dir=args.baseline_adapter_dir,
        ) if args.baseline_tool else args.agent_command
        job = start_detached_job(
            baseline_host=args.remote_host,
            suite=args.suite,
            cases=merge_case_args(args.cases, args.cases_file),
            repo=args.repo,
            agent_command=command,
            remote_output_dir=args.remote_output_dir,
            remote_job_dir=args.remote_job_dir,
            timeout_seconds=args.timeout,
            dry_run=args.dry_run,
            keep_running=args.keep_running,
            sync_project=not args.no_sync,
            model=args.model,
            max_turns=args.max_turns,
            context_mode=args.context_mode,
            docker_cleanup=args.docker_cleanup,
            min_free_gb=args.min_free_gb,
            rate_limit_breaker_enabled=args.rate_limit_breaker_enabled,
            rate_limit_breaker_threshold=args.rate_limit_breaker_threshold,
        )
        print(json.dumps(job, indent=2, ensure_ascii=False))
    elif args.command == "resume-detached":
        print(json.dumps(
            resume_detached_job(
                baseline_host=args.remote_host,
                job_id=args.job_id,
                remote_job_dir=args.remote_job_dir,
                sync_project=not args.no_sync,
            ),
            indent=2,
            ensure_ascii=False,
        ))
    elif args.command == "docker-prune":
        print(prune_remote_docker(args.remote_host))
    elif args.command == "jobs":
        print(json.dumps(list_detached_jobs(args.remote_host, args.remote_job_dir), indent=2, ensure_ascii=False))
    elif args.command == "status":
        print(json.dumps(detached_job_status(args.remote_host, args.job_id, args.remote_job_dir), indent=2, ensure_ascii=False))
    elif args.command == "logs":
        print(detached_job_logs(args.remote_host, args.job_id, args.tail, args.remote_job_dir), end="")
    elif args.command == "stop":
        stop_detached_job(args.remote_host, args.job_id, args.remote_job_dir)
        print(f"stopped {args.job_id}")
    elif args.command == "attach":
        attach_detached_job(args.remote_host, args.job_id)
    elif args.command == "fetch":
        print(fetch_detached_job(args.remote_host, args.job_id, args.output_dir, args.remote_job_dir, args.remote_output_dir))
    elif args.command == "organize-job":
        print(organize_fetched_job(args.job_id, args.output_dir, move=args.move))
    elif args.command == "report":
        print(json.dumps(generate_report(args.root, args.output, args.markdown), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
