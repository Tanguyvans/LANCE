"""Execute a real comparison harness once per complete scenario scope.

Adapters are intentionally thin. They may translate native traces, but they do
not invent proof: unsupported or missing native tool records remain unverified
under strict-v3.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from src.benchmark.evaluator import evaluate
from src.benchmark.metric_contract import metric_contract_metadata


ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ROOT / "benchmarks" / "scenarios"
GROUND_TRUTH = ROOT / "benchmarks" / "ground_truth"
COMMAND_ENV = {
    "cai": "CAI_BENCHMARK_COMMAND",
    "vulnbot": "VULNBOT_BENCHMARK_COMMAND",
}


def _git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
            capture_output=True, text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip() or None


def _scenario_footholds(scenario_id: str) -> list[dict[str, Any]]:
    path = SCENARIOS / f"S{scenario_id}.yaml"
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    credentials = data.get("initial_credentials") or []
    return [dict(item) for item in credentials if isinstance(item, dict)]


def _native_command(call: dict[str, Any]) -> str:
    args = call.get("args")
    if isinstance(args, dict):
        for key in ("command", "cmd", "input"):
            if isinstance(args.get(key), str):
                return args[key]
    for key in ("command", "cmd"):
        if isinstance(call.get(key), str):
            return call[key]
    return ""


def _canonical_tool(call: dict[str, Any]) -> str:
    declared = str(call.get("tool") or call.get("name") or "baseline_native_tool")
    normalized = declared.strip().lower().replace("-", "_").replace(" ", "_")
    known = {
        "nmap": "nmap_scan", "nmap_scan": "nmap_scan",
        "curl": "http_request", "http": "http_request", "http_request": "http_request",
        "ssh": "ssh_exec", "ssh_exec": "ssh_exec",
        "mysql": "mysql_query", "mysql_query": "mysql_query",
        "redis": "redis_cmd", "redis_cmd": "redis_cmd",
        "ftp": "ftp_list", "ftp_list": "ftp_list",
        "telnet": "telnet_connect", "telnet_connect": "telnet_connect",
    }
    if normalized in known:
        return known[normalized]
    command = _native_command(call).lstrip()
    executable = shlex.split(command)[0] if command else ""
    executable = Path(executable).name.lower()
    return known.get(executable, f"baseline_native_{normalized}"[:80])


def _normalise_calls(raw_calls: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_calls, list):
        return []
    records: list[dict[str, Any]] = []
    for index, call in enumerate(raw_calls, start=1):
        if not isinstance(call, dict):
            continue
        ref = str(call.get("evidence_ref") or call.get("id") or f"native-{index:04d}")
        records.append({
            "evidence_ref": ref[:128],
            "tool": _canonical_tool(call),
            "args": call.get("args") if isinstance(call.get("args"), dict) else {
                "command": _native_command(call),
            },
            "result": call.get("result", call.get("output", {})),
            "native_tool": call.get("tool") or call.get("name"),
            "native_record": call,
        })
    return records


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _normalise_findings(raw_findings: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_findings, list):
        return []
    findings: list[dict[str, Any]] = []
    for index, item in enumerate(raw_findings, start=1):
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or item.get("exploitation_status") or "DETECTED").upper()
        findings.append({
            "id": str(item.get("id") or item.get("vuln_id") or f"B-{index:04d}"),
            "device_id": str(item.get("device_id") or item.get("device_ip") or item.get("ip") or ""),
            "device_ip": str(item.get("device_ip") or item.get("ip") or item.get("host") or ""),
            "type": str(item.get("type") or item.get("vuln_type") or item.get("category") or ""),
            "severity": str(item.get("severity") or "LOW").upper(),
            "service": str(item.get("service") or ""),
            "port": item.get("port"),
            "protocol": str(item.get("protocol") or "tcp"),
            "endpoint": str(item.get("endpoint") or ""),
            "product": str(item.get("product") or ""),
            "version": str(item.get("version") or ""),
            "details": str(item.get("details") or item.get("description") or ""),
            "evidence": str(item.get("evidence") or item.get("proof") or ""),
            "evidence_level": int(item.get("evidence_level") or (2 if status in {"CONFIRMED", "EXPLOITED"} else 1)),
            "tools_used": [str(value) for value in _as_list(item.get("tools_used") or item.get("tool_used"))],
            "evidence_refs": [str(value) for value in _as_list(item.get("evidence_refs"))],
            "data_extracted": _as_list(item.get("data_extracted")),
            "cve_ids": [str(value).upper() for value in _as_list(item.get("cve_ids") or item.get("cve"))],
            "status": status,
            "remediation": str(item.get("remediation") or ""),
        })
    return findings


def _write_artifacts(run_dir: Path, tool: str, findings: list[dict[str, Any]], calls: list[dict[str, Any]]) -> None:
    (run_dir / "03_vuln_analysis.json").write_text(json.dumps({
        "tool": tool,
        "vulnerabilities": findings,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    tests = []
    for finding in findings:
        tests.append({
            "vuln_id": finding["id"],
            "device_id": finding["device_id"],
            "device_ip": finding["device_ip"],
            "vuln_type": finding["type"],
            "severity": finding["severity"],
            "service": finding["service"],
            "port": finding["port"],
            "protocol": finding["protocol"],
            "endpoint": finding["endpoint"],
            "product": finding["product"],
            "version": finding["version"],
            "description": finding["details"],
            "evidence": finding["evidence"],
            "evidence_level": finding["evidence_level"],
            "tools_used": finding["tools_used"],
            "evidence_refs": finding["evidence_refs"],
            "data_extracted": finding["data_extracted"],
            "cve_ids": finding["cve_ids"],
            "status": finding["status"],
        })
    (run_dir / "04_exploitation.json").write_text(json.dumps({
        "tool": tool,
        "tests": tests,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    with (run_dir / "tool_calls.jsonl").open("w", encoding="utf-8") as handle:
        for call in calls:
            handle.write(json.dumps(call, ensure_ascii=False) + "\n")


def run_local_baseline(
    *,
    tool: str,
    scenario_id: str,
    mode: str,
    scope: str,
    model: str,
    max_turns: int,
    output_root: Path,
    command_template: str | None = None,
    dry_run: bool = False,
) -> Path:
    if tool not in COMMAND_ENV:
        raise ValueError(f"unsupported real baseline: {tool}")
    if mode != "blind":
        raise ValueError("paper CAI/VulnBot baselines are precommitted in blind mode only")
    template = command_template or os.environ.get(COMMAND_ENV[tool])
    if not template:
        raise RuntimeError(
            f"{COMMAND_ENV[tool]} is required and must invoke the real upstream {tool} wrapper"
        )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = output_root / tool / f"scenario_{scenario_id}" / timestamp
    run_dir.mkdir(parents=True, exist_ok=False)
    raw_path = run_dir / "native_output.json"
    trace_path = run_dir / "native_tool_calls.jsonl"
    credentials_path = run_dir / "initial_credentials.json"
    credentials_path.write_text(
        json.dumps(_scenario_footholds(scenario_id), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    values = {
        "scope": scope,
        "scenario": scenario_id,
        "mode": mode,
        "output": str(raw_path),
        "trace": str(trace_path),
        "credentials_file": str(credentials_path),
        "model": model,
        "max_turns": str(max_turns),
    }
    command = shlex.split(template.format(**values))
    planned = {
        "tool": tool,
        "implementation": "upstream-real",
        "scenario_id": scenario_id,
        "mode": mode,
        "scope": scope,
        "model": model,
        "max_turns": max_turns,
        "command_env": COMMAND_ENV[tool],
        "command_executable": command[0] if command else None,
    }
    (run_dir / "planned.json").write_text(json.dumps(planned, indent=2), encoding="utf-8")
    if dry_run:
        return run_dir

    env = os.environ.copy()
    env.update({
        "BENCHMARK_SCOPE": scope,
        "BENCHMARK_SCENARIO": scenario_id,
        "BENCHMARK_MODE": mode,
        "BENCHMARK_OUTPUT": str(raw_path),
        "BENCHMARK_TRACE": str(trace_path),
        "BENCHMARK_INITIAL_CREDENTIALS_FILE": str(credentials_path),
    })
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    if not raw_path.is_file():
        raise RuntimeError(f"real {tool} adapter did not create {raw_path}")
    raw_bytes = raw_path.read_bytes()
    raw = json.loads(raw_bytes)
    if not isinstance(raw, dict):
        raise ValueError("baseline native output must be a JSON object")
    calls = _normalise_calls(raw.get("tool_calls"))
    if trace_path.exists():
        native_lines = []
        for line in trace_path.read_text(encoding="utf-8").splitlines():
            try:
                native_lines.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        calls.extend(_normalise_calls(native_lines))
    findings = _normalise_findings(
        raw.get("findings") or raw.get("vulnerabilities") or raw.get("results")
    )
    _write_artifacts(run_dir, tool, findings, calls)
    metadata = {
        **planned,
        "git_commit": _git_commit(),
        "blind": True,
        "manage_scenario": False,
        "oracle_access": False,
        "native_output_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "finding_count": len(findings),
        "native_tool_call_count": len(calls),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        **metric_contract_metadata(ROOT),
    }
    (run_dir / "run_meta.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (run_dir / "scenario_meta.json").write_text(json.dumps({
        "scenario_id": scenario_id,
        "split": "test-public",
        "mode": mode,
        "blind": True,
        "system": tool,
    }, indent=2), encoding="utf-8")
    ground_truth = GROUND_TRUTH / f"scenario_{scenario_id}.yaml"
    score = evaluate(run_dir, ground_truth, policy="strict-v3")
    (run_dir / "evaluator_score.json").write_text(
        json.dumps(asdict(score), indent=2, ensure_ascii=False), encoding="utf-8",
    )
    return run_dir
