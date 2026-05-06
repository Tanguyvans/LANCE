"""Normalize external pentest-agent outputs into evaluator-compatible JSON."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from src.agent.vuln_taxonomy import canonicalize, is_noise
from src.baselines.scenarios import BaselineTarget


SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _first(mapping: dict[str, Any], keys: tuple[str, ...], default: Any = "") -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, "", []):
            return value
    return default


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _severity(value: Any) -> str:
    if not value:
        return "LOW"
    sev = str(value).strip().upper()
    return sev if sev in SEVERITIES else "LOW"


def _findings_from_json(data: Any) -> list[dict]:
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []
    for key in ("findings", "vulnerabilities", "results", "issues", "tests"):
        value = data.get(key)
        if isinstance(value, list):
            return value
    return [data]


def _cve_ids(finding: dict[str, Any]) -> list[str]:
    explicit = _first(finding, ("cve_ids", "cves", "cve", "cve_id"), [])
    values = [str(v).upper() for v in _as_list(explicit)]
    text = " ".join(
        str(_first(finding, keys, ""))
        for keys in (("details", "description"), ("evidence", "proof"), ("title", "name"))
    )
    values.extend(c.upper() for c in _CVE_RE.findall(text))
    return sorted(set(v for v in values if _CVE_RE.match(v)))


def normalize_finding(
    finding: dict[str, Any],
    target: BaselineTarget | None,
    tool: str,
    index: int,
) -> dict[str, Any]:
    ip = str(_first(finding, ("device_ip", "ip", "host", "target"), target.ip if target else ""))
    raw_type = str(
        _first(
            finding,
            ("type", "vuln_type", "category", "finding_type", "name", "title"),
            "misconfiguration",
        )
    )
    details = str(_first(finding, ("details", "description", "summary", "title", "name"), ""))
    evidence = str(_first(finding, ("evidence", "proof", "output", "log"), ""))
    status = str(_first(finding, ("status", "exploitation_status"), "suspected")).upper()
    evidence_level = _first(finding, ("evidence_level",), 2 if status in {"CONFIRMED", "EXPLOITED"} else 1)

    try:
        evidence_level = int(evidence_level)
    except (TypeError, ValueError):
        evidence_level = 1

    return {
        "id": str(_first(finding, ("id", "vuln_id"), f"{tool.upper()}-{index:03d}")),
        "device_id": str(_first(finding, ("device_id",), target.device_id if target else ip)),
        "device_ip": ip,
        "type": canonicalize(raw_type),
        "severity": _severity(_first(finding, ("severity", "risk", "impact"), "LOW")),
        "details": details,
        "evidence": evidence,
        "evidence_level": evidence_level,
        "cve_ids": _cve_ids(finding),
        "source_tool": tool,
    }


def normalize_tool_outputs(
    tool: str,
    target_outputs: list[tuple[BaselineTarget | None, Path]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for target, path in target_outputs:
        if not path.exists():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            raw = {"findings": _parse_markdown_findings(path.read_text(encoding="utf-8"))}
        for item in _findings_from_json(raw):
            if isinstance(item, dict):
                finding = normalize_finding(item, target, tool, len(findings) + 1)
                if finding["severity"] == "INFO" or is_noise(finding["type"]):
                    continue
                findings.append(finding)
    return findings


def write_vuln_analysis(tool: str, scenario_id: str, findings: list[dict[str, Any]], run_dir: Path) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "tool": tool,
        "scenario_id": str(scenario_id),
        "mode": "external_baseline_device_by_device",
        "vulnerabilities": findings,
    }
    output = run_dir / "03_vuln_analysis.json"
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return output


def write_exploitation_results(tool: str, scenario_id: str, findings: list[dict[str, Any]], run_dir: Path) -> Path:
    """Write Phase-4-shaped baseline output preferred by the evaluator."""
    run_dir.mkdir(parents=True, exist_ok=True)
    tests = []
    for finding in findings:
        evidence_level = int(finding.get("evidence_level", 0) or 0)
        tests.append(
            {
                "vuln_id": finding.get("id", ""),
                "device_id": finding.get("device_id", ""),
                "device_ip": finding.get("device_ip", ""),
                "vuln_type": finding.get("type", ""),
                "severity": finding.get("severity", ""),
                "description": finding.get("details", ""),
                "evidence": finding.get("evidence", ""),
                "evidence_level": evidence_level,
                "cve_ids": finding.get("cve_ids", []),
                "status": "CONFIRMED" if evidence_level >= 2 else "DETECTED",
                "source_tool": tool,
            }
        )
    payload = {
        "tool": tool,
        "scenario_id": str(scenario_id),
        "mode": "external_baseline_device_by_device",
        "tests": tests,
    }
    output = run_dir / "04_exploitation.json"
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return output


def _parse_markdown_findings(text: str) -> list[dict[str, Any]]:
    """Tiny fallback parser for human reports.

    It only extracts structured bullet-like lines. Real CAI/PentGPT adapters can
    emit JSON directly, but this keeps manual reports evaluable during experiments.
    """
    findings: list[dict[str, Any]] = []
    pattern = re.compile(
        r"(?P<ip>\d+\.\d+\.\d+\.\d+).*?(?P<sev>CRITICAL|HIGH|MEDIUM|LOW|INFO).*?(?P<title>[A-Za-z0-9_ /:-]{6,})",
        re.IGNORECASE,
    )
    for match in pattern.finditer(text):
        findings.append(
            {
                "ip": match.group("ip"),
                "severity": match.group("sev").upper(),
                "title": match.group("title").strip(),
                "details": match.group(0).strip(),
            }
        )
    return findings
