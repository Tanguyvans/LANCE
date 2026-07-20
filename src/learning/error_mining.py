"""Mine public benchmark errors into a versioned, reviewable feedback dataset.

The generated records are deliberately *not* training conversations.  They are
review candidates that must be accepted before export to the training workspace.

Usage:
    python -m src.learning.error_mining mine \
        --runs-root output/agent \
        --output output/learning/feedback-2026-07-16

    python -m src.learning.error_mining review \
        output/learning/feedback-2026-07-16 <candidate-id> --status accepted

    python -m src.learning.error_mining export \
        output/learning/feedback-2026-07-16 \
        --destination /home/leo/LANCE/data/finetuning/vuln/reviewed_feedback/feedback-2026-07-16
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

from src.benchmark.catalog import DEV_PUBLIC, get_scenario
from src.benchmark.evaluator import _load_llm_findings, evaluate, resolve_policy


SCHEMA_VERSION = "1.1"
DEFAULT_POLICY = "strict-v2"
REVIEW_STATUSES = frozenset({"pending", "accepted", "rejected"})
ERROR_TYPES = frozenset({
    "false_negative",
    "false_positive",
    "severity_mismatch",
    "recon_coverage_omission",
    "unsupported_exploit_verdict",
    "invalid_exploit_status",
    "topology_coverage_omission",
    "report_alignment_correction",
})
FEEDBACK_TASKS = frozenset({
    "finding_correction",
    "recon_correction",
    "exploit_correction",
    "secretary_correction",
})
LEARNING_SPLITS = frozenset({DEV_PUBLIC, "custom"})
ARTIFACT_NAMES = (
    "01_graph_analysis.md",
    "01_reconnaissance.json",
    "02_recon.md",
    "02_mapping.json",
    "03_vuln_analysis.json",
    "04_exploitation.json",
    "05_intrusion.json",
    "06_report.md",
    "06_phase6_context.json",
    "tool_calls.jsonl",
)


class LearningLoopError(RuntimeError):
    """Raised when feedback mining would be unsafe or produce invalid data."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_object(path: Path, *, required: bool = False) -> dict[str, Any]:
    if path.is_symlink():
        raise LearningLoopError(f"Refusing symlink: {path}")
    if not path.exists():
        if required:
            raise LearningLoopError(f"Missing required file: {path}")
        return {}
    if not path.is_file():
        raise LearningLoopError(f"Expected a regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LearningLoopError(f"Invalid JSON object: {path}") from exc
    if not isinstance(value, dict):
        raise LearningLoopError(f"Expected a JSON object: {path}")
    return value


def _normalise_scenario_id(value: object) -> str:
    return str(value).strip().removeprefix("S").removeprefix("s")


def _run_context(
    run_dir: Path,
    *,
    ground_truth_dir: Path,
    allow_custom: bool,
) -> tuple[str, Path, dict[str, Any], dict[str, Any]]:
    if run_dir.is_symlink() or not run_dir.is_dir():
        raise LearningLoopError(f"Unsafe run directory: {run_dir}")

    scenario_meta = _read_object(run_dir / "scenario_meta.json", required=True)
    run_meta = _read_object(run_dir / "run_meta.json")
    split = scenario_meta.get("split") or run_meta.get("benchmark_split")
    scenario_id = _normalise_scenario_id(scenario_meta.get("scenario_id", ""))

    # Fail closed before considering custom mode.  A forged custom_config marker
    # must never turn a sealed run into reusable learning data.
    if split == "eval-sealed":
        raise LearningLoopError(f"Refusing sealed run: {run_dir.name}")
    if scenario_id.isdigit() and 20 <= int(scenario_id) <= 25:
        raise LearningLoopError(f"Refusing sealed scenario S{scenario_id}")
    if not scenario_id:
        raise LearningLoopError(f"scenario_id missing in {run_dir / 'scenario_meta.json'}")

    try:
        descriptor = get_scenario(scenario_id)
    except Exception as exc:
        if not scenario_meta.get("custom_config"):
            raise LearningLoopError(f"Unknown benchmark scenario S{scenario_id}") from exc
        descriptor = None
    if descriptor is not None and descriptor.sealed:
        raise LearningLoopError(f"Refusing sealed scenario S{scenario_id}")

    if scenario_meta.get("custom_config"):
        if not allow_custom:
            raise LearningLoopError(
                f"Custom run {run_dir.name} requires explicit --allow-custom"
            )
        ground_truth = run_dir / "ground_truth.yaml"
    else:
        if split not in (None, DEV_PUBLIC):
            raise LearningLoopError(f"Unsupported benchmark split {split!r}")
        if descriptor is None or descriptor.split != DEV_PUBLIC:
            raise LearningLoopError(f"Scenario S{scenario_id} is not dev-public")
        ground_truth = ground_truth_dir / f"scenario_{scenario_id}.yaml"

    if ground_truth.is_symlink() or not ground_truth.is_file():
        raise LearningLoopError(f"Trusted ground truth not found: {ground_truth}")
    return scenario_id, ground_truth, scenario_meta, run_meta


def _load_ground_truth(path: Path, expected_scenario_id: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise LearningLoopError(f"Invalid ground truth: {path}") from exc
    if not isinstance(data, dict):
        raise LearningLoopError(f"Ground truth must be a mapping: {path}")
    if _normalise_scenario_id(data.get("scenario_id", "")) != expected_scenario_id:
        raise LearningLoopError(f"Ground truth scenario mismatch: {path}")
    vulnerabilities = data.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list) or not all(
        isinstance(item, dict) for item in vulnerabilities
    ):
        raise LearningLoopError(f"Invalid vulnerabilities list: {path}")
    return data


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _candidate_id(identity: dict[str, Any]) -> str:
    digest = hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()
    return f"lf-{digest[:20]}"


def _finding_identity(finding: dict[str, Any]) -> dict[str, str]:
    return {
        "device_ip": str(finding.get("device_ip") or "").strip(),
        "type": str(finding.get("type") or "").strip().lower(),
        "severity": str(finding.get("severity") or "").strip().lower(),
        "details": " ".join(str(finding.get("details") or "").lower().split()),
    }


def _source(
    run_dir: Path,
    scenario_id: str,
    scenario_meta: dict[str, Any],
    run_meta: dict[str, Any],
    policy: str,
    run_id: str | None = None,
) -> dict[str, Any]:
    artifacts = [
        name
        for name in ARTIFACT_NAMES
        if (run_dir / name).is_file() and not (run_dir / name).is_symlink()
    ]
    return {
        "run_id": run_id or run_dir.name,
        "run_dir": str(run_dir),
        "scenario_id": scenario_id,
        "model": scenario_meta.get("model") or run_meta.get("model"),
        "git_commit": scenario_meta.get("git_commit") or run_meta.get("git_commit"),
        "policy": policy,
        "artifacts": artifacts,
    }


def _new_candidate(
    *,
    error_type: str,
    scenario_id: str,
    split: str,
    identity: dict[str, Any],
    predicted: dict[str, Any] | None,
    expected: dict[str, Any] | None,
    action: str,
    evaluation: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    candidate_id = _candidate_id(identity)
    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "task": "finding_correction",
        "error_type": error_type,
        "split": split,
        "scenario_id": scenario_id,
        "review": {
            "status": "pending",
            "reviewer": None,
            "reviewed_at": None,
            "notes": "",
        },
        "input": {"predicted_finding": predicted},
        "target": {"action": action, "expected_finding": expected},
        "evaluation": evaluation,
        "occurrences": [source],
    }


def _new_deliverable_candidate(
    *,
    task: str,
    expert: str,
    phase: int,
    error_type: str,
    scenario_id: str,
    split: str,
    identity: dict[str, Any],
    draft_filename: str,
    draft_content: str,
    target_filename: str,
    target_content: str | dict[str, Any],
    correction: dict[str, Any],
    evaluation: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": _candidate_id(identity),
        "task": task,
        "expert": expert,
        "phase": phase,
        "error_type": error_type,
        "split": split,
        "scenario_id": scenario_id,
        "review": {
            "status": "pending",
            "reviewer": None,
            "reviewed_at": None,
            "notes": "",
        },
        "input": {
            "draft_deliverable": {
                "filename": draft_filename,
                "content": draft_content,
            },
            "correction": correction,
        },
        "target": {
            "expected_deliverable": {
                "filename": target_filename,
                "content": target_content,
            }
        },
        "evaluation": evaluation,
        "occurrences": [source],
    }


def _read_text(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ""


def _topology_nodes(ground_truth: dict[str, Any]) -> list[dict[str, str]]:
    topology = ground_truth.get("topology")
    if not isinstance(topology, dict):
        return []
    raw_nodes: list[dict[str, Any]] = []
    router = topology.get("router")
    if isinstance(router, dict):
        raw_nodes.append(router)
    services = topology.get("services")
    if isinstance(services, list):
        raw_nodes.extend(item for item in services if isinstance(item, dict))
    nodes = []
    for item in raw_nodes:
        name = str(item.get("name") or "").strip()
        ip = str(item.get("ip") or "").strip()
        if name and ip:
            nodes.append({
                "name": name,
                "ip": ip,
                "role": str(item.get("role") or item.get("type") or "device"),
            })
    return nodes


def _mine_topology_feedback(
    run_dir: Path,
    ground_truth: dict[str, Any],
    *,
    scenario_id: str,
    split: str,
    source: dict[str, Any],
) -> list[dict[str, Any]]:
    draft = _read_text(run_dir / "01_graph_analysis.md")
    if not draft.strip():
        return []
    draft_lower = draft.lower()
    missing = [
        node for node in _topology_nodes(ground_truth)
        if node["name"].lower() not in draft_lower or node["ip"] not in draft
    ]
    if not missing:
        return []
    rows = "\n".join(
        f'| {node["name"]} | {node["ip"]} | {node["role"]} |'
        for node in missing
    )
    correction_block = (
        "\n\n## Reviewed Topology Coverage Correction\n\n"
        "The following declared nodes must be represented explicitly in the graph "
        "analysis and Phase 2 scan plan.\n\n"
        "| Device | IP address | Role |\n"
        "|---|---|---|\n"
        f"{rows}\n"
    )
    identity = {
        "task": "secretary_correction",
        "error_type": "topology_coverage_omission",
        "scenario_id": scenario_id,
        "run_id": source["run_id"],
        "missing_nodes": missing,
    }
    return [_new_deliverable_candidate(
        task="secretary_correction",
        expert="secretary",
        phase=1,
        error_type="topology_coverage_omission",
        scenario_id=scenario_id,
        split=split,
        identity=identity,
        draft_filename="01_graph_analysis.md",
        draft_content=draft,
        target_filename="01_graph_analysis.md",
        target_content=draft.rstrip() + correction_block,
        correction={"missing_nodes": missing},
        evaluation={"missing_node_count": len(missing)},
        source=source,
    )]


_ROLE_PORTS = {
    "router": {22, 23, 80},
    "ssh_server": {22},
    "ssh_server_v2": {22},
    "web_server": {80},
    "web_server_v2": {80},
    "web_upload": {80},
    "mqtt_broker": {1883},
    "mqtt_broker_v2": {1883},
    "iot_gateway": {22, 80},
    "gateway": {22, 80},
    "db_server": {3306},
    "db_server_v2": {6379},
    "ftp_server": {21},
    "nodered_server": {1880},
    "camera_server": {80, 554},
    "coap_server": {5683},
    "snmp_server": {161},
    "modbus_server": {502},
}


def _expected_ports(expected: dict[str, Any]) -> list[int]:
    text = " ".join([
        str(expected.get("verification") or ""),
        " ".join(str(item) for item in expected.get("indicators") or []),
    ])
    ports = {
        int(value)
        for value in re.findall(
            r"(?<!\d)(\d{1,5})(?=\s*(?:/\s*)?(?:tcp|udp)\b)",
            text,
            flags=re.IGNORECASE,
        )
        if 0 < int(value) <= 65535
    }
    if not ports:
        ports.update(_ROLE_PORTS.get(str(expected.get("role") or "").lower(), set()))
    return sorted(ports)


def _recon_omission(expected: dict[str, Any], recon: str) -> dict[str, Any] | None:
    ip = str(expected.get("ip") or "").strip()
    if not ip:
        return None
    if ip not in recon:
        return {
            "gt_id": str(expected.get("id") or ""),
            "device": str(expected.get("device") or expected.get("role") or "device"),
            "ip": ip,
            "ports": _expected_ports(expected),
            "reason": "target_ip_absent",
        }
    ports = _expected_ports(expected)
    if not ports:
        return None
    position = recon.find(ip)
    window = recon[max(0, position - 300):position + 700].lower()
    if not any(re.search(rf"(?<!\d){port}(?!\d)", window) for port in ports):
        return {
            "gt_id": str(expected.get("id") or ""),
            "device": str(expected.get("device") or expected.get("role") or "device"),
            "ip": ip,
            "ports": ports,
            "reason": "expected_service_absent",
        }
    return None


def _mine_recon_feedback(
    run_dir: Path,
    matches: list[dict[str, Any]],
    gt_by_id: dict[str, dict[str, Any]],
    *,
    scenario_id: str,
    split: str,
    source: dict[str, Any],
) -> tuple[list[dict[str, Any]], set[str]]:
    recon = _read_text(run_dir / "02_recon.md")
    if not recon.strip() or "## 2." not in recon:
        return [], set()
    omissions = []
    for match in matches:
        if match.get("matched"):
            continue
        gt_id = str(match.get("gt_id") or "")
        expected = gt_by_id.get(gt_id)
        if expected:
            omission = _recon_omission(expected, recon)
            if omission:
                omissions.append(omission)
    if not omissions:
        return [], set()
    unique = {
        (item["device"], item["ip"], tuple(item["ports"]), item["reason"]): item
        for item in omissions
    }
    omissions = list(unique.values())
    rows = "\n".join(
        f'| {item["device"]} | {item["ip"]} | '
        f'{", ".join(str(port) for port in item["ports"]) or "baseline discovery"} | '
        f'{item["reason"]} |'
        for item in omissions
    )
    correction_block = (
        "\n\n## Reviewed Coverage Correction\n\n"
        "These targets or expected services were omitted from the reconnaissance "
        "coverage. They must be scanned and represented explicitly; this correction "
        "does not by itself assert that a vulnerability is exploitable.\n\n"
        "| Device | IP address | Required service coverage | Review reason |\n"
        "|---|---|---|---|\n"
        f"{rows}\n"
    )
    identity = {
        "task": "recon_correction",
        "error_type": "recon_coverage_omission",
        "scenario_id": scenario_id,
        "run_id": source["run_id"],
        "omissions": omissions,
    }
    candidate = _new_deliverable_candidate(
        task="recon_correction",
        expert="recon",
        phase=2,
        error_type="recon_coverage_omission",
        scenario_id=scenario_id,
        split=split,
        identity=identity,
        draft_filename="02_recon.md",
        draft_content=recon,
        target_filename="02_recon.md",
        target_content=recon.rstrip() + correction_block,
        correction={"coverage_omissions": omissions},
        evaluation={"attributed_false_negatives": [item["gt_id"] for item in omissions]},
        source=source,
    )
    return [candidate], {item["gt_id"] for item in omissions}



def _negative_or_empty_exploit_evidence(test: dict[str, Any]) -> bool:
    combined = " ".join([
        str(test.get("evidence") or ""),
        str(test.get("description") or ""),
    ]).strip().lower()
    if not combined:
        return True
    negative_markers = (
        "not confirmed",
        "not accepted",
        "rejected",
        "counter-measure",
        "countermeasure",
        "no output",
        "empty response",
        "connection refused",
        "timed out",
        "timeout",
        "failed to",
        "inconclusive",
        "likely unrestricted",
        "supports kex-strict",
    )
    return any(marker in combined for marker in negative_markers)


def _load_exploit_tests(run_dir: Path) -> list[dict[str, Any]]:
    data = _read_object(run_dir / "04_exploitation.json")
    tests = data.get("tests") or data.get("vulnerabilities") or []
    if not isinstance(tests, list):
        return []
    return [item for item in tests if isinstance(item, dict)]


def _exploit_filename(test: dict[str, Any]) -> str:
    device = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(test.get("device_id") or "unknown"))
    vuln_type = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(test.get("vuln_type") or test.get("type") or "finding"))
    vuln_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(test.get("vuln_id") or test.get("id") or "unknown"))
    return f"04_exploits/{device}/{vuln_type}_{vuln_id}.json"


def _mine_exploit_feedback(
    run_dir: Path,
    false_positive_ids: set[str],
    *,
    scenario_id: str,
    split: str,
    source: dict[str, Any],
) -> list[dict[str, Any]]:
    candidates = []
    positive_statuses = {"CONFIRMED", "EXPLOITED", "COMPROMISED"}
    valid_statuses = {"CONFIRMED", "EXPLOITED", "FAILED", "ERROR"}
    for test in _load_exploit_tests(run_dir):
        status = str(test.get("status") or "").upper()
        vuln_id = str(test.get("vuln_id") or test.get("id") or "")
        unsupported = (
            vuln_id in false_positive_ids
            and status in positive_statuses
            and _negative_or_empty_exploit_evidence(test)
        )
        invalid = status not in valid_statuses
        if not unsupported and not invalid:
            continue
        corrected = dict(test)
        corrected["status"] = "FAILED"
        corrected["evidence_level"] = min(int(test.get("evidence_level", 0) or 0), 1)
        original_evidence = str(test.get("evidence") or "").strip()
        reason = (
            "Positive exploitation verdict rejected because no direct positive tool "
            "evidence supports it."
            if unsupported else
            f"Invalid exploitation status {status!r}; it is not a Phase 4 verdict."
        )
        corrected["evidence"] = " ".join(part for part in (original_evidence, reason) if part)
        corrected.setdefault("data_extracted", [])
        filename = _exploit_filename(test)
        error_type = "unsupported_exploit_verdict" if unsupported else "invalid_exploit_status"
        identity = {
            "task": "exploit_correction",
            "error_type": error_type,
            "scenario_id": scenario_id,
            "run_id": source["run_id"],
            "vuln_id": test.get("vuln_id") or test.get("id"),
            "status": status,
        }
        candidates.append(_new_deliverable_candidate(
            task="exploit_correction",
            expert="exploit",
            phase=4,
            error_type=error_type,
            scenario_id=scenario_id,
            split=split,
            identity=identity,
            draft_filename=filename,
            draft_content=_canonical_json(test),
            target_filename=filename,
            target_content=corrected,
            correction={"previous_status": status, "expected_status": "FAILED", "reason": reason},
            evaluation={"positive_evidence": False, "status_contract_valid": not invalid},
            source=source,
        ))
    return candidates


def _canonical_report(ground_truth: dict[str, Any], scenario_id: str) -> str:
    vulnerabilities = ground_truth.get("vulnerabilities") or []
    vulnerabilities = [item for item in vulnerabilities if isinstance(item, dict)]
    severity_counts = Counter(str(item.get("severity") or "unknown").upper() for item in vulnerabilities)
    nodes = _topology_nodes(ground_truth)
    attack_paths = ground_truth.get("attack_paths") or []
    finding_rows = "\n".join(
        f'- **{item.get("id", "?")} — {item.get("device", item.get("role", "device"))} '
        f'({item.get("ip", "unknown")}): {item.get("title", "Reviewed finding")} '
        f'[{str(item.get("severity", "unknown")).upper()}]'
        for item in vulnerabilities
    ) or "- No reportable finding in the reviewed ground truth."
    topology_rows = "\n".join(
        f'| {node["name"]} | {node["ip"]} | {node["role"]} |' for node in nodes
    ) or "| No declared node | - | - |"
    remediation_rows = "\n".join(
        f'{index}. Remediate {item.get("id", "the finding")} on '
        f'{item.get("device", item.get("ip", "the affected device"))}: '
        f'{item.get("title", item.get("category", "apply the reviewed control"))}.'
        for index, item in enumerate(vulnerabilities, 1)
    ) or "1. Preserve the reviewed secure baseline."
    path_lines = "\n".join(
        f"- {path.get('name') or path.get('id') or _canonical_json(path)}"
        if isinstance(path, dict) else f"- {path}"
        for path in attack_paths
    ) or "- No benchmark attack path is declared for this scenario."
    severity_summary = ", ".join(
        f"{severity}: {count}" for severity, count in sorted(severity_counts.items())
    ) or "none"
    return f"""# Reviewed Pentest Report — Scenario S{scenario_id}

## 1. Executive Summary

The reviewed benchmark contains {len(nodes)} declared devices and {len(vulnerabilities)} reportable root vulnerabilities. Findings are deduplicated by root cause and do not inherit severity from evidence level.

Severity breakdown: {severity_summary}.

## 2. Scope and Methodology

This correction aligns the final report with the trusted public benchmark review. It preserves only declared devices and root vulnerabilities, separates observation from exploitation, and excludes unsupported positive verdicts.

## 3. Topology and Attack Surface

| Device | IP address | Role |
|---|---|---|
{topology_rows}

## 4. Reconnaissance Results

Every declared target must receive explicit Phase 2 coverage. Service observations remain evidence, not automatic proof of exploitation.

{{{{SECTION_5_TABLE}}}}

{{{{SECTION_6_TABLES}}}}

## 7. Attack Paths

{path_lines}

## 8. Risk Scores

The authoritative severity distribution is: {severity_summary}. A high evidence level strengthens confidence but never changes the reviewed severity on its own.

Reviewed root findings:

{finding_rows}

## 9. Remediation Recommendations

{remediation_rows}

## 10. Appendices

This report is a reviewed correction generated from dev-public ground truth. False positives, duplicate consequences, invalid exploit statuses, and unsupported exploitation claims are excluded from the authoritative result.
"""


def _mine_report_feedback(
    run_dir: Path,
    ground_truth: dict[str, Any],
    result: Any,
    *,
    scenario_id: str,
    split: str,
    source: dict[str, Any],
) -> list[dict[str, Any]]:
    draft = _read_text(run_dir / "06_report.md")
    error_count = result.false_negatives + result.false_positives + result.severity_mismatches
    if not draft.strip() or not error_count:
        return []
    target = _canonical_report(ground_truth, scenario_id)
    identity = {
        "task": "secretary_correction",
        "error_type": "report_alignment_correction",
        "scenario_id": scenario_id,
        "run_id": source["run_id"],
        "evaluation_errors": {
            "false_negatives": result.false_negatives,
            "false_positives": result.false_positives,
            "severity_mismatches": result.severity_mismatches,
        },
    }
    return [_new_deliverable_candidate(
        task="secretary_correction",
        expert="secretary",
        phase=6,
        error_type="report_alignment_correction",
        scenario_id=scenario_id,
        split=split,
        identity=identity,
        draft_filename="06_report.md",
        draft_content=draft,
        target_filename="06_report.md",
        target_content=target,
        correction=identity["evaluation_errors"],
        evaluation=identity["evaluation_errors"],
        source=source,
    )]


def _match_full_false_positives(
    summaries: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    matched: list[dict[str, Any]] = []
    used: set[int] = set()
    for summary in summaries:
        candidates: list[int] = []
        for index, finding in enumerate(findings):
            if index in used:
                continue
            same_fields = all(
                finding.get(key) == summary.get(key)
                for key in ("id", "device_ip", "type", "severity")
            )
            details = str(finding.get("details") or "")
            if same_fields and details.startswith(str(summary.get("details") or "")):
                candidates.append(index)
        if not candidates:
            # Keep the evaluator summary rather than silently losing an error.
            matched.append(dict(summary))
            continue
        index = candidates[0]
        used.add(index)
        matched.append(dict(findings[index]))
    return matched


def _merge_candidate(
    candidates: dict[str, dict[str, Any]],
    candidate: dict[str, Any],
) -> None:
    candidate_id = candidate["candidate_id"]
    existing = candidates.get(candidate_id)
    if existing is None:
        candidates[candidate_id] = candidate
        return
    occurrence = candidate["occurrences"][0]
    if occurrence not in existing["occurrences"]:
        existing["occurrences"].append(occurrence)


def _mine_run(
    run_dir: Path,
    *,
    run_id: str | None = None,
    ground_truth_dir: Path,
    policy: str,
    allow_custom: bool,
) -> list[dict[str, Any]]:
    scenario_id, gt_path, scenario_meta, run_meta = _run_context(
        run_dir,
        ground_truth_dir=ground_truth_dir,
        allow_custom=allow_custom,
    )
    gt_data = _load_ground_truth(gt_path, scenario_id)
    gt_by_id = {
        str(item.get("id")): item
        for item in gt_data.get("vulnerabilities", [])
        if item.get("id") is not None
    }
    result = evaluate(run_dir, gt_path, policy=policy)
    source = _source(
        run_dir, scenario_id, scenario_meta, run_meta, policy, run_id=run_id
    )
    learning_split = "custom" if scenario_meta.get("custom_config") else DEV_PUBLIC
    candidates: list[dict[str, Any]] = []

    candidates.extend(_mine_topology_feedback(
        run_dir,
        gt_data,
        scenario_id=scenario_id,
        split=learning_split,
        source=source,
    ))
    recon_candidates, recon_attributed_gt_ids = _mine_recon_feedback(
        run_dir,
        result.matches,
        gt_by_id,
        scenario_id=scenario_id,
        split=learning_split,
        source=source,
    )
    candidates.extend(recon_candidates)
    false_positive_ids = {
        str(item.get("id") or item.get("vuln_id") or "")
        for item in result.unmatched_llm
    }
    candidates.extend(_mine_exploit_feedback(
        run_dir,
        false_positive_ids,
        scenario_id=scenario_id,
        split=learning_split,
        source=source,
    ))
    candidates.extend(_mine_report_feedback(
        run_dir,
        gt_data,
        result,
        scenario_id=scenario_id,
        split=learning_split,
        source=source,
    ))

    for match in result.matches:
        gt_id = str(match.get("gt_id") or "")
        expected = gt_by_id.get(gt_id, {
            "id": gt_id,
            "title": match.get("gt_title"),
            "device": match.get("gt_device"),
            "ip": match.get("gt_ip"),
            "severity": match.get("gt_severity"),
        })
        if not match.get("matched"):
            if gt_id in recon_attributed_gt_ids:
                continue
            identity = {
                "error_type": "false_negative",
                "scenario_id": scenario_id,
                "gt_id": gt_id,
            }
            candidates.append(_new_candidate(
                error_type="false_negative",
                scenario_id=scenario_id,
                split=learning_split,
                identity=identity,
                predicted=None,
                expected=expected,
                action="add_finding",
                evaluation={"gt_id": gt_id, "match_method": ""},
                source=source,
            ))
        elif not match.get("severity_match"):
            predicted = {
                "id": match.get("llm_id"),
                "device_ip": match.get("gt_ip"),
                "type": match.get("llm_type"),
                "severity": match.get("llm_severity"),
            }
            identity = {
                "error_type": "severity_mismatch",
                "scenario_id": scenario_id,
                "gt_id": gt_id,
                "predicted": _finding_identity(predicted),
            }
            candidates.append(_new_candidate(
                error_type="severity_mismatch",
                scenario_id=scenario_id,
                split=learning_split,
                identity=identity,
                predicted=predicted,
                expected=expected,
                action="correct_finding",
                evaluation={
                    "gt_id": gt_id,
                    "match_method": match.get("match_method"),
                    "expected_severity": match.get("gt_severity"),
                    "predicted_severity": match.get("llm_severity"),
                },
                source=source,
            ))

    full_false_positives = _match_full_false_positives(
        result.unmatched_llm,
        _load_llm_findings(run_dir),
    )
    for finding in full_false_positives:
        identity = {
            "error_type": "false_positive",
            "scenario_id": scenario_id,
            "predicted": _finding_identity(finding),
        }
        candidates.append(_new_candidate(
            error_type="false_positive",
            scenario_id=scenario_id,
            split=learning_split,
            identity=identity,
            predicted=finding,
            expected=None,
            action="remove_finding",
            evaluation={"gt_id": None, "match_method": None},
            source=source,
        ))
    return candidates


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_candidates(path: Path, candidates: Iterable[dict[str, Any]]) -> None:
    lines = [_canonical_json(candidate) for candidate in candidates]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _refresh_manifest(dataset_dir: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    candidates = _read_candidates(dataset_dir)
    counts = Counter(item["error_type"] for item in candidates)
    review_counts = Counter(item["review"]["status"] for item in candidates)
    task_counts = Counter(item.get("task", "unknown") for item in candidates)
    expert_counts = Counter(
        item.get("expert") or ("vuln" if item.get("task") == "finding_correction" else "unknown")
        for item in candidates
    )
    manifest["candidate_count"] = len(candidates)
    manifest["counts_by_error_type"] = dict(sorted(counts.items()))
    manifest["counts_by_review_status"] = dict(sorted(review_counts.items()))
    manifest["counts_by_task"] = dict(sorted(task_counts.items()))
    manifest["counts_by_expert"] = dict(sorted(expert_counts.items()))
    manifest["candidates_sha256"] = _sha256(dataset_dir / "candidates.jsonl")
    manifest["updated_at"] = _utc_now()
    _write_json(dataset_dir / "manifest.json", manifest)
    return manifest


def mine_runs(
    runs_root: Path,
    output_dir: Path,
    *,
    ground_truth_dir: Path | None = None,
    run_ids: Iterable[str] | None = None,
    policy: str = DEFAULT_POLICY,
    allow_custom: bool = False,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Mine eligible runs and write a deduplicated feedback dataset."""
    runs_root = Path(runs_root)
    output_dir = Path(output_dir)
    policy = resolve_policy(policy).name
    if runs_root.is_symlink() or not runs_root.is_dir():
        raise LearningLoopError(f"Runs root not found or unsafe: {runs_root}")
    if output_dir.exists():
        if not overwrite:
            raise LearningLoopError(f"Output already exists: {output_dir}")
        if output_dir.is_symlink() or not output_dir.is_dir():
            raise LearningLoopError(f"Unsafe output directory: {output_dir}")
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    if ground_truth_dir is None:
        ground_truth_dir = Path(__file__).resolve().parents[2] / "benchmarks" / "ground_truth"
    selected = set(run_ids or ())
    discovered = sorted({
        meta.parent
        for meta in runs_root.rglob("scenario_meta.json")
        if meta.is_file() and not meta.is_symlink()
    })
    identified_runs = [
        (path.relative_to(runs_root).as_posix(), path)
        for path in discovered
    ]
    if selected:
        matching = [
            (run_id, path)
            for run_id, path in identified_runs
            if run_id in selected or path.name in selected
        ]
        matched_selectors = {
            selector
            for selector in selected
            if any(run_id == selector or path.name == selector for run_id, path in matching)
        }
        missing = selected - matched_selectors
        if missing:
            raise LearningLoopError(f"Unknown run IDs: {sorted(missing)}")
        identified_runs = matching

    candidates: dict[str, dict[str, Any]] = {}
    skipped: list[dict[str, str]] = []
    processed: list[str] = []
    for run_id, run_dir in identified_runs:
        try:
            mined = _mine_run(
                run_dir,
                run_id=run_id,
                ground_truth_dir=Path(ground_truth_dir),
                policy=policy,
                allow_custom=allow_custom,
            )
        except (LearningLoopError, FileNotFoundError, ValueError) as exc:
            skipped.append({"run_id": run_id, "reason": str(exc)})
            continue
        processed.append(run_id)
        for candidate in mined:
            _merge_candidate(candidates, candidate)

    ordered = [candidates[key] for key in sorted(candidates)]
    _write_candidates(output_dir / "candidates.jsonl", ordered)
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "dataset_kind": "learning-feedback-candidates",
        "dataset_version": output_dir.name,
        "created_at": _utc_now(),
        "updated_at": _utc_now(),
        "evaluation_policy": policy,
        "runs_root": str(runs_root),
        "processed_runs": processed,
        "skipped_runs": skipped,
    }
    return _refresh_manifest(output_dir, manifest)


def _read_candidates(dataset_dir: Path) -> list[dict[str, Any]]:
    path = dataset_dir / "candidates.jsonl"
    if path.is_symlink() or not path.is_file():
        raise LearningLoopError(f"Missing candidates file: {path}")
    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            value = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise LearningLoopError(f"Invalid JSON at {path}:{line_number}") from exc
        if not isinstance(value, dict):
            raise LearningLoopError(f"Candidate must be an object at {path}:{line_number}")
        records.append(value)
    return records


def validate_dataset(dataset_dir: Path, *, verify_checksum: bool = True) -> dict[str, Any]:
    """Validate the candidate schema, identities, review states and checksum."""
    dataset_dir = Path(dataset_dir)
    manifest = _read_object(dataset_dir / "manifest.json", required=True)
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise LearningLoopError("Unsupported manifest schema")
    if manifest.get("dataset_kind") != "learning-feedback-candidates":
        raise LearningLoopError("Invalid dataset kind")
    candidates = _read_candidates(dataset_dir)
    seen: set[str] = set()
    for index, candidate in enumerate(candidates, start=1):
        candidate_id = candidate.get("candidate_id")
        if not isinstance(candidate_id, str) or not candidate_id.startswith("lf-"):
            raise LearningLoopError(f"Invalid candidate_id at record {index}")
        if candidate_id in seen:
            raise LearningLoopError(f"Duplicate candidate_id: {candidate_id}")
        seen.add(candidate_id)
        if candidate.get("schema_version") != SCHEMA_VERSION:
            raise LearningLoopError(f"Unsupported schema at record {index}")
        if candidate.get("error_type") not in ERROR_TYPES:
            raise LearningLoopError(f"Invalid error_type at record {index}")
        task = candidate.get("task")
        if task not in FEEDBACK_TASKS:
            raise LearningLoopError(f"Invalid feedback task at record {index}")
        if task != "finding_correction":
            expected_expert = {
                "recon_correction": ("recon", {2}),
                "exploit_correction": ("exploit", {4, 5}),
                "secretary_correction": ("secretary", {1, 6}),
            }[task]
            if candidate.get("expert") != expected_expert[0]:
                raise LearningLoopError(f"Invalid expert routing at record {index}")
            if candidate.get("phase") not in expected_expert[1]:
                raise LearningLoopError(f"Invalid expert phase at record {index}")
            deliverable = candidate.get("target", {}).get("expected_deliverable", {})
            if not isinstance(deliverable, dict) or not deliverable.get("filename"):
                raise LearningLoopError(f"Missing deliverable target at record {index}")
        review = candidate.get("review")
        if not isinstance(review, dict) or review.get("status") not in REVIEW_STATUSES:
            raise LearningLoopError(f"Invalid review status at record {index}")
        occurrences = candidate.get("occurrences")
        if not isinstance(occurrences, list) or not occurrences:
            raise LearningLoopError(f"Missing occurrences at record {index}")
        if candidate.get("split") not in LEARNING_SPLITS:
            raise LearningLoopError(f"Invalid learning split at record {index}")
        scenario_id = _normalise_scenario_id(candidate.get("scenario_id", ""))
        if scenario_id.isdigit() and 20 <= int(scenario_id) <= 25:
            raise LearningLoopError(f"Sealed candidate at record {index}")

    checksum = _sha256(dataset_dir / "candidates.jsonl")
    if verify_checksum and manifest.get("candidates_sha256") != checksum:
        raise LearningLoopError("Candidate checksum does not match manifest")
    if manifest.get("candidate_count") != len(candidates):
        raise LearningLoopError("Candidate count does not match manifest")
    return {
        "candidate_count": len(candidates),
        "candidates_sha256": checksum,
        "valid": True,
    }


def review_candidate(
    dataset_dir: Path,
    candidate_id: str,
    *,
    status: str,
    reviewer: str | None = None,
    notes: str = "",
) -> dict[str, Any]:
    """Set a candidate review decision and refresh dataset integrity metadata."""
    if status not in REVIEW_STATUSES:
        raise LearningLoopError(f"Invalid review status: {status}")
    dataset_dir = Path(dataset_dir)
    validate_dataset(dataset_dir)
    candidates = _read_candidates(dataset_dir)
    found = None
    for candidate in candidates:
        if candidate["candidate_id"] != candidate_id:
            continue
        found = candidate
        candidate["review"] = {
            "status": status,
            "reviewer": reviewer,
            "reviewed_at": _utc_now() if status != "pending" else None,
            "notes": notes,
        }
        break
    if found is None:
        raise LearningLoopError(f"Unknown candidate: {candidate_id}")
    _write_candidates(dataset_dir / "candidates.jsonl", candidates)
    manifest = _read_object(dataset_dir / "manifest.json", required=True)
    _refresh_manifest(dataset_dir, manifest)
    return found


def export_accepted(
    dataset_dir: Path,
    destination: Path,
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Export accepted candidates only, suitable for the Leo training workspace."""
    dataset_dir = Path(dataset_dir)
    destination = Path(destination)
    validate_dataset(dataset_dir)
    accepted = [
        candidate for candidate in _read_candidates(dataset_dir)
        if candidate["review"]["status"] == "accepted"
    ]
    if not accepted:
        raise LearningLoopError("No accepted candidates to export")
    if destination.exists():
        if not overwrite:
            raise LearningLoopError(f"Destination already exists: {destination}")
        if destination.is_symlink() or not destination.is_dir():
            raise LearningLoopError(f"Unsafe destination: {destination}")
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    _write_candidates(destination / "accepted_candidates.jsonl", accepted)
    source_manifest = _read_object(dataset_dir / "manifest.json", required=True)
    export_manifest = {
        "schema_version": SCHEMA_VERSION,
        "dataset_kind": "accepted-learning-feedback",
        "exported_at": _utc_now(),
        "source_dataset": str(dataset_dir),
        "source_candidates_sha256": source_manifest["candidates_sha256"],
        "candidate_count": len(accepted),
        "counts_by_error_type": dict(sorted(Counter(
            candidate["error_type"] for candidate in accepted
        ).items())),
        "counts_by_expert": dict(sorted(Counter(
            candidate.get("expert") or ("vuln" if candidate.get("task") == "finding_correction" else "unknown")
            for candidate in accepted
        ).items())),
        "accepted_candidates_sha256": _sha256(destination / "accepted_candidates.jsonl"),
    }
    _write_json(destination / "manifest.json", export_manifest)
    return export_manifest


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    mine = subparsers.add_parser("mine", help="Mine errors from public benchmark runs")
    mine.add_argument("--runs-root", type=Path, default=Path("output/agent"))
    mine.add_argument("--output", type=Path, required=True)
    mine.add_argument("--ground-truth-dir", type=Path)
    mine.add_argument("--run-id", action="append", dest="run_ids")
    mine.add_argument("--policy", default=DEFAULT_POLICY)
    mine.add_argument("--allow-custom", action="store_true")
    mine.add_argument("--overwrite", action="store_true")

    validate = subparsers.add_parser("validate", help="Validate a feedback dataset")
    validate.add_argument("dataset_dir", type=Path)

    review = subparsers.add_parser("review", help="Review one feedback candidate")
    review.add_argument("dataset_dir", type=Path)
    review.add_argument("candidate_id")
    review.add_argument("--status", choices=sorted(REVIEW_STATUSES), required=True)
    review.add_argument("--reviewer")
    review.add_argument("--notes", default="")

    export = subparsers.add_parser("export", help="Export accepted candidates only")
    export.add_argument("dataset_dir", type=Path)
    export.add_argument("--destination", type=Path, required=True)
    export.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "mine":
            result = mine_runs(
                args.runs_root,
                args.output,
                ground_truth_dir=args.ground_truth_dir,
                run_ids=args.run_ids,
                policy=args.policy,
                allow_custom=args.allow_custom,
                overwrite=args.overwrite,
            )
        elif args.command == "validate":
            result = validate_dataset(args.dataset_dir)
        elif args.command == "review":
            result = review_candidate(
                args.dataset_dir,
                args.candidate_id,
                status=args.status,
                reviewer=args.reviewer,
                notes=args.notes,
            )
        else:
            result = export_accepted(
                args.dataset_dir,
                args.destination,
                overwrite=args.overwrite,
            )
    except LearningLoopError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
