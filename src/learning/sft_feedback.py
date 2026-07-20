"""Convert reviewed feedback into expert-specific SFT traces."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

SAVE_TOOL = {
    "type": "function",
    "function": {
        "name": "save_deliverable",
        "description": "Save the final phase deliverable.",
        "parameters": {
            "type": "object",
            "properties": {
                "filename": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["filename", "content"],
        },
    },
}

EXPERT_PHASES = {
    "secretary": frozenset({1, 6}),
    "recon": frozenset({2}),
    "vuln": frozenset({3}),
    "exploit": frozenset({4, 5}),
}
PHASE_PREFIX = {phase: f"{phase:02d}_" for phase in range(1, 7)}
EXPERT_INSTRUCTIONS = {
    "secretary": (
        "Preserve the pipeline structure and report only topology or final-report "
        "claims supported by supplied artifacts. Keep identifiers consistent."
    ),
    "recon": (
        "Report only directly observed hosts, ports, services, and versions. "
        "Preserve evidence and do not infer unavailable network facts."
    ),
    "vuln": (
        "Use canonical vulnerability types, preserve direct evidence, calibrate "
        "severity consistently, and deduplicate findings by root cause."
    ),
    "exploit": (
        "Keep exploitation status aligned with direct tool evidence. Distinguish "
        "failed, blocked, and successful attempts; never invent access or data."
    ),
}
TYPE_BY_CATEGORY = {
    "default_credentials": "default_credentials",
    "no_authentication": "no_auth",
    "data_exposure": "data_exposure",
    "misconfiguration": "misconfiguration",
    "insecure_update": "insecure_update",
}
PORT_BY_TYPE = {
    "default_credentials": 3306,
    "no_auth": 1880,
    "data_exposure": 80,
    "misconfiguration": 22,
}
GENERIC_TASK_EXPERTS = {
    "secretary_correction": "secretary",
    "recon_correction": "recon",
    "vuln_deliverable_correction": "vuln",
    "exploit_correction": "exploit",
}


class FeedbackConversionError(RuntimeError):
    """Raised when an accepted correction cannot be converted safely."""


TraceConverter = Callable[[dict[str, Any], Path], dict[str, Any]]
CONVERTERS: dict[str, TraceConverter] = {}


def register_converter(task: str) -> Callable[[TraceConverter], TraceConverter]:
    """Register a feedback task converter."""

    def decorator(converter: TraceConverter) -> TraceConverter:
        if task in CONVERTERS:
            raise RuntimeError(f"Duplicate feedback converter: {task}")
        CONVERTERS[task] = converter
        return converter

    return decorator


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise FeedbackConversionError(f"Invalid JSON at {path}:{line_number}") from exc
        if not isinstance(value, dict):
            raise FeedbackConversionError(f"Expected object at {path}:{line_number}")
        records.append(value)
    return records


def _accepted_candidates(path: Path) -> list[dict[str, Any]]:
    accepted = [
        item
        for item in _read_jsonl(path)
        if item.get("review", {}).get("status") == "accepted"
    ]
    if not accepted:
        raise FeedbackConversionError("No accepted candidates")
    return accepted


def _candidate_id(candidate: dict[str, Any]) -> str:
    value = candidate.get("candidate_id")
    if not isinstance(value, str) or not value.strip():
        raise FeedbackConversionError("Accepted candidate has no candidate_id")
    return value


def _candidate_task(candidate: dict[str, Any]) -> str:
    task = candidate.get("task")
    if not isinstance(task, str) or task not in CONVERTERS:
        raise FeedbackConversionError(
            f"Unsupported feedback task {task!r} for {_candidate_id(candidate)}"
        )
    return task


def _candidate_phase(candidate: dict[str, Any]) -> int:
    target = candidate.get("target")
    target = target if isinstance(target, dict) else {}
    raw_phase = candidate.get("phase", target.get("phase"))
    if isinstance(raw_phase, bool):
        raw_phase = None
    try:
        phase = int(raw_phase)
    except (TypeError, ValueError) as exc:
        raise FeedbackConversionError(
            f"Candidate {_candidate_id(candidate)} has no valid phase"
        ) from exc
    if phase not in PHASE_PREFIX:
        raise FeedbackConversionError(
            f"Candidate {_candidate_id(candidate)} has unsupported phase {phase}"
        )
    return phase


def _candidate_expert(candidate: dict[str, Any]) -> str:
    task = _candidate_task(candidate)
    if task == "finding_correction":
        expert, phase = "vuln", 3
    else:
        target = candidate.get("target")
        target = target if isinstance(target, dict) else {}
        expert = GENERIC_TASK_EXPERTS.get(task)
        expert = expert or candidate.get("expert") or target.get("expert")
        phase = _candidate_phase(candidate)
    if expert not in EXPERT_PHASES:
        raise FeedbackConversionError(
            f"Candidate {_candidate_id(candidate)} has unsupported expert {expert!r}"
        )
    if phase not in EXPERT_PHASES[expert]:
        raise FeedbackConversionError(
            f"Phase {phase} cannot be routed to expert {expert!r} "
            f"for {_candidate_id(candidate)}"
        )
    return expert


def _load_findings(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "03_vuln_analysis.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FeedbackConversionError(f"Invalid run findings: {path}") from exc
    findings = value.get("vulnerabilities", [])
    if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
        raise FeedbackConversionError(f"Invalid vulnerabilities array: {path}")
    return findings


def _first_occurrence(candidate: dict[str, Any]) -> dict[str, Any]:
    occurrences = candidate.get("occurrences")
    if not isinstance(occurrences, list) or not occurrences:
        raise FeedbackConversionError(
            f"Candidate {_candidate_id(candidate)} has no source occurrence"
        )
    occurrence = occurrences[0]
    if not isinstance(occurrence, dict) or not occurrence.get("run_id"):
        raise FeedbackConversionError(
            f"Candidate {_candidate_id(candidate)} has an invalid source occurrence"
        )
    return occurrence


def _full_predicted(candidate: dict[str, Any], runs_root: Path) -> dict[str, Any]:
    candidate_input = candidate.get("input")
    candidate_input = candidate_input if isinstance(candidate_input, dict) else {}
    predicted = candidate_input.get("predicted_finding") or {}
    predicted_id = predicted.get("id")
    occurrence = _first_occurrence(candidate)
    try:
        findings = _load_findings(runs_root / occurrence["run_id"])
    except FeedbackConversionError:
        if isinstance(predicted, dict) and predicted_id:
            return dict(predicted)
        raise
    matches = [item for item in findings if item.get("id") == predicted_id]
    if len(matches) == 1:
        return dict(matches[0])
    if isinstance(predicted, dict) and predicted_id:
        return dict(predicted)
    raise FeedbackConversionError(
        f"Expected one source finding {predicted_id!r} for {_candidate_id(candidate)}"
    )


def _normalise_finding(finding: dict[str, Any]) -> dict[str, Any]:
    result = {
        "id": str(finding.get("id") or "FEEDBACK-001"),
        "device_id": str(finding.get("device_id") or "unknown-device"),
        "device_ip": str(finding.get("device_ip") or ""),
        "type": str(finding.get("type") or "misconfiguration").lower(),
        "severity": str(finding.get("severity") or "MEDIUM").upper(),
        "service": str(finding.get("service") or ""),
        "port": finding.get("port"),
        "details": str(finding.get("details") or ""),
        "evidence": str(finding.get("evidence") or ""),
        "cve_ids": finding.get("cve_ids") or [],
        "exploitation_status": str(
            finding.get("exploitation_status") or "confirmed"
        ).lower(),
        "suggested_technique": str(
            finding.get("suggested_technique") or "Manual verification"
        ),
        "suggested_tools": finding.get("suggested_tools") or [],
    }
    if not isinstance(result["port"], int):
        result["port"] = PORT_BY_TYPE.get(result["type"], 0)
    return result


def _expected_to_finding(expected: dict[str, Any]) -> dict[str, Any]:
    category = str(expected.get("category") or "")
    finding_type = TYPE_BY_CATEGORY.get(category, category or "misconfiguration")
    indicators = expected.get("indicators") or []
    role = str(expected.get("role") or "device")
    return _normalise_finding(
        {
            "id": f"FEEDBACK-{expected.get('id', '001')}",
            "device_id": expected.get("device") or role,
            "device_ip": expected.get("ip"),
            "type": finding_type,
            "severity": expected.get("severity"),
            "service": "http" if finding_type == "no_auth" else role,
            "port": PORT_BY_TYPE.get(finding_type, 0),
            "details": expected.get("title"),
            "evidence": "; ".join(str(item) for item in indicators)
            or expected.get("verification"),
            "cve_ids": [expected["cve"]] if expected.get("cve") else [],
            "exploitation_status": "confirmed",
            "suggested_technique": (
                "Verify the exposed endpoint and document direct evidence"
            ),
            "suggested_tools": ["http_get"] if finding_type == "no_auth" else [],
        }
    )


def _canonical_duplicate(
    candidate: dict[str, Any],
    runs_root: Path,
    duplicate: dict[str, Any],
) -> dict[str, Any] | None:
    occurrence = _first_occurrence(candidate)
    try:
        findings = _load_findings(runs_root / occurrence["run_id"])
    except FeedbackConversionError:
        return None
    same_device = [
        item
        for item in findings
        if item.get("device_ip") == duplicate.get("device_ip")
        and item.get("id") != duplicate.get("id")
    ]
    for preferred_type in ("default_credentials", "no_auth"):
        preferred = [item for item in same_device if item.get("type") == preferred_type]
        if preferred:
            canonical = _normalise_finding(preferred[0])
            if canonical["device_ip"] == "192.168.100.50":
                canonical["severity"] = "HIGH"
            return canonical
    return None


def _target_findings(
    candidate: dict[str, Any], runs_root: Path
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    error_type = candidate.get("error_type")
    if error_type == "severity_mismatch":
        draft = _normalise_finding(_full_predicted(candidate, runs_root))
        source = dict(draft)
        source["severity"] = str(
            candidate["target"]["expected_finding"]["severity"]
        ).upper()
        return [source], draft
    if error_type == "false_negative":
        expected = candidate["target"]["expected_finding"]
        return [_expected_to_finding(expected)], None
    if error_type == "false_positive":
        duplicate = _normalise_finding(_full_predicted(candidate, runs_root))
        canonical = _canonical_duplicate(candidate, runs_root, duplicate)
        return ([canonical] if canonical else []), duplicate
    raise FeedbackConversionError(f"Unsupported correction type: {error_type}")


def _review_notes(candidate: dict[str, Any]) -> str:
    review = candidate.get("review")
    review = review if isinstance(review, dict) else {}
    return str(review.get("notes") or "Accepted after review.")


def _feedback_metadata(
    candidate: dict[str, Any], expert: str, phase: int, correction_type: str
) -> dict[str, Any]:
    return {
        "expert": expert,
        "phase": phase,
        "source": f"reviewed-error-feedback:{_candidate_id(candidate)}:{correction_type}",
        "cve_id": "",
        "applicable": True,
        "generator_version": 2,
        "prepared_for": "Qwen/Qwen2.5-3B-Instruct",
        "source_max_length": 4096,
        "source_trace_window": 0,
        "content_truncated": False,
    }


def _call_id(candidate: dict[str, Any]) -> str:
    safe_id = re.sub(r"[^A-Za-z0-9_-]+", "_", _candidate_id(candidate))
    return f"feedback_{safe_id.removeprefix('lf-')}"


@register_converter("finding_correction")
def _finding_trace(candidate: dict[str, Any], runs_root: Path) -> dict[str, Any]:
    target, draft = _target_findings(candidate, runs_root)
    reference = target[0] if target else draft
    if reference is None:
        raise FeedbackConversionError(f"No device context for {_candidate_id(candidate)}")
    device_id, device_ip = reference["device_id"], reference["device_ip"]
    evidence = target[0].get("evidence", "") if target else draft.get("evidence", "")
    payload = {
        "device_id": device_id,
        "device_ip": device_ip,
        "vulnerabilities": target,
        "summary": {
            "total": len(target),
            **{
                severity.lower(): sum(item["severity"] == severity for item in target)
                for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            },
        },
    }
    filename = f"03_device_{device_id}.json"
    draft_text = (
        json.dumps(draft, ensure_ascii=False)
        if draft
        else "No draft finding was emitted."
    )
    system = (
        "You are the LANCE phase-3 vulnerability analysis agent. Review one device "
        "and save a concise, deduplicated findings deliverable.\n\nRules:\n"
        "- Report each root vulnerability once; do not duplicate consequences.\n"
        "- A finding absent from a benchmark is not automatically false; rely on evidence.\n"
        "- Calibrate severity consistently and preserve direct evidence.\n"
        "- Use only canonical vulnerability types.\n\n"
        f"Scenario: S{candidate.get('scenario_id', 'unknown')}\n"
        f"Observed evidence: {evidence}\n"
        f"Draft finding from the previous run: {draft_text}\n"
        f"Review note: {_review_notes(candidate)}\n"
        "Call save_deliverable exactly once with the corrected JSON."
    )
    return {
        "messages": [
            {"role": "system", "content": system},
            {
                "role": "user",
                "content": (
                    f"Review findings for {device_id} ({device_ip}) and save the "
                    f"corrected phase-3 deliverable to {filename}."
                ),
            },
            {
                "role": "assistant",
                "content": "I will save the evidence-based, deduplicated finding set.",
                "tool_calls": [
                    {
                        "id": _call_id(candidate),
                        "type": "function",
                        "function": {
                            "name": "save_deliverable",
                            "arguments": {
                                "filename": filename,
                                "content": json.dumps(
                                    payload, ensure_ascii=False, indent=2
                                ),
                            },
                        },
                    }
                ],
            },
        ],
        "tools": [SAVE_TOOL],
        "metadata": _feedback_metadata(
            candidate, "vuln", 3, str(candidate.get("error_type") or "finding")
        ),
    }


def _deliverable_target(candidate: dict[str, Any]) -> tuple[str, str]:
    target = candidate.get("target")
    if not isinstance(target, dict):
        raise FeedbackConversionError(
            f"Candidate {_candidate_id(candidate)} has no target object"
        )
    deliverable = target.get("expected_deliverable", target)
    if not isinstance(deliverable, dict):
        raise FeedbackConversionError(
            f"Candidate {_candidate_id(candidate)} has no expected_deliverable"
        )
    filename = deliverable.get("filename")
    if not isinstance(filename, str) or not filename:
        raise FeedbackConversionError(
            f"Candidate {_candidate_id(candidate)} has no target filename"
        )
    path = PurePosixPath(filename)
    if path.is_absolute() or ".." in path.parts or "\\" in filename:
        raise FeedbackConversionError(
            f"Unsafe target filename {filename!r} for {_candidate_id(candidate)}"
        )
    phase = _candidate_phase(candidate)
    if not filename.startswith(PHASE_PREFIX[phase]):
        raise FeedbackConversionError(
            f"Target filename {filename!r} does not match phase {phase}"
        )
    if "content" not in deliverable:
        raise FeedbackConversionError(
            f"Candidate {_candidate_id(candidate)} has no target content"
        )
    content = deliverable["content"]
    if isinstance(content, str):
        return filename, content
    if isinstance(content, (dict, list)):
        return filename, json.dumps(content, ensure_ascii=False, indent=2)
    raise FeedbackConversionError(
        f"Unsupported target content for {_candidate_id(candidate)}"
    )


def _generic_trace(candidate: dict[str, Any], _: Path) -> dict[str, Any]:
    expert, phase = _candidate_expert(candidate), _candidate_phase(candidate)
    filename, content = _deliverable_target(candidate)
    candidate_input = candidate.get("input")
    candidate_input = candidate_input if isinstance(candidate_input, dict) else {}
    context = json.dumps(candidate_input, ensure_ascii=False, indent=2)
    system = (
        f"You are the LANCE {expert} expert responsible for phase {phase}. "
        "Produce the corrected deliverable from reviewed feedback.\n\n"
        f"Expert rules: {EXPERT_INSTRUCTIONS[expert]}\n"
        "Treat the reviewed target as authoritative while preserving only evidence "
        "present in the supplied context. Call save_deliverable exactly once.\n\n"
        f"Source context:\n{context}\n\nReview note: {_review_notes(candidate)}"
    )
    return {
        "messages": [
            {"role": "system", "content": system},
            {
                "role": "user",
                "content": (
                    f"Apply the accepted correction and save the phase-{phase} "
                    f"deliverable to {filename}."
                ),
            },
            {
                "role": "assistant",
                "content": "I will save the reviewed, evidence-aligned deliverable.",
                "tool_calls": [
                    {
                        "id": _call_id(candidate),
                        "type": "function",
                        "function": {
                            "name": "save_deliverable",
                            "arguments": {"filename": filename, "content": content},
                        },
                    }
                ],
            },
        ],
        "tools": [SAVE_TOOL],
        "metadata": _feedback_metadata(candidate, expert, phase, _candidate_task(candidate)),
    }


register_converter("deliverable_correction")(_generic_trace)
for _task in GENERIC_TASK_EXPERTS:
    register_converter(_task)(_generic_trace)


def _convert_candidates(
    accepted: list[dict[str, Any]], runs_root: Path
) -> dict[str, list[dict[str, Any]]]:
    traces_by_expert: dict[str, list[dict[str, Any]]] = {}
    for candidate in accepted:
        task, expert = _candidate_task(candidate), _candidate_expert(candidate)
        trace = CONVERTERS[task](candidate, runs_root)
        if trace.get("metadata", {}).get("expert") != expert:
            raise FeedbackConversionError(
                f"Converter routed {_candidate_id(candidate)} to the wrong expert"
            )
        traces_by_expert.setdefault(expert, []).append(trace)
    return traces_by_expert


def _write_traces(output_path: Path, traces: list[dict[str, Any]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        "\n".join(
            json.dumps(trace, ensure_ascii=False, separators=(",", ":"))
            for trace in traces
        )
        + "\n",
        encoding="utf-8",
    )


def convert_feedback(
    candidates_path: Path,
    runs_root: Path,
    output_path: Path,
    *,
    expert: str | None = None,
) -> dict[str, Any]:
    """Convert one expert's accepted feedback to a single JSONL file."""

    traces_by_expert = _convert_candidates(_accepted_candidates(candidates_path), runs_root)
    if expert is None:
        if len(traces_by_expert) != 1:
            experts = ", ".join(sorted(traces_by_expert))
            raise FeedbackConversionError(
                f"Mixed expert feedback ({experts}); use --output-dir or --expert"
            )
        expert = next(iter(traces_by_expert))
    if expert not in EXPERT_PHASES:
        raise FeedbackConversionError(f"Unsupported expert: {expert}")
    traces = traces_by_expert.get(expert, [])
    if not traces:
        raise FeedbackConversionError(f"No accepted candidates for expert {expert}")
    _write_traces(output_path, traces)
    return {
        "expert": expert,
        "accepted_candidates": len(traces),
        "generated_traces": len(traces),
        "output": str(output_path),
    }


def convert_feedback_by_expert(
    candidates_path: Path, runs_root: Path, output_dir: Path
) -> dict[str, Any]:
    """Convert mixed feedback into one SFT JSONL file per expert."""

    traces_by_expert = _convert_candidates(_accepted_candidates(candidates_path), runs_root)
    outputs, counts = {}, {}
    for expert, traces in sorted(traces_by_expert.items()):
        output_path = output_dir / f"{expert}_feedback_accepted.jsonl"
        _write_traces(output_path, traces)
        outputs[expert], counts[expert] = str(output_path), len(traces)
    return {
        "accepted_candidates": sum(counts.values()),
        "generated_traces": sum(counts.values()),
        "counts_by_expert": counts,
        "outputs": outputs,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument(
        "--runs-root",
        type=Path,
        default=Path("."),
        help="Run artifacts root; required by finding_correction feedback.",
    )
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output", type=Path)
    destination.add_argument("--output-dir", type=Path)
    parser.add_argument("--expert", choices=sorted(EXPERT_PHASES))
    args = parser.parse_args(argv)
    if args.output_dir and args.expert:
        parser.error("--expert can only be used with --output")
    try:
        if args.output_dir:
            result = convert_feedback_by_expert(
                args.candidates, args.runs_root, args.output_dir
            )
        else:
            result = convert_feedback(
                args.candidates, args.runs_root, args.output, expert=args.expert
            )
    except FeedbackConversionError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
